// SPDX-License-Identifier: GPL-2.0
/*
 * A deliberately hostile cache_ext policy. Every callback abuses the kfunc
 * surface in ways the kernel must refuse: re-adopting folios it just gave
 * up (would double-link folio->lru), using bogus list handles, evicting
 * folios it no longer owns, nesting iterators, and overflowing the list
 * table. The pass condition is not good cache behavior — it is that every
 * abuse is refused, the counters prove the refusals happened, and the
 * kernel survives with everything accounted for.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern s32 bpf_cache_ext_list_create(struct mem_cgroup *memcg) __ksym;
extern int bpf_cache_ext_list_add(struct folio *folio, u64 list) __ksym;
extern int bpf_cache_ext_list_add_tail(struct folio *folio, u64 list) __ksym;
extern int bpf_cache_ext_list_move(struct folio *folio, u64 list,
				   bool tail) __ksym;
extern int bpf_cache_ext_list_del(struct folio *folio) __ksym;
extern int bpf_cache_ext_evict(struct cache_ext_eviction_ctx *ctx,
			       struct folio *folio) __ksym;
extern int bpf_iter_cache_ext_list_new(struct bpf_iter_cache_ext_list *it,
				       struct mem_cgroup *memcg,
				       u64 list) __ksym;
extern struct folio *
bpf_iter_cache_ext_list_next(struct bpf_iter_cache_ext_list *it) __ksym;
extern void
bpf_iter_cache_ext_list_destroy(struct bpf_iter_cache_ext_list *it) __ksym;

#define BOGUS_LIST	42

static u64 list0;

__u64 nr_lists_created;
__u64 nr_create_blocked;
__u64 nr_readd_blocked;
__u64 nr_bogus_add_blocked;
__u64 nr_bogus_move_blocked;
__u64 nr_stale_evict_blocked;
__u64 nr_iter_busy;
__u64 nr_ctx_add_blocked;
__u64 nr_added;
__u64 nr_evicted;

SEC("struct_ops.s/init")
s32 BPF_PROG(hostile_init, struct mem_cgroup *memcg)
{
	s32 ret;
	int i;

	/* Exhaust the list table; creation past the limit must fail. */
	for (i = 0; i < 16; i++) {
		ret = bpf_cache_ext_list_create(memcg);
		if (ret < 0) {
			__sync_fetch_and_add(&nr_create_blocked, 1);
			break;
		}
		if (i == 0)
			list0 = ret;
		__sync_fetch_and_add(&nr_lists_created, 1);
	}
	return 0;
}

SEC("struct_ops/folio_added")
void BPF_PROG(hostile_folio_added, struct folio *folio)
{
	/* Bogus handles must be refused. */
	if (bpf_cache_ext_list_add(folio, BOGUS_LIST))
		__sync_fetch_and_add(&nr_bogus_add_blocked, 1);

	if (folio->index & 1) {
		/* Behave for odd indexes so eviction has something to do. */
		if (!bpf_cache_ext_list_add_tail(folio, list0))
			__sync_fetch_and_add(&nr_added, 1);
		if (bpf_cache_ext_list_move(folio, BOGUS_LIST, true))
			__sync_fetch_and_add(&nr_bogus_move_blocked, 1);
	} else {
		/*
		 * The double-link attack: adopt, give the folio back (it is
		 * now headed for the kernel LRU through the per-CPU batch,
		 * PG_lru not yet set), then try to adopt it again. The
		 * second adoption must be refused or folio->lru would be
		 * linked into two lists at once.
		 */
		if (bpf_cache_ext_list_add_tail(folio, list0))
			return;
		if (bpf_cache_ext_list_del(folio))
			return;
		if (bpf_cache_ext_list_add(folio, list0))
			__sync_fetch_and_add(&nr_readd_blocked, 1);
	}
}

SEC("struct_ops/folio_accessed")
void BPF_PROG(hostile_folio_accessed, struct folio *folio)
{
	/* Adoption is only legal from folio_added(); this must fail. */
	if (bpf_cache_ext_list_add(folio, list0))
		__sync_fetch_and_add(&nr_ctx_add_blocked, 1);
}

SEC("struct_ops/evict_folios")
void BPF_PROG(hostile_evict_folios, struct cache_ext_eviction_ctx *ectx,
	      struct mem_cgroup *memcg)
{
	struct bpf_iter_cache_ext_list it, it2;
	struct folio *folio;
	bool abused = false;

	if (bpf_iter_cache_ext_list_new(&it, memcg, list0))
		goto out;

	/* A second iterator on the same list must be refused. */
	if (bpf_iter_cache_ext_list_new(&it2, memcg, list0) == -16 /* EBUSY */)
		__sync_fetch_and_add(&nr_iter_busy, 1);
	bpf_iter_cache_ext_list_destroy(&it2);

	while ((folio = bpf_iter_cache_ext_list_next(&it))) {
		if (!abused) {
			/*
			 * Give the folio up, then try to evict it anyway.
			 * The stale eviction must be refused.
			 */
			abused = true;
			if (bpf_cache_ext_list_del(folio))
				continue;
			if (bpf_cache_ext_evict(ectx, folio))
				__sync_fetch_and_add(&nr_stale_evict_blocked, 1);
			continue;
		}
		if (bpf_cache_ext_evict(ectx, folio))
			break;
		__sync_fetch_and_add(&nr_evicted, 1);
	}
out:
	bpf_iter_cache_ext_list_destroy(&it);
}

SEC(".struct_ops.link")
struct cache_ext_ops hostile_ops = {
	.init = (void *)hostile_init,
	.folio_added = (void *)hostile_folio_added,
	.folio_accessed = (void *)hostile_folio_accessed,
	.evict_folios = (void *)hostile_evict_folios,
	.name = "hostile",
};
