// SPDX-License-Identifier: GPL-2.0
/* FIFO page cache eviction policy: evict in insertion order. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern s32 bpf_cache_ext_list_create(struct mem_cgroup *memcg) __ksym;
extern int bpf_cache_ext_list_add_tail(struct folio *folio, u64 list) __ksym;
extern int bpf_cache_ext_evict(struct cache_ext_eviction_ctx *ctx,
			       struct folio *folio) __ksym;
extern int bpf_iter_cache_ext_list_new(struct bpf_iter_cache_ext_list *it,
				       struct mem_cgroup *memcg,
				       u64 list) __ksym;
extern struct folio *
bpf_iter_cache_ext_list_next(struct bpf_iter_cache_ext_list *it) __ksym;
extern void
bpf_iter_cache_ext_list_destroy(struct bpf_iter_cache_ext_list *it) __ksym;

static u64 main_list;

__u64 nr_added;
__u64 nr_evict_requests;
__u64 nr_evicted;

SEC("struct_ops.s/init")
s32 BPF_PROG(fifo_init, struct mem_cgroup *memcg)
{
	s32 list = bpf_cache_ext_list_create(memcg);

	if (list < 0)
		return list;
	main_list = list;
	return 0;
}

SEC("struct_ops/folio_added")
void BPF_PROG(fifo_folio_added, struct folio *folio)
{
	if (!bpf_cache_ext_list_add_tail(folio, main_list))
		__sync_fetch_and_add(&nr_added, 1);
}

SEC("struct_ops/evict_folios")
void BPF_PROG(fifo_evict_folios, struct cache_ext_eviction_ctx *ectx,
	      struct mem_cgroup *memcg)
{
	struct bpf_iter_cache_ext_list it;
	struct folio *folio;

	__sync_fetch_and_add(&nr_evict_requests, 1);

	if (bpf_iter_cache_ext_list_new(&it, memcg, main_list))
		goto out;

	while ((folio = bpf_iter_cache_ext_list_next(&it))) {
		/* Not worth an IO round-trip for a FIFO test policy. */
		if (folio->flags.f & ((1UL << PG_dirty) | (1UL << PG_writeback)))
			continue;
		if (bpf_cache_ext_evict(ectx, folio))
			break;
		__sync_fetch_and_add(&nr_evicted, 1);
	}
out:
	bpf_iter_cache_ext_list_destroy(&it);
}

SEC(".struct_ops.link")
struct cache_ext_ops fifo_ops = {
	.init = (void *)fifo_init,
	.folio_added = (void *)fifo_folio_added,
	.evict_folios = (void *)fifo_evict_folios,
};

/* Second instance, for exercising live replacement via link update. */
SEC(".struct_ops.link")
struct cache_ext_ops fifo_ops2 = {
	.init = (void *)fifo_init,
	.folio_added = (void *)fifo_folio_added,
	.evict_folios = (void *)fifo_evict_folios,
};

/*
 * A policy that adopts nothing. Used as an attachment-precedence pawn:
 * while it governs a memcg, every folio stays with the kernel LRU.
 */
SEC("struct_ops.s/init")
s32 BPF_PROG(noop_init, struct mem_cgroup *memcg)
{
	return 0;
}

SEC(".struct_ops.link")
struct cache_ext_ops noop_ops = {
	.init = (void *)noop_init,
};

/* A policy whose per-memcg setup always fails; attaching it must fail. */
SEC("struct_ops.s/init")
s32 BPF_PROG(failing_init, struct mem_cgroup *memcg)
{
	return -22; /* -EINVAL */
}

SEC(".struct_ops.link")
struct cache_ext_ops fail_ops = {
	.init = (void *)failing_init,
};
