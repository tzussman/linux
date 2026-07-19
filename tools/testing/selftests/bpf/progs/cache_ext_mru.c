// SPDX-License-Identifier: GPL-2.0
/*
 * MRU (most-recently-used) page cache eviction policy.
 *
 * The point of this policy is the classic case where LRU is pessimal: a
 * cyclic sequential scan of a file larger than the cache. LRU (and MGLRU)
 * keep the most recently touched pages, which under a loop are exactly the
 * ones needed last, so every access misses. MRU keeps the least-recently-
 * accessed pages — the ones the scan is about to reach — and evicts the
 * just-accessed ones, so a stable working set stays resident and is hit on
 * every loop.
 *
 * Folios are kept on one list ordered by recency, most-recent at the head
 * (folio_accessed moves a folio there). Eviction walks from the head and
 * evicts the most-recently-used folios — but skips the newest ones that are
 * still in flight (not uptodate, or locked/dirty/under writeback). Handing
 * such a folio to the kernel would just fail to reclaim it and bounce it to
 * the kernel LRU; worse, if the kernel then keeps asking, it marches this
 * policy's cursor into the working set it is trying to retain. This mirrors
 * the original cache_ext MRU policy, which skipped its first ~200 nodes for
 * the same reason.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

extern s32 bpf_cache_ext_list_create(struct mem_cgroup *memcg) __ksym;
extern int bpf_cache_ext_list_add(struct folio *folio, u64 list) __ksym;
extern int bpf_cache_ext_list_move(struct folio *folio, u64 list,
				   bool tail) __ksym;
extern int bpf_cache_ext_evict(struct cache_ext_eviction_ctx *ctx,
			       struct folio *folio) __ksym;
extern int bpf_iter_cache_ext_list_new(struct bpf_iter_cache_ext_list *it,
				       struct mem_cgroup *memcg,
				       u64 list) __ksym;
extern struct folio *
bpf_iter_cache_ext_list_next(struct bpf_iter_cache_ext_list *it) __ksym;
extern void
bpf_iter_cache_ext_list_destroy(struct bpf_iter_cache_ext_list *it) __ksym;

static u64 list;

/* volatile so the verifier converges on the loop instead of unrolling. */
static volatile __u32 scan_budget;
#define SCAN_LIMIT	4096

#define F_LOCKED	(1UL << 0)	/* PG_locked */
#define F_WRITEBACK	(1UL << 1)	/* PG_writeback */
#define F_UPTODATE	(1UL << 3)	/* PG_uptodate */
#define F_DIRTY		(1UL << 4)	/* PG_dirty */

__u64 nr_added;
__u64 nr_hits;
__u64 nr_evicted;

SEC("struct_ops.s/init")
s32 BPF_PROG(mru_init, struct mem_cgroup *memcg)
{
	s32 l = bpf_cache_ext_list_create(memcg);

	if (l < 0)
		return l;
	list = l;
	return 0;
}

SEC("struct_ops/folio_added")
void BPF_PROG(mru_folio_added, struct folio *folio)
{
	/* Newest at the head. */
	if (!bpf_cache_ext_list_add(folio, list))
		__sync_fetch_and_add(&nr_added, 1);
}

SEC("struct_ops/folio_accessed")
void BPF_PROG(mru_folio_accessed, struct folio *folio)
{
	/* Accessing a folio makes it most-recent: move it to the head. */
	if (!bpf_cache_ext_list_move(folio, list, false))
		__sync_fetch_and_add(&nr_hits, 1);
}

/* A folio is safe to hand to the kernel for reclaim only when settled. */
static bool folio_reclaimable(struct folio *folio)
{
	unsigned long f = folio->flags.f;

	return (f & F_UPTODATE) &&
	       !(f & (F_LOCKED | F_DIRTY | F_WRITEBACK));
}

SEC("struct_ops/evict_folios")
void BPF_PROG(mru_evict_folios, struct cache_ext_eviction_ctx *ectx,
	      struct mem_cgroup *memcg)
{
	struct bpf_iter_cache_ext_list it;
	struct folio *folio;

	scan_budget = SCAN_LIMIT;
	if (bpf_iter_cache_ext_list_new(&it, memcg, list))
		goto out;

	/*
	 * Head is the most-recently-used folio; evicting from here is MRU.
	 * Skip the newest folios that are still in flight — the current read
	 * is touching them — and hand over only settled folios the kernel can
	 * actually reclaim. Evicting an in-flight folio would just bounce it
	 * to the kernel LRU and, worse, make the kernel keep asking, marching
	 * this cursor into the working set MRU is trying to retain.
	 */
	while ((folio = bpf_iter_cache_ext_list_next(&it))) {
		if (scan_budget-- == 0)
			break;
		if (!folio_reclaimable(folio))
			continue;
		if (bpf_cache_ext_evict(ectx, folio))
			break;
		__sync_fetch_and_add(&nr_evicted, 1);
	}
out:
	bpf_iter_cache_ext_list_destroy(&it);
}

SEC(".struct_ops.link")
struct cache_ext_ops mru_ops = {
	.init = (void *)mru_init,
	.folio_added = (void *)mru_folio_added,
	.folio_accessed = (void *)mru_folio_accessed,
	.evict_folios = (void *)mru_evict_folios,
	.name = "mru",
};
