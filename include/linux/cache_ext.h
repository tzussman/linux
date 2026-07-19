/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cache_ext: BPF-managed page cache eviction policies.
 */
#ifndef _LINUX_CACHE_EXT_H
#define _LINUX_CACHE_EXT_H

#include <linux/types.h>

struct folio;
struct mem_cgroup;

/**
 * struct cache_ext_eviction_ctx - one eviction request to a policy.
 * @request_nr_folios: number of folios the kernel wants handed over.
 * @nid: NUMA node reclaim is targeting, or NUMA_NO_NODE.
 * @nr_evicted: folios handed over so far; maintained by
 *		bpf_cache_ext_evict(), read-only to the program.
 *
 * The context intentionally carries no folio pointers. Folios are handed
 * over exclusively through the bpf_cache_ext_evict() kfunc, which takes a
 * trusted folio and claims it kernel-side, so a policy can never inject a
 * pointer the kernel would have to revalidate.
 */
struct cache_ext_eviction_ctx {
	u64 request_nr_folios;
	int nid;
	u64 nr_evicted;
};

/**
 * struct cache_ext_ops - a BPF page cache eviction policy.
 *
 * A policy is attached to a cgroup through a struct_ops link and governs
 * the memcgs in that cgroup's subtree (nearest attached ancestor wins).
 * All callbacks except init() run under RCU and must not sleep. Folio
 * arguments are trusted pointers valid for the duration of the call.
 */
struct cache_ext_ops {
	/**
	 * @init: Set up policy state for one memcg.
	 *
	 * Runs once per governed memcg before any other callback for it.
	 * May be sleepable; this is the only callback allowed to call
	 * bpf_cache_ext_list_create(). A negative return aborts the
	 * attachment.
	 */
	s32 (*init)(struct mem_cgroup *memcg);

	/**
	 * @evict_folios: The kernel is under memory pressure and asks the
	 * policy to hand over up to ctx->request_nr_folios folios via
	 * bpf_cache_ext_evict(). Handing over fewer (or none) is legal;
	 * the kernel falls back to the LRU for the remainder and may
	 * force-claim folios if the policy consistently starves reclaim.
	 */
	void (*evict_folios)(struct cache_ext_eviction_ctx *ctx,
			     struct mem_cgroup *memcg);

	/**
	 * @folio_added: A folio was inserted into the page cache. The
	 * policy may take ownership with bpf_cache_ext_list_add(); if it
	 * does not, the folio goes to the kernel LRU as usual.
	 */
	void (*folio_added)(struct folio *folio);

	/**
	 * @folio_accessed: An owned folio was accessed.
	 */
	void (*folio_accessed)(struct folio *folio);

	/**
	 * @folio_evicted: An owned folio was claimed away by the kernel for
	 * a reason the policy did not initiate: truncation or other page
	 * cache removal, or a THP split. Bookkeeping only; the folio is no
	 * longer owned when this runs. Not called for folios the policy
	 * itself evicts via bpf_cache_ext_evict(), nor for the near-OOM
	 * force-release or detach-time drain, where per-folio notification
	 * would run in the reclaim or teardown path.
	 */
	void (*folio_evicted)(struct folio *folio);

	/**
	 * @admit_folio: Should this newly inserted folio be cached at all?
	 * Returning false marks the folio dropbehind: it is read once and
	 * dropped on IO completion instead of polluting the cache.
	 */
	bool (*admit_folio)(struct folio *folio);

	/**
	 * @exit: Tear down policy state for one memcg.
	 *
	 * Pairs with @init: runs once per governed memcg after the domain
	 * has been unpublished and drained (every list is empty, no folio
	 * is owned), on detach, replacement, and memcg offlining. May be
	 * sleepable. Bookkeeping only — no folio-taking kfunc can succeed
	 * from here; use it to drop per-memcg map state that would
	 * otherwise go stale across attachments.
	 */
	void (*exit)(struct mem_cgroup *memcg);
};

#ifdef CONFIG_CACHE_EXT

void cache_ext_memcg_offline(struct mem_cgroup *memcg);
int cache_ext_memcg_online(struct mem_cgroup *memcg);

#else /* CONFIG_CACHE_EXT */

static inline void cache_ext_memcg_offline(struct mem_cgroup *memcg)
{
}

static inline int cache_ext_memcg_online(struct mem_cgroup *memcg)
{
	return 0;
}

#endif /* CONFIG_CACHE_EXT */

#endif /* _LINUX_CACHE_EXT_H */
