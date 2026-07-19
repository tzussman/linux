/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cache_ext: BPF-managed page cache eviction policies.
 *
 * Internal definitions shared between the cache_ext core and its BPF
 * plumbing. Nothing in here is visible to policies; the BPF-facing
 * interface lives in include/linux/cache_ext.h.
 */
#ifndef _MM_CACHE_EXT_H
#define _MM_CACHE_EXT_H

#include <linux/cache_ext.h>
#include <linux/jump_label.h>
#include <linux/list.h>
#include <linux/memcontrol.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct bpf_map;
struct cache_ext_ops;
struct folio;
struct mem_cgroup;

#ifdef CONFIG_CACHE_EXT

/*
 * A policy allocates its lists from a small fixed array during init().
 * Handles given out to BPF are indices into it, so validating a handle is
 * a bounds check rather than a hash lookup.
 */
#define CACHE_EXT_MAX_LISTS	8

struct cache_ext_list {
	struct list_head head;
	/*
	 * Cursor of the (single) active iterator, threaded into ->head
	 * among the folios while ->iter_active. Entries on a policy list
	 * are folios linked via folio->lru, which leaves no way to tag an
	 * in-list cursor as "not a folio" — so there is exactly one cursor
	 * per list, at a known address, and at most one iterator at a time.
	 */
	struct list_head cursor;
	bool iter_active;
	bool in_use;
};

enum cache_ext_domain_state {
	CACHE_EXT_ATTACHED,
	CACHE_EXT_DRAINING,
};

/*
 * Per-memcg policy state. Reached from the hot paths through
 * mem_cgroup::cache_ext under RCU; freed through an RCU grace period after
 * the pointer is cleared.
 *
 * ->lock is a leaf lock: it nests inside the page cache xa_lock (the folio
 * removal path claims folios back while holding it) and must never be held
 * across acquiring the lruvec lock, the xa_lock, or a call into BPF. It is
 * irq-safe because the xa_lock nesting runs with interrupts disabled.
 */
struct cache_ext_domain {
	spinlock_t lock;
	enum cache_ext_domain_state state;
	struct cache_ext_list lists[CACHE_EXT_MAX_LISTS];
	unsigned int nr_lists;
	unsigned long nr_folios;

	/* Serializes evict_folios() among concurrent reclaimers. */
	struct mutex evict_mutex;

	struct cache_ext_ops *ops;	/* struct_ops kdata */
	struct bpf_map *map;		/* reference held for ->ops' lifetime */
	struct mem_cgroup *memcg;	/* css reference held until teardown */

	/*
	 * Task running this domain's sleepable init(), while it runs.
	 * Init-only kfuncs (list creation) verify the caller against it;
	 * a per-CPU context cannot describe a sleepable callback.
	 */
	struct task_struct *init_task;

	struct work_struct teardown_work;
	struct rcu_head rcu;
};

DECLARE_STATIC_KEY_FALSE(cache_ext_enabled_key);

/*
 * Which policy callback is running on this CPU, if any. Set (with
 * preemption disabled) around every non-sleepable callback invocation and
 * checked by kfuncs whose validity depends on the calling context — the
 * same job sched_ext's kf_mask does. Sleepable callbacks (init) are
 * identified through cache_ext_domain::init_task instead.
 */
enum cache_ext_kf_ctx {
	CACHE_EXT_KF_NONE = 0,
	CACHE_EXT_KF_ADDED,
	CACHE_EXT_KF_ACCESSED,
	CACHE_EXT_KF_EVICTED,
	CACHE_EXT_KF_EVICT,
};

DECLARE_PER_CPU(enum cache_ext_kf_ctx, cache_ext_kf_ctx);

/*
 * The one folio that may be adopted in the current CACHE_EXT_KF_ADDED
 * window. Placement compares against this rather than inferring "on no
 * list" from folio state: a folio the policy just gave back sits in the
 * per-CPU LRU-add batch with PG_lru still clear, and re-adopting it would
 * double-link folio->lru. bpf_cache_ext_list_del() clears the window, so
 * adoption is one-shot per insertion.
 */
DECLARE_PER_CPU(struct folio *, cache_ext_adoptable_folio);

/*
 * Look up the policy domain governing @memcg, if any. The returned domain
 * is only stable for the duration of the RCU read-side critical section;
 * anything that must outlive it has to be pinned through place/claim.
 */
static inline struct cache_ext_domain *
mem_cgroup_cache_ext_domain(struct mem_cgroup *memcg)
{
	if (!memcg)
		return NULL;
	return rcu_dereference(memcg->cache_ext);
}

struct cache_ext_domain *cache_ext_domain_alloc(struct mem_cgroup *memcg);
void cache_ext_domain_free(struct cache_ext_domain *domain);

void cache_ext_domain_publish(struct mem_cgroup *memcg,
			      struct cache_ext_domain *domain);
struct cache_ext_domain *cache_ext_domain_unpublish(struct mem_cgroup *memcg);
void cache_ext_domain_release(struct cache_ext_domain *domain, bool sync);

int cache_ext_list_create(struct cache_ext_domain *domain);

bool cache_ext_place_folio(struct cache_ext_domain *domain, u64 handle,
			   struct folio *folio, bool tail);
bool cache_ext_move_folio(struct cache_ext_domain *domain, u64 handle,
			  struct folio *folio, bool tail);
bool cache_ext_claim_folio(struct cache_ext_domain *domain,
			   struct folio *folio);
void cache_ext_domain_drain(struct cache_ext_domain *domain);
unsigned int cache_ext_domain_force_release(struct cache_ext_domain *domain,
					    unsigned int nr);

/* Folios the kernel asks for per evict_folios() invocation, at most. */
#define CACHE_EXT_EVICTION_BATCH	32

/*
 * Reclaim priority at or below which a policy that owns folios but
 * reclaims none of them gets folios force-released to the kernel LRU.
 */
#define CACHE_EXT_OOM_PRIORITY		2

/*
 * Kernel-side wrapper around the BPF-visible eviction context. Only the
 * embedded ctx is exposed to the policy (read-only); the folios the
 * policy hands over through bpf_cache_ext_evict() are claimed and
 * collected here, with the list references inherited, so by the time
 * evict_folios() returns every folio in ->folios is off all lists with
 * the ownership bit clear and one reference held. There is no pointer a
 * policy could forge and nothing to revalidate.
 */
struct cache_ext_eviction_ctx_kern {
	struct cache_ext_eviction_ctx ctx;
	struct cache_ext_domain *domain;
	struct list_head folios;
};

void __cache_ext_folio_add_lru(struct folio *folio);
void __cache_ext_folio_removed(struct folio *folio);
bool __cache_ext_folio_accessed(struct folio *folio);
void __cache_ext_folio_release(struct folio *folio);

/*
 * Insertion hook; replaces folio_add_lru() on the page cache insertion
 * path. Runs admission and gives the governing policy (if any) the chance
 * to take ownership; folios the policy does not take go to the kernel LRU
 * as usual.
 */
static inline void cache_ext_folio_add_lru(struct folio *folio)
{
	if (static_branch_unlikely(&cache_ext_enabled_key)) {
		__cache_ext_folio_add_lru(folio);
		return;
	}
	folio_add_lru(folio);
}

/*
 * Removal hook; called after the folio has been deleted from the page
 * cache xarray (i.e. after folio->mapping has been cleared — placement
 * re-checks ->mapping under the domain lock, which is what makes this
 * pairing race-free). Claims the folio back from its policy list, if it
 * is on one, and drops the list's reference. That put is never final:
 * every remover holds the folio locked with its own reference.
 */
static inline void cache_ext_folio_removed(struct folio *folio)
{
	if (static_branch_unlikely(&cache_ext_enabled_key) &&
	    folio_test_cache_ext(folio))
		__cache_ext_folio_removed(folio);
}

/*
 * Access hook; returns true if the folio is policy-owned and the access
 * has been handed to the policy, in which case the caller must skip the
 * kernel LRU aging.
 */
static inline bool cache_ext_folio_accessed(struct folio *folio)
{
	if (static_branch_unlikely(&cache_ext_enabled_key) &&
	    folio_test_cache_ext(folio))
		return __cache_ext_folio_accessed(folio);
	return false;
}

/*
 * Give an owned folio back to the kernel LRU, e.g. because a kernel
 * operation (THP split) needs the folio in its normal, unpinned state.
 */
static inline void cache_ext_folio_release(struct folio *folio)
{
	if (static_branch_unlikely(&cache_ext_enabled_key) &&
	    folio_test_cache_ext(folio))
		__cache_ext_folio_release(folio);
}

#else /* CONFIG_CACHE_EXT */

static inline void cache_ext_folio_add_lru(struct folio *folio)
{
	folio_add_lru(folio);
}

static inline void cache_ext_folio_removed(struct folio *folio)
{
}

static inline bool cache_ext_folio_accessed(struct folio *folio)
{
	return false;
}

static inline void cache_ext_folio_release(struct folio *folio)
{
}

#endif /* CONFIG_CACHE_EXT */

#endif /* _MM_CACHE_EXT_H */
