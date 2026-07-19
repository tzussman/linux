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

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/workqueue.h>

struct bpf_map;
struct cache_ext_ops;
struct folio;
struct mem_cgroup;

/*
 * A policy allocates its lists from a small fixed array during init().
 * Handles given out to BPF are indices into it, so validating a handle is
 * a bounds check rather than a hash lookup.
 */
#define CACHE_EXT_MAX_LISTS	8

struct cache_ext_list {
	struct list_head head;
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

	struct work_struct teardown_work;
	struct rcu_head rcu;
};

struct cache_ext_domain *cache_ext_domain_alloc(struct mem_cgroup *memcg);
void cache_ext_domain_free(struct cache_ext_domain *domain);

int cache_ext_list_create(struct cache_ext_domain *domain);

bool cache_ext_place_folio(struct cache_ext_domain *domain, u64 handle,
			   struct folio *folio, bool tail);
bool cache_ext_move_folio(struct cache_ext_domain *domain, u64 handle,
			  struct folio *folio, bool tail);
bool cache_ext_claim_folio(struct cache_ext_domain *domain,
			   struct folio *folio);
void cache_ext_domain_drain(struct cache_ext_domain *domain);

#endif /* _MM_CACHE_EXT_H */
