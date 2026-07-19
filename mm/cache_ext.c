// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext: BPF-managed page cache eviction policies.
 *
 * A policy owns the file folios it chooses to track. Ownership follows the
 * same protocol the kernel LRU uses for folio->lru: a folio whose lru field
 * is linked into a policy list has PG_lru clear, so every existing
 * folio_test_lru()-gated path (isolation, migration, compaction, the
 * folio_batch operations) skips it without needing to know cache_ext
 * exists. What distinguishes a policy-owned folio from a transiently
 * isolated one is the MEMCG_DATA_CACHE_EXT bit, and unlike transient
 * isolation, the policy list holds a real folio reference.
 *
 * Ownership changes hands through exactly two primitives:
 *
 *  - place: with the domain lock held, verify the folio is still in the
 *    page cache and not on (or headed for) an LRU, take a reference, set
 *    the ownership bit and link the folio into a policy list.
 *
 *  - claim: with the domain lock held, test-and-clear the ownership bit;
 *    the winner unlinks the folio and inherits the list's reference.
 *    Everyone who needs to take an owned folio away from a policy —
 *    eviction, page cache removal, policy teardown — goes through claim,
 *    so exactly one of them succeeds no matter how they race.
 */
#include <linux/bpf.h>
#include <linux/cache_ext.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/swap.h>

#include "cache_ext.h"
#include "internal.h"

/*
 * Enabled while at least one domain is published anywhere in the system;
 * keeps every hook in the page cache paths behind a static branch.
 */
DEFINE_STATIC_KEY_FALSE(cache_ext_enabled_key);

/*
 * Set on the local CPU only while a policy's folio_added() callback runs.
 * A folio may be taken onto a policy list exclusively from there, where it
 * is provably fresh: it has just entered the page cache and has not yet
 * reached folio_add_lru(), so it is on no LRU, in no per-CPU LRU batch, and
 * in no eviction batch. Adopting a folio in any other context could race a
 * concurrent claim and double-link folio->lru. Guarded by preempt_disable()
 * around the callback so the flag reliably describes the current CPU.
 */
static DEFINE_PER_CPU(bool, cache_ext_in_folio_added);

struct cache_ext_domain *cache_ext_domain_alloc(struct mem_cgroup *memcg)
{
	struct cache_ext_domain *domain;
	int i;

	domain = kzalloc(sizeof(*domain), GFP_KERNEL);
	if (!domain)
		return NULL;

	spin_lock_init(&domain->lock);
	mutex_init(&domain->evict_mutex);
	domain->state = CACHE_EXT_ATTACHED;
	domain->memcg = memcg;
	for (i = 0; i < CACHE_EXT_MAX_LISTS; i++)
		INIT_LIST_HEAD(&domain->lists[i].head);

	return domain;
}

void cache_ext_domain_free(struct cache_ext_domain *domain)
{
	if (!domain)
		return;
	WARN_ON_ONCE(domain->nr_folios);
	kfree(domain);
}

/*
 * Hand out a new policy list. Only called from the policy's init()
 * callback, which runs single-threaded per domain before the domain is
 * published, so no locking is needed against other list creation.
 */
int cache_ext_list_create(struct cache_ext_domain *domain)
{
	unsigned int i;

	for (i = 0; i < CACHE_EXT_MAX_LISTS; i++) {
		if (!domain->lists[i].in_use) {
			domain->lists[i].in_use = true;
			domain->nr_lists++;
			return i;
		}
	}
	return -ENOSPC;
}

static struct cache_ext_list *cache_ext_get_list(struct cache_ext_domain *domain,
						 u64 handle)
{
	if (handle >= CACHE_EXT_MAX_LISTS || !domain->lists[handle].in_use)
		return NULL;
	return &domain->lists[handle];
}

static void cache_ext_stat_mod(struct folio *folio, int sign)
{
	lruvec_stat_mod_folio(folio, NR_CACHE_EXT_FILE,
			      sign * folio_nr_pages(folio));
}

/**
 * cache_ext_place_folio - transfer a folio from the kernel to a policy list.
 * @domain: policy domain of the folio's memcg.
 * @handle: policy list to place the folio on.
 * @folio: the folio; the caller must hold a reference.
 * @tail: add to the tail instead of the head.
 *
 * The folio must not be on an LRU: the only two callers that can hand a
 * folio over are the insertion hook (which runs before folio_add_lru()) and
 * an explicit adopt of a folio already isolated from the LRU. Re-checking
 * folio->mapping under the domain lock closes the race with concurrent
 * removal from the page cache: the removal path clears ->mapping before it
 * tries to claim, so either we see NULL here and refuse, or the removal
 * path sees the ownership bit and claims the folio back.
 *
 * Returns true if the folio was placed; the list now holds its own
 * reference. Returns false if the folio is not eligible (already owned,
 * still on an LRU, unevictable, or no longer in the page cache).
 */
bool cache_ext_place_folio(struct cache_ext_domain *domain, u64 handle,
			   struct folio *folio, bool tail)
{
	struct cache_ext_list *list;
	unsigned long flags;
	bool placed = false;

	spin_lock_irqsave(&domain->lock, flags);

	list = cache_ext_get_list(domain, handle);
	if (!list || domain->state != CACHE_EXT_ATTACHED)
		goto out;

	/*
	 * Only adopt a folio during its folio_added() callback, where it is
	 * fresh. Outside that context a folio that momentarily has the
	 * ownership bit clear may still be linked through folio->lru into an
	 * LRU-add batch or an eviction batch, and adopting it would corrupt
	 * that list.
	 */
	if (!this_cpu_read(cache_ext_in_folio_added))
		goto out;

	if (folio_test_lru(folio) || folio_test_cache_ext(folio))
		goto out;
	if (!folio->mapping || !folio_evictable(folio))
		goto out;
	if (folio_test_dropbehind(folio))
		goto out;

	/*
	 * An owned folio is off the kernel LRU, so it must carry no LRU
	 * placement state: workingset_refault() can set PG_active just
	 * before the insertion hook runs, and unlike a folio on the LRU
	 * (whose flags __page_cache_release() strips on the final put),
	 * nothing would clear it before the folio is freed. The policy
	 * orders folios itself and does not consult PG_active.
	 */
	folio_clear_active(folio);
	folio_clear_referenced(folio);

	folio_get(folio);
	VM_WARN_ON_ONCE_FOLIO(folio_test_set_cache_ext(folio), folio);
	if (tail)
		list_add_tail(&folio->lru, &list->head);
	else
		list_add(&folio->lru, &list->head);
	domain->nr_folios++;
	cache_ext_stat_mod(folio, 1);
	placed = true;
out:
	spin_unlock_irqrestore(&domain->lock, flags);
	return placed;
}

/**
 * cache_ext_move_folio - move an owned folio to another policy list.
 * @domain: policy domain of the folio's memcg.
 * @handle: destination list.
 * @folio: the folio; the caller must hold a reference.
 * @tail: move to the tail instead of the head.
 *
 * The check for the ownership bit under the domain lock makes this safe
 * against a concurrent claim: once someone else has claimed the folio, it
 * is no longer ours to move.
 *
 * Returns true if the folio was moved.
 */
bool cache_ext_move_folio(struct cache_ext_domain *domain, u64 handle,
			  struct folio *folio, bool tail)
{
	struct cache_ext_list *list;
	unsigned long flags;
	bool moved = false;

	spin_lock_irqsave(&domain->lock, flags);

	list = cache_ext_get_list(domain, handle);
	if (!list || !folio_test_cache_ext(folio))
		goto out;

	if (tail)
		list_move_tail(&folio->lru, &list->head);
	else
		list_move(&folio->lru, &list->head);
	moved = true;
out:
	spin_unlock_irqrestore(&domain->lock, flags);
	return moved;
}

/**
 * cache_ext_claim_folio - take an owned folio away from its policy list.
 * @domain: policy domain of the folio's memcg.
 * @folio: the folio.
 *
 * Returns true if the caller won the claim: the folio is unlinked, the
 * ownership bit is clear, and the caller has inherited the reference the
 * list was holding. Returns false if the folio was not owned (or someone
 * else claimed it first); the caller must not touch folio->lru.
 */
bool cache_ext_claim_folio(struct cache_ext_domain *domain,
			   struct folio *folio)
{
	unsigned long flags;
	bool claimed = false;

	spin_lock_irqsave(&domain->lock, flags);
	if (folio_test_clear_cache_ext(folio)) {
		list_del_init(&folio->lru);
		domain->nr_folios--;
		cache_ext_stat_mod(folio, -1);
		claimed = true;
	}
	spin_unlock_irqrestore(&domain->lock, flags);
	return claimed;
}

#define CACHE_EXT_DRAIN_BATCH	15

/**
 * cache_ext_domain_drain - return every owned folio to the kernel LRU.
 * @domain: the domain to drain.
 *
 * Marks the domain draining (which makes further placement fail) and
 * splices all owned folios back onto the kernel LRU in small batches so
 * the domain lock is never held for long. Called from policy teardown
 * after the domain has been unpublished and an RCU grace period has
 * passed, so no new folios can arrive; anything a racing truncation
 * claims out from under us is simply not ours to put back anymore.
 */
void cache_ext_domain_drain(struct cache_ext_domain *domain)
{
	struct folio *batch[CACHE_EXT_DRAIN_BATCH];
	unsigned long flags;
	unsigned int i, nr;

	spin_lock_irqsave(&domain->lock, flags);
	domain->state = CACHE_EXT_DRAINING;
	spin_unlock_irqrestore(&domain->lock, flags);

	do {
		nr = 0;
		spin_lock_irqsave(&domain->lock, flags);
		for (i = 0; i < domain->nr_lists && nr < CACHE_EXT_DRAIN_BATCH; i++) {
			struct list_head *head = &domain->lists[i].head;

			while (nr < CACHE_EXT_DRAIN_BATCH && !list_empty(head)) {
				struct folio *folio = list_first_entry(head,
							struct folio, lru);

				if (!folio_test_clear_cache_ext(folio)) {
					/*
					 * Cannot happen: every folio on a
					 * policy list has the bit set, and
					 * clearing it requires the domain
					 * lock we hold.
					 */
					VM_WARN_ON_ONCE_FOLIO(1, folio);
					list_del_init(&folio->lru);
					continue;
				}
				list_del_init(&folio->lru);
				domain->nr_folios--;
				cache_ext_stat_mod(folio, -1);
				batch[nr++] = folio;
			}
		}
		spin_unlock_irqrestore(&domain->lock, flags);

		/* Consumes the reference each folio's list was holding. */
		for (i = 0; i < nr; i++)
			folio_putback_lru(batch[i]);
	} while (nr);
}

/**
 * cache_ext_domain_publish - make a domain govern a memcg.
 * @memcg: the memcg.
 * @domain: fully initialized domain; the policy's init() has already run.
 *
 * Pins the memcg and makes the domain visible to the page cache hooks.
 * Caller holds cgroup_mutex, which serializes all publish/unpublish
 * against each other.
 */
void cache_ext_domain_publish(struct mem_cgroup *memcg,
			      struct cache_ext_domain *domain)
{
	css_get(&memcg->css);
	rcu_assign_pointer(memcg->cache_ext, domain);
	static_branch_inc(&cache_ext_enabled_key);
}

/**
 * cache_ext_domain_unpublish - detach a memcg's domain, if any.
 * @memcg: the memcg.
 *
 * Caller holds cgroup_mutex. Returns the domain that was governing
 * @memcg, no longer reachable by new RCU readers, or NULL. The caller
 * must hand a returned domain to cache_ext_domain_release().
 */
struct cache_ext_domain *cache_ext_domain_unpublish(struct mem_cgroup *memcg)
{
	struct cache_ext_domain *domain;

	domain = rcu_dereference_protected(memcg->cache_ext,
					   lockdep_is_held(&cgroup_mutex));
	if (domain)
		rcu_assign_pointer(memcg->cache_ext, NULL);
	return domain;
}

static void cache_ext_domain_teardown(struct cache_ext_domain *domain)
{
	/*
	 * Wait for hook invocations that found the domain before it was
	 * unpublished. Once they have drained, no new folios can be placed
	 * and no BPF program of this policy can be entered from this
	 * domain.
	 */
	synchronize_rcu();
	cache_ext_domain_drain(domain);

	if (domain->map)
		bpf_map_put(domain->map);
	css_put(&domain->memcg->css);
	static_branch_dec(&cache_ext_enabled_key);
	cache_ext_domain_free(domain);
}

static void cache_ext_teardown_workfn(struct work_struct *work)
{
	struct cache_ext_domain *domain =
		container_of(work, struct cache_ext_domain, teardown_work);

	cache_ext_domain_teardown(domain);
}

/**
 * cache_ext_domain_release - tear down an unpublished domain.
 * @domain: domain returned by cache_ext_domain_unpublish().
 * @sync: tear down synchronously instead of deferring to a workqueue.
 *
 * Tearing down means waiting out RCU readers, splicing every owned folio
 * back onto the kernel LRU, and dropping the domain's map and css
 * references. The deferred flavor exists because detach notifications
 * arrive under cgroup_mutex, where a synchronize_rcu() would stall every
 * other cgroup operation in the system.
 */
void cache_ext_domain_release(struct cache_ext_domain *domain, bool sync)
{
	if (sync) {
		cache_ext_domain_teardown(domain);
	} else {
		INIT_WORK(&domain->teardown_work, cache_ext_teardown_workfn);
		queue_work(system_dfl_wq, &domain->teardown_work);
	}
}

/**
 * cache_ext_memcg_offline - detach any policy before a memcg goes offline.
 * @memcg: the memcg being offlined.
 *
 * Called from mem_cgroup_css_offline() before the memcg's LRU folios are
 * reparented, so that folios sitting on policy lists are back under
 * kernel control (and thus visible to reparenting) first. Offlining is a
 * slow path and holds cgroup_mutex; the synchronous teardown is fine
 * here. The struct_ops link's later auto-detach will find no domain and
 * do nothing.
 */
void cache_ext_memcg_offline(struct mem_cgroup *memcg)
{
	struct cache_ext_domain *domain;

	domain = cache_ext_domain_unpublish(memcg);
	if (domain)
		cache_ext_domain_release(domain, true);
}
