// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext: struct_ops registration and cgroup attachment.
 *
 * cache_ext_ops is a cgroup-attached struct_ops. Attachment bookkeeping
 * (links, effective arrays, hierarchy, query) is all handled by the cgroup
 * BPF core; what this file adds is exclusive-ownership resolution on top:
 * each memcg is governed by at most one policy — the first policy attached
 * to the nearest ancestor cgroup (including itself) that has one — and that
 * resolution is materialized as a cache_ext_domain published on the memcg.
 *
 * Resolution runs from the cg_attach/cg_detach notifiers and from memcg
 * css_online, always under cgroup_mutex, and is a pure function of the
 * attachment state: every caller just re-syncs the affected subtree, which
 * makes attach, detach, replace, inert-attachment promotion, and unwinding
 * after a failed attach all the same operation.
 */
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/cache_ext.h>
#include <linux/btf_ids.h>
#include <linux/cgroup.h>
#include <linux/memcontrol.h>

#include "cache_ext.h"
#include "internal.h"

static struct mem_cgroup *cache_ext_cgroup_memcg(struct cgroup *cgrp)
{
	struct cgroup_subsys_state *css;

	css = rcu_dereference_protected(cgrp->subsys[memory_cgrp_id],
					lockdep_is_held(&cgroup_mutex));
	return css ? mem_cgroup_from_css(css) : NULL;
}

/*
 * The policy that should govern @memcg: the first one attached to the
 * nearest ancestor cgroup that has any. @exclude is the cgroup whose
 * attachments should be disregarded, used to unwind a failed attach as if
 * it had never happened.
 */
static struct bpf_map *cache_ext_effective_map(struct mem_cgroup *memcg,
					       struct cgroup *exclude)
{
	struct mem_cgroup *iter;

	for (iter = memcg; iter; iter = parent_mem_cgroup(iter)) {
		struct cgroup *cgrp = iter->css.cgroup;
		struct bpf_map *map;

		if (cgrp == exclude)
			continue;
		map = cgroup_bpf_struct_ops_first_map(cgrp, CGROUP_CACHE_EXT);
		if (map)
			return map;
	}
	return NULL;
}

/*
 * Bring one memcg in line with the attachment state. Idempotent: if the
 * governing policy is unchanged this is a no-op; otherwise the old domain
 * (if any) is torn down through the deferred path and a new one is built
 * and published.
 *
 * The new domain is published before the policy's init() runs so that the
 * list-creation kfunc can reach it through the memcg. The hooks tolerate
 * this window: placement fails until init() has created lists, and an
 * eviction request against a policy with no lists simply returns nothing.
 * If init() fails, the domain is unpublished and torn down again.
 */
static int cache_ext_sync_memcg(struct mem_cgroup *memcg,
				struct cgroup *exclude)
{
	struct cache_ext_domain *old, *domain;
	struct cache_ext_ops *ops;
	struct bpf_map *map;
	s32 err;

	map = cache_ext_effective_map(memcg, exclude);

	old = rcu_dereference_protected(memcg->cache_ext,
					lockdep_is_held(&cgroup_mutex));
	if (old ? old->map == map : !map)
		return 0;

	if (old)
		cache_ext_domain_release(cache_ext_domain_unpublish(memcg),
					 false);
	if (!map)
		return 0;

	domain = cache_ext_domain_alloc(memcg);
	if (!domain)
		return -ENOMEM;

	bpf_map_inc(map);
	domain->map = map;
	domain->ops = bpf_struct_ops_map_kdata(map);
	ops = domain->ops;

	cache_ext_domain_publish(memcg, domain);

	if (ops->init) {
		domain->init_task = current;
		err = ops->init(memcg);
		domain->init_task = NULL;
		if (err) {
			cache_ext_domain_release(
				cache_ext_domain_unpublish(memcg), false);
			return err;
		}
	}
	return 0;
}

static int cache_ext_sync_subtree(struct mem_cgroup *root,
				  struct cgroup *exclude)
{
	struct cgroup_subsys_state *css;
	int err = 0;

	/* Descendant walk is safe: cgroup_mutex is held. */
	css_for_each_descendant_pre(css, &root->css) {
		struct mem_cgroup *memcg = mem_cgroup_from_css(css);

		if (!mem_cgroup_online(memcg))
			continue;
		err = cache_ext_sync_memcg(memcg, exclude);
		if (err)
			break;
	}
	return err;
}

static int bpf_cache_ext_cg_attach(struct bpf_map *map, struct cgroup *cgrp)
{
	struct mem_cgroup *memcg;
	int err;

	memcg = cache_ext_cgroup_memcg(cgrp);
	if (!memcg)
		return -ENODEV;

	err = cache_ext_sync_subtree(memcg, NULL);
	if (err) {
		/*
		 * Unwind as if this attachment never existed. If
		 * re-initializing a previously governing policy fails now,
		 * the affected memcg is left to the kernel LRU; there is no
		 * older state to restore beyond that.
		 */
		if (cache_ext_sync_subtree(memcg, cgrp))
			pr_warn("cache_ext: unwind of failed attach left memcgs unmanaged\n");
	}
	return err;
}

static void bpf_cache_ext_cg_detach(struct bpf_map *map, struct cgroup *cgrp)
{
	struct mem_cgroup *memcg;

	memcg = cache_ext_cgroup_memcg(cgrp);
	if (!memcg)
		return;

	/*
	 * The detached link is already unpublished, so a plain re-sync
	 * computes the successor state (an inert attachment on this cgroup,
	 * an ancestor's policy, or nothing).
	 */
	if (cache_ext_sync_subtree(memcg, NULL))
		pr_warn("cache_ext: re-sync after detach left memcgs unmanaged\n");
}

/**
 * cache_ext_memcg_online - resolve the governing policy for a new memcg.
 * @memcg: the memcg coming online.
 *
 * Called from mem_cgroup_css_online() (under cgroup_mutex) so that a child
 * cgroup created below an attached cgroup is governed from the start. A
 * policy init() failure does not fail the online: the memcg just stays
 * with the kernel LRU.
 */
int cache_ext_memcg_online(struct mem_cgroup *memcg)
{
	int err;

	/*
	 * An attachment anywhere implies at least one published domain, so
	 * with the key off there is nothing this memcg could inherit. This
	 * also keeps early-boot onlining (root memcg) out of the resolver.
	 */
	if (!static_branch_unlikely(&cache_ext_enabled_key))
		return 0;

	err = cache_ext_sync_memcg(memcg, NULL);
	if (err)
		pr_warn("cache_ext: policy init failed for new memcg (%d), using kernel LRU\n",
			err);
	return 0;
}

/*
 * Kfuncs exposed to policies. Kfunc arguments are trusted by default, so
 * every folio argument is one the kernel handed to the policy: either a
 * callback argument (pinned for the duration of the call by the hook that
 * invoked the policy) or an iterator element. There is nothing to
 * revalidate.
 */

__bpf_kfunc_start_defs();

/**
 * bpf_cache_ext_list_create - allocate a policy list.
 * @memcg: memcg whose domain the list belongs to.
 *
 * Only callable from a policy's init() (it is the only sleepable member).
 *
 * Return: a list handle (>= 0) on success, -errno on failure.
 */
__bpf_kfunc s32 bpf_cache_ext_list_create(struct mem_cgroup *memcg)
{
	struct cache_ext_domain *domain;
	s32 ret = -ENOENT;

	rcu_read_lock();
	domain = mem_cgroup_cache_ext_domain(memcg);
	/*
	 * Lists may only be created from this domain's init() while it
	 * runs; the sleepable-only kfunc flag alone would also admit a
	 * future sleepable callback.
	 */
	if (domain)
		ret = domain->init_task == current ?
			cache_ext_list_create(domain) : -EPERM;
	rcu_read_unlock();
	return ret;
}

static int cache_ext_folio_list_op(struct folio *folio, u64 list, bool tail,
				   bool move)
{
	struct cache_ext_domain *domain;
	bool ok = false;

	rcu_read_lock();
	domain = mem_cgroup_cache_ext_domain(folio_memcg(folio));
	if (domain) {
		if (move)
			ok = cache_ext_move_folio(domain, list, folio, tail);
		else
			ok = cache_ext_place_folio(domain, list, folio, tail);
	}
	rcu_read_unlock();
	return ok ? 0 : -EINVAL;
}

/**
 * bpf_cache_ext_list_add - take ownership of a folio at the head of a list.
 * @folio: folio to place.
 * @list: destination list handle.
 *
 * Fails if the folio is already owned, on an LRU, unevictable, or no
 * longer in the page cache.
 *
 * Return: 0 on success, -errno on failure.
 */
__bpf_kfunc int bpf_cache_ext_list_add(struct folio *folio, u64 list)
{
	return cache_ext_folio_list_op(folio, list, false, false);
}

/**
 * bpf_cache_ext_list_add_tail - like bpf_cache_ext_list_add(), at the tail.
 * @folio: folio to place.
 * @list: destination list handle.
 *
 * Return: 0 on success, -errno on failure.
 */
__bpf_kfunc int bpf_cache_ext_list_add_tail(struct folio *folio, u64 list)
{
	return cache_ext_folio_list_op(folio, list, true, false);
}

/**
 * bpf_cache_ext_list_move - move an owned folio to another list position.
 * @folio: folio to move.
 * @list: destination list handle.
 * @tail: move to the tail instead of the head.
 *
 * Return: 0 on success, -errno if the folio is not currently owned.
 */
__bpf_kfunc int bpf_cache_ext_list_move(struct folio *folio, u64 list,
					bool tail)
{
	return cache_ext_folio_list_op(folio, list, tail, true);
}

/**
 * bpf_cache_ext_list_del - stop tracking a folio.
 * @folio: folio to release.
 *
 * The policy gives the folio up; it is claimed back and returned to the
 * kernel LRU, since every pagecache folio must live on exactly one list.
 *
 * Return: 0 on success, -errno if the folio is not currently owned.
 */
__bpf_kfunc int bpf_cache_ext_list_del(struct folio *folio)
{
	struct cache_ext_domain *domain;
	int ret = -EINVAL;

	rcu_read_lock();
	domain = mem_cgroup_cache_ext_domain(folio_memcg(folio));
	if (domain && cache_ext_claim_folio(domain, folio)) {
		if (this_cpu_read(cache_ext_adoptable_folio) == folio) {
			/*
			 * The policy adopted this folio and gave it back
			 * within its own folio_added() callback, before it
			 * ever reached an LRU. Close the one-shot adoption
			 * window and drop the reference placement took; the
			 * insertion path's fallback will add the folio to the
			 * kernel LRU exactly once. Returning it here as well
			 * would double-add it to the per-CPU LRU batch.
			 */
			this_cpu_write(cache_ext_adoptable_folio, NULL);
			folio_put(folio);
		} else {
			/*
			 * The folio was on an LRU before adoption; return it
			 * there. Consumes the reference inherited from the
			 * list.
			 */
			folio_putback_lru(folio);
		}
		ret = 0;
	}
	rcu_read_unlock();
	return ret;
}

/**
 * bpf_cache_ext_evict - hand a folio over to the kernel for eviction.
 * @ctx: the eviction context passed to evict_folios().
 * @folio: folio to evict.
 *
 * Claims the folio off its policy list and appends it to the kernel-side
 * eviction batch. Only callable while the evict_folios() invocation that
 * received @ctx is running, and only for folios of the same domain.
 *
 * Handing a folio over is final from the policy's point of view: if the
 * kernel then fails to reclaim it (dirty, under writeback, mlocked in the
 * meantime), the folio goes to the kernel LRU, not back to the policy.
 *
 * Return: 0 on success, -ENOSPC when the batch is full, -EINVAL if the
 * folio cannot be claimed.
 */
__bpf_kfunc int bpf_cache_ext_evict(struct cache_ext_eviction_ctx *ctx,
				    struct folio *folio)
{
	struct cache_ext_eviction_ctx_kern *kctx =
		container_of(ctx, struct cache_ext_eviction_ctx_kern, ctx);
	struct cache_ext_domain *domain;
	int ret = -EINVAL;

	/* Only valid while the evict_folios() that received @ctx runs. */
	if (this_cpu_read(cache_ext_kf_ctx) != CACHE_EXT_KF_EVICT)
		return -EPERM;

	if (kctx->ctx.nr_evicted >= kctx->ctx.request_nr_folios)
		return -ENOSPC;

	rcu_read_lock();
	domain = mem_cgroup_cache_ext_domain(folio_memcg(folio));
	if (domain == kctx->domain && cache_ext_claim_folio(domain, folio)) {
		list_add_tail(&folio->lru, &kctx->folios);
		kctx->ctx.nr_evicted++;
		ret = 0;
	}
	rcu_read_unlock();
	return ret;
}

/*
 * Open-coded policy list iterator, for use with bpf_for_each(). The
 * BPF-visible iterator is opaque; the kernel-side state is a pointer to
 * the list plus the current folio.
 *
 * The iterator advances through a cursor threaded into the list, so it
 * tolerates concurrent removal (eviction, truncation) of any folio,
 * including the current one. _next() returns each folio with a reference
 * held until the following _next()/_destroy() call, which is what makes
 * the returned pointer trusted for the body of the loop.
 *
 * Iteration never runs under the domain lock across the loop body: the
 * lock is taken per step, so the body may call any list kfunc, including
 * ones that take folios off this very list. This replaces the prototype's
 * callback-style iterate/sample kfuncs, which invoked BPF while holding
 * the registry rwlock (a self-deadlock if the callback used a list kfunc)
 * and required bespoke verifier support.
 */
struct bpf_iter_cache_ext_list_kern {
	struct cache_ext_domain *domain;
	struct cache_ext_list *list;
	struct folio *folio;
} __aligned(8);

struct bpf_iter_cache_ext_list {
	u64 __opaque[3];
} __aligned(8);

/**
 * bpf_iter_cache_ext_list_new - create a policy list iterator.
 * @it: iterator to initialize.
 * @memcg: memcg whose domain the list belongs to.
 * @list: list handle to iterate.
 *
 * At most one iterator can be active per list; a second one fails with
 * -EBUSY (and its _next() then yields nothing).
 *
 * Return: 0 on success, -errno on failure.
 */
__bpf_kfunc int bpf_iter_cache_ext_list_new(struct bpf_iter_cache_ext_list *it,
					    struct mem_cgroup *memcg, u64 list)
{
	struct bpf_iter_cache_ext_list_kern *kit = (void *)it;
	struct cache_ext_domain *domain;
	struct cache_ext_list *l;
	unsigned long flags;
	int ret = -ENOENT;

	BUILD_BUG_ON(sizeof(struct bpf_iter_cache_ext_list_kern) >
		     sizeof(struct bpf_iter_cache_ext_list));
	BUILD_BUG_ON(__alignof__(struct bpf_iter_cache_ext_list_kern) !=
		     __alignof__(struct bpf_iter_cache_ext_list));

	/* _next() and _destroy() run regardless of our return value. */
	kit->list = NULL;
	kit->folio = NULL;

	rcu_read_lock();
	domain = mem_cgroup_cache_ext_domain(memcg);
	if (!domain)
		goto out;

	if (this_cpu_read(cache_ext_kf_ctx) != CACHE_EXT_KF_EVICT &&
	    domain->init_task != current) {
		ret = -EPERM;
		goto out;
	}

	spin_lock_irqsave(&domain->lock, flags);
	if (list >= CACHE_EXT_MAX_LISTS || !domain->lists[list].in_use) {
		spin_unlock_irqrestore(&domain->lock, flags);
		goto out;
	}
	l = &domain->lists[list];
	if (l->iter_active) {
		ret = -EBUSY;
		spin_unlock_irqrestore(&domain->lock, flags);
		goto out;
	}
	l->iter_active = true;
	list_add(&l->cursor, &l->head);
	kit->domain = domain;
	kit->list = l;
	ret = 0;
	spin_unlock_irqrestore(&domain->lock, flags);
out:
	rcu_read_unlock();
	return ret;
}

/**
 * bpf_iter_cache_ext_list_next - progress a policy list iterator.
 * @it: iterator to progress.
 *
 * Return: the next folio, with a reference held until the next call, or
 * NULL when the end of the list is reached.
 */
__bpf_kfunc struct folio *
bpf_iter_cache_ext_list_next(struct bpf_iter_cache_ext_list *it)
{
	struct bpf_iter_cache_ext_list_kern *kit = (void *)it;
	struct folio *prev = kit->folio, *folio = NULL;
	struct cache_ext_list *l = kit->list;
	unsigned long flags;

	if (!l)
		return NULL;

	spin_lock_irqsave(&kit->domain->lock, flags);
	if (l->cursor.next != &l->head) {
		folio = list_entry(l->cursor.next, struct folio, lru);
		/* Owned folios always have at least the list's reference. */
		folio_get(folio);
		list_move(&l->cursor, &folio->lru);
	}
	kit->folio = folio;
	spin_unlock_irqrestore(&kit->domain->lock, flags);

	if (prev)
		folio_put(prev);
	return folio;
}

/**
 * bpf_iter_cache_ext_list_destroy - destroy a policy list iterator.
 * @it: iterator to destroy.
 */
__bpf_kfunc void bpf_iter_cache_ext_list_destroy(struct bpf_iter_cache_ext_list *it)
{
	struct bpf_iter_cache_ext_list_kern *kit = (void *)it;
	struct cache_ext_list *l = kit->list;
	unsigned long flags;

	if (!l)
		return;

	spin_lock_irqsave(&kit->domain->lock, flags);
	list_del_init(&l->cursor);
	l->iter_active = false;
	spin_unlock_irqrestore(&kit->domain->lock, flags);

	if (kit->folio)
		folio_put(kit->folio);
	kit->list = NULL;
	kit->folio = NULL;
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(cache_ext_kfuncs)
BTF_ID_FLAGS(func, bpf_cache_ext_list_create, KF_SLEEPABLE)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add)
BTF_ID_FLAGS(func, bpf_cache_ext_list_add_tail)
BTF_ID_FLAGS(func, bpf_cache_ext_list_move)
BTF_ID_FLAGS(func, bpf_cache_ext_list_del)
BTF_ID_FLAGS(func, bpf_cache_ext_evict)
BTF_ID_FLAGS(func, bpf_iter_cache_ext_list_new, KF_ITER_NEW)
BTF_ID_FLAGS(func, bpf_iter_cache_ext_list_next, KF_ITER_NEXT | KF_RET_NULL)
BTF_ID_FLAGS(func, bpf_iter_cache_ext_list_destroy, KF_ITER_DESTROY)
BTF_KFUNCS_END(cache_ext_kfuncs)

static struct bpf_struct_ops bpf_cache_ext_ops;

/*
 * The list kfuncs mutate exclusive per-folio ownership state; nothing
 * outside a cache_ext policy has any business calling them. See
 * scx_kfunc_filter() for the st_ops == NULL early-pass caveat.
 */
static int bpf_cache_ext_kfunc_filter(const struct bpf_prog *prog,
				      u32 kfunc_id)
{
	if (!btf_id_set8_contains(&cache_ext_kfuncs, kfunc_id))
		return 0;
	if (prog->type != BPF_PROG_TYPE_STRUCT_OPS)
		return -EACCES;
	if (!prog->aux->st_ops)
		return 0;
	return prog->aux->st_ops == &bpf_cache_ext_ops ? 0 : -EACCES;
}

static const struct btf_kfunc_id_set cache_ext_kfunc_set = {
	.owner	= THIS_MODULE,
	.set	= &cache_ext_kfuncs,
	.filter	= bpf_cache_ext_kfunc_filter,
};

/* struct_ops boilerplate below. */

static s32 cache_ext_init_stub(struct mem_cgroup *memcg)
{
	return 0;
}

static void cache_ext_evict_folios_stub(struct cache_ext_eviction_ctx *ctx,
					struct mem_cgroup *memcg)
{
}

static void cache_ext_folio_added_stub(struct folio *folio)
{
}

static void cache_ext_folio_accessed_stub(struct folio *folio)
{
}

static void cache_ext_folio_evicted_stub(struct folio *folio)
{
}

static bool cache_ext_admit_folio_stub(struct folio *folio)
{
	return true;
}

static void cache_ext_exit_stub(struct mem_cgroup *memcg)
{
}

static struct cache_ext_ops __bpf_cache_ext_ops = {
	.init		= cache_ext_init_stub,
	.evict_folios	= cache_ext_evict_folios_stub,
	.folio_added	= cache_ext_folio_added_stub,
	.folio_accessed	= cache_ext_folio_accessed_stub,
	.folio_evicted	= cache_ext_folio_evicted_stub,
	.admit_folio	= cache_ext_admit_folio_stub,
	.exit		= cache_ext_exit_stub,
};

static const struct bpf_func_proto *
bpf_cache_ext_get_func_proto(enum bpf_func_id func_id,
			     const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static bool bpf_cache_ext_is_valid_access(int off, int size,
					  enum bpf_access_type type,
					  const struct bpf_prog *prog,
					  struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

static const struct bpf_verifier_ops bpf_cache_ext_verifier_ops = {
	.get_func_proto		= bpf_cache_ext_get_func_proto,
	.is_valid_access	= bpf_cache_ext_is_valid_access,
};

static int bpf_cache_ext_init(struct btf *btf)
{
	return 0;
}

static int bpf_cache_ext_init_member(const struct btf_type *t,
				     const struct btf_member *member,
				     void *kdata, const void *udata)
{
	return 0;
}

static int bpf_cache_ext_check_member(const struct btf_type *t,
				      const struct btf_member *member,
				      const struct bpf_prog *prog)
{
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	/*
	 * Everything except init() and exit() is called from atomic
	 * context under RCU; those two run from attachment and teardown
	 * respectively and may sleep.
	 */
	if (prog->sleepable &&
	    moff != offsetof(struct cache_ext_ops, init) &&
	    moff != offsetof(struct cache_ext_ops, exit))
		return -EINVAL;

	return 0;
}

static struct bpf_struct_ops bpf_cache_ext_ops = {
	.verifier_ops	= &bpf_cache_ext_verifier_ops,
	.init		= bpf_cache_ext_init,
	.init_member	= bpf_cache_ext_init_member,
	.check_member	= bpf_cache_ext_check_member,
	.name		= "cache_ext_ops",
	.cgroup_atype	= CGROUP_CACHE_EXT,
	.cg_attach	= bpf_cache_ext_cg_attach,
	.cg_detach	= bpf_cache_ext_cg_detach,
	.cfi_stubs	= &__bpf_cache_ext_ops,
	.owner		= THIS_MODULE,
};

static int __init bpf_cache_ext_ops_init(void)
{
	int err;

	err = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&cache_ext_kfunc_set);
	if (err)
		return err;

	return register_bpf_struct_ops(&bpf_cache_ext_ops, cache_ext_ops);
}
late_initcall(bpf_cache_ext_ops_init);
