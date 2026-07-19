.. SPDX-License-Identifier: GPL-2.0

=========
cache_ext
=========

cache_ext lets a BPF struct_ops program implement the page cache eviction
policy for a cgroup. A policy decides which file folios to track, in what
order to keep them, and which of them to hand to the kernel when the memcg
comes under memory pressure — replacing LRU (or MGLRU) aging for exactly
the folios it owns, while the kernel retains a fallback for everything
else and for every situation in which the policy goes away or misbehaves.

Ownership model
===============

A folio is on exactly one list at any time: a kernel LRU list (or MGLRU
generation), or one of the policy's lists, linked through ``folio->lru``.
To the rest of the kernel a policy-owned folio looks like a long-term
isolated folio — ``PG_lru`` clear — so every path that manipulates
``folio->lru`` (isolation, migration, compaction, mlock, the folio_batch
operations) skips owned folios through the checks it already performs.
Unlike transient isolation, the policy list holds a folio reference,
which is why folios can be handed to BPF as trusted pointers with nothing
to revalidate.

Ownership is marked by the ``MEMCG_DATA_CACHE_EXT`` bit in
``folio->memcg_data`` and changes hands through two primitives, both
under a per-memcg spinlock:

* *place*: taken from the insertion hook or a list kfunc; requires that
  the folio is still in the page cache, evictable, and on no LRU.
* *claim*: test-and-clear of the ownership bit; the winner unlinks the
  folio and inherits the list's reference. Eviction, page cache removal
  (truncation etc.), THP split, policy teardown, and the near-OOM
  watchdog all race through claim, and exactly one of them wins.

Consequences of ownership: owned folios are unmovable (compaction and
migration skip them) and are accounted in ``cache_ext_file`` /
``nr_cache_ext_file`` rather than the active/inactive file counters.
Splitting a file THP releases it back to the kernel LRU first.

Attachment
==========

``cache_ext_ops`` is a cgroup-attached struct_ops: it is attached with a
``BPF_LINK_CREATE`` targeting a cgroup fd (``bpf_map__attach_cgroup_opts()``
in libbpf), replaced with a link update, and queried like any other cgroup
BPF attachment. Each memcg is governed by at most one policy: the first
policy attached to the nearest ancestor cgroup (including itself) that
has one. Later attachments on the same cgroup are inert until the winner
detaches. A memcg created below an attached cgroup is governed from
birth; the policy's ``init()`` runs once per governed memcg.

Callbacks
=========

``init(memcg)``
    Sleepable; runs on attachment for each governed memcg. The only
    callback allowed to call ``bpf_cache_ext_list_create()``.

``admit_folio(folio)``
    Return false to mark a newly inserted folio dropbehind: it is read
    once and dropped on IO completion instead of polluting the cache.

``folio_added(folio)``
    A folio entered the page cache; take ownership with
    ``bpf_cache_ext_list_add()``/``_add_tail()`` or leave it to the LRU.

``folio_accessed(folio)``
    An owned folio was accessed; reorder with ``bpf_cache_ext_list_move()``.

``folio_evicted(folio)``
    An owned folio was claimed away (truncation, split, teardown).
    Bookkeeping only.

``evict_folios(ctx, memcg)``
    Hand up to ``ctx->request_nr_folios`` folios to the kernel via
    ``bpf_cache_ext_evict()``, typically by scanning a list with the
    ``bpf_iter_cache_ext_list`` open-coded iterator. Handing over fewer
    is legal; unreclaimable leftovers go to the kernel LRU rather than
    back to the policy.

Kernel fallback
===============

The kernel can always reclaim its way out from under a policy:

* Folios the policy never adopts (or fails to adopt) age on the kernel
  LRU as usual.
* On detach, replacement, or memcg offlining, all owned folios are
  spliced back onto the kernel LRU (MGLRU-aware) after an RCU grace
  period.
* If reclaim is close to OOM (priority <= 2) and a policy that owns
  folios reclaims none of them, the kernel force-claims batches from the
  policy's list tails. A policy shapes eviction; it cannot pin memory.
