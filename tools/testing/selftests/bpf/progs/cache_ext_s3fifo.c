// SPDX-License-Identifier: GPL-2.0
/*
 * S3-FIFO page cache eviction policy (Yang et al., SOSP '23).
 *
 * Three structures: a small FIFO (S) receiving new folios, a main FIFO (M)
 * receiving folios promoted out of S, and a ghost FIFO (G) remembering
 * folios recently evicted from S. Insertion goes to M if the folio is in G
 * (it was hot enough to come back), else to S. Eviction from S promotes
 * folios with freq > 1 to M and evicts the rest into G; eviction from M
 * gives each folio freq lives (lazy promotion by reinsertion).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char _license[] SEC("license") = "GPL";

extern s32 bpf_cache_ext_list_create(struct mem_cgroup *memcg) __ksym;
extern int bpf_cache_ext_list_add_tail(struct folio *folio, u64 list) __ksym;
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

/* Set from userspace before load, in pages. */
const volatile __s64 cache_size = 8192;

#define FREQ_MAX	3
/* Work bound per evict_folios() invocation. */
#define SCAN_LIMIT	512

/*
 * volatile so the verifier sees an unknown scalar and the iterator loop
 * converges instead of being unrolled SCAN_LIMIT times.
 */
static volatile __u32 scan_budget;

struct folio_meta {
	__s64 freq;
	bool in_main;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);		/* folio pointer value */
	__type(value, struct folio_meta);
	__uint(max_entries, 1 << 16);
} folio_meta_map SEC(".maps");

struct ghost_key {
	__u64 ino;
	__u64 index;
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, struct ghost_key);
	__type(value, __u8);
	__uint(max_entries, 1 << 16);
} ghost_map SEC(".maps");

static u64 small_list;
static u64 main_list;

__s64 small_size;
__s64 main_size;

/* Test observability. */
__u64 nr_added;
__u64 nr_ghost_hits;
__u64 nr_promoted;
__u64 nr_evicted_small;
__u64 nr_evicted_main;
__u64 nr_evict_requests;

static struct folio_meta *folio_meta(struct folio *folio)
{
	__u64 key = (__u64)folio;

	return bpf_map_lookup_elem(&folio_meta_map, &key);
}

static void folio_meta_delete(struct folio *folio)
{
	__u64 key = (__u64)folio;

	bpf_map_delete_elem(&folio_meta_map, &key);
}

static void ghost_key_init(struct ghost_key *key, struct folio *folio)
{
	struct inode *host = BPF_CORE_READ(folio, mapping, host);

	key->ino = host ? BPF_CORE_READ(host, i_ino) : 0;
	key->index = folio->index;
}

/* Checking membership consumes the ghost entry, as in the paper. */
static bool folio_in_ghost(struct folio *folio)
{
	struct ghost_key key;

	ghost_key_init(&key, folio);
	return !bpf_map_delete_elem(&ghost_map, &key);
}

static void ghost_add(struct folio *folio)
{
	struct ghost_key key;
	__u8 val = 0;

	ghost_key_init(&key, folio);
	bpf_map_update_elem(&ghost_map, &key, &val, BPF_ANY);
}

static bool folio_evictable_now(struct folio *folio)
{
	return !(folio->flags.f &
		 ((1UL << PG_dirty) | (1UL << PG_writeback)));
}

SEC("struct_ops.s/init")
s32 BPF_PROG(s3fifo_init, struct mem_cgroup *memcg)
{
	s32 list;

	list = bpf_cache_ext_list_create(memcg);
	if (list < 0)
		return list;
	small_list = list;

	list = bpf_cache_ext_list_create(memcg);
	if (list < 0)
		return list;
	main_list = list;

	return 0;
}

SEC("struct_ops/folio_added")
void BPF_PROG(s3fifo_folio_added, struct folio *folio)
{
	struct folio_meta meta = { .freq = 0 };
	__u64 key = (__u64)folio;
	u64 list;

	if (folio_in_ghost(folio)) {
		list = main_list;
		meta.in_main = true;
	} else {
		list = small_list;
	}

	if (bpf_cache_ext_list_add_tail(folio, list))
		return;

	__sync_fetch_and_add(&nr_added, 1);
	if (meta.in_main) {
		__sync_fetch_and_add(&nr_ghost_hits, 1);
		__sync_fetch_and_add(&main_size, 1);
	} else {
		__sync_fetch_and_add(&small_size, 1);
	}
	/* Overwrites any stale entry left by a reused folio address. */
	bpf_map_update_elem(&folio_meta_map, &key, &meta, BPF_ANY);
}

SEC("struct_ops/folio_accessed")
void BPF_PROG(s3fifo_folio_accessed, struct folio *folio)
{
	struct folio_meta *meta = folio_meta(folio);

	if (!meta)
		return;
	if (__sync_add_and_fetch(&meta->freq, 1) > FREQ_MAX)
		meta->freq = FREQ_MAX;
}

/*
 * A folio was claimed away by the kernel (truncation, THP split, teardown).
 * Not called for folios the policy itself evicted. No ghost entry: the
 * kernel took it for reasons unrelated to its temperature.
 */
SEC("struct_ops/folio_evicted")
void BPF_PROG(s3fifo_folio_evicted, struct folio *folio)
{
	struct folio_meta *meta = folio_meta(folio);

	if (meta) {
		if (meta->in_main)
			__sync_fetch_and_sub(&main_size, 1);
		else
			__sync_fetch_and_sub(&small_size, 1);
	}
	folio_meta_delete(folio);
}

static void evict_small(struct cache_ext_eviction_ctx *ectx,
			struct mem_cgroup *memcg)
{
	struct bpf_iter_cache_ext_list it;
	struct folio *folio;

	scan_budget = SCAN_LIMIT;
	if (bpf_iter_cache_ext_list_new(&it, memcg, small_list))
		goto out;

	while ((folio = bpf_iter_cache_ext_list_next(&it))) {
		struct folio_meta *meta;

		if (scan_budget-- == 0)
			break;
		if (!folio_evictable_now(folio))
			continue;

		meta = folio_meta(folio);
		if (meta && meta->freq > 1) {
			/* Promote to the main queue. */
			if (!bpf_cache_ext_list_move(folio, main_list, true)) {
				meta->in_main = true;
				meta->freq = 0;
				__sync_fetch_and_sub(&small_size, 1);
				__sync_fetch_and_add(&main_size, 1);
				__sync_fetch_and_add(&nr_promoted, 1);
			}
			continue;
		}

		ghost_add(folio);
		if (bpf_cache_ext_evict(ectx, folio)) {
			/* Batch full (or lost a race); undo the ghost hint. */
			struct ghost_key key;

			ghost_key_init(&key, folio);
			bpf_map_delete_elem(&ghost_map, &key);
			break;
		}
		folio_meta_delete(folio);
		__sync_fetch_and_sub(&small_size, 1);
		__sync_fetch_and_add(&nr_evicted_small, 1);
	}
out:
	bpf_iter_cache_ext_list_destroy(&it);
}

static void evict_main(struct cache_ext_eviction_ctx *ectx,
		       struct mem_cgroup *memcg)
{
	struct bpf_iter_cache_ext_list it;
	struct folio *folio;

	scan_budget = SCAN_LIMIT;
	if (bpf_iter_cache_ext_list_new(&it, memcg, main_list))
		goto out;

	while ((folio = bpf_iter_cache_ext_list_next(&it))) {
		struct folio_meta *meta;

		if (scan_budget-- == 0)
			break;
		if (!folio_evictable_now(folio))
			continue;

		meta = folio_meta(folio);
		if (meta && meta->freq > 0) {
			/* Spend one life; reinsert at the tail. */
			meta->freq--;
			bpf_cache_ext_list_move(folio, main_list, true);
			continue;
		}

		if (bpf_cache_ext_evict(ectx, folio))
			break;
		folio_meta_delete(folio);
		__sync_fetch_and_sub(&main_size, 1);
		__sync_fetch_and_add(&nr_evicted_main, 1);
	}
out:
	bpf_iter_cache_ext_list_destroy(&it);
}

SEC("struct_ops/evict_folios")
void BPF_PROG(s3fifo_evict_folios, struct cache_ext_eviction_ctx *ectx,
	      struct mem_cgroup *memcg)
{
	__sync_fetch_and_add(&nr_evict_requests, 1);

	if (small_size >= (__s64)((__u64)cache_size / 10) || main_size <= 2 * small_size)
		evict_small(ectx, memcg);
	if (ectx->nr_evicted < ectx->request_nr_folios)
		evict_main(ectx, memcg);
	/* Final sweep of S if M could not satisfy the request either. */
	if (ectx->nr_evicted < ectx->request_nr_folios)
		evict_small(ectx, memcg);
}

SEC(".struct_ops.link")
struct cache_ext_ops s3fifo_ops = {
	.init = (void *)s3fifo_init,
	.folio_added = (void *)s3fifo_folio_added,
	.folio_accessed = (void *)s3fifo_folio_accessed,
	.folio_evicted = (void *)s3fifo_folio_evicted,
	.evict_folios = (void *)s3fifo_evict_folios,
};
