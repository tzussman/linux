// SPDX-License-Identifier: GPL-2.0
/*
 * Tests for cache_ext: BPF-managed page cache eviction policies.
 *
 * Covers the full lifecycle with a FIFO policy (attach, adoption, policy-
 * driven eviction under memory.max, detach draining, live replacement,
 * cgroup removal underneath a live policy), the S3-FIFO policy's ghost/
 * promotion machinery, hierarchical attachment semantics (nearest ancestor
 * wins, first attachment wins, inert attachments are promoted), attachment
 * error paths, and load-time rejection of illegally sleepable callbacks.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "cache_ext_fifo.skel.h"
#include "cache_ext_s3fifo.skel.h"
#include "cache_ext_sleepable_fail.skel.h"

#define CG_A		"/cache_ext_a"
#define CG_A_CHILD	CG_A "/child"
#define CG_B		"/cache_ext_b"
#define CG_B_CHILD	CG_B "/child"
#define MEMORY_MAX	(32 << 20)
#define FILE_SIZE	(2 * MEMORY_MAX)
#define IO_CHUNK	(1 << 20)

static long read_cache_ext_file_stat(int cgroup_fd)
{
	char buf[4096], *line;
	long val = -1;
	ssize_t len;
	int fd;

	fd = openat(cgroup_fd, "memory.stat", O_RDONLY);
	if (fd < 0)
		return -1;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return -1;
	buf[len] = '\0';

	line = strstr(buf, "cache_ext_file ");
	if (line && sscanf(line, "cache_ext_file %ld", &val) != 1)
		val = -1;
	return val;
}

/*
 * Fill the page cache well past memory.max with clean file folios.
 * @passes: read passes over the file; > 1 generates refaults of
 * previously evicted ranges, which exercises ghost-hit paths.
 * @keep_fd: if non-NULL, the (O_TMPFILE) file is kept open and returned,
 * so its cached folios stay owned while the caller inspects statistics;
 * closing it truncates the inode and claims everything back.
 */
static int __churn_pagecache(int passes, int *keep_fd)
{
	char *chunk;
	int fd, err = 0;
	size_t off;
	int pass;

	chunk = malloc(IO_CHUNK);
	if (!ASSERT_OK_PTR(chunk, "alloc chunk"))
		return -1;
	memset(chunk, 0x5a, IO_CHUNK);

	fd = open(".", O_TMPFILE | O_RDWR, 0600);
	if (!ASSERT_GE(fd, 0, "open tmpfile")) {
		free(chunk);
		return -1;
	}

	for (off = 0; off < FILE_SIZE && !err; off += IO_CHUNK)
		err = write(fd, chunk, IO_CHUNK) != IO_CHUNK;
	if (!ASSERT_OK(err, "write file"))
		goto out;
	/* Clean folios only: the test policies skip dirty/writeback. */
	err = fsync(fd);
	if (!ASSERT_OK(err, "fsync"))
		goto out;

	for (pass = 0; pass < passes && !err; pass++)
		for (off = 0; off < FILE_SIZE && !err; off += IO_CHUNK)
			err = pread(fd, chunk, IO_CHUNK, off) != IO_CHUNK;
	ASSERT_OK(err, "read file");
out:
	if (!err && keep_fd)
		*keep_fd = fd;
	else
		close(fd);
	free(chunk);
	return err ? -1 : 0;
}

static int churn_pagecache(int passes)
{
	return __churn_pagecache(passes, NULL);
}

/*
 * The memcg's memory.stat lags: a residual below the rstat flush
 * threshold may never be folded in. The global vmstat counter can be
 * folded on demand through vm.stat_refresh, so poll that one to verify
 * draining.
 */
static long read_global_cache_ext_stat(void)
{
	char buf[16384], *line;
	long val = -1;
	ssize_t len;
	int fd;

	fd = open("/proc/sys/vm/stat_refresh", O_WRONLY);
	if (fd >= 0) {
		(void)!write(fd, "1", 1);
		close(fd);
	}
	fd = open("/proc/vmstat", O_RDONLY);
	if (fd < 0)
		return -1;
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0)
		return -1;
	buf[len] = '\0';
	line = strstr(buf, "nr_cache_ext_file ");
	if (line && sscanf(line, "nr_cache_ext_file %ld", &val) != 1)
		val = -1;
	return val;
}

static bool stat_drains_to_zero(void)
{
	int i;

	/*
	 * Teardown is deferred to a workqueue and begins with an RCU grace
	 * period; on a loaded machine that can take a while. Be generous —
	 * a genuine leak fails just as reliably at any timeout.
	 */
	for (i = 0; i < 150; i++) {
		if (!read_global_cache_ext_stat())
			return true;
		usleep(100 * 1000);
	}
	return false;
}

static int setup_memcg_cgroup(const char *path, int *out_fd)
{
	char buf[32];
	int fd;

	fd = create_and_get_cgroup(path);
	if (!ASSERT_GE(fd, 0, "create cgroup"))
		return -1;
	snprintf(buf, sizeof(buf), "%d", MEMORY_MAX);
	if (!ASSERT_OK(write_cgroup_file(path, "memory.max", buf),
		       "set memory.max")) {
		close(fd);
		return -1;
	}
	write_cgroup_file(path, "memory.swap.max", "0");
	*out_fd = fd;
	return 0;
}

/* Attach, churn, verify counters, drain on detach, replace, rmdir-live. */
static void subtest_fifo_lifecycle(void)
{
	struct cache_ext_fifo *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1, churn_fd = -1;
	int err;

	if (setup_memcg_cgroup(CG_A, &cgroup_fd))
		return;
	if (!ASSERT_OK(join_cgroup(CG_A), "join cgroup"))
		goto out;

	skel = cache_ext_fifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, cgroup_fd,
					   NULL);
	if (!ASSERT_OK_PTR(link, "attach fifo_ops"))
		goto out;

	if (__churn_pagecache(2, &churn_fd))
		goto out;

	ASSERT_GT(skel->bss->nr_added, 0, "policy adopted folios");
	ASSERT_GT(skel->bss->nr_evict_requests, 0, "eviction requested");
	ASSERT_GT(skel->bss->nr_evicted, 0, "policy evicted folios");
	ASSERT_GT(read_cache_ext_file_stat(cgroup_fd), 0,
		  "cache_ext_file accounted");
	/* Closing the tmpfile truncates it and claims everything back. */
	close(churn_fd);
	churn_fd = -1;

	/* Detach: owned folios must drain back to the kernel LRU. */
	bpf_link__destroy(link);
	link = NULL;
	ASSERT_TRUE(stat_drains_to_zero(), "drained on detach");

	/* Re-attach and replace the policy map through a link update. */
	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, cgroup_fd,
					   NULL);
	if (!ASSERT_OK_PTR(link, "re-attach fifo_ops"))
		goto out;
	if (churn_pagecache(1))
		goto out;
	err = bpf_link__update_map(link, skel->maps.fifo_ops2);
	ASSERT_OK(err, "live replace via link update");
	/*
	 * A global zero cannot be expected while the new policy still
	 * governs the cgroup this test runs in: it adopts the test's own
	 * file-backed pages as they fault in. Detach, then everything must
	 * drain.
	 */
	bpf_link__destroy(link);
	link = NULL;
	ASSERT_TRUE(stat_drains_to_zero(),
		    "all domains drained after replace and detach");

	/*
	 * Attach once more and tear the cgroup down underneath the live
	 * policy: memcg offline must detach the domain, and the link's
	 * auto-detach must cope with finding nothing.
	 */
	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, cgroup_fd,
					   NULL);
	ASSERT_OK_PTR(link, "attach again before cgroup removal");
	churn_pagecache(1);
	join_root_cgroup();
	remove_cgroup(CG_A);
	ASSERT_TRUE(stat_drains_to_zero(), "drained on cgroup removal");
out:
	if (churn_fd >= 0)
		close(churn_fd);
	join_root_cgroup();
	if (link)
		bpf_link__destroy(link);
	cache_ext_fifo__destroy(skel);
	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		remove_cgroup(CG_A);
	}
}

/* S3-FIFO: ghost hits route refaulting folios to the main queue. */
static void subtest_s3fifo(void)
{
	struct cache_ext_s3fifo *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;

	if (setup_memcg_cgroup(CG_A, &cgroup_fd))
		return;
	if (!ASSERT_OK(join_cgroup(CG_A), "join cgroup"))
		goto out;

	skel = cache_ext_s3fifo__open();
	if (!ASSERT_OK_PTR(skel, "open"))
		goto out;
	skel->rodata->cache_size = MEMORY_MAX / 4096;
	if (!ASSERT_OK(cache_ext_s3fifo__load(skel), "load"))
		goto out;

	link = bpf_map__attach_cgroup_opts(skel->maps.s3fifo_ops, cgroup_fd,
					   NULL);
	if (!ASSERT_OK_PTR(link, "attach s3fifo_ops"))
		goto out;

	/*
	 * Three passes over 2x memory.max: pass 1 populates, evictions from
	 * the small queue populate the ghost; passes 2-3 refault evicted
	 * ranges, so insertions start hitting the ghost and going to the
	 * main queue.
	 */
	if (churn_pagecache(3))
		goto out;

	ASSERT_GT(skel->bss->nr_added, 0, "adopted folios");
	ASSERT_GT(skel->bss->nr_evict_requests, 0, "eviction requested");
	ASSERT_GT(skel->bss->nr_evicted_small, 0, "evicted from small queue");
	ASSERT_GT(skel->bss->nr_ghost_hits, 0, "refaults hit the ghost queue");
	ASSERT_GT(skel->bss->nr_ghost_hits + skel->bss->nr_promoted, 0,
		  "main queue is populated");

	bpf_link__destroy(link);
	link = NULL;
	ASSERT_TRUE(stat_drains_to_zero(), "drained on detach");
	/* exit() runs from the teardown worker; give it a moment. */
	for (int i = 0; i < 50 && !skel->bss->nr_exits; i++)
		usleep(100 * 1000);
	ASSERT_GT(skel->bss->nr_exits, 0, "exit() ran on detach");
out:
	join_root_cgroup();
	if (link)
		bpf_link__destroy(link);
	cache_ext_s3fifo__destroy(skel);
	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		remove_cgroup(CG_A);
	}
}

/* A policy attached to a parent governs newly created children. */
static void subtest_hierarchy(void)
{
	struct cache_ext_fifo *skel = NULL;
	struct bpf_link *link = NULL;
	int parent_fd = -1, child_fd = -1, churn_fd = -1;
	__u64 before;

	if (setup_memcg_cgroup(CG_B, &parent_fd))
		return;

	skel = cache_ext_fifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, parent_fd,
					   NULL);
	if (!ASSERT_OK_PTR(link, "attach to parent"))
		goto out;

	/* Child created after attach must be governed from birth. */
	if (!ASSERT_OK(enable_controllers(CG_B, "memory"),
		       "enable memory for children"))
		goto out;
	if (setup_memcg_cgroup(CG_B_CHILD, &child_fd))
		goto out;
	if (!ASSERT_OK(join_cgroup(CG_B_CHILD), "join child"))
		goto out;

	before = skel->bss->nr_added;
	if (__churn_pagecache(1, &churn_fd))
		goto out;
	ASSERT_GT(skel->bss->nr_added, before,
		  "parent policy governs child memcg");
	ASSERT_GT(read_cache_ext_file_stat(child_fd), 0,
		  "child memcg accounts cache_ext_file");
	close(churn_fd);
	churn_fd = -1;
out:
	if (churn_fd >= 0)
		close(churn_fd);
	join_root_cgroup();
	if (link)
		bpf_link__destroy(link);
	ASSERT_TRUE(stat_drains_to_zero(), "drained after hierarchy test");
	cache_ext_fifo__destroy(skel);
	if (child_fd >= 0) {
		close(child_fd);
		remove_cgroup(CG_B_CHILD);
	}
	if (parent_fd >= 0) {
		close(parent_fd);
		remove_cgroup(CG_B);
	}
}

/*
 * First attachment wins; a second attachment is inert until the winner
 * detaches, then it is promoted.
 */
static void subtest_inert_promotion(void)
{
	struct cache_ext_fifo *skel = NULL;
	struct bpf_link *noop_link = NULL, *fifo_link = NULL;
	int cgroup_fd = -1;
	__u64 before;

	if (setup_memcg_cgroup(CG_A, &cgroup_fd))
		return;
	if (!ASSERT_OK(join_cgroup(CG_A), "join cgroup"))
		goto out;

	skel = cache_ext_fifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	noop_link = bpf_map__attach_cgroup_opts(skel->maps.noop_ops,
						cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(noop_link, "attach noop (winner)"))
		goto out;
	fifo_link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops,
						cgroup_fd, NULL);
	if (!ASSERT_OK_PTR(fifo_link, "attach fifo (inert)"))
		goto out;

	before = skel->bss->nr_added;
	if (churn_pagecache(1))
		goto out;
	ASSERT_EQ(skel->bss->nr_added, before,
		  "inert policy adopted nothing");

	/* Detaching the winner promotes the inert attachment. */
	bpf_link__destroy(noop_link);
	noop_link = NULL;
	before = skel->bss->nr_added;
	if (churn_pagecache(1))
		goto out;
	ASSERT_GT(skel->bss->nr_added, before,
		  "promoted policy governs after winner detach");
out:
	join_root_cgroup();
	if (noop_link)
		bpf_link__destroy(noop_link);
	if (fifo_link)
		bpf_link__destroy(fifo_link);
	ASSERT_TRUE(stat_drains_to_zero(), "drained after promotion test");
	cache_ext_fifo__destroy(skel);
	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		remove_cgroup(CG_A);
	}
}

/* A failing init() must fail the attach and leave the memcg governable. */
static void subtest_init_failure(void)
{
	struct cache_ext_fifo *skel = NULL;
	struct bpf_link *link = NULL;
	int cgroup_fd = -1;

	if (setup_memcg_cgroup(CG_A, &cgroup_fd))
		return;

	skel = cache_ext_fifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cgroup_opts(skel->maps.fail_ops, cgroup_fd,
					   NULL);
	if (!ASSERT_NULL(link, "attach of failing policy rejected")) {
		bpf_link__destroy(link);
		link = NULL;
		goto out;
	}

	/* The failed attach must not have wedged the cgroup. */
	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, cgroup_fd,
					   NULL);
	ASSERT_OK_PTR(link, "attach works after failed attach");
out:
	if (link)
		bpf_link__destroy(link);
	cache_ext_fifo__destroy(skel);
	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		remove_cgroup(CG_A);
	}
}

/* Attaching to a cgroup without a memory controller css fails. */
static void subtest_attach_no_memcg(void)
{
	struct cache_ext_fifo *skel = NULL;
	struct bpf_link *link = NULL;
	int parent_fd = -1, child_fd = -1;

	parent_fd = create_and_get_cgroup(CG_B);
	if (!ASSERT_GE(parent_fd, 0, "create parent"))
		return;
	/*
	 * CG_B's own subtree_control starts empty, so its child has no
	 * memory controller css — exactly the -ENODEV case.
	 */
	child_fd = create_and_get_cgroup(CG_B_CHILD);
	if (!ASSERT_GE(child_fd, 0, "create child"))
		goto out;

	skel = cache_ext_fifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, child_fd,
					   NULL);
	if (!ASSERT_NULL(link, "attach without memcg rejected")) {
		bpf_link__destroy(link);
		link = NULL;
	}
out:
	cache_ext_fifo__destroy(skel);
	if (child_fd >= 0) {
		close(child_fd);
		remove_cgroup(CG_B_CHILD);
	}
	if (parent_fd >= 0) {
		close(parent_fd);
		remove_cgroup(CG_B);
	}
}

/* Only init() may be sleepable; a sleepable folio_added must not load. */
static void subtest_sleepable_reject(void)
{
	struct cache_ext_sleepable_fail *skel;

	skel = cache_ext_sleepable_fail__open_and_load();
	if (!ASSERT_NULL(skel, "sleepable folio_added rejected"))
		cache_ext_sleepable_fail__destroy(skel);
}

void test_cache_ext(void)
{
	int env_fd;

	env_fd = test__join_cgroup("/cache_ext_env");
	if (!ASSERT_GE(env_fd, 0, "setup cgroup environment"))
		return;

	if (test__start_subtest("fifo_lifecycle"))
		subtest_fifo_lifecycle();
	if (test__start_subtest("s3fifo"))
		subtest_s3fifo();
	if (test__start_subtest("hierarchy"))
		subtest_hierarchy();
	if (test__start_subtest("inert_promotion"))
		subtest_inert_promotion();
	if (test__start_subtest("init_failure"))
		subtest_init_failure();
	if (test__start_subtest("attach_no_memcg"))
		subtest_attach_no_memcg();
	if (test__start_subtest("sleepable_reject"))
		subtest_sleepable_reject();

	close(env_fd);
	cleanup_cgroup_environment();
}
