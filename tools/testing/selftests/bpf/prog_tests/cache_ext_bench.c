// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext performance comparison: cyclic sequential scan of a file larger
 * than the cache, under three regimes — classic LRU, MGLRU, and a cache_ext
 * MRU policy. LRU is pessimal for looping access; MRU keeps a stable prefix
 * resident and re-hits it every loop.
 *
 * Readahead is disabled (POSIX_FADV_RANDOM) so every access is a true
 * demand fault: otherwise readahead re-prefetches evicted pages and hides
 * the policy's effect on the resident set. The benchmark reports refaults
 * and read throughput per regime and asserts MRU beats both kernel LRUs.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <time.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "cache_ext_mru.skel.h"

#define CG_BENCH	"/cache_ext_bench"
#define MEMORY_MAX	(64 << 20)
#define FILE_SIZE	(80 << 20)		/* 1.25x the cache */
#define IO_CHUNK	(1 << 20)
#define NR_LOOPS	6

static int mglru_set(const char *val)
{
	int fd = open("/sys/kernel/mm/lru_gen/enabled", O_WRONLY);
	int ret;

	if (fd < 0)
		return -1;
	ret = write(fd, val, strlen(val)) < 0 ? -1 : 0;
	close(fd);
	return ret;
}

/* Global vmstat counter, folded on demand via vm.stat_refresh. */
static long vmstat(const char *key)
{
	char buf[32768], needle[64], *line;
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
	snprintf(needle, sizeof(needle), "%s ", key);
	line = strstr(buf, needle);
	if (!line || sscanf(line + strlen(needle), "%ld", &val) != 1)
		return -1;
	return val;
}

/*
 * Cyclic read scan with readahead disabled. Returns refaults incurred and
 * fills @mbps with read throughput over the measured loops.
 */
static long run_scan(int fd, double *mbps)
{
	struct timespec t0, t1;
	long refault_before, refault_after;
	double secs;
	char *chunk;
	int loop;
	off_t off;

	/* Every access is a demand fault, not a readahead prefetch. */
	posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);

	chunk = malloc(IO_CHUNK);
	if (!ASSERT_OK_PTR(chunk, "alloc chunk"))
		return -1;

	/* Prime one loop so every regime starts from a full-then-pressured
	 * cache, then measure the steady-state loops.
	 */
	for (off = 0; off < FILE_SIZE; off += IO_CHUNK)
		if (pread(fd, chunk, IO_CHUNK, off) != IO_CHUNK)
			goto err;

	refault_before = vmstat("workingset_refault_file");
	clock_gettime(CLOCK_MONOTONIC, &t0);
	for (loop = 0; loop < NR_LOOPS; loop++)
		for (off = 0; off < FILE_SIZE; off += IO_CHUNK)
			if (pread(fd, chunk, IO_CHUNK, off) != IO_CHUNK)
				goto err;
	clock_gettime(CLOCK_MONOTONIC, &t1);
	refault_after = vmstat("workingset_refault_file");

	free(chunk);
	secs = (t1.tv_sec - t0.tv_sec) + (t1.tv_nsec - t0.tv_nsec) / 1e9;
	*mbps = secs > 0 ?
		((double)FILE_SIZE * NR_LOOPS) / (1 << 20) / secs : 0;
	return refault_after - refault_before;
err:
	free(chunk);
	ASSERT_TRUE(false, "scan IO");
	return -1;
}

/* Write a fresh FILE_SIZE file into the cgroup and return its fd. */
static int make_file(void)
{
	char *chunk;
	int fd;
	off_t off;

	fd = open("bench_file", O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (!ASSERT_GE(fd, 0, "open bench file"))
		return -1;
	chunk = malloc(IO_CHUNK);
	if (!ASSERT_OK_PTR(chunk, "alloc")) {
		close(fd);
		return -1;
	}
	memset(chunk, 0x5a, IO_CHUNK);
	for (off = 0; off < FILE_SIZE; off += IO_CHUNK)
		if (pwrite(fd, chunk, IO_CHUNK, off) != IO_CHUNK) {
			ASSERT_TRUE(false, "write");
			free(chunk);
			close(fd);
			return -1;
		}
	fsync(fd);
	free(chunk);
	return fd;
}

/* One regime: fresh file, scan, report. Caller sets up LRU/MGLRU/policy. */
static long bench_once(const char *label, double *mbps)
{
	long refaults;
	int fd;

	fd = make_file();
	if (fd < 0)
		return -1;
	refaults = run_scan(fd, mbps);
	fprintf(stdout, "  %-16s refaults=%-9ld throughput=%.0f MB/s  retained=%ldM\n",
		label, refaults, *mbps,
		vmstat("nr_cache_ext_file") * 4096 / (1 << 20));
	close(fd);
	unlink("bench_file");
	return refaults;
}

void test_cache_ext_bench(void)
{
	struct cache_ext_mru *skel = NULL;
	struct bpf_link *link = NULL;
	long lru_rf, mglru_rf, mru_rf;
	double lru_mbps, mglru_mbps, mru_mbps;
	int cgroup_fd = -1, env_fd;
	char buf[32];

	env_fd = test__join_cgroup("/cache_ext_bench_env");
	if (!ASSERT_GE(env_fd, 0, "cgroup env"))
		return;
	cgroup_fd = create_and_get_cgroup(CG_BENCH);
	if (!ASSERT_GE(cgroup_fd, 0, "create cgroup"))
		goto out;
	snprintf(buf, sizeof(buf), "%d", MEMORY_MAX);
	if (!ASSERT_OK(write_cgroup_file(CG_BENCH, "memory.max", buf),
		       "memory.max"))
		goto out;
	write_cgroup_file(CG_BENCH, "memory.swap.max", "0");
	if (!ASSERT_OK(join_cgroup(CG_BENCH), "join"))
		goto out;

	fprintf(stdout, "cache_ext cyclic-scan benchmark: file=%dM cache=%dM loops=%d\n",
		FILE_SIZE >> 20, MEMORY_MAX >> 20, NR_LOOPS);

	/* 1. Classic LRU. */
	mglru_set("0");
	lru_rf = bench_once("classic-LRU", &lru_mbps);

	/* 2. MGLRU. */
	if (mglru_set("y")) {
		fprintf(stdout, "  (MGLRU unavailable, skipping)\n");
		mglru_rf = lru_rf;
		mglru_mbps = lru_mbps;
	} else {
		mglru_rf = bench_once("MGLRU", &mglru_mbps);
	}
	mglru_set("0");

	/* 3. cache_ext MRU. */
	skel = cache_ext_mru__open_and_load();
	if (!ASSERT_OK_PTR(skel, "load mru"))
		goto out;
	link = bpf_map__attach_cgroup_opts(skel->maps.mru_ops, cgroup_fd,
					   NULL);
	if (!ASSERT_OK_PTR(link, "attach mru"))
		goto out;
	mru_rf = bench_once("cache_ext-MRU", &mru_mbps);
	fprintf(stdout, "  MRU policy: added=%llu hits=%llu evicted=%llu\n",
		skel->bss->nr_added, skel->bss->nr_hits, skel->bss->nr_evicted);

	if (lru_rf > 0 && mru_rf >= 0) {
		fprintf(stdout, "  MRU refaults %.1fx fewer vs LRU, %.1fx fewer vs MGLRU\n",
			(double)lru_rf / (mru_rf ? mru_rf : 1),
			(double)mglru_rf / (mru_rf ? mru_rf : 1));
		fprintf(stdout, "  MRU throughput %.1fx vs LRU, %.1fx vs MGLRU\n",
			mru_mbps / (lru_mbps ? lru_mbps : 1),
			mru_mbps / (mglru_mbps ? mglru_mbps : 1));
	}

	/* The whole point: MRU must retain a working set that LRU/MGLRU
	 * throw away on a cyclic scan.
	 */
	ASSERT_GT(skel->bss->nr_hits, 0, "MRU scored cache hits");
	ASSERT_LT(mru_rf, lru_rf, "MRU refaults fewer than classic LRU");
	ASSERT_LT(mru_rf, mglru_rf, "MRU refaults fewer than MGLRU");
	ASSERT_GT(mru_mbps, lru_mbps, "MRU throughput beats classic LRU");
out:
	join_root_cgroup();
	if (link)
		bpf_link__destroy(link);
	cache_ext_mru__destroy(skel);
	mglru_set("0");
	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		remove_cgroup(CG_BENCH);
	}
	close(env_fd);
	cleanup_cgroup_environment();
}
