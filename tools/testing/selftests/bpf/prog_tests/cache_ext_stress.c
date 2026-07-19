// SPDX-License-Identifier: GPL-2.0
/*
 * cache_ext stress test: hammer the attachment lifecycle while worker
 * processes churn and truncate page cache in the governed memcg.
 *
 * The main process loops attach / inert-attach / live-replace / detach as
 * fast as the control plane allows, while workers generate the races the
 * design claims to survive: placement vs truncation, eviction vs refault,
 * partial truncation of large folios (splits of owned folios), and
 * continuous reclaim at memory.max. Success is: no worker dies (an OOM
 * kill would be a SIGKILL), the lifecycle operations keep succeeding, and
 * everything drains to zero at the end.
 */
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <test_progs.h>
#include "cgroup_helpers.h"
#include "cache_ext_fifo.skel.h"

#define CG_STRESS	"/cache_ext_stress"
#define MEMORY_MAX	(32 << 20)
#define CHURN_FILE_SIZE	(16 << 20)
#define IO_CHUNK	(1 << 20)
#define NR_CHURN_WORKERS 2
#define RUN_SECS	15

static volatile char *stop_flag;

static void churn_worker(int id)
{
	char path[64];
	char *chunk;
	int fd;

	chunk = malloc(IO_CHUNK);
	if (!chunk)
		exit(1);
	memset(chunk, 0xa5, IO_CHUNK);
	snprintf(path, sizeof(path), "stress_churn_%d", id);

	/*
	 * The file persists across rounds: both workers' files together
	 * exceed memory.max, so the read passes generate sustained clean-
	 * cache pressure that only policy (or fallback) eviction relieves —
	 * unlinking each round would free everything via truncation instead.
	 */
	fd = open(path, O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		exit(2);
	while (!*stop_flag) {
		size_t off;
		int pass;

		for (off = 0; off < CHURN_FILE_SIZE; off += IO_CHUNK)
			if (pwrite(fd, chunk, IO_CHUNK, off) != IO_CHUNK)
				exit(3);
		if (fsync(fd))
			exit(4);
		for (pass = 0; pass < 2 && !*stop_flag; pass++)
			for (off = 0; off < CHURN_FILE_SIZE; off += IO_CHUNK)
				if (pread(fd, chunk, IO_CHUNK, off) != IO_CHUNK)
					exit(5);
	}
	close(fd);
	unlink(path);
	free(chunk);
	exit(0);
}

/*
 * Truncation/extension worker: races page cache removal against placement
 * and forces splits of any large folios straddling the truncation point.
 */
static void truncate_worker(void)
{
	char *chunk;
	unsigned int seed = 12345;
	int fd;

	chunk = malloc(IO_CHUNK);
	if (!chunk)
		exit(1);
	memset(chunk, 0x3c, IO_CHUNK);

	fd = open("stress_trunc", O_CREAT | O_RDWR, 0600);
	if (fd < 0)
		exit(2);

	while (!*stop_flag) {
		size_t size = ((rand_r(&seed) % 4) + 1) * IO_CHUNK;
		size_t cut = rand_r(&seed) % size;
		size_t off;

		for (off = 0; off < size; off += IO_CHUNK)
			if (pwrite(fd, chunk, IO_CHUNK, off) != IO_CHUNK)
				exit(3);
		if (fsync(fd))
			exit(4);
		for (off = 0; off < size; off += IO_CHUNK)
			if (pread(fd, chunk, IO_CHUNK, off) != IO_CHUNK)
				exit(5);
		/* Non-page-aligned cuts split large folios. */
		if (ftruncate(fd, cut + 511))
			exit(6);
	}
	close(fd);
	unlink("stress_trunc");
	free(chunk);
	exit(0);
}

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

	for (i = 0; i < 150; i++) {
		if (!read_global_cache_ext_stat())
			return true;
		usleep(100 * 1000);
	}
	return false;
}

void test_cache_ext_stress(void)
{
	struct cache_ext_fifo *skel = NULL;
	struct bpf_link *link = NULL, *inert = NULL;
	pid_t workers[NR_CHURN_WORKERS + 1];
	int nr_workers = 0, lifecycle_ops = 0;
	int cgroup_fd = -1, env_fd, i;
	__u64 start;
	char buf[32];

	env_fd = test__join_cgroup("/cache_ext_stress_env");
	if (!ASSERT_GE(env_fd, 0, "setup cgroup environment"))
		return;

	cgroup_fd = create_and_get_cgroup(CG_STRESS);
	if (!ASSERT_GE(cgroup_fd, 0, "create cgroup"))
		goto out;
	snprintf(buf, sizeof(buf), "%d", MEMORY_MAX);
	if (!ASSERT_OK(write_cgroup_file(CG_STRESS, "memory.max", buf),
		       "set memory.max"))
		goto out;
	write_cgroup_file(CG_STRESS, "memory.swap.max", "0");

	stop_flag = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (!ASSERT_OK_PTR((void *)stop_flag, "mmap stop flag"))
		goto out;
	*stop_flag = 0;

	skel = cache_ext_fifo__open_and_load();
	if (!ASSERT_OK_PTR(skel, "open_and_load"))
		goto out;

	link = bpf_map__attach_cgroup_opts(skel->maps.fifo_ops, cgroup_fd,
					   NULL);
	if (!ASSERT_OK_PTR(link, "initial attach"))
		goto out;

	for (i = 0; i < NR_CHURN_WORKERS + 1; i++) {
		pid_t pid = fork();

		if (pid < 0)
			break;
		if (pid == 0) {
			/* The workdir path is PID-derived; use the parent's. */
			if (join_parent_cgroup(CG_STRESS))
				exit(10);
			if (i < NR_CHURN_WORKERS)
				churn_worker(i);
			else
				truncate_worker();
			exit(0); /* not reached */
		}
		workers[nr_workers++] = pid;
	}
	if (!ASSERT_EQ(nr_workers, NR_CHURN_WORKERS + 1, "forked workers"))
		goto stop;

	/* Lifecycle hammer, alternating through distinct operations. */
	start = time(NULL);
	while (time(NULL) - start < RUN_SECS) {
		switch (lifecycle_ops % 6) {
		case 0: /* inert second attachment appears... */
			inert = bpf_map__attach_cgroup_opts(
					skel->maps.noop_ops, cgroup_fd, NULL);
			if (!ASSERT_OK_PTR(inert, "attach inert"))
				goto stop;
			break;
		case 1: /* ...and disappears (resync no-op path). */
			bpf_link__destroy(inert);
			inert = NULL;
			break;
		case 2: /* live replace forward. */
			if (!ASSERT_OK(bpf_link__update_map(
						link, skel->maps.fifo_ops2),
				       "replace to fifo_ops2"))
				goto stop;
			break;
		case 3: /* live replace back. */
			if (!ASSERT_OK(bpf_link__update_map(
						link, skel->maps.fifo_ops),
				       "replace to fifo_ops"))
				goto stop;
			break;
		case 4: /* full detach: workers run on the kernel LRU. */
			bpf_link__destroy(link);
			link = NULL;
			usleep(50 * 1000);
			break;
		case 5: /* re-attach. */
			link = bpf_map__attach_cgroup_opts(
					skel->maps.fifo_ops, cgroup_fd, NULL);
			if (!ASSERT_OK_PTR(link, "re-attach"))
				goto stop;
			break;
		}
		lifecycle_ops++;
		usleep(100 * 1000);
	}

stop:
	*stop_flag = 1;
	for (i = 0; i < nr_workers; i++) {
		int status;

		if (waitpid(workers[i], &status, 0) < 0)
			continue;
		/* An OOM kill shows up as SIGKILL. */
		ASSERT_TRUE(WIFEXITED(status), "worker exited normally");
		if (WIFEXITED(status))
			ASSERT_EQ(WEXITSTATUS(status), 0, "worker status");
	}

	ASSERT_GT(lifecycle_ops, RUN_SECS * 5, "lifecycle ops kept flowing");
	ASSERT_GT(skel->bss->nr_added, 0, "policy adopted folios");
	ASSERT_GT(skel->bss->nr_evicted, 0, "policy evicted folios");

	if (inert)
		bpf_link__destroy(inert);
	inert = NULL;
	if (link)
		bpf_link__destroy(link);
	link = NULL;
	ASSERT_TRUE(stat_drains_to_zero(), "everything drained at the end");
out:
	cache_ext_fifo__destroy(skel);
	if (cgroup_fd >= 0) {
		close(cgroup_fd);
		remove_cgroup(CG_STRESS);
	}
	close(env_fd);
	cleanup_cgroup_environment();
}
