#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE	(0x00000080)
#endif

#define CHUNK_SIZE	(1024 * 1024)		/* 1MB */
#define DEFAULT_TOTAL	(64UL * 1024 * 1024)	/* 64MB */

static ssize_t do_preadv2(int fd, void *buf, size_t len, off_t offset,
			   int flags)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };

	return syscall(SYS_preadv2, fd, &iov, 1, offset, (off_t)0, flags);
}

static ssize_t do_pwritev2(int fd, void *buf, size_t len, off_t offset,
			    int flags)
{
	struct iovec iov = { .iov_base = buf, .iov_len = len };

	return syscall(SYS_pwritev2, fd, &iov, 1, offset, (off_t)0, flags);
}

static long count_cached_pages(int fd, size_t len)
{
	unsigned char *vec;
	void *map;
	size_t nr_pages;
	long cached = 0;

	map = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
	if (map == MAP_FAILED)
		return -1;

	nr_pages = (len + 4095) / 4096;
	vec = malloc(nr_pages);
	if (!vec) {
		munmap(map, len);
		return -1;
	}

	if (mincore(map, len, vec) < 0) {
		free(vec);
		munmap(map, len);
		return -1;
	}

	for (size_t i = 0; i < nr_pages; i++)
		if (vec[i] & 1)
			cached++;

	free(vec);
	munmap(map, len);
	return cached;
}

struct meminfo {
	unsigned long cached;
	unsigned long buffers;
};

static struct meminfo read_meminfo(void)
{
	struct meminfo mi = { 0, 0 };
	FILE *f;
	char line[256];
	int found = 0;

	f = fopen("/proc/meminfo", "r");
	if (!f)
		return mi;

	while (fgets(line, sizeof(line), f) && found < 2) {
		if (sscanf(line, "Buffers: %lu kB", &mi.buffers) == 1)
			found++;
		else if (sscanf(line, "Cached: %lu kB", &mi.cached) == 1)
			found++;
	}
	fclose(f);
	return mi;
}

static void drop_caches(void)
{
	int fd;

	sync();
	fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (fd >= 0) {
		write(fd, "3", 1);
		close(fd);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] <device>\n"
		"\n"
		"Options:\n"
		"  -r          read test (default)\n"
		"  -w          write test\n"
		"  -d          use RWF_DONTCACHE\n"
		"  -s <bytes>  total size to read/write (default: 64M)\n"
		"  -D          drop caches before test\n"
		"  -h          this help\n",
		prog);
}

int main(int argc, char **argv)
{
	int fd, opt, flags = 0;
	int do_write = 0, do_drop = 0;
	size_t total = DEFAULT_TOTAL;
	struct meminfo mi_before, mi_after;
	long delta_cached, delta_buffers, cached_pages;
	char *buf;
	const char *dev;

	while ((opt = getopt(argc, argv, "rwds:Dh")) != -1) {
		switch (opt) {
		case 'r':
			do_write = 0;
			break;
		case 'w':
			do_write = 1;
			break;
		case 'd':
			flags = RWF_DONTCACHE;
			break;
		case 's':
			total = strtoul(optarg, NULL, 0);
			break;
		case 'D':
			do_drop = 1;
			break;
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (optind >= argc) {
		usage(argv[0]);
		return 1;
	}
	dev = argv[optind];

	buf = aligned_alloc(4096, CHUNK_SIZE);
	if (!buf) {
		perror("aligned_alloc");
		return 1;
	}
	memset(buf, 0xAB, CHUNK_SIZE);

	fd = open(dev, do_write ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		perror(dev);
		free(buf);
		return 1;
	}

	/* For block devices, cap total to the device size. */
	{
		unsigned long long dev_bytes;

		if (ioctl(fd, BLKGETSIZE64, &dev_bytes) == 0) {
			if (total > dev_bytes)
				total = dev_bytes;
		}
	}

	if (do_drop)
		drop_caches();

	mi_before = read_meminfo();

	for (size_t off = 0; off < total; off += CHUNK_SIZE) {
		ssize_t ret;

		if (do_write)
			ret = do_pwritev2(fd, buf, CHUNK_SIZE, off, flags);
		else
			ret = do_preadv2(fd, buf, CHUNK_SIZE, off, flags);

		if (ret < 0) {
			fprintf(stderr, "%s at offset %zu: %s\n",
				do_write ? "pwritev2" : "preadv2",
				off, strerror(errno));
			close(fd);
			free(buf);
			return 1;
		}
	}

	if (do_write)
		fsync(fd);

	/* Give the dropbehind workqueue time to drain after writes. */
	if (do_write && flags)
		usleep(200000);

	mi_after = read_meminfo();
	delta_cached = (long)mi_after.cached - (long)mi_before.cached;
	delta_buffers = (long)mi_after.buffers - (long)mi_before.buffers;

	/*
	 * Use mincore() to count pages resident in cache for this
	 * specific file/device while the fd is still open.
	 */
	cached_pages = count_cached_pages(fd, total);

	printf("%-5s %s  Cached: %+ld kB  Buffers: %+ld kB",
	       do_write ? "WRITE" : "READ",
	       flags ? "DONTCACHE" : "normal   ",
	       delta_cached, delta_buffers);
	if (cached_pages >= 0)
		printf("  pages: %ld/%zu",
		       cached_pages, total / 4096);
	printf("\n");

	/*
	 * Sanity check: with DONTCACHE, the file-specific page count
	 * should be well under the total. Fall back to the global
	 * delta (Cached + Buffers) if mincore() isn't available.
	 */
	if (flags) {
		long total_pages = total / 4096;
		int pass;

		if (cached_pages >= 0) {
			/* Allow 25% of pages to still be resident. */
			pass = cached_pages < total_pages / 4;
			if (!pass)
				fprintf(stderr,
					"FAIL: %ld/%ld pages still cached for DONTCACHE\n",
					cached_pages, total_pages);
		} else {
			long expected_max = (long)(total / 1024) / 4;
			long delta_total = delta_cached + delta_buffers;

			pass = delta_total < expected_max;
			if (!pass)
				fprintf(stderr,
					"FAIL: cache grew by %ld kB, expected < %ld kB for DONTCACHE\n",
					delta_total, expected_max);
		}

		if (pass)
			printf("PASS\n");
		else {
			close(fd);
			free(buf);
			return 1;
		}
	}

	close(fd);
	free(buf);
	return 0;
}
