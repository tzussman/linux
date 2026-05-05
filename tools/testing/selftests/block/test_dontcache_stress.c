#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE	(0x00000080)
#endif

#define CHUNK_SIZE	(1024 * 1024)

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

static double now_sec(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

int main(int argc, char **argv)
{
	int fd, flags = 0, duration = 10, do_write = 0;
	size_t range = 1UL * 1024 * 1024 * 1024; /* 1GB default */
	unsigned long long dev_bytes;
	char *buf;
	const char *dev;
	int opt;

	while ((opt = getopt(argc, argv, "ds:t:w")) != -1) {
		switch (opt) {
		case 'd':
			flags = RWF_DONTCACHE;
			break;
		case 's':
			range = strtoul(optarg, NULL, 0);
			break;
		case 't':
			duration = atoi(optarg);
			break;
		case 'w':
			do_write = 1;
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-d] [-w] [-s range_bytes] [-t seconds] <device>\n",
				argv[0]);
			return 1;
		}
	}

	if (optind >= argc) {
		fprintf(stderr,
			"Usage: %s [-d] [-s range_bytes] [-t seconds] <device>\n",
			argv[0]);
		return 1;
	}
	dev = argv[optind];

	buf = aligned_alloc(4096, CHUNK_SIZE);
	if (!buf) {
		perror("aligned_alloc");
		return 1;
	}

	fd = open(dev, do_write ? O_RDWR : O_RDONLY);
	if (fd < 0) {
		perror(dev);
		free(buf);
		return 1;
	}

	if (ioctl(fd, BLKGETSIZE64, &dev_bytes) == 0) {
		if (range > dev_bytes)
			range = dev_bytes;
	}

	/* Drop caches before starting. */
	sync();
	{
		int dc = open("/proc/sys/vm/drop_caches", O_WRONLY);
		if (dc >= 0) {
			write(dc, "3", 1);
			close(dc);
		}
	}

	memset(buf, 0xAB, CHUNK_SIZE);

	printf("%s %zu MB range on %s, %s, %d seconds\n",
	       do_write ? "Writing" : "Reading",
	       range / (1024 * 1024), dev,
	       flags ? "DONTCACHE" : "normal", duration);
	printf("%4s  %10s  %10s\n", "sec", "MB/s", "total MB");

	size_t off = 0;
	size_t total_bytes = 0;
	double t_start = now_sec();
	double t_interval = t_start;
	size_t interval_bytes = 0;
	int sec = 0;

	while (now_sec() - t_start < duration) {
		ssize_t ret;

		if (do_write)
			ret = do_pwritev2(fd, buf, CHUNK_SIZE, off, flags);
		else
			ret = do_preadv2(fd, buf, CHUNK_SIZE, off, flags);

		if (ret < 0) {
			fprintf(stderr, "%s offset %zu: %s\n",
				do_write ? "pwritev2" : "preadv2",
				off, strerror(errno));
			break;
		}

		total_bytes += ret;
		interval_bytes += ret;
		off += ret;
		if (off >= range)
			off = 0;

		double now = now_sec();
		double elapsed = now - t_interval;

		if (elapsed >= 1.0) {
			double mbps = (double)interval_bytes / elapsed /
				      (1024 * 1024);

			sec++;
			printf("%4d  %10.1f  %10zu\n",
			       sec, mbps, total_bytes / (1024 * 1024));
			interval_bytes = 0;
			t_interval = now;
		}
	}

	double total_elapsed = now_sec() - t_start;
	double avg_mbps = (double)total_bytes / total_elapsed / (1024 * 1024);

	printf("──────────────────────────────\n");
	printf(" avg  %10.1f  %10zu\n", avg_mbps, total_bytes / (1024 * 1024));

	close(fd);
	free(buf);
	return 0;
}
