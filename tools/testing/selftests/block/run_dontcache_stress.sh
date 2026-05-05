#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Run DONTCACHE stress tests across all 4 configurations and produce
# side-by-side comparison tables.
#
# Reads run without a cgroup using a range larger than RAM so that
# normal reads thrash the page cache while DONTCACHE avoids it.
#
# Writes run inside a memory cgroup sized smaller than the write
# device so that normal writes stall on reclaim while DONTCACHE
# pages are evicted immediately after writeback.
#
# Usage: ./run_dontcache_stress.sh [options]
#   -r <device>    block device for read tests   (default: /dev/nvme0n1p2)
#   -w <device>    block device for write tests  (default: none, skips writes)
#   -t <seconds>   duration per test             (default: 15)
#   -o <file>      write results to file
#
# Read range defaults to 2x RAM. Write cgroup defaults to 1/4 of the
# write device size.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
STRESS="$SCRIPT_DIR/test_dontcache_stress"
READ_DEV="/dev/nvme0n1p2"
WRITE_DEV=""
DURATION=15
OUTFILE=""

usage() {
	echo "Usage: $0 [options]"
	echo "  -r <device>   read test device    (default: $READ_DEV)"
	echo "  -w <device>   write test device   (default: skip writes)"
	echo "  -t <seconds>  duration per test   (default: $DURATION)"
	echo "  -o <file>     write results to file"
	exit 1
}

while getopts "r:w:t:o:h" opt; do
	case $opt in
	r) READ_DEV="$OPTARG" ;;
	w) WRITE_DEV="$OPTARG" ;;
	t) DURATION="$OPTARG" ;;
	o) OUTFILE="$OPTARG" ;;
	*) usage ;;
	esac
done

if [ -n "$OUTFILE" ]; then
	exec > >(tee "$OUTFILE") 2>&1
fi

if [ ! -x "$STRESS" ]; then
	echo "Compiling test_dontcache_stress..."
	gcc -O2 -Wall -o "$STRESS" "$SCRIPT_DIR/test_dontcache_stress.c"
fi

if [ "$(id -u)" -ne 0 ]; then
	echo "Error: must run as root" >&2
	exit 1
fi

# Compute read range: 2x total RAM.
RAM_KB=$(awk '/MemTotal/{print $2}' /proc/meminfo)
READ_RANGE=$(( RAM_KB * 1024 * 2 ))

# Compute write cgroup: 1/4 of write device size.
WRITE_CG_MEM=""
WRITE_DEV_BYTES=""
if [ -n "$WRITE_DEV" ]; then
	WRITE_DEV_BYTES=$(blockdev --getsize64 "$WRITE_DEV")
	WRITE_CG_MEM=$(( WRITE_DEV_BYTES / 4 ))
fi

CG_DIR=""
cleanup() {
	[ -n "$CG_DIR" ] && rmdir "$CG_DIR" 2>/dev/null || true
}
trap cleanup EXIT

drop_caches() {
	sync
	echo 3 > /proc/sys/vm/drop_caches
	sleep 1
}

run_test() {
	local args="$1"
	local use_cgroup="$2"

	drop_caches

	if [ "$use_cgroup" = "1" ] && [ -n "$CG_DIR" ]; then
		sh -c "echo \$\$ > $CG_DIR/cgroup.procs && exec $STRESS $args"
	else
		$STRESS $args
	fi
}

parse_mbps() {
	grep -E '^ *[0-9]+ ' "$1" | awk '{print $2}'
}

parse_avg() {
	grep '^ *avg' "$1" | awk '{print $2}'
}

parse_total() {
	grep '^ *avg' "$1" | awk '{print $3}'
}

print_table() {
	local label="$1"
	local file_normal="$2"
	local file_dontcache="$3"

	mapfile -t normal < <(parse_mbps "$file_normal")
	mapfile -t dontcache < <(parse_mbps "$file_dontcache")

	local avg_normal avg_dontcache total_normal total_dontcache
	avg_normal=$(parse_avg "$file_normal")
	avg_dontcache=$(parse_avg "$file_dontcache")
	total_normal=$(parse_total "$file_normal")
	total_dontcache=$(parse_total "$file_dontcache")

	local max=${#normal[@]}
	[ ${#dontcache[@]} -gt "$max" ] && max=${#dontcache[@]}

	echo ""
	echo "=== $label ==="
	printf "%4s  %12s  %14s  %10s\n" "sec" "normal MB/s" "dontcache MB/s" "delta"
	printf "%4s  %12s  %14s  %10s\n" "----" "------------" "--------------" "----------"

	for ((i = 0; i < max; i++)); do
		local n="${normal[$i]:-}"
		local d="${dontcache[$i]:-}"
		local delta=""

		if [ -n "$n" ] && [ -n "$d" ]; then
			delta=$(awk "BEGIN {
				n=$n; d=$d;
				if (n > 0) printf \"%+.0f%%\", (d - n) / n * 100;
				else print \"--\"
			}")
		fi

		printf "%4d  %12s  %14s  %10s\n" \
			$((i + 1)) \
			"${n:---}" \
			"${d:---}" \
			"${delta:---}"
	done

	printf "%4s  %12s  %14s  %10s\n" "----" "------------" "--------------" "----------"

	local avg_delta=""
	if [ -n "$avg_normal" ] && [ -n "$avg_dontcache" ]; then
		avg_delta=$(awk "BEGIN {
			n=$avg_normal; d=$avg_dontcache;
			if (n > 0) printf \"%+.0f%%\", (d - n) / n * 100;
			else print \"--\"
		}")
	fi

	printf "%4s  %12s  %14s  %10s\n" \
		"avg" \
		"${avg_normal:---}" \
		"${avg_dontcache:---}" \
		"${avg_delta:---}"

	printf "%4s  %12s  %14s\n" \
		"tot" \
		"${total_normal:---} MB" \
		"${total_dontcache:---} MB"
}

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR; cleanup" EXIT

echo "========================================"
echo " DONTCACHE Stress Test"
echo " kernel:    $(uname -r)"
echo " date:      $(date -Iseconds)"
echo " duration:  ${DURATION}s per test"
echo " RAM:       $((RAM_KB / 1024)) MB"
[ -n "$READ_DEV" ]  && \
echo " read dev:  $READ_DEV (range: $((READ_RANGE / 1024 / 1024 / 1024)) GB, no cgroup)"
[ -n "$WRITE_DEV" ] && \
echo " write dev: $WRITE_DEV (range: $((WRITE_DEV_BYTES / 1024 / 1024)) MB, cgroup: $((WRITE_CG_MEM / 1024 / 1024)) MB)"
echo "========================================"

# --- Read tests (no cgroup, range > RAM) ---
if [ -n "$READ_DEV" ]; then
	echo ""
	echo ">> Read tests on $READ_DEV (no cgroup, ${READ_RANGE} byte range)"

	echo "  [1/4] read normal..."
	run_test "-t $DURATION -s $READ_RANGE $READ_DEV" 0 \
		> "$TMPDIR/read_normal.out" 2>&1

	echo "  [2/4] read dontcache..."
	run_test "-d -t $DURATION -s $READ_RANGE $READ_DEV" 0 \
		> "$TMPDIR/read_dontcache.out" 2>&1
fi

# --- Write tests (in cgroup) ---
if [ -n "$WRITE_DEV" ]; then
	CG_DIR="/sys/fs/cgroup/dontcache_stress_$$"
	mkdir -p "$CG_DIR"
	echo "+memory" > /sys/fs/cgroup/cgroup.subtree_control
	echo "$WRITE_CG_MEM" > "$CG_DIR/memory.max"
	echo 0 > "$CG_DIR/memory.swap.max" 2>/dev/null || true

	echo ""
	echo ">> Write tests on $WRITE_DEV (cgroup: $((WRITE_CG_MEM / 1024 / 1024)) MB)"

	echo "  [3/4] write normal..."
	run_test "-w -t $DURATION $WRITE_DEV" 1 \
		> "$TMPDIR/write_normal.out" 2>&1

	echo "  [4/4] write dontcache..."
	run_test "-w -d -t $DURATION $WRITE_DEV" 1 \
		> "$TMPDIR/write_dontcache.out" 2>&1

	rmdir "$CG_DIR" 2>/dev/null || true
	CG_DIR=""
fi

# --- Results ---
echo ""
echo "========================================"
echo " Results"
echo "========================================"

if [ -n "$READ_DEV" ]; then
	print_table "READS ($READ_DEV, no cgroup, $((READ_RANGE / 1024 / 1024 / 1024)) GB range)" \
		"$TMPDIR/read_normal.out" \
		"$TMPDIR/read_dontcache.out"
fi

if [ -n "$WRITE_DEV" ]; then
	print_table "WRITES ($WRITE_DEV, $((WRITE_CG_MEM / 1024 / 1024)) MB cgroup)" \
		"$TMPDIR/write_normal.out" \
		"$TMPDIR/write_dontcache.out"
fi

echo ""
