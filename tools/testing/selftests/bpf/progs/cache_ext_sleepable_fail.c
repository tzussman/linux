// SPDX-License-Identifier: GPL-2.0
/*
 * Negative test: only init() may be sleepable. A sleepable folio_added
 * must be rejected by check_member at map load.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops.s/folio_added")
void BPF_PROG(sleepy_folio_added, struct folio *folio)
{
}

SEC(".struct_ops.link")
struct cache_ext_ops sleepy_ops = {
	.folio_added = (void *)sleepy_folio_added,
};
