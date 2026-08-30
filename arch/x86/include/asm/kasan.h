/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KASAN_H
#define _ASM_X86_KASAN_H

#include <linux/const.h>
#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)
#define KASAN_SHADOW_SCALE_SHIFT 3

#ifndef __ASSEMBLER__
extern unsigned int __pgtable_l5_enabled;
#endif

/*
 * KASAN_SHADOW_START/END depend on whether 5-level paging is enabled.
 * Deliberately do NOT use __VIRTUAL_MASK_SHIFT / pgtable_l5_enabled() here:
 * those are backed by cpu_feature_enabled(X86_FEATURE_LA57), which, until
 * alternatives have been applied, reads boot_cpu_data.x86_capability at run
 * time. identify_cpu(&boot_cpu_data) zeroes that array with interrupts
 * enabled, and apply_alternatives() flips it mid-way, so any out-of-line
 * KASAN check (kasan_check_range()) running in that window would compute the
 * 4-level KASAN_SHADOW_START on a 5-level kernel and report a bogus
 * wild-memory-access for perfectly valid direct-map addresses. Use the
 * early-boot variable instead, which is set once in startup code and never
 * changes.
 */
#define KASAN_VIRTUAL_MASK_SHIFT (__pgtable_l5_enabled ? 56 : 47)
/*
 * Compiler uses shadow offset assuming that addresses start
 * from 0. Kernel addresses don't start from 0, so shadow
 * for kernel really starts from compiler's shadow offset +
 * 'kernel address space start' >> KASAN_SHADOW_SCALE_SHIFT
 */
#define KASAN_SHADOW_START      (KASAN_SHADOW_OFFSET + \
					((-1UL << KASAN_VIRTUAL_MASK_SHIFT) >> \
						KASAN_SHADOW_SCALE_SHIFT))
/*
 * 47 bits for kernel address -> (47 - KASAN_SHADOW_SCALE_SHIFT) bits for shadow
 * 56 bits for kernel address -> (56 - KASAN_SHADOW_SCALE_SHIFT) bits for shadow
 */
#define KASAN_SHADOW_END        (KASAN_SHADOW_START + \
					(1ULL << (__VIRTUAL_MASK_SHIFT - \
						  KASAN_SHADOW_SCALE_SHIFT)))

#ifndef __ASSEMBLER__

#ifdef CONFIG_KASAN
void __init kasan_early_init(void);
void __init kasan_init(void);
void __init kasan_populate_shadow_for_vaddr(void *va, size_t size, int nid);
#else
static inline void kasan_early_init(void) { }
static inline void kasan_init(void) { }
static inline void kasan_populate_shadow_for_vaddr(void *va, size_t size,
						   int nid) { }
#endif

#endif

#endif
