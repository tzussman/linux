/* SPDX-License-Identifier: GPL-2.0 */
/*
 * cache_ext: BPF-managed page cache eviction policies.
 */
#ifndef _LINUX_CACHE_EXT_H
#define _LINUX_CACHE_EXT_H

struct mem_cgroup;

#ifdef CONFIG_CACHE_EXT

void cache_ext_memcg_offline(struct mem_cgroup *memcg);

#else /* CONFIG_CACHE_EXT */

static inline void cache_ext_memcg_offline(struct mem_cgroup *memcg)
{
}

#endif /* CONFIG_CACHE_EXT */

#endif /* _LINUX_CACHE_EXT_H */
