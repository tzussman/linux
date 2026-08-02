// SPDX-License-Identifier: GPL-2.0-or-later
/* file-nommu.c: no-MMU version of ramfs
 *
 * Copyright (C) 2005 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/highmem.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/backing-dev.h>
#include <linux/ramfs.h>
#include <linux/folio_batch.h>
#include <linux/mman.h>
#include <linux/sched.h>
#include <linux/slab.h>

#include <linux/uaccess.h>
#include "internal.h"

static int ramfs_nommu_setattr(struct mnt_idmap *, struct dentry *, struct iattr *);
static unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
						   unsigned long addr,
						   unsigned long len,
						   unsigned long pgoff,
						   unsigned long flags);
static int ramfs_nommu_mmap_prepare(struct vm_area_desc *desc);

static unsigned ramfs_mmap_capabilities(struct file *file)
{
	return NOMMU_MAP_DIRECT | NOMMU_MAP_COPY | NOMMU_MAP_READ |
		NOMMU_MAP_WRITE | NOMMU_MAP_EXEC;
}

const struct file_operations ramfs_file_operations = {
	.mmap_capabilities	= ramfs_mmap_capabilities,
	.mmap_prepare		= ramfs_nommu_mmap_prepare,
	.get_unmapped_area	= ramfs_nommu_get_unmapped_area,
	.read_iter		= generic_file_read_iter,
	.write_iter		= generic_file_write_iter,
	.fsync			= noop_fsync,
	.splice_read		= filemap_splice_read,
	.splice_write		= iter_file_splice_write,
	.llseek			= generic_file_llseek,
};

const struct inode_operations ramfs_file_inode_operations = {
	.setattr		= ramfs_nommu_setattr,
	.getattr		= simple_getattr,
};

/*****************************************************************************/
/*
 * add a contiguous set of pages into a ramfs inode when it's truncated from
 * size 0 on the assumption that it's going to be used for an mmap of shared
 * memory
 */
int ramfs_nommu_expand_for_mapping(struct inode *inode, size_t newsize)
{
	unsigned long npages, loop;
	void *data;
	int ret;
	gfp_t gfp = mapping_gfp_mask(inode->i_mapping);

	/* make various checks */
	if (unlikely(get_order(newsize) > MAX_PAGE_ORDER))
		return -EFBIG;

	ret = inode_newsize_ok(inode, newsize);
	if (ret)
		return ret;

	i_size_write(inode, newsize);

	npages = (newsize + PAGE_SIZE - 1) >> PAGE_SHIFT;

	/*
	 * The nommu mmap path hands userspace a pointer straight into the
	 * page cache, so the file has to be backed by one physically
	 * contiguous run.  alloc_pages_exact() makes the high order
	 * allocation, splits it into single pages and returns the tail
	 * beyond npages, and rejects __GFP_HIGHMEM, which ramfs asks for.
	 */
	data = alloc_pages_exact(npages << PAGE_SHIFT,
				 (gfp & ~__GFP_HIGHMEM) | __GFP_ZERO);
	if (!data)
		return -ENOMEM;

	/* attach all the pages to the inode's address space */
	for (loop = 0; loop < npages; loop++) {
		struct page *page = virt_to_page(data + (loop << PAGE_SHIFT));

		ret = add_to_page_cache_lru(page, inode->i_mapping, loop,
					gfp);
		if (ret < 0)
			goto add_error;

		/* prevent the page from being discarded on memory pressure */
		SetPageDirty(page);
		SetPageUptodate(page);

		unlock_page(page);
		put_page(page);
	}

	return 0;

add_error:
	/*
	 * The run is already split and the pages handed over belong to the
	 * page cache now, so free_pages_exact() cannot be used on the rest.
	 */
	while (loop < npages)
		__free_page(virt_to_page(data + (loop++ << PAGE_SHIFT)));
	return ret;
}

/*****************************************************************************/
/*
 *
 */
static int ramfs_nommu_resize(struct inode *inode, loff_t newsize, loff_t size)
{
	int ret;

	/* assume a truncate from zero size is going to be for the purposes of
	 * shared mmap */
	if (size == 0) {
		if (unlikely(newsize >> 32))
			return -EFBIG;

		return ramfs_nommu_expand_for_mapping(inode, newsize);
	}

	/* check that a decrease in size doesn't cut off any shared mappings */
	if (newsize < size) {
		ret = nommu_shrink_inode_mappings(inode, size, newsize);
		if (ret < 0)
			return ret;
	}

	truncate_setsize(inode, newsize);
	return 0;
}

/*****************************************************************************/
/*
 * handle a change of attributes
 * - we're specifically interested in a change of size
 */
static int ramfs_nommu_setattr(struct mnt_idmap *idmap,
			       struct dentry *dentry, struct iattr *ia)
{
	struct inode *inode = d_inode(dentry);
	unsigned int old_ia_valid = ia->ia_valid;
	int ret = 0;

	/* POSIX UID/GID verification for setting inode attributes */
	ret = setattr_prepare(&nop_mnt_idmap, dentry, ia);
	if (ret)
		return ret;

	/* pick out size-changing events */
	if (ia->ia_valid & ATTR_SIZE) {
		loff_t size = inode->i_size;

		if (ia->ia_size != size) {
			ret = ramfs_nommu_resize(inode, ia->ia_size, size);
			if (ret < 0 || ia->ia_valid == ATTR_SIZE)
				goto out;
		} else {
			/* we skipped the truncate but must still update
			 * timestamps
			 */
			ia->ia_valid |= ATTR_MTIME|ATTR_CTIME;
		}
	}

	setattr_copy(&nop_mnt_idmap, inode, ia);
 out:
	ia->ia_valid = old_ia_valid;
	return ret;
}

/*****************************************************************************/
/*
 * try to determine where a shared mapping can be made
 * - we require that:
 *   - the pages to be mapped must exist
 *   - the pages be physically contiguous in sequence
 */
static unsigned long ramfs_nommu_get_unmapped_area(struct file *file,
					    unsigned long addr, unsigned long len,
					    unsigned long pgoff, unsigned long flags)
{
	unsigned long maxpages, lpages, nr_folios, loop, ret, nr_pages, pfn;
	struct inode *inode = file_inode(file);
	unsigned long first = pgoff;
	struct folio_batch fbatch;
	unsigned long skip = 0;
	loff_t isize;

	/* the mapping mustn't extend beyond the EOF */
	lpages = (len + PAGE_SIZE - 1) >> PAGE_SHIFT;
	isize = i_size_read(inode);

	ret = -ENOSYS;
	maxpages = (isize + PAGE_SIZE - 1) >> PAGE_SHIFT;
	if (pgoff >= maxpages)
		goto out;

	if (maxpages - pgoff < lpages)
		goto out;

	/* gang-find the pages */
	folio_batch_init(&fbatch);
	nr_pages = 0;
repeat:
	nr_folios = filemap_get_folios_contig(inode->i_mapping, &pgoff,
			ULONG_MAX, &fbatch);
	if (!nr_folios) {
		ret = -ENOSYS;
		goto out_free;
	}

	if (ret == -ENOSYS) {
		struct folio *folio = fbatch.folios[0];

		/*
		 * The requested offset may land inside the first folio rather
		 * than on its first page, so start from there rather than
		 * from the front of the folio.
		 */
		skip = first - folio->index;
		ret = (unsigned long)folio_address(folio) +
			(skip << PAGE_SHIFT);
		pfn = folio_pfn(folio) + skip;
	}
	/* check the pages for physical adjacency */
	for (loop = 0; loop < nr_folios; loop++) {
		struct folio *folio = fbatch.folios[loop];

		if (pfn + nr_pages != folio_pfn(folio) + skip) {
			ret = -ENOSYS;
			goto out_free; /* leave if not physical adjacent */
		}
		nr_pages += folio_nr_pages(folio) - skip;
		skip = 0;
		if (nr_pages >= lpages)
			goto out_free; /* successfully found desired pages*/
	}

	if (nr_pages < lpages) {
		folio_batch_release(&fbatch);
		goto repeat; /* loop if pages are missing */
	}
	/* okay - all conditions fulfilled */

out_free:
	folio_batch_release(&fbatch);
out:
	return ret;
}

/*****************************************************************************/
/*
 * set up a mapping for shared memory segments
 */
static int ramfs_nommu_mmap_prepare(struct vm_area_desc *desc)
{
	if (!is_nommu_shared_vma_flags(&desc->vma_flags))
		return -ENOSYS;

	file_accessed(desc->file);
	desc->vm_ops = &generic_file_vm_ops;
	return 0;
}
