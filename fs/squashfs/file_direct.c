// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2013
 * Phillip Lougher <phillip@squashfs.org.uk>
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/mutex.h>

#include "squashfs_fs.h"
#include "squashfs_fs_sb.h"
#include "squashfs_fs_i.h"
#include "squashfs.h"
#include "page_actor.h"

/* Read separately compressed datablock directly into page cache */
int squashfs_readpage_block(struct folio *folio, u64 block, int bsize,
		int expected)
{
	struct inode *inode = folio->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	loff_t file_end = (i_size_read(inode) - 1) >> PAGE_SHIFT;
	unsigned int nr = squashfs_pages_per_block(msblk);
	loff_t start_index = squashfs_block_first_index(msblk, folio->index);
	loff_t end_index = start_index + nr - 1;
	loff_t start = start_index << PAGE_SHIFT;
	loff_t index;
	int i, nr_folios, res = -ENOMEM;
	struct folio **folios, *last_folio;
	struct squashfs_page_actor *actor;

	if (end_index > file_end)
		end_index = file_end;

	nr_folios = end_index - start_index + 1;

	folios = kmalloc_objs(*folios, nr_folios);
	if (folios == NULL)
		return res;

	/* Try to grab all the folios covered by the Squashfs block */
	for (i = 0, index = start_index; index <= end_index; index++) {
		struct folio *f;

		if (index == folio->index)
			f = folio;
		else
			f = __filemap_get_folio(folio->mapping, index,
					FGP_LOCK | FGP_CREAT | FGP_NOWAIT,
					mapping_gfp_mask(folio->mapping));

		if (IS_ERR(f))
			continue;

		if (folio_test_uptodate(f)) {
			folio_unlock(f);
			folio_put(f);
			continue;
		}

		folios[i++] = f;
	}

	nr_folios = i;

	/*
	 * Create a "page actor" which will kmap and kunmap the
	 * page cache folios appropriately within the decompressor.
	 */
	actor = squashfs_page_actor_init_folios(msblk, folios, nr_folios,
					expected, start);
	if (actor == NULL)
		goto mark_errored;

	/* Decompress directly into the page cache buffers */
	res = squashfs_read_data(inode->i_sb, block, bsize, NULL, actor);

	last_folio = squashfs_page_actor_free(actor);

	if (res < 0)
		goto mark_errored;

	if (res != expected || IS_ERR(last_folio)) {
		res = -EIO;
		goto mark_errored;
	}

	/* Last folio (if present) may have trailing bytes not filled */
	if (end_index == file_end && last_folio)
		squashfs_actor_zero_tail(last_folio, start, res);

	/* Mark folios as uptodate, unlock and release */
	for (i = 0; i < nr_folios; i++) {
		flush_dcache_folio(folios[i]);
		folio_end_read(folios[i], true);
		if (folios[i] != folio)
			folio_put(folios[i]);
	}

	kfree(folios);

	return 0;

mark_errored:
	/*
	 * Decompression failed. The target folio is dealt with by the
	 * caller.
	 */
	for (i = 0; i < nr_folios; i++) {
		if (folios[i] == folio)
			continue;
		flush_dcache_folio(folios[i]);
		folio_unlock(folios[i]);
		folio_put(folios[i]);
	}

	kfree(folios);
	return res;
}
