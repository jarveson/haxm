#include "include/npt.h"

#include "../include/hax.h"
#include "../include/hax_host_mem.h"
#include "include/paging.h"

static hax_pdpe INVALID_PDPE = {
	.pfn = INVALID_PFN
	// Other fields are initialized to 0
};

static inline uint get_pml4_index(uint64_t gfn)
{
	return (uint)(gfn >> (HAX_NPT_TABLE_SHIFT * 3));
}

static inline uint get_pdpt_gross_index(uint64_t gfn)
{
	return (uint)(gfn >> (HAX_NPT_TABLE_SHIFT * 2));
}

static inline uint get_pdpt_index(uint64_t gfn)
{
	return (uint)((gfn >> (HAX_NPT_TABLE_SHIFT * 2)) &
		(HAX_NPT_TABLE_SIZE - 1));
}

static inline uint get_pd_gross_index(uint64_t gfn)
{
	return (uint)(gfn >> HAX_NPT_TABLE_SHIFT);
}

static inline uint get_pd_index(uint64_t gfn)
{
	return (uint)((gfn >> HAX_NPT_TABLE_SHIFT) & (HAX_NPT_TABLE_SIZE - 1));
}

static inline uint get_pt_index(uint64_t gfn)
{
	return (uint)(gfn & (HAX_NPT_TABLE_SIZE - 1));
}

static hax_npt_page * npt_tree_alloc_page(hax_npt_tree *tree)
{
	hax_npt_page *page;
	int ret;

	page = (hax_npt_page *)hax_vmalloc(sizeof(*page), 0);
	if (!page) {
		return NULL;
	}
	ret = hax_alloc_page_frame(HAX_PAGE_ALLOC_ZEROED, &page->memdesc);
	if (ret) {
		hax_error("%s: hax_alloc_page_frame() returned %d\n", __func__, ret);
		hax_vfree(page, sizeof(*page));
		return NULL;
	}
	hax_assert(tree != NULL);
	npt_tree_lock(tree);
	hax_list_add(&page->entry, &tree->page_list);
	npt_tree_unlock(tree);
	return page;
}

// Returns a buffer containing cached information about the |hax_ept_page|
// specified by the given EPT level (PML4, PDPT, PD or PT) and the given GFN.
// The returned buffer can be used to fill the cache if it is not yet available.
// Returns NULL if the |hax_ept_page| in question is not a frequently-used page.
static inline hax_npt_page_kmap * npt_tree_get_freq_page(hax_npt_tree *tree,
	uint64_t gfn, int level)
{
	// Only HAX_EPT_FREQ_PAGE_COUNT EPT pages are considered frequently-used,
	// whose KVA mappings are cached in tree->freq_pages[]. They are:
	// a) The EPT PML4 table, covering the entire GPA space. Cached in
	//    freq_pages[0].
	// b) The first EPT PDPT table, pointed to by entry 0 of a), covering the
	//    first 512GB of the GPA space. Cached in freq_pages[1].
	// c) The first n EPT PD tables (n = HAX_EPT_FREQ_PAGE_COUNT - 2), pointed
	//    to by entries 0..(n - 1) of b), covering the first nGB of the GPA
	//    space. Cached in freq_pages[2..(n + 1)].
	hax_npt_page_kmap *freq_page = NULL;

	hax_assert(tree != NULL);
	switch (level) {
	case HAX_NPT_LEVEL_PML4: {
		freq_page = &tree->freq_pages[0];
		break;
	}
	case HAX_NPT_LEVEL_PDPT: {
		// Extract bits 63..39 of the GPA (== gfn << 12)
		uint pml4_index = get_pml4_index(gfn);
		if (pml4_index == 0) {
			freq_page = &tree->freq_pages[1];
		}
		break;
	}
	case HAX_NPT_LEVEL_PD: {
		// Extract bits 63..30 of the GPA (== gfn << 12)
		uint pml4_pdpt_index = get_pdpt_gross_index(gfn);
		if (pml4_pdpt_index < HAX_NPT_FREQ_PAGE_COUNT - 2) {
			freq_page = &tree->freq_pages[2 + pml4_pdpt_index];
		}
		break;
	}
	default: {
		break;
	}
	}
	return freq_page;
}

int npt_tree_init(hax_npt_tree *tree)
{
	hax_npt_page *root_page;
	hax_npt_page_kmap *root_page_kmap;
	void *kva;
	uint64_t pfn;

	if (!tree) {
		hax_error("%s: tree == NULL\n", __func__);
		return -EINVAL;
	}

	hax_init_list_head(&tree->page_list);
	memset(tree->freq_pages, 0, sizeof(tree->freq_pages));
	tree->invept_pending = false;

	tree->lock = hax_spinlock_alloc_init();
	if (!tree->lock) {
		hax_error("%s: Failed to allocate NPT tree lock\n", __func__);
		return -ENOMEM;
	}

	root_page = npt_tree_alloc_page(tree);
	if (!root_page) {
		hax_error("%s: Failed to allocate NPT root page\n", __func__);
		hax_spinlock_free(tree->lock);
		return -ENOMEM;
	}
	kva = hax_get_kva_phys(&root_page->memdesc);
	hax_assert(kva != NULL);
	pfn = hax_get_pfn_phys(&root_page->memdesc);
	hax_assert(pfn != INVALID_PFN);
	root_page_kmap = npt_tree_get_freq_page(tree, 0, HAX_NPT_LEVEL_PML4);
	hax_assert(root_page_kmap != NULL);
	root_page_kmap->page = root_page;
	root_page_kmap->kva = kva;

	tree->root_page = root_page_kmap;
	// only 'valid' other bits in this are cachedisable and writethrough, but are being ignored
	tree->ncr3.val = 0;
	tree->ncr3.pfn = pfn;
	hax_info("%s: nptp=0x%llx\n", __func__, tree->ncr3.val);
	return 0;
}

static void npt_page_free(hax_npt_page *page)
{
	int ret;

	if (!page) {
		hax_warning("%s: page == NULL\n", __func__);
		return;
	}

	ret = hax_free_page_frame(&page->memdesc);
	if (ret) {
		hax_warning("%s: hax_free_page_frame() returned %d\n", __func__, ret);
		// Still need to free the hax_npt_page object
	}
	hax_vfree(page, sizeof(*page));
}

int npt_tree_free(hax_npt_tree *tree)
{
	hax_npt_page *page, *tmp;
	int i = 0;

	if (!tree) {
		hax_error("%s: tree == NULL\n", __func__);
		return -EINVAL;
	}

	hax_list_entry_for_each_safe(page, tmp, &tree->page_list, hax_npt_page,
		entry) {
		hax_list_del(&page->entry);
		npt_page_free(page);
		i++;
	}
	hax_info("%s: Total %d NPT page(s) freed\n", __func__, i);

	hax_spinlock_free(tree->lock);
	return 0;
}

// Returns a pointer (KVA) to the root page (PML4 table) of the given
// |hax_ept_tree|.
static inline hax_pdpe * npt_tree_get_root_table(hax_npt_tree *tree)
{
	hax_npt_page_kmap *root_page_kmap;

	root_page_kmap = npt_tree_get_freq_page(tree, 0, HAX_NPT_LEVEL_PML4);
	hax_assert(root_page_kmap != NULL);
	return (hax_pdpe *)root_page_kmap->kva;
}

void npt_tree_lock(hax_npt_tree *tree)
{
	hax_spin_lock(tree->lock);
}

void npt_tree_unlock(hax_npt_tree *tree)
{
	hax_spin_unlock(tree->lock);
}

// Given a GFN and a pointer (KVA) to an EPT page table at a non-leaf level
// (PML4, PDPT or PD) that covers the GFN, returns a pointer (KVA) to the next-
// level page table that covers the GFN. This function can be used to walk a
// |hax_ept_tree| from root to leaf.
// |tree|: The |hax_ept_tree| to walk.
// |gfn|: The GFN from which to obtain EPT page table indices.
// |current_level|: The EPT level to which |current_table| belongs. Must be a
//                  non-leaf level (PML4, PDPT or PD).
// |current_table|: The KVA of the current EPT page table. Must not be NULL.
// |kmap|: A buffer to store a host-specific KVA mapping descriptor, which may
//         be created if the next-level EPT page table is not a frequently-used
//         page. The caller must call hax_unmap_page_frame() to destroy the KVA
//         mapping when it is done with the returned pointer.
// |create|: If true and the next-level EPT page table does not yet exist,
//           creates it and updates the corresponding |hax_epte| in
//           |current_table|.
// |visit_current_epte|: An optional callback to be invoked on the |hax_epte|
//                       that belongs to |current_table| and covers |gfn|. May
//                       be NULL.
// |opaque|: An arbitrary pointer passed as-is to |visit_current_epte|.
static hax_pdpe * npt_tree_get_next_table(hax_npt_tree *tree, uint64_t gfn,
	int current_level,
	hax_pdpe *current_table,
	hax_kmap_phys *kmap, bool create,
	npte_visitor visit_current_epte,
	void *opaque)
{
	int next_level = current_level - 1;
	hax_npt_page_kmap *freq_page;
	uint index;
	hax_pdpe *npte;
	hax_pdpe *next_table = NULL;

	hax_assert(tree != NULL);
	hax_assert(next_level >= HAX_NPT_LEVEL_PT && next_level <= HAX_NPT_LEVEL_PDPT);
	index = (uint)((gfn >> (HAX_NPT_TABLE_SHIFT * current_level)) &
		(HAX_NPT_TABLE_SIZE - 1));
	hax_assert(current_table != NULL);
	npte = &current_table[index];
	if (visit_current_epte) {
		visit_current_epte(tree, gfn, current_level, npte, opaque);
	}
	if (!npte->valid && !create) {
		return NULL;
	}

	freq_page = npt_tree_get_freq_page(tree, gfn, next_level);

	if (hax_cmpxchg64(0, INVALID_PDPE.val, &npte->val)) {
		// epte->value was 0, implying epte->perm == HAX_EPT_PERM_NONE, which
		// means the EPT entry pointing to the next-level page table is not
		// present, i.e. the next-level table does not exist
		hax_npt_page *page;
		uint64_t pfn;
		hax_pdpe temp_pdpe = { 0 };
		void *kva;

		page = npt_tree_alloc_page(tree);
		if (!page) {
			npte->val = 0;
			hax_error("%s: Failed to create EPT page table: gfn=0x%llx,"
				" next_level=%d\n", __func__, gfn, next_level);
			return NULL;
		}
		pfn = hax_get_pfn_phys(&page->memdesc);
		hax_assert(pfn != INVALID_PFN);

		temp_pdpe.valid = 1;
		temp_pdpe.readWrite = 1;
		temp_pdpe.user = 1;
		// This is a non-leaf |hax_epte|, so ept_mt and ignore_pat_mt are
		// reserved (see IA SDM Vol. 3C 28.2.2 Figure 28-1)
		temp_pdpe.pfn = pfn;

		kva = hax_get_kva_phys(&page->memdesc);
		hax_assert(kva != NULL);
		if (freq_page) {
			// The next-level EPT table is frequently used, so initialize its
			// KVA mapping cache
			freq_page->page = page;
			freq_page->kva = kva;
		}

		// Create this non-leaf EPT entry
		npte->val = temp_pdpe.val;

		next_table = (hax_pdpe *)kva;
		hax_debug("%s: Created NPT page table: gfn=0x%llx, next_level=%d,"
			" pfn=0x%llx, kva=%p, freq_page_index=%ld\n", __func__, gfn,
			next_level, pfn, kva, freq_page ? freq_page - tree->freq_pages
			: -1);
	}
	else {  // !hax_cmpxchg64(0, INVALID_EPTE.value, &epte->value)
	 // epte->value != 0, which could mean epte->perm != HAX_EPT_PERM_NONE,
	 // i.e. the EPT entry pointing to the next-level EPT page table is
	 // present. But there is another case: *epte == INVALID_EPTE, which
	 // means the next-level page table is being created by another thread
		void *kva;
		int i = 0;

		while (npte->val == INVALID_PDPE.val) {
			// Eventually the other thread will set epte->pfn to either a valid
			// PFN or 0
			if (!(++i % 10000)) {  // 10^4
				hax_info("%s: In iteration %d of while loop\n", __func__, i);
				if (i == 100000000) {  // 10^8 (< INT_MAX)
					hax_error("%s: Breaking out of infinite loop: gfn=0x%llx,"
						" next_level=%d\n", __func__, gfn, next_level);
					return NULL;
				}
			}
		}
		if (!npte->val) {
			// The other thread has cleared epte->value, indicating it could not
			// create the next-level page table
			hax_error("%s: Another thread tried to create the same EPT page"
				" table first, but failed: gfn=0x%llx, next_level=%d\n",
				__func__, gfn, next_level);
			return NULL;
		}

		if (freq_page) {
			// The next-level EPT table is frequently used, so its KVA mapping
			// must have been cached
			kva = freq_page->kva;
			hax_assert(kva != NULL);
		}
		else {
			// The next-level EPT table is not frequently used, which means a
			// temporary KVA mapping needs to be created
			hax_assert(npte->pfn != INVALID_PFN);
			hax_assert(kmap != NULL);
			kva = hax_map_page_frame(npte->pfn, kmap);
			if (!kva) {
				hax_error("%s: Failed to map pfn=0x%llx into KVA space\n",
					__func__, npte->pfn);
			}
		}
		next_table = (hax_pdpe *)kva;
	}
	return next_table;
}

static inline void kmap_swap(hax_kmap_phys *kmap1, hax_kmap_phys *kmap2)
{
	hax_kmap_phys tmp;

	hax_assert(kmap1 != NULL && kmap2 != NULL);
	tmp = *kmap1;
	*kmap1 = *kmap2;
	*kmap2 = tmp;
}

int npt_tree_create_entry(hax_npt_tree *tree, uint64_t gfn, hax_pdpe value)
{
	hax_pdpe *table;
	int level;
	hax_kmap_phys kmap = { 0 }, prev_kmap = { 0 };
	int ret;
	uint pt_index;
	hax_pdpe *pte;

	if (!tree) {
		hax_error("%s: tree == NULL\n", __func__);
		return -EINVAL;
	}
	if (!value.valid) {
		hax_error("%s: value.perm == 0\n", __func__);
		return -EINVAL;
	}

	table = npt_tree_get_root_table(tree);
	hax_assert(table != NULL);
	for (level = HAX_NPT_LEVEL_PML4; level >= HAX_NPT_LEVEL_PD; level--) {
		table = npt_tree_get_next_table(tree, gfn, level, table, &kmap, true,
			NULL, NULL);
		// The previous table is no longer used, so destroy its KVA mapping
		// Note that hax_unmap_page_frame() does not fail when the KVA mapping
		// descriptor is filled with zeroes
		ret = hax_unmap_page_frame(&prev_kmap);
		hax_assert(ret == 0);
		// prev_kmap is now filled with zeroes
		if (!table) {
			hax_error("%s: Failed to grab the next-level NPT page table:"
				" gfn=0x%llx, level=%d\n", __func__, gfn, level);
			return -ENOMEM;
		}
		// Swap prev_kmap with kmap
		kmap_swap(&prev_kmap, &kmap);
		// kmap is now filled with zeroes
	}
	// Now level == HAX_EPT_LEVEL_PT, and table points to an EPT leaf page (PT)
	pt_index = get_pt_index(gfn);
	hax_assert(table != NULL);
	pte = &table[pt_index];
	if (!hax_cmpxchg64(0, value.val, &pte->val)) {
		// pte->value != 0, implying pte->perm != HAX_EPT_PERM_NONE
		if ((pte->val & NPT_IGNORE_ACCESS_DIRTY) != (value.val & NPT_IGNORE_ACCESS_DIRTY)) {
			hax_error("%s: A different PTE corresponding to gfn=0x%llx already"
				" exists: old_value=0x%llx, new_value=0x%llx\n", __func__,
				gfn, pte->val, value.val);
			hax_unmap_page_frame(&kmap);
			return -EEXIST;
		}
		else {
			hax_info("%s: Another thread has already created the same PTE:"
				" gfn=0x%llx, value=0x%llx\n", __func__, gfn, value.val);
		}
	}

	ret = hax_unmap_page_frame(&prev_kmap);
	hax_assert(ret == 0);
	return 0;
}


int npt_tree_create_entries(hax_npt_tree *tree, uint64_t start_gfn, uint64_t npages,
	hax_chunk *chunk, uint64_t offset_within_chunk, uint8_t flags)
{
	bool is_rom = flags & HAX_MEMSLOT_READONLY;
	hax_pdpe new_pte = { 0 };
	uint64_t gfn, end_gfn;
	hax_pdpe *pml4, *pdpt, *pd, *pt;
	hax_kmap_phys pdpt_kmap = { 0 }, pd_kmap = { 0 }, pt_kmap = { 0 };
	int ret;
	uint index, start_index, end_index;
	uint64_t offset = offset_within_chunk;
	int created_count = 0;

	hax_assert(tree != NULL);
	hax_assert(npages != 0);
	hax_assert(chunk != NULL);
	hax_assert(offset_within_chunk + (npages << PG_ORDER_4K) <= chunk->size);

	new_pte.valid = 1;
	new_pte.user = 1;
	new_pte.readWrite = is_rom ? 0 : 1;
	// TODO: Should ignore_pat_mt be set?

	gfn = start_gfn;
	end_gfn = start_gfn + npages - 1;
	pml4 = npt_tree_get_root_table(tree);
	hax_assert(pml4 != NULL);
next_pdpt:
	pdpt = npt_tree_get_next_table(tree, gfn, HAX_NPT_LEVEL_PML4, pml4,
		&pdpt_kmap, true, NULL, NULL);
	if (!pdpt) {
		hax_error("%s: Failed to grab the NPT PDPT for %s gfn=0x%llx\n",
			__func__, is_rom ? "ROM" : "RAM", gfn);
		ret = -ENOMEM;
		goto out;
	}
next_pd:
	pd = npt_tree_get_next_table(tree, gfn, HAX_NPT_LEVEL_PDPT, pdpt, &pd_kmap,
		true, NULL, NULL);
	if (!pd) {
		hax_error("%s: Failed to grab the NPT PD for %s gfn=0x%llx\n", __func__,
			is_rom ? "ROM" : "RAM", gfn);
		ret = -ENOMEM;
		goto out_pdpt;
	}
next_pt:
	pt = npt_tree_get_next_table(tree, gfn, HAX_NPT_LEVEL_PD, pd, &pt_kmap,
		true, NULL, NULL);
	if (!pt) {
		hax_error("%s: Failed to grab the EPT PT for %s gfn=0x%llx\n", __func__,
			is_rom ? "ROM" : "RAM", gfn);
		ret = -ENOMEM;
		goto out_pd;
	}

	// Suppose that there was a macro
	//  make_gfn(pml4_index, pdpt_index, pd_index, pt_index)
	// and that gfn == make_gfn(w, x, y, z), where each of w, x, y, z is between
	// 0 and 511 (i.e. HAX_EPT_TABLE_SIZE - 1). Now we have obtained the PT that
	// covers GFNs make_gfn(w, x, y, 0) .. make_gfn(w, x, y, 511).
	start_index = get_pt_index(gfn);
	// There are two cases here:
	//  i) end_gfn == make_gfn(w, x, y, z'), where z <= z' <= 511. Obviously we
	//     just need to create PTEs pt[z] .. pt[z'].
	// ii) end_gfn == make_gfn(w', x', y', z'), where
	//      make_gfn(w', x', y', 0) > make_gfn(w, x, y, 0)
	//     which implies end_gfn > make_gfn(w, x, y, 511). This means we need to
	//     first create PTEs pt[z] .. pt[511], and then grab the next PT by
	//     incrementing y.
	end_index = get_pd_gross_index(end_gfn) > get_pd_gross_index(gfn) ?
		HAX_NPT_TABLE_SIZE - 1 : get_pt_index(end_gfn);
	for (index = start_index; index <= end_index; index++) {
		hax_pdpe *pte = &pt[index];

		new_pte.pfn = hax_get_pfn_user(&chunk->memdesc, offset);
		hax_assert(new_pte.pfn != INVALID_PFN);
		if (!hax_cmpxchg64(0, new_pte.val, &pte->val)) {
			// pte->value != 0, implying pte->perm != HAX_EPT_PERM_NONE
			// ignore access and dirty/ignore bit
			if ((pte->val & NPT_IGNORE_ACCESS_DIRTY) != (new_pte.val & NPT_IGNORE_ACCESS_DIRTY)) {
				hax_error("%s: A different PTE corresponding to %s gfn=0x%llx"
					" already exists: old_value=0x%llx, new_value=0x%llx"
					"\n", __func__, is_rom ? "ROM" : "RAM", gfn,
					pte->val, new_pte.val);
				ret = -EEXIST;
				goto out_pt;
			}
			else {
				hax_debug("%s: Another thread has already created the same PTE:"
					" gfn=0x%llx, value=0x%llx, is_rom=%s\n", __func__,
					gfn, new_pte.val, is_rom ? "true" : "false");
			}
		}
		else {
			// pte->value was 0, but has been set to new_pte.value
			created_count++;
		}
		gfn++;
		offset += PAGE_SIZE_4K;
	}
	if (gfn <= end_gfn) {
		// We are in case ii) described above, i.e. we just created a PTE for
		// gfn - 1 == make_gfn(w, x, y, 511), and need to grab the next PT.
		// Now gfn must be equal to one of the following:
		// a) make_gfn(w, x, y + 1, 0), if y < 511;
		// b) make_gfn(w, x + 1, 0, 0), if y == 511 and x < 511;
		// c) make_gfn(w + 1, 0, 0, 0), if x == y == 511 and w < 511;
		// d) make_gfn(512, 0, 0, 0) (invalid), if w == x == y == 511. This
		//    cannot possibly happen, because end_gfn must be valid.
		hax_assert(!get_pt_index(gfn));
		hax_unmap_page_frame(&pt_kmap);
		if (!get_pd_index(gfn)) {
			hax_unmap_page_frame(&pd_kmap);
			if (!get_pdpt_index(gfn)) {
				// This is case c) above
				hax_unmap_page_frame(&pdpt_kmap);
				goto next_pdpt;
			}
			else {  // get_pdpt_index(gfn) != 0
			 // This is case b) above
				goto next_pd;
			}
		}
		else {  // get_pd_index(gfn) != 0
		 // This is case a) above
			goto next_pt;
		}
	}
	// Now gfn > end_gfn, i.e. we are done
	ret = created_count;

out_pt:
	hax_unmap_page_frame(&pt_kmap);
out_pd:
	hax_unmap_page_frame(&pd_kmap);
out_pdpt:
	hax_unmap_page_frame(&pdpt_kmap);
out:
	return ret;
}

static void get_pte(hax_npt_tree *tree, uint64_t gfn, int level, hax_pdpe *epte,
	void *opaque)
{
	hax_pdpe *pte;

	if (level > HAX_NPT_LEVEL_PT) {
		return;
	}

	// level == HAX_EPT_LEVEL_PT
	hax_assert(epte != NULL);
	hax_assert(opaque != NULL);
	pte = (hax_pdpe *)opaque;
	*pte = *epte;
}

hax_pdpe npt_tree_get_entry(hax_npt_tree *tree, uint64_t gfn)
{
	hax_pdpe pte = { 0 };

	npt_tree_walk(tree, gfn, get_pte, &pte);
	return pte;
}

void npt_tree_walk(hax_npt_tree *tree, uint64_t gfn, npte_visitor visit_epte,
	void *opaque)
{
	hax_pdpe *table;
	int level;
	hax_kmap_phys kmap = { 0 }, prev_kmap = { 0 };
	int ret;
	uint pt_index;
	hax_pdpe *pte;

	if (!tree) {
		hax_error("%s: tree == NULL\n", __func__);
		return;
	}
	if (!visit_epte) {
		hax_warning("%s: visit_epte == NULL\n", __func__);
		return;
	}

	table = npt_tree_get_root_table(tree);
	hax_assert(table != NULL);
	for (level = HAX_NPT_LEVEL_PML4; level >= HAX_NPT_LEVEL_PD; level--) {
		table = npt_tree_get_next_table(tree, gfn, level, table, &kmap, false,
			visit_epte, opaque);
		ret = hax_unmap_page_frame(&prev_kmap);
		hax_assert(ret == 0);
		if (!table) {
			// An intermediate EPT page table is missing, which means the EPT
			// leaf entry to be invalidated is not present
			return;
		}
		kmap_swap(&prev_kmap, &kmap);
	}
	pt_index = get_pt_index(gfn);
	hax_assert(table != NULL);
	pte = &table[pt_index];
	visit_epte(tree, gfn, HAX_NPT_LEVEL_PT, pte, opaque);

	ret = hax_unmap_page_frame(&prev_kmap);
	hax_assert(ret == 0);
}

static void invalidate_pte(hax_npt_tree *tree, uint64_t gfn, int level, hax_pdpe *epte,
	void *opaque)
{
	hax_pdpe *pte;
	bool *modified;

	if (level > HAX_NPT_LEVEL_PT) {
		return;
	}

	// level == HAX_EPT_LEVEL_PT
	hax_assert(tree != NULL);
	hax_assert(epte != NULL);
	hax_assert(opaque != NULL);
	pte = epte;
	modified = (bool *)opaque;
	if (!pte->valid) {
		*modified = false;
		return;
	}

	hax_info("%s: Invalidating PTE: gfn=0x%llx, value=0x%llx\n", __func__, gfn,
		pte->val);
	npt_tree_lock(tree);
	pte->val = 0;  // implies pte->perm == HAX_EPT_PERM_NONE
	npt_tree_unlock(tree);
	*modified = true;
}

// Returns 1 if the NPT leaf entry to be invalidated was present, or 0 if it is
// not present.
static int npt_tree_invalidate_entry(hax_npt_tree *tree, uint64_t gfn)
{
	bool modified = false;

	npt_tree_walk(tree, gfn, invalidate_pte, &modified);
	return modified ? 1 : 0;
}

int npt_tree_invalidate_entries(hax_npt_tree *tree, uint64_t start_gfn,
	uint64_t npages)
{
	uint64_t end_gfn = start_gfn + npages, gfn;
	int modified_count = 0;

	if (!tree) {
		hax_error("%s: tree == NULL\n", __func__);
		return -EINVAL;
	}

	// TODO: Implement a faster algorithm
	for (gfn = start_gfn; gfn < end_gfn; gfn++) {
		int ret = npt_tree_invalidate_entry(tree, gfn);
		hax_assert(ret == 0 || ret == 1);
		modified_count += ret;
	}
	if (modified_count) {
		if (hax_test_and_set_bit(0, (uint64_t *)&tree->invept_pending)) {
			hax_warning("%s: INVEPT pending flag is already set\n", __func__);
		}
	}
	return modified_count;
}
