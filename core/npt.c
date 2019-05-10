
#include "include/npt.h"
#include "include/cpu.h"
#include "../include/hax.h"
#include "include/paging.h"
#include "../include/hax_host_mem.h"
#include "include/vm.h"

void npt_handle_mapping_removed(hax_gpa_space_listener *listener,
	uint64_t start_gfn, uint64_t npages, uint64_t uva,
	uint8_t flags)
{
	bool is_rom = flags & HAX_MEMSLOT_READONLY;
	hax_npt_tree *tree;
	int ret;

	hax_info("%s: %s=>MMIO: start_gfn=0x%llx, npages=0x%llx, uva=0x%llx\n",
		__func__, is_rom ? "ROM" : "RAM", start_gfn, npages, uva);
	hax_assert(listener != NULL);
	tree = (hax_npt_tree *)listener->opaque;
	ret = npt_tree_invalidate_entries(tree, start_gfn, npages);
	hax_info("%s: Invalidated %d PTEs\n", __func__, ret);
}

void npt_handle_mapping_changed(hax_gpa_space_listener *listener,
	uint64_t start_gfn, uint64_t npages,
	uint64_t old_uva, uint8_t old_flags,
	uint64_t new_uva, uint8_t new_flags)
{
	bool was_rom = old_flags & HAX_MEMSLOT_READONLY;
	bool is_rom = new_flags & HAX_MEMSLOT_READONLY;
	hax_npt_tree *tree;
	int ret;

	hax_info("%s: %s=>%s: start_gfn=0x%llx, npages=0x%llx, old_uva=0x%llx,"
		" new_uva=0x%llx\n", __func__, was_rom ? "ROM" : "RAM",
		is_rom ? "ROM" : "RAM", start_gfn, npages, old_uva, new_uva);
	hax_assert(listener != NULL);
	tree = (hax_npt_tree *)listener->opaque;
	ret = npt_tree_invalidate_entries(tree, start_gfn, npages);
	hax_info("%s: Invalidated %d PTEs\n", __func__, ret);
}

int npt_handle_access_violation(hax_gpa_space *gpa_space, hax_npt_tree *tree,
	uint64_t exitinfo1, uint64_t gpa,
	uint64_t *fault_gfn)
{
	uint combined_perm;
	uint64_t gfn;
	hax_memslot *slot;
	bool is_rom;
	hax_ramblock *block;
	hax_chunk *chunk;
	uint64_t offset_within_slot, offset_within_block, offset_within_chunk;
	uint64_t chunk_offset_low, chunk_offset_high, slot_offset_high;
	uint64_t start_gpa, size;
	int ret;

	if (exitinfo1 & 1) {
		gfn = gpa >> PG_ORDER_4K;
		hax_assert(gpa_space != NULL);
		slot = memslot_find(gpa_space, gfn);
		hax_error("%s: Cannot handle the case where the PTE corresponding to"
			" the faulting GPA is present: qual=0x%llx, gpa=0x%llx, memslotflag=0x%x\n",
			__func__, exitinfo1, gpa, slot->flags);
		return -EACCES;
	}

	gfn = gpa >> PG_ORDER_4K;
	hax_assert(gpa_space != NULL);
	slot = memslot_find(gpa_space, gfn);
	if (!slot) {
		// The faulting GPA is reserved for MMIO
		hax_debug("%s: gpa=0x%llx is reserved for MMIO\n", __func__, gpa);
		return 0;
	}

	// Ideally we should call gpa_space_is_page_protected() and ask user space
	// to unprotect just the host virtual page that |gfn| maps to. But since we
	// pin host RAM one chunk (rather than one page) at a time, if the chunk
	// that |gfn| maps to contains any other host virtual page that is protected
	// (by means of a VirtualProtect() or mprotect() call from user space), we
	// will not be able to pin the chunk when we handle the next EPT violation
	// caused by the same |gfn|.
	// For now, we ask user space to unprotect all host virtual pages in the
	// chunk, so our next hax_pin_user_pages() call will not fail. This is a
	// dirty hack.
	// TODO: Make chunks more flexible, so we can pin host RAM in finer
	// granularity (as small as one page) and hide chunks from user space.
	if (gpa_space_is_chunk_protected(gpa_space, gfn, fault_gfn))
		return -EFAULT;

	// The faulting GPA maps to RAM/ROM
	is_rom = slot->flags & HAX_MEMSLOT_READONLY;
	offset_within_slot = gpa - (slot->base_gfn << PG_ORDER_4K);
	hax_assert(offset_within_slot < (slot->npages << PG_ORDER_4K));
	block = slot->block;
	hax_assert(block != NULL);
	offset_within_block = slot->offset_within_block + offset_within_slot;
	hax_assert(offset_within_block < block->size);
	chunk = ramblock_get_chunk(block, offset_within_block, true);
	if (!chunk) {
		hax_error("%s: Failed to grab the RAM chunk for %s gpa=0x%llx:"
			" slot.base_gfn=0x%llx, slot.offset_within_block=0x%llx,"
			" offset_within_slot=0x%llx, block.base_uva=0x%llx,"
			" block.size=0x%llx\n", __func__, is_rom ? "ROM" : "RAM", gpa,
			slot->base_gfn, slot->offset_within_block, offset_within_slot,
			block->base_uva, block->size);
		return -ENOMEM;
	}

	// Compute the union of the UVA ranges covered by |slot| and |chunk|
	chunk_offset_low = chunk->base_uva - block->base_uva;
	start_gpa = slot->base_gfn << PG_ORDER_4K;
	if (chunk_offset_low > slot->offset_within_block) {
		start_gpa += chunk_offset_low - slot->offset_within_block;
		offset_within_chunk = 0;
	}
	else {
		offset_within_chunk = slot->offset_within_block - chunk_offset_low;
	}
	chunk_offset_high = chunk_offset_low + chunk->size;
	slot_offset_high = slot->offset_within_block +
		(slot->npages << PG_ORDER_4K);
	size = chunk->size - offset_within_chunk;
	if (chunk_offset_high > slot_offset_high) {
		size -= chunk_offset_high - slot_offset_high;
	}
	ret = npt_tree_create_entries(tree, start_gpa >> PG_ORDER_4K,
		size >> PG_ORDER_4K, chunk,
		offset_within_chunk, slot->flags);
	if (ret < 0) {
		hax_error("%s: Failed to create PTEs for GFN range: ret=%d, gpa=0x%llx,"
			" start_gfn=0x%llx, npages=%llu\n", __func__, ret, gpa,
			start_gpa >> PG_ORDER_4K, size >> PG_ORDER_4K);
		return ret;
	}
	hax_debug("%s: Created %d PTEs for GFN range: gpa=0x%llx, start_gfn=0x%llx,"
		" npages=%llu\n", __func__, ret, gpa, start_gpa >> PG_ORDER_4K,
		size >> PG_ORDER_4K);
	return 1;
}

static void npt_flush_tlb_smpfunc(void* null) {
	struct per_cpu_data* cpu_data = current_cpu_data();
	hax_smp_mb();

	cpu_data->invept_res = 1;
}

void npt_flush_tlb(struct vm_t *hax_vm, uint type) {

	// jake
	// todo: check feature and flush by asid

	switch (type) {
	case NPT_FLUSH_SINGLE_CONTEXT: {
		type = NPT_FLUSH_ALL_CONTEXT;
	}
	case NPT_FLUSH_ALL_CONTEXT: {
	}
	default: {
		hax_panic("Invalid invept type %u\n", type);
	}
	}

	hax_smp_call_function(&cpu_online_map, (void (*)(void*))npt_flush_tlb_smpfunc, NULL);

	/*struct vcpu_t *vcpu = NULL;
	hax_list_head *list;

	if (hax_vm->vm_lock)
		hax_mutex_lock(hax_vm->vm_lock);
	hax_list_for_each(list, (hax_list_head *)(&hax_vm->vcpu_list)) {
		vcpu = hax_list_entry(vcpu_list, struct vcpu_t, list);
		svm(vcpu)->control.tlb_ctl = TLB_CONTROL_FLUSH_ALL_ASID;
	}
	if (hax_vm->vm_lock)
		hax_mutex_unlock(hax_vm->vm_lock);
	*/
}
