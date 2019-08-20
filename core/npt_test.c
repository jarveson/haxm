/*
 * Copyright (c) 2009 Intel Corporation
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice,
 *      this list of conditions and the following disclaimer.
 *
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 *   3. Neither the name of the copyright holder nor the names of its
 *      contributors may be used to endorse or promote products derived from
 *      this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

 /* Design rule:
  * 1. EPT page table is used as a p2m mapping in vTLB case.
  * 2. Only support EPT_MAX_MEM_G memory for the guest at maximum
  * 3. EPT table is preallocated at VM initilization stage.
  * 4. Doesn't support super page.
  * 5. To traverse it easily, the uppest three levels are designed as the fixed
  *    mapping.
  */

#include "../include/hax.h"
#include "include/npt.h"
#include "include/cpu.h"
#include "include/paging.h"
#include "include/vtlb.h"
#include "include/vm.h"

// Get the PDE entry for the specified gpa in EPT
static hax_pdpe * ept_get_pde(struct hax_npt *ept, hax_paddr_t gpa)
{
    hax_pdpe *e;
    uint which_g = gpa >> 30;
    // PML4 and PDPTE level needs 2 pages
    uint64_t offset = (2 + which_g) * PAGE_SIZE_4K;
    // Need Xiantao's check
    unsigned char *ept_addr = hax_page_va(ept->ept_root_page);

    hax_assert(which_g < EPT_MAX_MEM_G);

    e = (hax_pdpe *)(ept_addr + offset) + npt_get_pde_idx(gpa);
    return e;
}

// ept_set_pte: caller can use it to setup p2m mapping for the guest.
bool npt_set_pte(struct vm_t* hax_vm, hax_paddr_t gpa, hax_paddr_t hpa, uint emt,
    uint mem_type, bool *is_modified)
{
    bool ret = true;
    struct hax_page *page;
    hax_paddr_t pte_ha;
    hax_pdpe *pte;
    void *pte_base, *addr;
    struct hax_npt *ept = hax_vm->npt;
    uint which_g = gpa >> 30;
    uint perm;
    hax_pdpe *pde = ept_get_pde(ept, gpa);

    // hax_debug("hpa %llx gpa %llx\n", hpa, gpa);
    if (which_g >= EPT_MAX_MEM_G) {
        hax_error("Error: Guest's memory size is beyond %dG!\n", EPT_MAX_MEM_G);
        return false;
    }
    hax_mutex_lock(hax_vm->vm_lock);
    if (!npte_is_present(pde)) {
        if (mem_type == EPT_TYPE_NONE) {  // unmap
            // Don't bother allocating the PT
            goto out_unlock;
        }

        page = hax_alloc_page(0, 1);
        if (!page) {
            ret = false;
            goto out_unlock;
        }

        hax_list_add(&page->list, &ept->ept_page_list);
        addr = hax_page_va(page);
        memset(addr, 0, PAGE_SIZE_4K);
        pte_ha = hax_page_pa(page);
        // Always own full access rights
        npte_set_entry(pde, pte_ha, 7, 0);
    }

    // Grab the PTE entry
    pte_base = hax_vmap_pfn(pde->pfn);
    if (!pte_base) {
        ret = false;
        goto out_unlock;
    }
    pte = (hax_pdpe *)pte_base + npt_get_pte_idx(gpa);
    // TODO: Just for debugging, need check QEMU for more information
    /* if (epte_is_present(pte)) {
     *     hax_debug("Can't change the pte entry!\n");
     *     hax_mutex_unlock(hax_vm->vm_lock);
     *     hax_debug("\npte %llx\n", pte->val);
     *     hax_vunmap_pfn(pte_base);
     *     return 0;
     * }
     */
    switch (mem_type) {
    case EPT_TYPE_NONE: {
        perm = 0;  // unmap
        break;
    }
    case EPT_TYPE_MEM: {
        perm = 7;
        break;
    }
    case EPT_TYPE_ROM: {
        perm = 5;
        break;
    }
    default: {
        hax_error("Unsupported mapping type 0x%x\n", mem_type);
        ret = false;
        goto out_unmap;
    }
    }
    *is_modified = npte_is_present(pte) && (npte_get_address(pte) != hpa);
    npte_set_entry(pte, hpa, perm, emt);

out_unmap:
    hax_vunmap_pfn(pte_base);
out_unlock:
    hax_mutex_unlock(hax_vm->vm_lock);
    return ret;
}

static bool ept_lookup(struct vcpu_t *vcpu, hax_paddr_t gpa, hax_paddr_t *hpa)
{
    hax_pdpe *pde, *pte;
    void *pte_base;
    struct hax_npt *ept = vcpu->vm->npt;
    uint which_g = gpa >> 30;

    hax_assert(ept->ept_root_page);
    if (which_g >= EPT_MAX_MEM_G) {
        hax_debug("ept_lookup error!\n");
        return 0;
    }

    pde = ept_get_pde(ept, gpa);

    if (!npte_is_present(pde))
        return 0;

    pte_base = hax_vmap_pfn(pde->pfn);
    if (!pte_base)
        return 0;

    pte = (hax_pdpe *)pte_base + npt_get_pte_idx(gpa);

    if (!npte_is_present(pte)) {
        hax_vunmap_pfn(pte_base);
        return 0;
    }

    *hpa = (pte->pfn << 12) | (gpa & 0xfff);
    hax_vunmap_pfn(pte_base);
    return 1;
}

/*
 * Deprecated API of EPT
 * Translate a GPA to an HPA
 * @param vcpu:     current vcpu structure pointer
 * @param gpa:      guest physical address
 * @param order:    order for gpa
 * @param hpa       host physical address pointer
 */

 // TODO: Do we need to consider cross-page case ??
bool npt_translate(struct vcpu_t *vcpu, hax_paddr_t gpa, uint order, hax_paddr_t *hpa)
{
    hax_assert(order == PG_ORDER_4K);
    return ept_lookup(vcpu, gpa, hpa);
}
