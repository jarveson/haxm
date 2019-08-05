#pragma once

#include "../../include/hax_types.h"
#include "../../include/hax_list.h"
#include "memory.h"
#include "svm.h"

#define HAX_NPT_LEVEL_PML4 3
#define HAX_NPT_LEVEL_PDPT 2
#define HAX_NPT_LEVEL_PD   1
#define HAX_NPT_LEVEL_PT   0
#define HAX_NPT_LEVEL_MAX  HAX_NPT_LEVEL_PML4

#define HAX_NPT_TABLE_SHIFT 9
#define HAX_NPT_TABLE_SIZE  (1 << HAX_NPT_TABLE_SHIFT)

#define NPT_FLUSH_SINGLE_CONTEXT 1
#define NPT_FLUSH_ALL_CONTEXT    2

#define NPT_IGNORE_ACCESS_DIRTY (~(0x60ull))

typedef struct hax_pdpe {
	union {
		uint64_t val;
		struct {
			uint64_t valid : 1;
			uint64_t readWrite : 1;
			uint64_t user : 1;
			uint64_t writeThrough : 1;
			uint64_t cacheDisable : 1;
			uint64_t access : 1;
			uint64_t ignore : 1;
			uint64_t pageSize : 1;
			uint64_t resv1 : 1;
			uint64_t avl : 3;
			uint64_t pfn : 40;
			uint64_t resv2 : 11;
			uint64_t nx : 1;
		};
	};
} hax_pdpe;

typedef struct hax_pde {
	union {
		uint64_t val;
		struct {
			uint64_t valid : 1;
			uint64_t readWrite : 1;
			uint64_t user : 1;
			uint64_t writeThrough : 1;
			uint64_t cacheDisable : 1;
			uint64_t access : 1;
			uint64_t dirty : 1;
			uint64_t largePage : 1;
			uint64_t global : 1; 
			uint64_t avl : 3;
			//uint64_t pat : 1;
			uint64_t pfn : 40;
			uint64_t resv : 11;
			uint64_t nx : 1;
		};
	};
} hax_pde;

#define INVALID_EPTP ~(uint64_t)0

struct hax_npt {
	bool is_enabled;
	struct hax_link_list ept_page_list;
	struct hax_page *ept_root_page;
	struct hax_pdpe eptp;
};

typedef struct hax_npt_page {
	hax_memdesc_phys memdesc;
	// Turns this object into a list node
	hax_list_node entry;
} hax_npt_page;

typedef struct hax_npt_page_kmap {
	hax_npt_page *page;
	void *kva;
} hax_npt_page_kmap;

#define HAX_NPT_FREQ_PAGE_COUNT 10

typedef struct hax_npt_tree {
	hax_list_head page_list;
	hax_pdpe ncr3;
	hax_npt_page_kmap freq_pages[HAX_NPT_FREQ_PAGE_COUNT];
	bool invept_pending;
	hax_spinlock *lock;
	hax_npt_page_kmap* root_page;
	// TODO: pointer to vm_t?
} hax_npt_tree;

/* 4 bits are avaiable for software use. */
#define EPT_TYPE_NONE  0
#define EPT_TYPE_MEM   0x1
#define EPT_TYPE_MMIO  0x2
#define EPT_TYPE_ROM   0x3
#define EPT_TYPE_RSVD  0x4

/* FIXME: Only support 4-level EPT page table. */
#define EPT_DEFAULT_GAW 3

/* Support up to 14G memory for the guest */
#define EPT_PRE_ALLOC_PAGES 16

/* Two pages used to build up to 2-level table */
#define EPT_MAX_MEM_G MAX_GMEM_G

#define EPT_PRE_ALLOC_PG_ORDER 4
/* 2 ^ EPT_PRE_ALLOC_PG_ORDER = EPT_PRE_ALLOC_PAGES */


static inline bool npte_is_present(hax_pdpe *entry)
{
	return entry->valid;
}

static inline hax_paddr_t npte_get_address(hax_pdpe *entry)
{
	return (entry->pfn << 12);
}

static inline uint npte_get_perm(hax_pdpe *entry)
{
	return (uint)entry->readWrite;
}

static void npte_set_entry(hax_pdpe *entry, hax_paddr_t addr, uint perm, uint emt)
{
	entry->val = 0;
	entry->pfn = addr >> 12;
	entry->valid = 1;
	entry->readWrite = 1;
	entry->user = 1;
}

static inline uint npt_get_pde_idx(hax_paddr_t gpa)
{
	return ((gpa >> 21) & 0x1ff);
}

static inline uint npt_get_pte_idx(hax_paddr_t gpa)
{
	return ((gpa >> 12) & 0x1ff);
}

bool npt_init(void *hax_vm);
void npt_free(void *hax_vm);
bool npt_translate(struct vcpu_t *vcpu, hax_paddr_t gpa, uint order, hax_paddr_t *hpa);
bool npt_set_pte(void *hax_vm, hax_paddr_t gpa, hax_paddr_t hpa, uint emt,
	uint mem_type, bool *is_modified);


// Initializes the given |hax_npt_tree|. This includes allocating the root
// |hax_npt_page| (PML4 table), computing the nptP, initializing the cache for
// frequently-used |hax_npt_page|s, etc.
// Returns 0 on success, or one of the following error codes:
// -EINVAL: Invalid input, e.g. |tree| is NULL.
// -ENOMEM: Memory allocation error.
int npt_tree_init(hax_npt_tree *tree);

// Frees up resources taken up by the given |hax_npt_tree|, including all the
// constituent |hax_npt_page|s.
// Returns 0 on success, or one of the following error codes:
// -EINVAL: Invalid input, e.g. |tree| is NULL.
int npt_tree_free(hax_npt_tree *tree);

// Acquires the lock of the given |hax_npt_tree|. A thread must make sure it has
// acquired the lock before modifying the |hax_npt_tree|.
void npt_tree_lock(hax_npt_tree *tree);

// Releases the lock of the given |hax_npt_tree|. The same thread that called
// npt_tree_lock() must release the lock when it has finished modifying the
// |hax_npt_tree|.
void npt_tree_unlock(hax_npt_tree *tree);

// Creates a leaf |hax_npte| that maps the given GFN to the given value (which
// includes the target PFN and mapping properties). Also creates any missing
// |hax_npt_page|s and non-leaf |hax_npte|s in the process.
// |tree|: The |hax_npt_tree| to modify.
// |gfn|: The GFN to create the |hax_npte| for. The leaf |hax_npte|
//        corresponding to this GFN should not be present.
// |value|: The value for the new leaf |hax_npte|. It should mark the |hax_npte|
//          as present.
// Returns 0 on success, or one of the following error codes:
// -EINVAL: Invalid input, e.g. |tree| is NULL, or |value| denotes a non-present
//          |hax_npte|.
// -EEXIST: The leaf |hax_npte| corresponding to |gfn| is already present, whose
//          value is different from |value|.
// -ENOMEM: Memory allocation/mapping error.
int npt_tree_create_entry(hax_npt_tree *tree, uint64_t gfn, hax_pdpe value);

// Creates leaf |hax_npte|s that map the given GFN range, using PFNs obtained
// from the given |hax_chunk| and the given mapping properties. Also creates any
// missing |hax_npt_page|s and non-leaf |hax_npte|s in the process.
// |tree|: The |hax_npt_tree| to modify. Must not be NULL.
// |start_gfn|: The start of the GFN range to map.
// |npages|: The number of pages covered by the GFN range. Must not be 0.
// |chunk|: The |hax_chunk| that covers all the host virtual pages (already
//          pinned in RAM) backing the guest page frames in the GFN range. Must
//          not be NULL.
// |offset_within_chunk|: The offset, in bytes, of the host virtual page backing
//                        the guest page frame at |start_gfn| within the UVA
//                        range covered by |chunk|. The UVA range defined by
//                        this offset and the size of |chunk| must cover no
//                        fewer than |npages| pages.
// |flags|: The mapping properties (e.g. read-only, etc.) applicable to the
//          entire GFN range.
// Returns the number of leaf |hax_npte|s created (i.e. changed from non-present
// to present), or one of the following error codes:
// -EEXIST: Any of the leaf |hax_npte|s corresponding to the GFN range is
//          already present and different from what would be created.
// -ENOMEM: Memory allocation/mapping error.
int npt_tree_create_entries(hax_npt_tree *tree, uint64_t start_gfn, uint64_t npages,
	hax_chunk *chunk, uint64_t offset_within_chunk,
	uint8_t flags);

// Invalidates all leaf |hax_npte|s corresponding to the given GFN range, i.e.
// marks them as not present. Also sets the |invnpt_pending| flag of the
// |hax_npt_tree| (but does not invoke INVnpt) if any of such |hax_npte|s was
// present.
// |tree|: The |hax_npt_tree| to modify.
// |start_gfn|: The start of the GFN range, whose corresponding |hax_npte|s are
//              to be invalidated.
// |npages|: The number of pages covered by the GFN range.
// Returns the number of leaf |hax_npte|s invalidated (i.e. changed from present
// to not present), or one of the following error codes:
// -EINVAL: Invalid input, e.g. |tree| is NULL.
// -ENOMEM: Memory mapping error.
int npt_tree_invalidate_entries(hax_npt_tree *tree, uint64_t start_gfn,
	uint64_t npages);

// Returns the leaf |hax_npte| that maps the given GFN. If the leaf |hax_npte|
// does not exist, returns an all-zero |hax_npte|.
// Returns an invalid |hax_npte| on error.
hax_pdpe npt_tree_get_entry(hax_npt_tree *tree, uint64_t gfn);

// A visitor callback invoked by npt_tree_walk() on each |hax_npte| visited
// along the walk.
// |tree|: The |hax_npt_tree| that |npte| belongs to.
// |gfn|: The GFN used by npt_tree_walk().
// |level|: The level in |tree| that |npte| belongs to (one of the
//          |HAX_npt_LEVEL_*| constants.
// |npte|: The |hax_npte| to visit.
// |opaque|: Additional data provided by the caller of npt_tree_walk().
typedef void(*npte_visitor)(hax_npt_tree *tree, uint64_t gfn, int level,
	hax_pdpe *npte, void *opaque);

// Walks the given |hax_npt_tree| from the root as if the given GFN were being
// translated. Invokes the given callback on each |hax_npte| visited. Returns
// after visiting the leaf |hax_npte| or a |hax_npte| that is not present (or
// both).
// |tree|: The |hax_npt_tree| to walk.
// |gfn|: The GFN that defines the |hax_npte|s in |tree| to visit.
// |visit_npte|: The callback to be invoked on each |hax_npte| visited. Should
//               not be NULL.
// |opaque|: An arbitrary pointer passed as-is to |visit_current_npte|.
void npt_tree_walk(hax_npt_tree *tree, uint64_t gfn, npte_visitor visit_npte,
	void *opaque);

// Handles a guest memory mapping change from RAM/ROM to MMIO. Used as a
// |hax_gpa_space_listener| callback.
// |listener|: The |hax_gpa_space_listener| that invoked this callback.
// |start_gfn|: The start of the GFN range whose mapping has changed.
// |npages|: The number of pages covered by the GFN range.
// |uva|: The old UVA to which |start_gfn| mapped before the change.
// |flags|: The old mapping properties for the GFN range, e.g. whether it was
//          mapped as read-only.
void npt_handle_mapping_removed(hax_gpa_space_listener *listener,
	uint64_t start_gfn, uint64_t npages, uint64_t uva,
	uint8_t flags);

// Handles a guest memory mapping change from RAM/ROM to RAM/ROM. Used as a
// |hax_gpa_space_listener| callback.
// |listener|: The |hax_gpa_space_listener| that invoked this callback.
// |start_gfn|: The start of the GFN range whose mapping has changed.
// |npages|: The number of pages covered by the GFN range.
// |old_uva|: The old UVA to which |start_gfn| mapped before the change.
// |old_flags|: The old mapping properties for the GFN range, e.g. whether it
//              was mapped as read-only.
// |new_uva|: The new UVA to which |start_gfn| maps after the change.
// |new_flags|: The new mapping properties for the GFN range, e.g. whether it is
//              mapped as read-only.
void npt_handle_mapping_changed(hax_gpa_space_listener *listener,
	uint64_t start_gfn, uint64_t npages,
	uint64_t old_uva, uint8_t old_flags,
	uint64_t new_uva, uint8_t new_flags);

// Handles an npt violation due to a guest RAM/ROM access.
// |gpa_space|: The |hax_gpa_space| of the guest.
// |tree|: The |hax_npt_tree| of the guest.
// |qual|: The VMCS Exit Qualification field that describes the npt violation.
// |gpa|: The faulting GPA.
// Returns 1 if the faulting GPA is mapped to RAM/ROM and the fault is
// successfully handled, 0 if the faulting GPA is reserved for MMIO and the
// fault is not handled, or one of the following error codes:
// -EACCES: Unexpected cause of the npt violation, i.e. the PTE mapping |gpa| is
//          present, but the access violates the permissions it allows.
// -ENOMEM: Memory allocation/mapping error.
int npt_handle_access_violation(hax_gpa_space *gpa_space, hax_npt_tree *tree,
	uint64_t exitinfo1, uint64_t gpa,
	uint64_t *fault_gfn);


void npt_flush_tlb(void *hax_vm, uint type);
