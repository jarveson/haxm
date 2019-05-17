#pragma once

#include "../../include/hax_types.h"

enum {
	SVM_INTERCEPT_INTR,
	SVM_INTERCEPT_NMI,
	SVM_INTERCEPT_SMI,
	SVM_INTERCEPT_INIT,
	SVM_INTERCEPT_VINTR,
	SVM_INTERCEPT_SELECTIVE_CR0,
	SVM_INTERCEPT_STORE_IDTR,
	SVM_INTERCEPT_STORE_GDTR,
	SVM_INTERCEPT_STORE_LDTR,
	SVM_INTERCEPT_STORE_TR,
	SVM_INTERCEPT_LOAD_IDTR,
	SVM_INTERCEPT_LOAD_GDTR,
	SVM_INTERCEPT_LOAD_LDTR,
	SVM_INTERCEPT_LOAD_TR,
	SVM_INTERCEPT_RDTSC,
	SVM_INTERCEPT_RDPMC,
	SVM_INTERCEPT_PUSHF,
	SVM_INTERCEPT_POPF,
	SVM_INTERCEPT_CPUID,
	SVM_INTERCEPT_RSM,
	SVM_INTERCEPT_IRET,
	SVM_INTERCEPT_INTn,
	SVM_INTERCEPT_INVD,
	SVM_INTERCEPT_PAUSE,
	SVM_INTERCEPT_HLT,
	SVM_INTERCEPT_INVLPG,
	SVM_INTERCEPT_INVLPGA,
	SVM_INTERCEPT_IOIO_PROT,
	SVM_INTERCEPT_MSR_PROT,
	SVM_INTERCEPT_TASK_SWITCH,
	SVM_INTERCEPT_FERR_FREEZE,
	SVM_INTERCEPT_SHUTDOWN,
	SVM_INTERCEPT_VMRUN,
	SVM_INTERCEPT_VMMCALL,
	SVM_INTERCEPT_VMLOAD,
	SVM_INTERCEPT_VMSAVE,
	SVM_INTERCEPT_STGI,
	SVM_INTERCEPT_CLGI,
	SVM_INTERCEPT_SKINIT,
	SVM_INTERCEPT_RDTSCP,
	SVM_INTERCEPT_ICEBP,
	SVM_INTERCEPT_WBINVD,
	SVM_INTERCEPT_MONITOR,
	SVM_INTERCEPT_MWAIT,
	SVM_INTERCEPT_MWAIT_COND,
	SVM_INTERCEPT_XSETBV,
};

#define SVM_INTERCEPT(i) (1ULL << i)

#define SVM_INTERCEPT_CR0_READ	0
#define SVM_INTERCEPT_CR3_READ	3
#define SVM_INTERCEPT_CR4_READ	4
#define SVM_INTERCEPT_CR8_READ	8
#define SVM_INTERCEPT_CR0_WRITE	(16 + 0)
#define SVM_INTERCEPT_CR3_WRITE	(16 + 3)
#define SVM_INTERCEPT_CR4_WRITE	(16 + 4)
#define SVM_INTERCEPT_CR8_WRITE	(16 + 8)
		
#define SVM_INTERCEPT_DR0_READ	0
#define SVM_INTERCEPT_DR1_READ	1
#define SVM_INTERCEPT_DR2_READ	2
#define SVM_INTERCEPT_DR3_READ	3
#define SVM_INTERCEPT_DR4_READ	4
#define SVM_INTERCEPT_DR5_READ	5
#define SVM_INTERCEPT_DR6_READ	6
#define SVM_INTERCEPT_DR7_READ	7
#define SVM_INTERCEPT_DR0_WRITE	(16 + 0)
#define SVM_INTERCEPT_DR1_WRITE	(16 + 1)
#define SVM_INTERCEPT_DR2_WRITE	(16 + 2)
#define SVM_INTERCEPT_DR3_WRITE	(16 + 3)
#define SVM_INTERCEPT_DR4_WRITE	(16 + 4)
#define SVM_INTERCEPT_DR5_WRITE	(16 + 5)
#define SVM_INTERCEPT_DR6_WRITE	(16 + 6)
#define SVM_INTERCEPT_DR7_WRITE	(16 + 7)

#define SVM_NESTED_CTL_NP_ENABLE     1ull
#define SVM_NESTED_CTL_SEV_ENABLE    2ull
#define SVM_NESTED_CTL_ESSEV_ENABLE  4ull

#define SVM_INTERRUPT_SHADOW_MASK 1

#define SVM_IOIO_STR_SHIFT 2
#define SVM_IOIO_REP_SHIFT 3
#define SVM_IOIO_SIZE_SHIFT 4
#define SVM_IOIO_ASIZE_SHIFT 7
#define SVM_IOIO_SEG_SHIFT 10

#define SVM_IOIO_TYPE_MASK 1
#define SVM_IOIO_STR_MASK (1 << SVM_IOIO_STR_SHIFT)
#define SVM_IOIO_REP_MASK (1 << SVM_IOIO_REP_SHIFT)
#define SVM_IOIO_SIZE_MASK (7 << SVM_IOIO_SIZE_SHIFT)
#define SVM_IOIO_ASIZE_MASK (7 << SVM_IOIO_ASIZE_SHIFT)
#define SVM_IOIO_SEG_MASK (7 << SVM_IOIO_SEG_SHIFT)

#define TLB_CONTROL_DO_NOTHING 0
#define TLB_CONTROL_FLUSH_ALL_ASID 1
#define TLB_CONTROL_FLUSH_ASID 3
#define TLB_CONTROL_FLUSH_ASID_LOCAL 7

#define SVM_LBR_CTL_ENABLE_MASK 1

#define SVM_V_INTR_MASKING_SHIFT 24
#define SVM_V_INTR_MASKING_MASK (1 << SVM_V_INTR_MASKING_SHIFT)
#define SVM_V_TPR_MASK 0x0f

#define SVM_V_IRQ_SHIFT 8
#define SVM_V_IRQ_MASK (1 << SVM_V_IRQ_SHIFT)

#define SVM_DEFAULT_TSC_RATIO 0x0100000000ULL

enum {
	SVM_EXIT_READ_CR0     = 0x000,
	SVM_EXIT_READ_CR3     = 0x003,
	SVM_EXIT_READ_CR4     = 0x004,
	SVM_EXIT_READ_CR8     = 0x008,
	SVM_EXIT_WRITE_CR0    = 0x010,
	SVM_EXIT_WRITE_CR3    = 0x013,
	SVM_EXIT_WRITE_CR4    = 0x014,
	SVM_EXIT_WRITE_CR8    = 0x018,
	SVM_EXIT_READ_DR0     = 0x020,
	SVM_EXIT_READ_DR1     = 0x021,
	SVM_EXIT_READ_DR2     = 0x022,
	SVM_EXIT_READ_DR3     = 0x023,
	SVM_EXIT_READ_DR4     = 0x024,
	SVM_EXIT_READ_DR5     = 0x025,
	SVM_EXIT_READ_DR6     = 0x026,
	SVM_EXIT_READ_DR7     = 0x027,
	SVM_EXIT_WRITE_DR0    = 0x030,
	SVM_EXIT_WRITE_DR1    = 0x031,
	SVM_EXIT_WRITE_DR2    = 0x032,
	SVM_EXIT_WRITE_DR3    = 0x033,
	SVM_EXIT_WRITE_DR4    = 0x034,
	SVM_EXIT_WRITE_DR5    = 0x035,
	SVM_EXIT_WRITE_DR6    = 0x036,
	SVM_EXIT_WRITE_DR7    = 0x037,
	SVM_EXIT_EXCP_BASE    = 0x040,
	SVM_EXIT_INTR         = 0x060,
	SVM_EXIT_NMI          = 0x061,
	SVM_EXIT_SMI          = 0x062,
	SVM_EXIT_INIT         = 0x063,
	SVM_EXIT_VINTR        = 0x064,
	SVM_EXIT_CR0_SEL_WRITE= 0x065,
	SVM_EXIT_IDTR_READ    = 0x066,
	SVM_EXIT_GDTR_READ    = 0x067,
	SVM_EXIT_LDTR_READ    = 0x068,
	SVM_EXIT_TR_READ      = 0x069,
	SVM_EXIT_IDTR_WRITE   = 0x06a,
	SVM_EXIT_GDTR_WRITE   = 0x06b,
	SVM_EXIT_LDTR_WRITE   = 0x06c,
	SVM_EXIT_TR_WRITE     = 0x06d,
	SVM_EXIT_RDTSC        = 0x06e,
	SVM_EXIT_RDPMC        = 0x06f,
	SVM_EXIT_PUSHF        = 0x070,
	SVM_EXIT_POPF         = 0x071,
	SVM_EXIT_CPUID        = 0x072,
	SVM_EXIT_RSM          = 0x073,
	SVM_EXIT_IRET         = 0x074,
	SVM_EXIT_SWINT        = 0x075,
	SVM_EXIT_INVD         = 0x076,
	SVM_EXIT_PAUSE        = 0x077,
	SVM_EXIT_HLT          = 0x078,
	SVM_EXIT_INVLPG       = 0x079,
	SVM_EXIT_INVLPGA      = 0x07a,
	SVM_EXIT_IOIO         = 0x07b,
	SVM_EXIT_MSR          = 0x07c,
	SVM_EXIT_TASK_SWITCH  = 0x07d,
	SVM_EXIT_FERR_FREEZE  = 0x07e,
	SVM_EXIT_SHUTDOWN     = 0x07f,
	SVM_EXIT_VMRUN        = 0x080,
	SVM_EXIT_VMMCALL      = 0x081,
	SVM_EXIT_VMLOAD       = 0x082,
	SVM_EXIT_VMSAVE       = 0x083,
	SVM_EXIT_STGI         = 0x084,
	SVM_EXIT_CLGI         = 0x085,
	SVM_EXIT_SKINIT       = 0x086,
	SVM_EXIT_RDTSCP       = 0x087,
	SVM_EXIT_ICEBP        = 0x088,
	SVM_EXIT_WBINVD       = 0x089,
	SVM_EXIT_MONITOR      = 0x08a,
	SVM_EXIT_MWAIT        = 0x08b,
	SVM_EXIT_MWAIT_COND   = 0x08c,
	SVM_EXIT_XSETBV       = 0x08d,
	SVM_EXIT_NPF          = 0x400,
};

#define SVM_EXIT_ERR           -1

#ifdef HAX_COMPILER_MSVC
#pragma pack(push, 1)
#endif

struct PACKED vmcb_control_area {
	uint32_t intercept_cr;
	uint32_t intercept_dr;
	uint32_t intercept_exceptions;
	uint64_t intercept;
	uint8_t reserved_1[42];
	uint16_t pause_filter_count;
	uint64_t iopm_base_pa;
	uint64_t msrpm_base_pa;
	uint64_t tsc_offset;
	uint32_t asid;
	uint8_t tlb_ctl;
	uint8_t reserved_2[3];
	uint32_t int_ctl;
	uint32_t int_vector;
	uint32_t int_state;
	uint8_t reserved_3[4];
	uint32_t exit_code;
	uint32_t exit_code_hi;
	uint64_t exit_info_1;
	uint64_t exit_info_2;
	uint32_t exit_int_info;
	uint32_t exit_int_info_err;
	uint64_t nested_ctl;
	uint64_t avic_vapic_bar;
	uint8_t reserved_4[8];
	uint32_t event_inj;
	uint32_t event_inj_err;
	uint64_t nested_cr3;
	uint64_t virt_ext;
	uint32_t clean;
	uint32_t reserved_5;
	uint64_t next_rip;
	uint8_t insn_len;
	uint8_t insn_bytes[15];
	uint64_t avic_backing_page;
	uint8_t reserved_6[8];
	uint64_t avic_logical_id;
	uint64_t avic_physical_id;
	uint8_t reserved_7[768];
};

struct PACKED vmcb_seg {
	uint16_t selector;
	uint16_t attrib;
	uint32_t limit;
	uint64_t base;
};

struct PACKED vmcb_save_area {
	struct vmcb_seg es;
	struct vmcb_seg cs;
	struct vmcb_seg ss;
	struct vmcb_seg ds;
	struct vmcb_seg fs;
	struct vmcb_seg gs;
	struct vmcb_seg gdtr;
	struct vmcb_seg ldtr;
	struct vmcb_seg idtr;
	struct vmcb_seg tr;
	uint8_t reserved_1[43];
	uint8_t cpl;
	uint8_t reserved_2[4];
	uint64_t efer;
	uint8_t reserved_3[112];
	uint64_t cr4;
	uint64_t cr3;
	uint64_t cr0;
	uint64_t dr7;
	uint64_t dr6;
	uint64_t rflags;
	uint64_t rip;
	uint8_t reserved_4[88];
	uint64_t rsp;
	uint8_t reserved_5[24];
	uint64_t rax;
	uint64_t star;
	uint64_t lstar;
	uint64_t cstar;
	uint64_t sfmask;
	uint64_t kernel_gs_base;
	uint64_t sysenter_cs;
	uint64_t sysenter_esp;
	uint64_t sysenter_eip;
	uint64_t cr2;
	uint8_t reserved_6[32];
	uint64_t g_pat;
	uint64_t dbgctl;
	uint64_t br_from;
	uint64_t br_to;
	uint64_t last_excp_from;
	uint64_t last_excp_to;
};

struct PACKED vmcb {
	struct vmcb_control_area control;
	struct vmcb_save_area save;
};

#ifdef HAX_COMPILER_MSVC
#pragma pack(pop)
#endif

uint32_t svm_msrpm_offset(uint32_t msr);

#define SVM_COMPACTATTRIB(a) (((((a) & 0xF000) >> 4) | (a & 0xFF)))
#define SVM_EXPANDATTRIB(a) ((((a) & 0xF00) << 4) | (a & 0xFF))
//#define SVM_COMPACTATTRIB(a) (((((a) & 0xF000) >> 4)) & 0xFFF)
//#define SVM_EXPANDATTRIB(a) ((((a) & 0xF00) << 4))

#define SVM_READDESC(save, desc, val)                               \
        ((val).base  = save.desc.base,          \
         (val).limit = save.desc.limit)

#define SVM_READSEG(save, seg, val)                                 \
        ((val).selector = save.seg.selector,    \
         (val).base     = save.seg.base,        \
         (val).limit    = save.seg.limit,       \
         (val).ar       = SVM_EXPANDATTRIB(save.seg.attrib));        

#define SVM_SETSEG(save, seg, val) {                          \
            save.seg.selector = (val).selector; \
            save.seg.base = (val).base;         \
            save.seg.limit = (val).limit;       \
            save.seg.attrib = SVM_COMPACTATTRIB((val).ar);               \
        }

#define SVM_SETDESC(save, desc, val)                              \
        (save.desc.base = (val).base,           \
         save.desc.limit = (val).limit)


void ASMCALL asm_clgi(void);
void ASMCALL asm_stgi(void);
void ASMCALL asm_vmload(hax_paddr_t vmcb);
void ASMCALL asm_vmsave(hax_paddr_t vmcb);
void ASMCALL asm_svmrun(struct vcpu_state_t *state, const hax_paddr_t vmcb);