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

#include "../include/hax.h"
#include "include/ia32_defs.h"
#include "include/cpu.h"
#include "include/cpuid.h"
#include "include/vcpu.h"
#include "include/debug.h"
#include "include/dump.h"
#include "include/name.h"
#include "include/vtlb.h"
#include "include/intr.h"
#include "include/ept.h"

static cpuid_cache_t cache = {
    .initialized = 0
};

static void cpu_vmentry_failed(struct vcpu_t *vcpu, vmx_result_t result);
static int cpu_vmexit_handler(struct vcpu_t *vcpu, exit_reason_t exit_reason,
                              struct hax_tunnel *htun);

static int cpu_emt64_enable(void)
{
    uint32_t efer;

    efer = ia32_rdmsr(IA32_EFER);
    return efer & 0x400;
}

static int cpu_nx_enable(void)
{
    uint32_t efer;

    efer = ia32_rdmsr(IA32_EFER);
    return efer & 0x800;
}

bool cpu_has_feature(uint32_t feature)
{
    if (!cache.initialized) {
        cpuid_host_init(&cache);
    }
    return cpuid_host_has_feature(&cache, feature);
}

void cpu_init_feature_cache(void)
{
    cpuid_host_init(&cache);
}

void cpu_init_svm(void *arg) {
	struct per_cpu_data *cpu_data;
	uint32_t vm_cr_msr, efer_msr, num_asids, svm_features, osvw;
	vmcs_t *vmxon;
	int nx_enable = 0, vt_enable = 0;
	cpuid_args_t cpuid_args;

	cpu_data = current_cpu_data();

	cpu_data->cpu_features |= HAX_CPUF_VALID;
	if (!cpu_has_feature(X86_FEATURE_SVM))
		return;

	cpuid_query_leaf(&cpuid_args, 0x8000000A);
	num_asids = cpuid_args.ebx;
	svm_features = cpuid_args.edx;
	hax_info("num_asids: %d\n", num_asids);
	// check that we have enough asid's for the vpid allocation
	// jake: todo: just using vm id for asid id, but im really not sure if thats correct -_-
	// commented out is the algo that vpid uses, which gives each vcpu a unique id, but amd doesnt offer as many bits for asid as intel
	// ryzen gen 1 gives 0x8000 id's, with nested and older giving at minimum 8, ther is a way to make this work better, but that involves looping the numbers on 
	// context switching
	//if (((HAX_MAX_VMS << 8) | HAX_MAX_VCPUS) > num_asids - 1) {
	if (HAX_MAX_VMS > num_asids - 1) {
		hax_info("haxm compiled to support more vpids than what processor supports: reported: 0x%x\n", num_asids);
		return;
	}

	if (!cpu_has_feature(X86_FEATURE_SVM_NRIP)) {
		hax_error("svm nrip feature required currently\n");
		return;
	}

	if (!cpu_has_feature(X86_FEATURE_SVM_NP)) {
		hax_error("svm requires nested page support\n");
		return;
	}

	/*if (!cpu_has_feature(X86_FEATURE_SVM_AVIC)) {
		hax_error("svm requires avic support currently\n");
		return;
	}*/

	osvw = ia32_rdmsr(MSR_AMD_OSVW);
	if (osvw & (1 << 3)) {
		// hardware erratum 383 in amd, probly need to deal with this for nested page guests
		// also do we have to do something with other errata?
		hax_error("amd erratum 383 not supported: osvw: 0x%x\n", osvw);
		return;
	}

	cpu_data->cpu_features |= HAX_CPUF_SUPPORT_VT;

	if (!cpu_has_feature(X86_FEATURE_NX))
		return;
	else
		cpu_data->cpu_features |= HAX_CPUF_SUPPORT_NX;

	if (cpu_has_feature(X86_FEATURE_EM64T))
		cpu_data->cpu_features |= HAX_CPUF_SUPPORT_EM64T;

	nx_enable = cpu_nx_enable();
	if (nx_enable)
		cpu_data->cpu_features |= HAX_CPUF_ENABLE_NX;

	vm_cr_msr = ia32_rdmsr(MSR_SVM_VM_CR);
	efer_msr = ia32_rdmsr(IA32_EFER);
	if (!(vm_cr_msr & VM_CR_SVMDIS) || (efer_msr & IA32_EFER_SVM))
		vt_enable = 1;
	if (vt_enable)
		cpu_data->cpu_features |= HAX_CPUF_ENABLE_VT;
	else 
		hax_info("svml %d\n", cpu_has_feature(X86_FEATURE_SVM_LOCK));

	hax_info("vm_cr_msr %x\n", vm_cr_msr);
	hax_info("vt_enable %d\n", vt_enable);
	hax_info("nx_enable %d\n", nx_enable);

	hax_info("svm features 0x%x\n", svm_features);

	memset(&cpu_data->vmx_info, 0, sizeof(info_t));

	if (!nx_enable || !vt_enable)
		return;

	/*
	 * EM64T disabled is ok for windows, but should cause failure in Mac
	 * Let Mac part roll back the whole staff
	 */
	if (cpu_emt64_enable())
		cpu_data->cpu_features |= HAX_CPUF_ENABLE_EM64T;

	/* Enable SVME */
	// todo: should we be locking something here like intel?
	//if (!(efer_msr & IA32_EFER_SVM))
	//	ia32_wrmsr(IA32_EFER, efer_msr | IA32_EFER_SVM);

	vmxon = (vmcs_t *)hax_page_va(cpu_data->vmxon_page);

	// just define as default, this is probably unnecessary
	if (cpu_has_feature(X86_FEATURE_SVM_TSCRATIO))
		ia32_wrmsr(MSR_AMD_TSC_RATIO, 0x0100000000ULL);

	cpu_data->lbr_support = cpu_has_feature(X86_FEATURE_SVM_LBRVIRT);
	cpu_data->decode_assists = cpu_has_feature(X86_FEATURE_SVM_DECODEASST);

	// cheating and using ept flag
	cpu_data->vmx_info._ept_cap = 1;

	cpu_data->cpu_features |= HAX_CPUF_INITIALIZED;
}

void cpu_init_vmx(void *arg)
{
    struct info_t vmx_info;
    struct per_cpu_data *cpu_data;
    uint32_t fc_msr;
    vmcs_t *vmxon;
    int nx_enable = 0, vt_enable = 0;

    cpu_data = current_cpu_data();

    cpu_data->cpu_features |= HAX_CPUF_VALID;
    if (!cpu_has_feature(X86_FEATURE_VMX))
        return;
    else
        cpu_data->cpu_features |= HAX_CPUF_SUPPORT_VT;

    if (!cpu_has_feature(X86_FEATURE_NX))
        return;
    else
        cpu_data->cpu_features |= HAX_CPUF_SUPPORT_NX;

    if (cpu_has_feature(X86_FEATURE_EM64T))
        cpu_data->cpu_features |= HAX_CPUF_SUPPORT_EM64T;

    nx_enable = cpu_nx_enable();
    if (nx_enable)
        cpu_data->cpu_features |= HAX_CPUF_ENABLE_NX;

    fc_msr = ia32_rdmsr(IA32_FEATURE_CONTROL);
    if ((fc_msr & FC_VMXON_OUTSMX) || !(fc_msr & FC_LOCKED))
        vt_enable = 1;
    if (vt_enable)
        cpu_data->cpu_features |= HAX_CPUF_ENABLE_VT;
    hax_info("fc_msr %x\n", fc_msr);
    hax_info("vt_enable %d\n", vt_enable);
    hax_info("nx_enable %d\n", nx_enable);

    if (!nx_enable || !vt_enable)
        return;

    /*
     * EM64T disabled is ok for windows, but should cause failure in Mac
     * Let Mac part roll back the whole staff
     */
    if (cpu_emt64_enable())
        cpu_data->cpu_features |= HAX_CPUF_ENABLE_EM64T;

    /* Enable FEATURE CONTROL MSR */
    if (!(fc_msr & FC_LOCKED))
        ia32_wrmsr(IA32_FEATURE_CONTROL,
                   fc_msr | FC_LOCKED | FC_VMXON_OUTSMX);

    /* get VMX capabilities */
    vmx_read_info(&vmx_info);
#if 0
    //hax_info("-----------cpu %d---------------\n", cpu_data->cpu_id);

    if ((cpu_data->cpu_id == 0 ||
         memcmp(&vmx_info, &hax_cpu_data[0]->vmx_info,
                sizeof(vmx_info)) != 0)) {
        dump_vmx_info(&vmx_info);
    }
#endif

    if (vmx_info._vmcs_region_length > HAX_PAGE_SIZE)
        hax_info("VMCS of %d bytes not supported by this Hypervisor. "
                "Max supported %u bytes\n",
                vmx_info._vmcs_region_length, (uint32_t)HAX_PAGE_SIZE);
    vmxon = (vmcs_t *)hax_page_va(cpu_data->vmxon_page);
    vmxon->_revision_id = vmx_info._vmcs_revision_id;

    //hax_info("enabled VMX mode (vmxon = %p)\n",
    //        hax_page_va(cpu_data->vmxon_page));

    vmx_read_info(&cpu_data->vmx_info);

    cpu_data->cpu_features |= HAX_CPUF_INITIALIZED;
}

void cpu_exit_vmx(void *arg)
{
}

void cpu_exit_svm(void *arg) {}

/*
 * Retrieves information about the performance monitoring capabilities of the
 * current host logical processor.
 * |arg| is unused.
 */
void cpu_pmu_init(void *arg)
{
    struct cpu_pmu_info *pmu_info = &current_cpu_data()->pmu_info;
    cpuid_args_t cpuid_args;

    memset(pmu_info, 0, sizeof(struct cpu_pmu_info));

    // Call CPUID with EAX = 0
    /*cpuid_query_leaf(&cpuid_args, 0x00);
    if (cpuid_args.eax < 0xa) {
        // Logical processor does not support APM
        return;
    }*/

	// amd hack, base amd64 has 4 counters, with feature flag for extended / more
	pmu_info->apm_version = 1;
	pmu_info->apm_general_count = 4;
	/*if (cpu_has_feature(X86_FEATURE_PERFCTREXTCORE)) {
		pmu_info->apm_general_count = 6;
	}
	else {
		pmu_info->apm_general_count = 4;
	}*/

    // Call CPUID with EAX = 0xa
    /*cpuid_query_leaf(&cpuid_args, 0xa);
    pmu_info->cpuid_eax = cpuid_args.eax;
    pmu_info->cpuid_ebx = cpuid_args.ebx;
    pmu_info->cpuid_edx = cpuid_args.edx;*/
}

static void vmread_cr(struct vcpu_t *vcpu)
{
    struct vcpu_state_t *state = vcpu->state;

    // Update only the bits the guest is allowed to change
    // This must use the actual cr0 mask, not _cr0_mask.
   // mword cr0 = vmread(vcpu, GUEST_CR0);
	mword cr0 = svm(vcpu)->save.cr0;
	state->_cr0 = cr0;
    hax_debug("vmread_cr, state->_cr0 %llx\n", state->_cr0);

	// jake
    // todo: update CR3 only if guest is allowed to change it
	// also clean bits
	state->_cr3 = svm(vcpu)->save.cr3;// vmread(vcpu, GUEST_CR3);

	state->_cr4 = svm(vcpu)->save.cr4;//vmread(vcpu, GUEST_CR4);
    //cr4_mask = vmread(vcpu, VMX_CR4_MASK); // should cache this
}

vmx_result_t cpu_vmx_vmptrld(struct per_cpu_data *cpu_data, hax_paddr_t vmcs,
                             struct vcpu_t *vcpu)
{
    vmx_result_t r = asm_vmptrld(&vmcs);
    return r;
}

bool vcpu_is_panic(struct vcpu_t *vcpu)
{
    struct hax_tunnel *htun = vcpu->tunnel;
    if (vcpu->panicked) {
        hax_error("vcpu has panicked, id:%d\n", vcpu->vcpu_id);
        hax_panic_log(vcpu);
        htun->_exit_status = HAX_EXIT_STATECHANGE;
        return 1;
    }
    return 0;
}

/*
 * Return:
 * 0 if need handling from qemu
 * 1 if return to guest
 * <0 if something wrong
 */
static int cpu_vmexit_handler(struct vcpu_t *vcpu, exit_reason_t exit_reason,
                              struct hax_tunnel *htun)
{
    int ret;

    ret = vcpu_vmexit_handler(vcpu, exit_reason, htun);

    if (vcpu_is_panic(vcpu)) {
        return HAX_EXIT;
    }

    if (ret == HAX_RESUME && !vcpu->event_injected && !vcpu->nr_pending_intrs &&
        htun->request_interrupt_window) {

        htun->_exit_status = HAX_EXIT_INTERRUPT;
        ret = HAX_EXIT;
    }

    /* Return for signal handling
     * We assume the signal handling will not cause vcpus state change
     * Otherwise we need consider situation that vcpu state impact, for example
     * if PG fault pending to guest
     */

    if ((ret == HAX_RESUME) && proc_event_pending(vcpu)) {
        htun->_exit_status = HAX_EXIT_INTERRUPT;
        ret = 0;
    }
    return ret;
}

#ifdef CONFIG_DARWIN
__attribute__ ((__noinline__))
#endif
vmx_result_t cpu_vmx_run(struct vcpu_t *vcpu, struct hax_tunnel *htun)
{
    vmx_result_t result = 0;
    mword host_rip;

    /* prepare the RIP */
    hax_debug("vm entry!\n");
    vcpu_save_host_state(vcpu);
    hax_disable_irq();

    /*
     * put the vmwrite before is_running, so that the vcpu->cpu_id is set
     * when we check vcpu->is_running in vcpu_pause
     */
    host_rip = vmx_get_rip();
    vmwrite(vcpu, HOST_RIP, (mword)host_rip);
    vcpu->is_running = 1;
#ifdef  DEBUG_HOST_STATE
    vcpu_get_host_state(current_cpu_data(), 1);
#endif
    /* Must ensure the IRQ is disabled before setting CR2 */
    set_cr2(vcpu->state->_cr2);

    vcpu_load_guest_state(vcpu);

    result = asm_vmxrun(vcpu->state, vcpu->launched);

    vcpu->is_running = 0;
    vcpu_save_guest_state(vcpu);
    vcpu_load_host_state(vcpu);

#ifdef  DEBUG_HOST_STATE
    vcpu_get_host_state(current_cpu_data(), 0);
    compare_host_state(vcpu, current_cpu_data());
#endif

    if (result != VMX_SUCCEED) {
        cpu_vmentry_failed(vcpu, result);
        htun->_exit_reason = 0;
        htun->_exit_status = HAX_EXIT_UNKNOWN;
    }
    return result;
}

#ifdef CONFIG_DARWIN
__attribute__((__noinline__))
#endif
vmx_result_t cpu_svm_run(struct vcpu_t *vcpu, struct hax_tunnel *htun)
{
	/* prepare the RIP */
	//hax_debug("vm entry!\n");
	hax_paddr_t hostvmpagepa;

	// disable gif for atomic state switch, processor reenables this on switch
	asm_clgi();

	hostvmpagepa = hax_page_pa(current_cpu_data()->hostvm_page);
	vcpu_save_host_state(vcpu);

	// jake: todo: deal with clean bits
	svm(vcpu)->control.clean = 0;

	vcpu->is_running = 1;
#ifdef  DEBUG_HOST_STATE
	vcpu_get_host_state(current_cpu_data(), 1);
#endif

	svm(vcpu)->save.rax = vcpu->state->_rax;
	asm_vmsave(hostvmpagepa);
	vcpu_load_guest_state(vcpu);

	// irq's might be disabled coming into this function, but we need to enable them
	// before we run to ensure guest exits from physical? ones. the gif still protects us until switch
	hax_enable_irq();
	asm_svmrun(vcpu->state, vcpu_vmcs_pa(vcpu), 0);
	asm_vmload(hostvmpagepa);

	vcpu->is_running = 0;

	vcpu->state->_rax = svm(vcpu)->save.rax;
	vcpu->state->_cr2 = svm(vcpu)->save.cr2;
	// todo:
	//svm(vcpu)->control.tlb_ctl = 0;

	vcpu_save_guest_state(vcpu);
	vcpu_load_host_state(vcpu);

	// reenable gif after we ensured processor is back to host state
	asm_stgi();

#ifdef  DEBUG_HOST_STATE
	vcpu_get_host_state(current_cpu_data(), 0);
	compare_host_state(vcpu, current_cpu_data());
#endif

	if (svm(vcpu)->control.exit_int_info != 0) {
		hax_error("exit int not 0\n");
		dump_svm_info(vcpu);
	}

	if (svm(vcpu)->control.exit_code == SVM_EXIT_ERR) {
		dump_svm_info(vcpu);
		hax_error("VM entry failed: RIP=%08lx\n",
			svm(vcpu)->save.rip);

		htun->_exit_reason = 0;
		htun->_exit_status = HAX_EXIT_UNKNOWN;
		return VMX_FAIL_INVALID;
	}

	return VMX_SUCCEED;
}

void vcpu_handle_vmcb_pending(struct vcpu_t *vcpu) {
	if (!vcpu || !vcpu->vmcs_pending)
		return;

	if (vcpu->vmcs_pending_entry_error_code) {
		vcpu->vmcs_pending_entry_error_code = 0;
	}

	if (vcpu->vmcs_pending_entry_instr_length) {
		vcpu->vmcs_pending_entry_instr_length = 0;
	}

	if (vcpu->vmcs_pending_entry_intr_info) {
		vcpu->vmcs_pending_entry_intr_info = 0;
	}

	// todo: should this require a flush of something?
	if (vcpu->vmcs_pending_guest_cr3) {
		svm(vcpu)->save.cr3 = vtlb_get_cr3(vcpu);
		vcpu->vmcs_pending_guest_cr3 = 0;
	}
	vcpu->vmcs_pending = 0;
	return;
}

void vcpu_handle_vmcs_pending(struct vcpu_t *vcpu)
{
    if (!vcpu || !vcpu->vmcs_pending)
        return;
    if (vcpu->vmcs_pending_entry_error_code) {
        vmwrite(vcpu, VMX_ENTRY_EXCEPTION_ERROR_CODE,
                vmx(vcpu, entry_exception_error_code));
        vcpu->vmcs_pending_entry_error_code = 0;
    }

    if (vcpu->vmcs_pending_entry_instr_length) {
        vmwrite(vcpu, VMX_ENTRY_INSTRUCTION_LENGTH,
                vmx(vcpu, entry_instr_length));
        vcpu->vmcs_pending_entry_instr_length = 0;
    }

    if (vcpu->vmcs_pending_entry_intr_info) {
        vmwrite(vcpu, VMX_ENTRY_INTERRUPT_INFO,
                vmx(vcpu, entry_intr_info).raw);
        vcpu->vmcs_pending_entry_intr_info = 0;
    }

    if (vcpu->vmcs_pending_guest_cr3) {
        vmwrite(vcpu, GUEST_CR3, vtlb_get_cr3(vcpu));
        vcpu->vmcs_pending_guest_cr3 = 0;
    }
    vcpu->vmcs_pending = 0;
    return;
}

/* Return the value same as ioctl value */
int cpu_svm_execute(struct vcpu_t *vcpu, struct hax_tunnel *htun) {
	vmx_result_t res = 0;
	int ret;
	preempt_flag flags;
	struct vcpu_state_t *state = vcpu->state;
	uint32_t vmcs_err = 0;

	while (1) {
		exit_reason_t exit_reason;

		if (vcpu->paused) {
			htun->_exit_status = HAX_EXIT_PAUSED;
			return 0;
		}
		if (vcpu_is_panic(vcpu))
			return 0;

		if ((vmcs_err = load_vmcs(vcpu, &flags))) {
			hax_panic_vcpu(vcpu, "load_vmcs fail: %x\n", vmcs_err);
			hax_panic_log(vcpu);
			return 0;
		}
		vcpu_handle_vmcb_pending(vcpu);
		vcpu_inject_intr(vcpu, htun);

		/* sometimes, the code segment type from qemu can be 10 (code segment),
		 * this will cause invalid guest state, since 11 (accessed code segment),
		 * not 10 is required by vmx hardware. Note: 11 is one of the allowed
		 * values by vmx hardware.
		 */
		{
			uint16_t temp = svm(vcpu)->save.cs.attrib;//vmread(vcpu, GUEST_CS_AR);

			if ((temp & 0xf) == 0xa) {
				temp = temp + 1;
				svm(vcpu)->save.cs.attrib = temp;
				//vmwrite(vcpu, GUEST_CS_AR, temp);
			}
		}
		/* sometimes, the TSS segment type from qemu is not right.
		 * let's hard-code it for now
		 */
		{
			uint16_t temp = svm(vcpu)->save.tr.attrib;//vmread(vcpu, GUEST_TR_AR);

			temp = (temp & ~0xf) | 0xb;
			svm(vcpu)->save.tr.attrib = temp;// vmwrite(vcpu, GUEST_TR_AR, temp);
		}

		res = cpu_svm_run(vcpu, htun);
		if (res) {
			hax_error("cpu_svm_run error, code:%x\n", res);
			if ((vmcs_err = put_vmcs(vcpu, &flags))) {
				hax_panic_vcpu(vcpu, "put_vmcs fail: %x\n", vmcs_err);
				hax_panic_log(vcpu);
			}
			return -EINVAL;
		}
		
		if (vmcs_err = put_vmcs(vcpu, &flags)) {
			hax_panic_vcpu(vcpu, "put_vmcs() fail after vmrun. %x\n",
				vmcs_err);
			hax_panic_log(vcpu);
		}

		exit_reason.raw = svm(vcpu)->control.exit_code;
		hax_debug("....exit_reason.raw %x, cpu %d %d\n", exit_reason.raw,
			vcpu->cpu_id, hax_cpuid());

		/* XXX Currently we take active save/restore for MSR and FPU, the main
		 * reason is, we have no schedule hook to get notified of preemption
		 * This should be changed later after get better idea
		 */
		vcpu->state->_rip = svm(vcpu)->save.rip;//vmread(vcpu, GUEST_RIP);

		hax_handle_idt_vectoring(vcpu);

		/*vmx(vcpu, exit_qualification).raw = vmread(
			vcpu, VM_EXIT_INFO_QUALIFICATION);
		vmx(vcpu, exit_intr_info).raw = vmread(
			vcpu, VM_EXIT_INFO_INTERRUPT_INFO);
		vmx(vcpu, exit_exception_error_code) = vmread(
			vcpu, VM_EXIT_INFO_EXCEPTION_ERROR_CODE);
		vmx(vcpu, exit_idt_vectoring) = vmread(
			vcpu, VM_EXIT_INFO_IDT_VECTORING);
		vmx(vcpu, exit_instr_length) = vmread(
			vcpu, VM_EXIT_INFO_INSTRUCTION_LENGTH);
		vmx(vcpu, exit_gpa) = vmread(
			vcpu, VM_EXIT_INFO_GUEST_PHYSICAL_ADDRESS);
		vmx(vcpu, interruptibility_state).raw = vmread(
			vcpu, GUEST_INTERRUPTIBILITY);*/
		vmx(vcpu, exit_gpa) = 0;

		vcpu->next_rip = svm(vcpu)->control.next_rip;
		state->_rflags = svm(vcpu)->save.rflags;//vmread(vcpu, GUEST_RFLAGS);
		state->_rsp = svm(vcpu)->save.rsp;//vmread(vcpu, GUEST_RSP);
		state->_sysenter_cs = svm(vcpu)->save.sysenter_cs;
		state->_sysenter_eip = svm(vcpu)->save.sysenter_eip;
		state->_sysenter_esp = svm(vcpu)->save.sysenter_esp;
		SVM_READSEG(svm(vcpu)->save, cs, state->_cs);
		SVM_READSEG(svm(vcpu)->save, ds, state->_ds);
		SVM_READSEG(svm(vcpu)->save, es, state->_es);
		/*SVM_READSEG(svm(vcpu)->save, fs, state->_fs);
		SVM_READSEG(svm(vcpu)->save, gs, state->_gs);
		SVM_READSEG(svm(vcpu)->save, ss, state->_ss);
		SVM_READSEG(svm(vcpu)->save, ldtr, state->_ldt);
		SVM_READSEG(svm(vcpu)->save, tr, state->_tr);
		SVM_READDESC(svm(vcpu)->save, gdtr, state->_gdt);
		SVM_READDESC(svm(vcpu)->save, idtr, state->_idt);*/
		vmread_cr(vcpu);

		if (vcpu->nr_pending_intrs > 0 || hax_intr_is_blocked(vcpu))
			htun->ready_for_interrupt_injection = 0;
		else
			htun->ready_for_interrupt_injection = 1;

		vcpu->cur_state = GS_STALE;

		ret = cpu_vmexit_handler(vcpu, exit_reason, htun);
		if (ret <= 0)
			return ret;
	}
}

/* Return the value same as ioctl value */
int cpu_vmx_execute(struct vcpu_t *vcpu, struct hax_tunnel *htun)
{
    vmx_result_t res = 0;
    int ret;
    preempt_flag flags;
    struct vcpu_state_t *state = vcpu->state;
    uint32_t vmcs_err = 0;

    while (1) {
        exit_reason_t exit_reason;

        if (vcpu->paused) {
            htun->_exit_status = HAX_EXIT_PAUSED;
            return 0;
        }
        if (vcpu_is_panic(vcpu))
            return 0;

        if ((vmcs_err = load_vmcs(vcpu, &flags))) {
            hax_panic_vcpu(vcpu, "load_vmcs fail: %x\n", vmcs_err);
            hax_panic_log(vcpu);
            return 0;
        }
        vcpu_handle_vmcs_pending(vcpu);
        vcpu_inject_intr(vcpu, htun);

        /* sometimes, the code segment type from qemu can be 10 (code segment),
         * this will cause invalid guest state, since 11 (accessed code segment),
         * not 10 is required by vmx hardware. Note: 11 is one of the allowed
         * values by vmx hardware.
         */
        {
            uint32_t temp= vmread(vcpu, GUEST_CS_AR);

            if( (temp & 0xf) == 0xa) {
                temp = temp +1;
                vmwrite(vcpu, GUEST_CS_AR, temp);
            }
        }
        /* sometimes, the TSS segment type from qemu is not right.
         * let's hard-code it for now
         */
        {
            uint32_t temp = vmread(vcpu, GUEST_TR_AR);

            temp = (temp & ~0xf) | 0xb;
            vmwrite(vcpu, GUEST_TR_AR, temp);
        }

        res = cpu_vmx_run(vcpu, htun);
        if (res) {
            hax_error("cpu_vmx_run error, code:%x\n", res);
            if ((vmcs_err = put_vmcs(vcpu, &flags))) {
                hax_panic_vcpu(vcpu, "put_vmcs fail: %x\n", vmcs_err);
                hax_panic_log(vcpu);
            }
            return -EINVAL;
        }

        exit_reason.raw = vmread(vcpu, VM_EXIT_INFO_REASON);
        hax_debug("....exit_reason.raw %x, cpu %d %d\n", exit_reason.raw,
                  vcpu->cpu_id, hax_cpuid());

        /* XXX Currently we take active save/restore for MSR and FPU, the main
         * reason is, we have no schedule hook to get notified of preemption
         * This should be changed later after get better idea
         */
        vcpu->state->_rip = vmread(vcpu, GUEST_RIP);

        hax_handle_idt_vectoring(vcpu);

        vmx(vcpu, exit_qualification).raw = vmread(
                vcpu, VM_EXIT_INFO_QUALIFICATION);
        vmx(vcpu, exit_intr_info).raw = vmread(
                vcpu, VM_EXIT_INFO_INTERRUPT_INFO);
        vmx(vcpu, exit_exception_error_code) = vmread(
                vcpu, VM_EXIT_INFO_EXCEPTION_ERROR_CODE);
        vmx(vcpu, exit_idt_vectoring) = vmread(
                vcpu, VM_EXIT_INFO_IDT_VECTORING);
        vmx(vcpu, exit_instr_length) = vmread(
                vcpu, VM_EXIT_INFO_INSTRUCTION_LENGTH);
        vmx(vcpu, exit_gpa) = vmread(
                vcpu, VM_EXIT_INFO_GUEST_PHYSICAL_ADDRESS);
        vmx(vcpu, interruptibility_state).raw = vmread(
                vcpu, GUEST_INTERRUPTIBILITY);

        state->_rflags = vmread(vcpu, GUEST_RFLAGS);
        state->_rsp = vmread(vcpu, GUEST_RSP);
        VMREAD_SEG(vcpu, CS, state->_cs);
        VMREAD_SEG(vcpu, DS, state->_ds);
        VMREAD_SEG(vcpu, ES, state->_es);
        vmread_cr(vcpu);

        if (vcpu->nr_pending_intrs > 0 || hax_intr_is_blocked(vcpu))
            htun->ready_for_interrupt_injection = 0;
        else
            htun->ready_for_interrupt_injection = 1;

        vcpu->cur_state = GS_STALE;
        vmcs_err = put_vmcs(vcpu, &flags);
        if (vmcs_err) {
            hax_panic_vcpu(vcpu, "put_vmcs() fail before vmexit. %x\n",
                           vmcs_err);
            hax_panic_log(vcpu);
        }
        hax_enable_irq();

        ret = cpu_vmexit_handler(vcpu, exit_reason, htun);
        if (ret <= 0)
            return ret;
    }
}

uint8_t is_vmcs_loaded(struct vcpu_t *vcpu)
{
    return (vcpu && vcpu->is_vmcs_loaded);
}

int debug_vmcs_count = 0;

void restore_host_cr4_vmxe(struct per_cpu_data *cpu_data);

uint32_t log_host_cr4_vmxe = 0;
uint64_t log_host_cr4 = 0;
vmx_result_t log_vmxon_res = 0;
uint64_t log_vmxon_addr = 0;
uint32_t log_vmxon_err_type1 = 0;
uint32_t log_vmxon_err_type2 = 0;
uint32_t log_vmxon_err_type3 = 0;
uint32_t log_vmclear_err = 0;
uint32_t log_vmptrld_err = 0;
uint32_t log_vmxoff_no = 0;
vmx_result_t log_vmxoff_res = 0;

void hax_clear_panic_log(struct vcpu_t *vcpu)
{
    log_host_cr4_vmxe = 0;
    log_host_cr4 = 0;
    log_vmxon_res = 0;
    log_vmxon_addr = 0;
    log_vmxon_err_type1 = 0;
    log_vmxon_err_type2 = 0;
    log_vmxon_err_type3 = 0;
    log_vmclear_err = 0;
    log_vmptrld_err = 0;
    log_vmxoff_no = 0;
    log_vmxoff_res = 0;
}

void hax_panic_log(struct vcpu_t *vcpu)
{
    if (!vcpu)
        return;
   /*hax_error("log_host_cr4_vmxe: %x\n", log_host_cr4_vmxe);
    hax_error("log_host_cr4 %llx\n", log_host_cr4);
    hax_error("log_vmxon_res %x\n", log_vmxon_res);
    hax_error("log_vmxon_addr %llx\n", log_vmxon_addr);
    hax_error("log_vmxon_err_type1 %x\n", log_vmxon_err_type1);
    hax_error("log_vmxon_err_type2 %x\n", log_vmxon_err_type2);
    hax_error("log_vmxon_err_type3 %x\n", log_vmxon_err_type3);
    hax_error("log_vmclear_err %x\n", log_vmclear_err);
    hax_error("log_vmptrld_err %x\n", log_vmptrld_err);
    hax_error("log_vmoff_no %x\n", log_vmxoff_no);
    hax_error("log_vmxoff_res %x\n", log_vmxoff_res);*/
}

uint32_t load_vmcs(struct vcpu_t *vcpu, preempt_flag *flags)
{
    struct per_cpu_data *cpu_data;
    hax_paddr_t vmcs_phy;
    hax_paddr_t curr_vmcs = VMCS_NONE;

    hax_disable_preemption(flags);

    /* when wake up from sleep, we need the barrier, as vm operation
     * are not serialized instructions.
     */
    hax_smp_mb();

    cpu_data = current_cpu_data();

    if (vcpu && is_vmcs_loaded(vcpu)) {
        cpu_data->nested++;
        return 0;
    }

    //if (cpu_vmxroot_enter() != VMX_SUCCEED) {
	if (cpu_svmroot_enter() != VMX_SUCCEED) {
        hax_enable_preemption(flags);
        return VMXON_FAIL;
    }

    if (vcpu) {
        vcpu->is_vmcs_loaded = 1;
        cpu_data->current_vcpu = vcpu;
        vcpu->prev_cpu_id = vcpu->cpu_id;
        vcpu->cpu_id = hax_cpuid();
    }

    cpu_data->other_vmcs = curr_vmcs;
    return VMXON_SUCCESS;
}

void restore_host_cr4_vmxe(struct per_cpu_data *cpu_data)
{
    if (cpu_data->host_cr4_vmxe) {
        if (cpu_data->vmm_flag & VMXON_HAX) {
            // TODO: Need to understand why this happens (on both Windows and
            // macOS)
            hax_debug("VMM flag (VMON_HAX) is not clear!\n");
        }
        set_cr4(get_cr4() | CR4_VMXE);
    } else {
        set_cr4(get_cr4() & (~CR4_VMXE));
    }
}

uint32_t put_vmcs(struct vcpu_t *vcpu, preempt_flag *flags)
{
    struct per_cpu_data *cpu_data = current_cpu_data();
    hax_paddr_t vmcs_phy;
    vmx_result_t vmxoff_res = 0;
    if (vcpu && cpu_data->nested > 0) {
        cpu_data->nested--;
        goto out;
    }

    //if (vcpu)
        vmcs_phy = vcpu_vmcs_pa(vcpu);
   //else
        //vmcs_phy = hax_page_pa(cpu_data->vmcs_page);

    cpu_data->current_vcpu = NULL;

    vmxoff_res = cpu_svmroot_leave();
    cpu_data->other_vmcs = VMCS_NONE;
    if (vcpu && vcpu->is_vmcs_loaded)
        vcpu->is_vmcs_loaded = 0;
out:
	hax_enable_irq();
    hax_enable_preemption(flags);

    return vmxoff_res;
}

void load_vmcb_common(struct vcpu_t *vcpu) {

	if (svm(vcpu)->control.intercept & SVM_INTERCEPT(SVM_INTERCEPT_IOIO_PROT))
		svm(vcpu)->control.iopm_base_pa = hax_page_pa(io_bitmap_page_a);
	
	if (svm(vcpu)->control.intercept & SVM_INTERCEPT(SVM_INTERCEPT_MSR_PROT))
		svm(vcpu)->control.msrpm_base_pa = hax_page_pa(msr_bitmap_page);

	svm(vcpu)->control.tsc_offset = vcpu->tsc_offset;

	vcpu_svmset_all(vcpu, 0);
}

void load_vmcs_common(struct vcpu_t *vcpu)
{
    // Update the cache for the PIN/EXIT ctls
    vmx(vcpu, pin_ctls) = vmx(vcpu, pin_ctls_base) = vmread(
            vcpu, VMX_PIN_CONTROLS);
    vmx(vcpu, pcpu_ctls) = vmx(vcpu, pcpu_ctls_base) = vmread(
            vcpu, VMX_PRIMARY_PROCESSOR_CONTROLS);
    vmx(vcpu, scpu_ctls) = vmx(vcpu, scpu_ctls_base) =
            vmx(vcpu, pcpu_ctls) & SECONDARY_CONTROLS ?
            vmread(vcpu, VMX_SECONDARY_PROCESSOR_CONTROLS) : 0;

    vmx(vcpu, exc_bitmap) = vmx(vcpu, exc_bitmap_base) = vmread(
            vcpu, VMX_EXCEPTION_BITMAP);
    vmx(vcpu, entry_ctls) = vmx(vcpu, entry_ctls_base) = vmread(
            vcpu, VMX_ENTRY_CONTROLS);
    vmx(vcpu, exit_ctls) = vmx(vcpu, exit_ctls_base) = vmread(
            vcpu, VMX_EXIT_CONTROLS);

    if (vmx(vcpu, pcpu_ctls) & IO_BITMAP_ACTIVE) {
        vmwrite(vcpu, VMX_IO_BITMAP_A, hax_page_pa(io_bitmap_page_a));
        vmwrite(vcpu, VMX_IO_BITMAP_B, hax_page_pa(io_bitmap_page_b));
    }

    if (vmx(vcpu, pcpu_ctls) & MSR_BITMAP_ACTIVE)
        vmwrite(vcpu, VMX_MSR_BITMAP, hax_page_pa(msr_bitmap_page));

    if (vmx(vcpu, pcpu_ctls) & USE_TSC_OFFSETTING)
        vmwrite(vcpu, VMX_TSC_OFFSET, vcpu->tsc_offset);

    vmwrite(vcpu, GUEST_ACTIVITY_STATE, vcpu->state->_activity_state);
    vcpu_vmwrite_all(vcpu, 0);
}


static void cpu_vmentry_failed(struct vcpu_t *vcpu, vmx_result_t result)
{
    uint64_t error, reason;

    hax_error("VM entry failed: RIP=%08lx\n",
              (mword)vmread(vcpu, GUEST_RIP));

    dump_vmcs(vcpu);

    reason = vmread(vcpu, VM_EXIT_INFO_REASON);
    if (result == VMX_FAIL_VALID) {
        error = vmread(vcpu, VMX_INSTRUCTION_ERROR_CODE);
        hax_error("VMfailValid. Prev exit: %llx. Error code: %llu (%s)\n",
                  reason, error, name_vmx_error(error));
    } else {
        hax_error("VMfailInvalid. Prev exit: %llx no error code\n",
                  reason);
    }
}

vmx_result_t cpu_vmxroot_leave(void)
{
    struct per_cpu_data *cpu_data = current_cpu_data();
    vmx_result_t result = VMX_SUCCEED;

    if (cpu_data->vmm_flag & VMXON_HAX) {
        result = asm_vmxoff();
        if (result == VMX_SUCCEED) {
            cpu_data->vmm_flag &= ~VMXON_HAX;
            restore_host_cr4_vmxe(cpu_data);
        } else {
            hax_error("VMXOFF Failed..........\n");
        }
    } else {
        log_vmxoff_no = 1;
#ifdef HAX_PLATFORM_DARWIN
        hax_debug("Skipping VMXOFF because another VMM (VirtualBox or macOS"
                  " Hypervisor Framework) is running\n");
#else
        // It should not go here in Win64/win32
        result = VMX_FAIL_VALID;
        hax_error("NO VMXOFF.......\n");
#endif
    }
    cpu_data->vmxoff_res = result;

    return result;
}

vmx_result_t cpu_svmroot_leave(void)
{
	struct per_cpu_data *cpu_data = current_cpu_data();
	uint64_t efer_msr;
	vmx_result_t result = VMX_SUCCEED;

	if (cpu_data->vmm_flag & VMXON_HAX) {
		cpu_data->vmm_flag &= ~VMXON_HAX;
	}
	else {
		log_vmxoff_no = 1;
#ifdef HAX_PLATFORM_DARWIN
		hax_debug("Skipping VMXOFF because another VMM (VirtualBox or macOS"
			" Hypervisor Framework) is running\n");
#else
		// It should not go here in Win64/win32
		result = VMX_FAIL_VALID;
		hax_error("NO VMXOFF.......\n");
#endif
	}
	

	efer_msr = ia32_rdmsr(IA32_EFER);
	if (!cpu_data->host_cr4_vmxe) {
		ia32_wrmsr(IA32_EFER, efer_msr & (~IA32_EFER_SVM));
	}

	cpu_data->vmxoff_res = result;

	return result;
}

vmx_result_t cpu_vmxroot_enter(void)
{
    struct per_cpu_data *cpu_data = current_cpu_data();
    uint64_t fc_msr;
    hax_paddr_t vmxon_addr;
    vmx_result_t result = VMX_SUCCEED;

    cpu_data->host_cr4_vmxe = (get_cr4() & CR4_VMXE);
    if (cpu_data->host_cr4_vmxe) {
        if (debug_vmcs_count % 100000 == 0) {
            hax_debug("host VT has enabled!\n");
            hax_debug("Cr4 value = 0x%lx\n", get_cr4());
            log_host_cr4_vmxe = 1;
            log_host_cr4 = get_cr4();
        }
        debug_vmcs_count++;
    }

    set_cr4(get_cr4() | CR4_VMXE);
    /* HP systems & Mac systems workaround
     * When resuming from S3, some HP/Mac set the IA32_FEATURE_CONTROL MSR to
     * zero. Setting the lock bit to zero & then doing 'vmxon' would cause a GP.
     * As a workaround, when we see this condition, we enable the bits so that
     * we can launch vmxon & thereby hax.
     * bit 0 - Lock bit
     * bit 2 - Enable VMX outside SMX operation
     *
     * ********* To Do **************************************
     * This is the workground to fix BSOD when resume from S3
     * The best way is to add one power management handler, and set
     * IA32_FEATURE_CONTROL MSR in that PM S3 handler
     * *****************************************************
     */
    fc_msr = ia32_rdmsr(IA32_FEATURE_CONTROL);
    if (!(fc_msr & FC_LOCKED))
        ia32_wrmsr(IA32_FEATURE_CONTROL,
                   fc_msr | FC_LOCKED | FC_VMXON_OUTSMX);

    vmxon_addr = hax_page_pa(cpu_data->vmxon_page);
    result = asm_vmxon(&vmxon_addr);

    log_vmxon_res = result;
    log_vmxon_addr = vmxon_addr;

    if (result == VMX_SUCCEED) {
        cpu_data->vmm_flag |= VMXON_HAX;
    } else {
        bool fatal = true;

#ifdef HAX_PLATFORM_DARWIN
        if ((result == VMX_FAIL_INVALID) && cpu_data->host_cr4_vmxe) {
            // On macOS, if VMXON fails with VMX_FAIL_INVALID and host CR4.VMXE
            // was already set, it is very likely that another VMM (VirtualBox
            // or any VMM based on macOS Hypervisor Framework, e.g. Docker) is
            // running and did not call VMXOFF. In that case, the current host
            // logical processor is already in VMX operation, and we can use an
            // innocuous VMX instruction (VMPTRST) to confirm that.
            // However, if the above assumption is wrong and the host processor
            // is not actually in VMX operation, VMPTRST will probably cause a
            // host reboot. But we don't have a better choice, and it is worth
            // taking the risk.
            hax_paddr_t vmcs_addr;
            asm_vmptrst(&vmcs_addr);

            // It is still alive - Just assumption is right.
            fatal = false;
            result = VMX_SUCCEED;
            // Indicate that it is not necessary to call VMXOFF later
            cpu_data->vmm_flag &= ~VMXON_HAX;
        }
#endif

        if (fatal) {
            hax_error("VMXON failed for region 0x%llx (result=0x%x, vmxe=%x)\n",
                      hax_page_pa(cpu_data->vmxon_page), (uint32_t)result,
                      (uint32_t)cpu_data->host_cr4_vmxe);
            restore_host_cr4_vmxe(cpu_data);
            if (result == VMX_FAIL_INVALID) {
                log_vmxon_err_type1 = 1;
            } else {
                // TODO: Should VMX_FAIL_VALID be ignored? The current VMCS can
                // be cleared (deactivated and saved to memory) using VMCLEAR
                log_vmxon_err_type2 = 1;
            }
        }
    }
    cpu_data->vmxon_res = result;
    return result;
}

vmx_result_t cpu_svmroot_enter(void)
{
	struct per_cpu_data *cpu_data = current_cpu_data();
	uint64_t efer_msr;
	hax_paddr_t hsave_addr;

	efer_msr = ia32_rdmsr(IA32_EFER);
	cpu_data->host_cr4_vmxe = (efer_msr & IA32_EFER_SVM);

	if (!(efer_msr & IA32_EFER_SVM))
		ia32_wrmsr(IA32_EFER, efer_msr | IA32_EFER_SVM);

	hsave_addr = hax_page_pa(cpu_data->vmxon_page);
	ia32_wrmsr(MSR_SVM_VM_HSAVE_PA, hsave_addr);

	log_vmxon_addr = hsave_addr;
	cpu_data->vmm_flag |= VMXON_HAX;
	cpu_data->vmxon_res = VMX_SUCCEED;

	return VMX_SUCCEED;
}
