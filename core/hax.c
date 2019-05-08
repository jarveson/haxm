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

#include "include/ia32_defs.h"
#include "include/vmx.h"
#include "include/svm.h"

#include "include/cpu.h"
#include "include/config.h"
#include "include/hax_driver.h"
#include "include/vm.h"
#include "../include/hax.h"
#include "../include/hax_release_ver.h"

/* deal with module parameter */
struct config_t config = {
    .memory_pass_through         = 0,
    .disable_ept                 = 0,
    .ept_small_pages             = 1,
    .disable_vpid                = 1,
    .disable_unrestricted_guest  = 1,
    .no_cpuid_pass_through       = 1,
    .cpuid_pass_through          = 0,
    .cpuid_no_mwait              = 0,
    .no_msr_pass_through         = 0
};

struct hax_page *io_bitmap_page_a;
struct hax_page *io_bitmap_page_b;
struct hax_page *msr_bitmap_page;

struct per_cpu_data **hax_cpu_data;
struct hax_t *hax;

extern hax_atomic_t vmx_cpu_num, vmx_enabled_num;
static void hax_enable_vmx(void)
{
    hax_smp_call_function(&cpu_online_map, cpu_init_vmx, NULL);
}

static void hax_enable_svm(void) {
	hax_smp_call_function(&cpu_online_map, cpu_init_svm, NULL);
}

static void hax_disable_svm(void) {
	hax_smp_call_function(&cpu_online_map, cpu_exit_svm, NULL);
}

static void hax_disable_vmx(void)
{
    hax_smp_call_function(&cpu_online_map, cpu_exit_vmx, NULL);
}

static void free_cpu_vmxon_region(void)
{
    int cpu;

    for (cpu = 0; cpu < max_cpus; cpu++) {
        if (!cpu_is_online(cpu) || !hax_cpu_data[cpu])
            continue;
        if (hax_cpu_data[cpu]->vmxon_page) {
            hax_free_pages(hax_cpu_data[cpu]->vmxon_page);
            hax_cpu_data[cpu]->vmxon_page = NULL;
        }
		if (hax_cpu_data[cpu]->hostvm_page) {
			hax_free_pages(hax_cpu_data[cpu]->hostvm_page);
			hax_cpu_data[cpu]->hostvm_page = NULL;
		}
    }
}

static int alloc_cpu_vmxon_region(void)
{
    int cpu;
    struct hax_page *page;
	struct hax_page *page2;

    for (cpu = 0; cpu < max_cpus; cpu++) {
        if (!cpu_is_online(cpu) || !hax_cpu_data[cpu])
            continue;
        page = hax_alloc_page(0, 1);
		page2 = hax_alloc_page(0, 1);
        if (!page || !page2) {
            free_cpu_vmxon_region();
            return -ENOMEM;
        }
        hax_clear_page(page);
		hax_clear_page(page2);
        hax_cpu_data[cpu]->vmxon_page = page;
		hax_cpu_data[cpu]->hostvm_page = page2;
    }
    return 0;
}

void free_cpu_template_vmcs(void)
{
    int cpu;

    for (cpu = 0; cpu < max_cpus; cpu++) {
        if (!cpu_is_online(cpu) || !hax_cpu_data[cpu])
            continue;
        //if (hax_cpu_data[cpu]->vmcs_page) {
        //    hax_free_pages(hax_cpu_data[cpu]->vmcs_page);
         //   hax_cpu_data[cpu]->vmcs_page = NULL;
        //}
    }
}

static int alloc_cpu_template_vmcs(void)
{
    int cpu;
    struct hax_page *page = NULL;

    for (cpu = 0; cpu < max_cpus; cpu++) {
        if (!cpu_is_online(cpu) || !hax_cpu_data[cpu])
            continue;
        //page = (struct hax_page *)hax_alloc_page(0, 1);
        //if (!page) {
        //    free_cpu_template_vmcs();
        //    return -ENOMEM;
        //}
        //hax_clear_page(page);
        //hax_cpu_data[cpu]->vmcs_page = page;
    }
    return 0;
}

int hax_em64t_enabled(void)
{
    return hax->em64t_enable_flag;
}

static int hax_svm_enable_check(void) {
	int vts = 0, nxs = 0, vte = 0, nxe = 0, em64s = 0, em64e = 0, finished = 0;
	int cpu, tnum = 0, error = 0;

	for (cpu = 0; cpu < max_cpus; cpu++) {
		struct per_cpu_data *cpu_data;

		if (!cpu_is_online(cpu))
			continue;
		cpu_data = hax_cpu_data[cpu];
		// This should not happen !
		if (!cpu_data)
			continue;

		if (cpu_data->cpu_features & HAX_CPUF_VALID) {
			tnum++;
			if (cpu_data->cpu_features & HAX_CPUF_SUPPORT_VT) {
				vts++;
			}
			if (cpu_data->cpu_features & HAX_CPUF_SUPPORT_NX) {
				nxs++;
			}
			if (cpu_data->cpu_features & HAX_CPUF_SUPPORT_EM64T) {
				em64s++;
			}
			if (cpu_data->cpu_features & HAX_CPUF_ENABLE_VT) {
				vte++;
			}
			if (cpu_data->cpu_features & HAX_CPUF_ENABLE_NX) {
				nxe++;
			}
			if (cpu_data->cpu_features & HAX_CPUF_ENABLE_EM64T) {
				em64e++;
			}
			if (cpu_data->cpu_features & HAX_CPUF_INITIALIZED) {
				finished++;
			}
		}
	}
	if (vts != tnum) {
		hax_error("VT is not supported in the system, HAXM exits, sorry!\n");
		hax_notify_host_event(HaxNoVtEvent, NULL, 0);
		return -1;
	}

	if (nxs != tnum) {
		hax_error("NX is not supported in the system, HAXM exits, sorry!\n");
		hax_notify_host_event(HaxNoNxEvent, NULL, 0);
		return -1;
	}
#if 0
	if (em64s != tnum) {
		hax_error("EM64T is not supported in the system, HAXM exits, sorry!\n");
		hax_notify_host_event(HaxNoEMT64Event, NULL, 0);
		return -1;
	}
#endif
	if (nxe != tnum) {
		hax_error("NX is not enabled in the system, HAXM does not function.\n");
		error = 1;
		hax_notify_host_event(HaxNxDisable, NULL, 0);
	}
	else {
		hax->nx_enable_flag = 1;
	}

	if (vte != tnum) {
		hax_error("VT is not enabled in the system, HAXM does not function.\n");
		hax_notify_host_event(HaxVtDisable, NULL, 0);
		error = 1;
	}
	else {
		hax->vmx_enable_flag = 1;
	}

	if (em64e == tnum) {
		hax->em64t_enable_flag = 1;
	}

	hax->ug_enable_flag = 1;

	if ((error == 0) && (tnum != finished)) {
		hax_error("Unknown reason happens to VT init, HAXM exit\n");
		hax_notify_host_event(HaxVtEnableFailure, NULL, 0);
		return -1;
	}
	return 0;
}

/*
 * This vcpu_data should not be accessed by anyone else at this step.
 * Return 0 if can continue, <0 for error.
 */
static int hax_vmx_enable_check(void)
{
    int vts = 0, nxs = 0, vte = 0, nxe = 0, em64s = 0, em64e = 0, finished = 0;
    int cpu, tnum = 0, error = 0;

    for (cpu = 0; cpu < max_cpus; cpu++) {
        struct per_cpu_data *cpu_data;

        if (!cpu_is_online(cpu))
            continue;
        cpu_data = hax_cpu_data[cpu];
        // This should not happen !
        if (!cpu_data)
            continue;

        if (cpu_data->cpu_features & HAX_CPUF_VALID) {
            tnum++;
            if (cpu_data->cpu_features & HAX_CPUF_SUPPORT_VT) {
                vts++;
            }
            if (cpu_data->cpu_features & HAX_CPUF_SUPPORT_NX) {
                nxs++;
            }
            if (cpu_data->cpu_features & HAX_CPUF_SUPPORT_EM64T) {
                em64s++;
            }
            if (cpu_data->cpu_features & HAX_CPUF_ENABLE_VT) {
                vte++;
            }
            if (cpu_data->cpu_features & HAX_CPUF_ENABLE_NX) {
                nxe++;
            }
            if (cpu_data->cpu_features & HAX_CPUF_ENABLE_EM64T) {
                em64e++;
            }
            if (cpu_data->cpu_features & HAX_CPUF_INITIALIZED) {
                finished++;
            }
        }
    }
    if (vts != tnum) {
        hax_error("VT is not supported in the system, HAXM exits, sorry!\n");
        hax_notify_host_event(HaxNoVtEvent, NULL, 0);
        return -1;
    }

    if (nxs != tnum) {
        hax_error("NX is not supported in the system, HAXM exits, sorry!\n");
        hax_notify_host_event(HaxNoNxEvent, NULL, 0);
        return -1;
    }
#if 0
    if (em64s != tnum) {
        hax_error("EM64T is not supported in the system, HAXM exits, sorry!\n");
        hax_notify_host_event(HaxNoEMT64Event, NULL, 0);
        return -1;
    }
#endif
    if (nxe != tnum) {
        hax_error("NX is not enabled in the system, HAXM does not function.\n");
        error = 1;
        hax_notify_host_event(HaxNxDisable, NULL, 0);
    } else {
        hax->nx_enable_flag = 1;
    }

    if (vte != tnum) {
        hax_error("VT is not enabled in the system, HAXM does not function.\n");
        hax_notify_host_event(HaxVtDisable, NULL, 0);
        error = 1;
    } else {
        hax->vmx_enable_flag = 1;
    }

    if (em64e == tnum) {
        hax->em64t_enable_flag = 1;
    }

    // If UG exists, we want it.
    if ((ia32_rdmsr(IA32_VMX_MISC) & IA32_VMX_MISC_UG_AVAILABLE) != 0) {
        hax->ug_enable_flag = 1;
    } else {
        hax->ug_enable_flag = 0;
    }

    if ((error == 0) && (tnum != finished)) {
        hax_error("Unknown reason happens to VT init, HAXM exit\n");
        hax_notify_host_event(HaxVtEnableFailure, NULL, 0);
        return -1;
    }
    return 0;
}

static int hax_svm_init(void) {
	int ret = -ENOMEM;

	io_bitmap_page_a = (struct hax_page *)hax_alloc_pages(2, 0, 1);
	if (!io_bitmap_page_a)
		return -ENOMEM;
	memset(hax_page_va(io_bitmap_page_a), 0xff, HAX_PAGE_SIZE * (1 << io_bitmap_page_a->order));

	msr_bitmap_page = (struct hax_page *)hax_alloc_pages(1, 0, 1);
	if (!msr_bitmap_page)
		goto out_2;
	memset(hax_page_va(msr_bitmap_page), 0xff, HAX_PAGE_SIZE * (1 << msr_bitmap_page->order));

	// we can reuse vmxon as hsave page for svm
	if ((ret = alloc_cpu_vmxon_region()) < 0)
		goto out_3;

	// we should be able to reuse this for vmcb
	if ((ret = alloc_cpu_template_vmcs()) < 0)
		goto out_4;

	hax_enable_svm();

	if ((ret = hax_svm_enable_check()) < 0)
		goto out_5;

	return 0;
out_5:
	hax_disable_svm();
	free_cpu_template_vmcs();
out_4:
	free_cpu_vmxon_region();
out_3:
	hax_free_pages(msr_bitmap_page);
out_2:
	hax_free_pages(io_bitmap_page_b);
out_1:
	hax_free_pages(io_bitmap_page_a);
	return ret;
}

static int hax_vmx_init(void)
{
    int ret = -ENOMEM;

    io_bitmap_page_a = (struct hax_page *)hax_alloc_page(0, 1);
    if (!io_bitmap_page_a)
        return -ENOMEM;
    hax_set_page(io_bitmap_page_a);

    io_bitmap_page_b = (struct hax_page *)hax_alloc_page(0, 1);
    if (!io_bitmap_page_b)
        goto out_1;
    hax_set_page(io_bitmap_page_b);

    msr_bitmap_page = (struct hax_page *)hax_alloc_page(0, 1);
    if (!msr_bitmap_page)
        goto out_2;
    hax_set_page(msr_bitmap_page);

    if ((ret = alloc_cpu_vmxon_region()) < 0)
        goto out_3;

    if ((ret = alloc_cpu_template_vmcs()) < 0)
        goto out_4;

    hax_enable_vmx();

    if ((ret = hax_vmx_enable_check()) < 0)
        goto out_5;

    return 0;
out_5:
    hax_disable_vmx();
    free_cpu_template_vmcs();
out_4:
    free_cpu_vmxon_region();
out_3:
    hax_free_pages(msr_bitmap_page);
out_2:
    hax_free_pages(io_bitmap_page_b);
out_1:
    hax_free_pages(io_bitmap_page_a);
    return ret;
}

static int hax_vmx_exit(void)
{
    hax_disable_vmx();
    free_cpu_template_vmcs();
    free_cpu_vmxon_region();
    hax_free_pages(msr_bitmap_page);
    hax_free_pages(io_bitmap_page_b);
    hax_free_pages(io_bitmap_page_a);
    return 0;
}

int hax_set_memlimit(void *buf, int bufLeng, int *outLength)
{
    struct hax_set_memlimit *memlimit = buf;

    hax_mutex_lock(hax->hax_lock);
    // We can't set the limit when VM created already.
    if (!hax_list_empty(&hax->hax_vmlist)) {
        hax_mutex_unlock(hax->hax_lock);
        return -EINVAL;
    }
    if (!memlimit->enable_memlimit) {
        hax->mem_limit = 0;
        hax_error("disable memlimit\n");
    } else {
        hax->mem_limit = hax->mem_quota = memlimit->memory_limit << 20;
        hax_info("set memlimit 0x%llx\n", hax->mem_limit);
    }
    hax_mutex_unlock(hax->hax_lock);
    return 0;
}

int hax_get_capability(void *buf, int bufLeng, int *outLength)
{
    struct hax_capabilityinfo *cap;

    cap = buf;
    if (bufLeng < sizeof(struct hax_capabilityinfo))
        return -EINVAL;

    if (!hax->vmx_enable_flag || !hax->nx_enable_flag) {
        cap->wstatus = 0;
        cap->winfo = 0;
        if (!hax->vmx_enable_flag) {
            cap->winfo |= HAX_CAP_FAILREASON_VT;
        }
        if (!hax->nx_enable_flag) {
            cap->winfo |= HAX_CAP_FAILREASON_NX;
        }
    } else {
        struct per_cpu_data *cpu_data = current_cpu_data();

        cap->wstatus = HAX_CAP_STATUS_WORKING;
        // Fast MMIO supported since API version 2
        cap->winfo = HAX_CAP_FASTMMIO;
        cap->winfo |= HAX_CAP_64BIT_RAMBLOCK;
#ifdef CONFIG_HAX_EPT2
        cap->winfo |= HAX_CAP_64BIT_SETRAM;
        cap->winfo |= HAX_CAP_IMPLICIT_RAMBLOCK;
#endif
        cap->winfo |= HAX_CAP_TUNNEL_PAGE;
        cap->winfo |= HAX_CAP_RAM_PROTECTION;
        cap->winfo |= HAX_CAP_DEBUG;
        if (cpu_data->vmx_info._ept_cap) {
            cap->winfo |= HAX_CAP_EPT;
        }
        if (hax->ug_enable_flag) {
            cap->winfo |= HAX_CAP_UG;
        }
    }

    if (hax->mem_limit) {
        cap->wstatus |= HAX_CAP_MEMQUOTA;
        cap->mem_quota = hax->mem_quota;
    }

    if (outLength) {
        *outLength = sizeof(struct hax_capabilityinfo);
    }
    return 0;
}

/*
 * Allows the guest to read from and/or write to the specified MSRs without
 * causing a VM exit.
 * |start| is the start MSR address, |count| the number of MSRs. Together they
 * specify a range of consecutive MSR addresses.
 * |read| and |write| determine if each MSR can be read or written freely by the
 * guest, respectively.
 */
static void set_msr_access(uint32_t start, uint32_t count, bool read, bool write)
{
    uint32_t end = start + count - 1;
    uint32_t bit_read, bit_write;
    uint8_t *msr_bitmap = hax_page_va(msr_bitmap_page);
	uint32_t offset, x, msr;
	uint8_t read_base;

    //hax_assert(((start ^ (start << 1)) & 0x80000000) == 0);
    //hax_assert((start & 0x3fffe000) == 0);
    //hax_assert(((start ^ end) & 0xffffe000) == 0);
    hax_assert(msr_bitmap);

	for (x = 0; x < count; ++x) {
		msr = start + x;
		offset = svm_msrpm_offset(msr);
		hax_assert(offset != -1);

		bit_read = 2 * (msr & 0x0f);
		bit_write = 2 * (msr & 0x0f) + 1;

		read_base = msr_bitmap[offset];
		if (read) {
			btr(&read_base, bit_read);
		}
		else {
			bts(&read_base, bit_read);
		}

		if (write) {
			btr(&read_base, bit_write);
		}
		else {
			bts(&read_base, bit_write);
		}
	}
}

/*
 * Probes the host CPU to determine its performance monitoring capabilities.
 */
static void hax_pmu_init(void)
{
    int cpu_id;
    int ref_cpu_id = -1;

    // Execute cpu_pmu_init() on each logical processor of the host CPU
    hax_smp_call_function(&cpu_online_map, cpu_pmu_init, NULL);

    // Find the common APM version supported by all host logical processors
    // TODO: Theoretically we should do the same for other APM parameters
    // (number of counters, etc.) as well
    for (cpu_id = 0; cpu_id < max_cpus; cpu_id++) {
        struct per_cpu_data *cpu_data;
        uint apm_version;

        if (!cpu_is_online(cpu_id)) {
            continue;
        }
        cpu_data = hax_cpu_data[cpu_id];
        // Should never happen
        if (!cpu_data) {
            hax_warning("hax_pmu_init: hax_cpu_data[%d] is NULL\n", cpu_id);
            continue;
        }

        apm_version = cpu_data->pmu_info.apm_version;
        if (!hax->apm_version || apm_version < hax->apm_version) {
            hax->apm_version = apm_version;
            ref_cpu_id = cpu_id;
        }
    }

    if (hax->apm_version) {
        struct cpu_pmu_info *ref_pmu_info, *pmu_info;
        uint apm_general_bitlen, apm_fixed_bitlen;

        ref_pmu_info = &hax_cpu_data[ref_cpu_id]->pmu_info;
        // IA SDM Vol. 3B 18.2 describes APM version 1 through 4, which can be
        // implemented in an incremental manner
        // TODO: Implement APM version 2
        if (hax->apm_version > 1) {
            hax->apm_version = 1;
        }
        hax->apm_general_count =
                ref_pmu_info->apm_general_count > APM_MAX_GENERAL_COUNT
                ? APM_MAX_GENERAL_COUNT : ref_pmu_info->apm_general_count;
        apm_general_bitlen = ref_pmu_info->apm_general_bitlen;
        hax->apm_general_mask = apm_general_bitlen > 63 ? (uint64_t)-1
                                : (1ULL << apm_general_bitlen) - 1;
        hax->apm_event_count =
                ref_pmu_info->apm_event_count > APM_MAX_EVENT_COUNT
                ? APM_MAX_EVENT_COUNT : ref_pmu_info->apm_event_count;
        hax->apm_event_unavailability = ref_pmu_info->apm_event_unavailability &
                                        ((1UL << hax->apm_event_count) - 1);
        hax_info("APM: version %u\n", hax->apm_version);
        hax_info("APM: %u general-purpose counters, bitmask 0x%llx\n",
                 hax->apm_general_count, hax->apm_general_mask);
        hax_info("APM: %u events, unavailability 0x%x\n", hax->apm_event_count,
                 hax->apm_event_unavailability);

		// todo: redo msr access here
        set_msr_access(MSR_AMD_PMC0, hax->apm_general_count, true, true);
        set_msr_access(MSR_AMD_PERFEVTSEL0, hax->apm_general_count, true, true);

        if (hax->apm_version > 1) {
            hax->apm_fixed_count =
                    ref_pmu_info->apm_fixed_count > APM_MAX_FIXED_COUNT
                    ? APM_MAX_FIXED_COUNT : ref_pmu_info->apm_fixed_count;
            apm_fixed_bitlen = ref_pmu_info->apm_fixed_bitlen;
            hax->apm_fixed_mask = apm_fixed_bitlen > 63 ? (uint64_t)-1
                                  : (1ULL << apm_fixed_bitlen) - 1;
            hax_info("APM: %u fixed-function counters, bitmask 0x%llx\n",
                     hax->apm_fixed_count, hax->apm_fixed_mask);
        } else {
            hax->apm_fixed_count = 0;
            apm_fixed_bitlen = 0;
            hax->apm_fixed_mask = 0;
        }

        // Copy the common APM parameters to hax->apm_cpuid_0xa, so as to
        // simplify CPUID virtualization

		// todo: support this differently for amd
        /*pmu_info = &hax->apm_cpuid_0xa;
        pmu_info->apm_version = hax->apm_version;
        pmu_info->apm_general_count = hax->apm_general_count;
        pmu_info->apm_general_bitlen = apm_general_bitlen;
        pmu_info->apm_event_count = hax->apm_event_count;
        pmu_info->apm_event_unavailability = hax->apm_event_unavailability;
        pmu_info->apm_fixed_count = hax->apm_fixed_count;
        pmu_info->apm_fixed_bitlen = apm_fixed_bitlen;*/
    } else {
        hax_warning("Host CPU does not support APM\n");
        hax->apm_general_count = 0;
        hax->apm_general_mask = 0;
        hax->apm_event_count = 0;
        hax->apm_event_unavailability = 0;
        hax->apm_fixed_count = 0;
        hax->apm_fixed_mask = 0;
    }
}

static void hax_msr_access_init(void) {
	int cpu_id;
	int supportslbr = 0;

	for (cpu_id = 0; cpu_id < max_cpus; cpu_id++) {
		struct per_cpu_data *cpu_data;

		if (!cpu_is_online(cpu_id)) {
			continue;
		}
		cpu_data = hax_cpu_data[cpu_id];
		// Should never happen
		if (!cpu_data) {
			hax_warning("hax_pmu_init: hax_cpu_data[%d] is NULL\n", cpu_id);
			continue;
		}
		if (cpu_data->lbr_support) {
			supportslbr = 1;
			break;
		}
	}
	if (supportslbr) {
		set_msr_access(IA32_LASTBRANCHFROMIP, 4, true, true);
	}

	//jake: this could also go somewhere else as its amd/svm specific
	//set_msr_access(IA32_SYSENTER_CS, 3, true, true);
	//set_msr_access(IA32_STAR, 7, true, true);
}

int hax_module_init(void)
{
    int ret = 0, cpu = 0;

    hax = (struct hax_t *)hax_vmalloc(sizeof(struct hax_t), HAX_MEM_NONPAGE);
    if (!hax)
        return -ENOMEM;

    hax->mem_quota = hax->mem_limit = hax_get_memory_threshold();
    hax->hax_lock = hax_mutex_alloc_init();
    if (!hax->hax_lock)
        goto out_0;

    hax_cpu_data = hax_vmalloc(max_cpus * sizeof(void *), 0);
    if (!hax_cpu_data)
        goto out_1;
    memset(hax_cpu_data, 0, max_cpus * sizeof(void *));

    for (cpu = 0; cpu < max_cpus; cpu++) {
        if (!cpu_is_online(cpu))
            continue;
        hax_cpu_data[cpu] = hax_vmalloc(sizeof(struct per_cpu_data), 0);
        if (!hax_cpu_data[cpu])
            goto out_2;
        memset(hax_cpu_data[cpu], 0, sizeof(struct per_cpu_data));

        hax_cpu_data[cpu]->hstate.hfxpage =
                (struct hax_page *)hax_alloc_page(0, 1);
        if (!hax_cpu_data[cpu]->hstate.hfxpage)
            goto out_2;
        hax_clear_page(hax_cpu_data[cpu]->hstate.hfxpage);
        hax_cpu_data[cpu]->cpu_id = cpu;
    }
    cpu_init_feature_cache();

	// todo: decide this based on feature set or something 
	//ret = hax_vmx_init();
	ret = hax_svm_init();
    if (ret < 0)
        goto out_2;

    hax_pmu_init();

	hax_msr_access_init();

    hax_init_list_head(&hax->hax_vmlist);
    hax_warning("-------- HAXM v%s Start --------\n", HAXM_RELEASE_VERSION_STR);

    return 0;

out_2:
    for (cpu = 0; cpu < max_cpus; cpu++) {
        if (hax_cpu_data[cpu]) {
            if (hax_cpu_data[cpu]->hstate.hfxpage) {
                hax_free_pages(hax_cpu_data[cpu]->hstate.hfxpage);
            }
            hax_vfree(hax_cpu_data[cpu], sizeof(struct per_cpu_data));
        }
    }
    hax_vfree(hax_cpu_data, max_cpus * sizeof(void *));
out_1:
    hax_mutex_free(hax->hax_lock);
out_0:
    hax_vfree(hax, sizeof(struct hax_t));
    return -ENOMEM;
}

int hax_module_exit(void)
{
    int i, ret;

    if (!hax_list_empty(&hax->hax_vmlist)) {
        hax_error("Still VM not be destroyed?\n");
        return -EBUSY;
    }

    ret = hax_destroy_host_interface();
    if (ret < 0)
        return ret;

    hax_vmx_exit();
    for (i = 0; i < max_cpus; i++) {
        if (!hax_cpu_data[i])
            continue;
        if (hax_cpu_data[i]->hstate.hfxpage) {
            hax_free_pages(hax_cpu_data[i]->hstate.hfxpage);
        }
        hax_vfree(hax_cpu_data[i], sizeof(struct per_cpu_data));
    }
    hax_vfree(hax_cpu_data, max_cpus * sizeof(void *));
    hax_mutex_free(hax->hax_lock);
    hax_vfree(hax, sizeof(struct hax_t));
    hax_warning("-------- HAXM v%s End --------\n", HAXM_RELEASE_VERSION_STR);

    return 0;
}
