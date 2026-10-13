/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * This file is part of LibVMI.
 *
 * LibVMI is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * LibVMI is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with LibVMI.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>

#include <libmicrovmi.h>

#include "private.h"
#include "driver/driver_interface.h"
#include "driver/memory_cache.h"
#include "driver/libmicrovmi/microvmi.h"
#include "msr-index.h"

// shortcut: memflow connector is fixed, add init data for it when someone needs another connector
#define DEFAULT_MEMFLOW_CONNECTOR "qemu_procfs"

typedef struct microvmi_instance {
    void *ctx;
    char *name;
    bool intr_on;    // Breakpoint intercept set on every vCPU
    bool *sstep_on;  // per vCPU: Singlestep intercept set, toggled by VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
} microvmi_instance_t;

static inline microvmi_instance_t *
microvmi_get_instance(vmi_instance_t vmi)
{
    return (microvmi_instance_t *) vmi->driver.driver_data;
}

static status_t
microvmi_open(
    const char *name,
    const DriverType *driver_type,
    vmi_init_data_t *init_data,
    void **ctx)
{
    static bool logger_initialized = false;

    if (!name) {
        errprint("libmicrovmi needs a VM name (VMI_INIT_DOMAINNAME)\n");
        return VMI_FAILURE;
    }

    DriverInitParamsFFI params = {
        .common.vm_name = (char *) name,
        .memflow.connector_name = DEFAULT_MEMFLOW_CONNECTOR,
        .memflow.connector_args.tag = Default,
    };

    if (init_data) {
        for (uint64_t i = 0; i < init_data->count; i++) {
            switch (init_data->entry[i].type) {
                case VMI_INIT_DATA_KVMI_SOCKET:
                    params.kvm.tag = UnixSocket;
                    params.kvm.unix_socket.path = (char *) init_data->entry[i].data;
                    break;
                case VMI_INIT_DATA_VBOX_ACCESS_METHOD:
                    switch ((uintptr_t) init_data->entry[i].data) {
                        case VMI_VBOX_ACCESS_METHOD_MACHINE_DEBUGGER:
                            params.virtualbox.access_method = VBOX_ACCESS_METHOD_MACHINE_DEBUGGER;
                            break;
                        case VMI_VBOX_ACCESS_METHOD_VBOXVMI:
                            params.virtualbox.access_method = VBOX_ACCESS_METHOD_VBOXVMI;
                            break;
                        default:
                            errprint("Unknown VirtualBox access method %"PRIuPTR"\n", (uintptr_t) init_data->entry[i].data);
                            return VMI_FAILURE;
                    }
                    break;
                case VMI_INIT_DATA_VBOX_SOCKET:
                    params.virtualbox.socket_path = (char *) init_data->entry[i].data;
                    break;
                default:
                    break;
            }
        }
    }

    if (!logger_initialized) {
        microvmi_envlogger_init();
        logger_initialized = true;
    }

    const char *init_error = NULL;
    *ctx = microvmi_init(driver_type, &params, &init_error);
    if (!*ctx) {
        errprint("libmicrovmi: %s\n", init_error ? init_error : "initialization failed");
        if (init_error)
            rs_cstring_free((char *) init_error);
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

status_t
libmicrovmi_test(
    const char *name,
    vmi_init_data_t *init_data,
    vmi_mode_t *mode)
{
    void *ctx = NULL;
    if (VMI_FAILURE == microvmi_open(name, NULL, init_data, &ctx))
        return VMI_FAILURE;

    status_t ret = VMI_SUCCESS;
    switch (microvmi_get_driver_type(ctx)) {
        case Xen:
            *mode = VMI_XEN;
            break;
        case KVM:
            *mode = VMI_KVM;
            break;
        case VirtualBox:
            *mode = VMI_VIRTUALBOX;
            break;
        case Memflow:
            *mode = VMI_MEMFLOW;
            break;
        default:
            errprint("libmicrovmi driver has no LibVMI mode\n");
            ret = VMI_FAILURE;
            break;
    }
    microvmi_destroy(ctx);
    return ret;
}

// memory cache callbacks
static void *
microvmi_get_memory(vmi_instance_t vmi, addr_t paddr, uint32_t length)
{
    void *buffer = g_try_malloc0(length);
    if (!buffer)
        return NULL;

    uint64_t bytes_read = 0;
    if (!microvmi_read_physical(microvmi_get_instance(vmi)->ctx, paddr, buffer, length, &bytes_read)
            || bytes_read != length) {
        dbprint(VMI_DEBUG_DRIVER, "--libmicrovmi: failed to read 0x%"PRIx32" bytes at 0x%"PRIx64"\n", length, paddr);
        g_free(buffer);
        return NULL;
    }
    return buffer;
}

static void
microvmi_release_memory(vmi_instance_t UNUSED(vmi), void *memory, size_t UNUSED(length))
{
    g_free(memory);
}

static status_t
microvmi_init_driver(vmi_instance_t vmi, uint32_t UNUSED(init_flags), vmi_init_data_t *UNUSED(init_data))
{
    vmi->driver.driver_data = g_try_malloc0(sizeof(microvmi_instance_t));
    return vmi->driver.driver_data ? VMI_SUCCESS : VMI_FAILURE;
}

static status_t
microvmi_init_vmi(vmi_instance_t vmi, uint32_t UNUSED(init_flags), vmi_init_data_t *init_data)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    DriverType driver_type;

    switch (vmi->mode) {
        case VMI_XEN:
            driver_type = Xen;
            break;
        case VMI_KVM:
            driver_type = KVM;
            break;
        case VMI_VIRTUALBOX:
            driver_type = VirtualBox;
            break;
        case VMI_MEMFLOW:
            driver_type = Memflow;
            break;
        default:
            errprint("LibVMI mode %d has no libmicrovmi driver\n", vmi->mode);
            return VMI_FAILURE;
    }

    if (VMI_FAILURE == microvmi_open(microvmi->name, &driver_type, init_data, &microvmi->ctx))
        return VMI_FAILURE;

    uint16_t vcpu_count = 0;
    if (!microvmi_get_vcpu_count(microvmi->ctx, &vcpu_count) || !vcpu_count) {
        errprint("libmicrovmi: failed to get a nonzero vCPU count\n");
        return VMI_FAILURE;
    }
    vmi->num_vcpus = vcpu_count;

    microvmi->sstep_on = g_try_new0(bool, vcpu_count);
    if (!microvmi->sstep_on)
        return VMI_FAILURE;

    // age 1, like the KVM driver: pages are copies, refresh them on a running guest
    memory_cache_init(vmi, microvmi_get_memory, microvmi_release_memory, 1);
    return VMI_SUCCESS;
}

static void
microvmi_events_destroy(vmi_instance_t vmi);

static void
microvmi_destroy_driver(vmi_instance_t vmi)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    if (!microvmi)
        return;

    if (microvmi->ctx) {
        if (microvmi->sstep_on)
            microvmi_events_destroy(vmi);
        microvmi_destroy(microvmi->ctx);
    }
    g_free(microvmi->sstep_on);
    g_free(microvmi->name);
    g_free(microvmi);
    vmi->driver.driver_data = NULL;
}

// libmicrovmi addresses VMs by name: the domain id is a placeholder
static uint64_t
microvmi_get_id_from_name(vmi_instance_t UNUSED(vmi), const char *UNUSED(name))
{
    return 0;
}

static status_t
microvmi_check_id(vmi_instance_t UNUSED(vmi), uint64_t UNUSED(domainid))
{
    errprint("libmicrovmi cannot open a VM by domain id, use its name (VMI_INIT_DOMAINNAME)\n");
    return VMI_FAILURE;
}

static void
microvmi_set_id(vmi_instance_t UNUSED(vmi), uint64_t UNUSED(domainid))
{
}

static status_t
microvmi_get_name(vmi_instance_t vmi, char **name)
{
    const char *vm_name = microvmi_get_instance(vmi)->name;
    if (!vm_name)
        return VMI_FAILURE;

    *name = strdup(vm_name);
    return *name ? VMI_SUCCESS : VMI_FAILURE;
}

static void
microvmi_set_name(vmi_instance_t vmi, const char *name)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    g_free(microvmi->name);
    microvmi->name = g_strdup(name);
}

static status_t
microvmi_get_memsize(vmi_instance_t vmi, uint64_t *allocated_ram_size, addr_t *max_physical_address)
{
    uint64_t max_addr = 0;
    if (!microvmi_get_max_physical_addr(microvmi_get_instance(vmi)->ctx, &max_addr))
        return VMI_FAILURE;

    // shortcut: libmicrovmi has no RAM size call, report the max physical address for both
    *allocated_ram_size = max_addr;
    *max_physical_address = max_addr;
    return VMI_SUCCESS;
}

static status_t
microvmi_get_vcpuregs(vmi_instance_t vmi, registers_t *regs, unsigned long vcpu)
{
    Registers microvmi_regs;
    if (vcpu > UINT16_MAX || !microvmi_read_registers(microvmi_get_instance(vmi)->ctx, (uint16_t) vcpu, &microvmi_regs))
        return VMI_FAILURE;

    const X86Registers *r = &microvmi_regs.x86;
    x86_registers_t *x86 = &regs->x86;
    memset(regs, 0, sizeof(*regs));
    x86->rax = r->rax;
    x86->rbx = r->rbx;
    x86->rcx = r->rcx;
    x86->rdx = r->rdx;
    x86->rsi = r->rsi;
    x86->rdi = r->rdi;
    x86->rsp = r->rsp;
    x86->rbp = r->rbp;
    x86->r8 = r->r8;
    x86->r9 = r->r9;
    x86->r10 = r->r10;
    x86->r11 = r->r11;
    x86->r12 = r->r12;
    x86->r13 = r->r13;
    x86->r14 = r->r14;
    x86->r15 = r->r15;
    x86->rip = r->rip;
    x86->rflags = r->rflags;
    x86->cr0 = r->cr0;
    x86->cr2 = r->cr2;
    x86->cr3 = r->cr3;
    x86->cr4 = r->cr4;
    x86->sysenter_cs = r->sysenter_cs;
    x86->sysenter_esp = r->sysenter_esp;
    x86->sysenter_eip = r->sysenter_eip;
    x86->msr_efer = r->msr_efer;
    x86->msr_star = r->msr_star;
    x86->msr_lstar = r->msr_lstar;
#define SEGMENT(lv, mv) \
    x86->lv##_base = r->mv.base; \
    x86->lv##_limit = r->mv.limit; \
    x86->lv##_sel = r->mv.selector
    SEGMENT(cs, cs);
    SEGMENT(ds, ds);
    SEGMENT(es, es);
    SEGMENT(fs, fs);
    SEGMENT(gs, gs);
    SEGMENT(ss, ss);
    SEGMENT(tr, tr);
    SEGMENT(ldt, ldt);
#undef SEGMENT
    x86->idtr_base = r->idt.base;
    x86->idtr_limit = r->idt.limit;
    x86->gdtr_base = r->gdt.base;
    x86->gdtr_limit = r->gdt.limit;
    return VMI_SUCCESS;
}

static status_t
microvmi_get_vcpureg(vmi_instance_t vmi, uint64_t *value, reg_t reg, unsigned long vcpu)
{
    registers_t regs;
    if (VMI_FAILURE == microvmi_get_vcpuregs(vmi, &regs, vcpu))
        return VMI_FAILURE;

    const x86_registers_t *x86 = &regs.x86;
    switch (reg) {
        case RAX:
            *value = x86->rax;
            break;
        case RBX:
            *value = x86->rbx;
            break;
        case RCX:
            *value = x86->rcx;
            break;
        case RDX:
            *value = x86->rdx;
            break;
        case RBP:
            *value = x86->rbp;
            break;
        case RSI:
            *value = x86->rsi;
            break;
        case RDI:
            *value = x86->rdi;
            break;
        case RSP:
            *value = x86->rsp;
            break;
        case R8:
            *value = x86->r8;
            break;
        case R9:
            *value = x86->r9;
            break;
        case R10:
            *value = x86->r10;
            break;
        case R11:
            *value = x86->r11;
            break;
        case R12:
            *value = x86->r12;
            break;
        case R13:
            *value = x86->r13;
            break;
        case R14:
            *value = x86->r14;
            break;
        case R15:
            *value = x86->r15;
            break;
        case RIP:
            *value = x86->rip;
            break;
        case RFLAGS:
            *value = x86->rflags;
            break;
        case CR0:
            *value = x86->cr0;
            break;
        case CR2:
            *value = x86->cr2;
            break;
        case CR3:
            *value = x86->cr3;
            break;
        case CR4:
            *value = x86->cr4;
            break;
        case CS_SEL:
            *value = x86->cs_sel;
            break;
        case DS_SEL:
            *value = x86->ds_sel;
            break;
        case ES_SEL:
            *value = x86->es_sel;
            break;
        case FS_SEL:
            *value = x86->fs_sel;
            break;
        case GS_SEL:
            *value = x86->gs_sel;
            break;
        case SS_SEL:
            *value = x86->ss_sel;
            break;
        case TR_SEL:
            *value = x86->tr_sel;
            break;
        case LDTR_SEL:
            *value = x86->ldt_sel;
            break;
        case CS_LIMIT:
            *value = x86->cs_limit;
            break;
        case DS_LIMIT:
            *value = x86->ds_limit;
            break;
        case ES_LIMIT:
            *value = x86->es_limit;
            break;
        case FS_LIMIT:
            *value = x86->fs_limit;
            break;
        case GS_LIMIT:
            *value = x86->gs_limit;
            break;
        case SS_LIMIT:
            *value = x86->ss_limit;
            break;
        case TR_LIMIT:
            *value = x86->tr_limit;
            break;
        case LDTR_LIMIT:
            *value = x86->ldt_limit;
            break;
        case IDTR_LIMIT:
            *value = x86->idtr_limit;
            break;
        case GDTR_LIMIT:
            *value = x86->gdtr_limit;
            break;
        case CS_BASE:
            *value = x86->cs_base;
            break;
        case DS_BASE:
            *value = x86->ds_base;
            break;
        case ES_BASE:
            *value = x86->es_base;
            break;
        case FS_BASE:
            *value = x86->fs_base;
            break;
        case GS_BASE:
            *value = x86->gs_base;
            break;
        case SS_BASE:
            *value = x86->ss_base;
            break;
        case TR_BASE:
            *value = x86->tr_base;
            break;
        case LDTR_BASE:
            *value = x86->ldt_base;
            break;
        case IDTR_BASE:
            *value = x86->idtr_base;
            break;
        case GDTR_BASE:
            *value = x86->gdtr_base;
            break;
        case SYSENTER_CS:
            *value = x86->sysenter_cs;
            break;
        case SYSENTER_ESP:
            *value = x86->sysenter_esp;
            break;
        case SYSENTER_EIP:
            *value = x86->sysenter_eip;
            break;
        case MSR_LSTAR:
            *value = x86->msr_lstar;
            break;
        case MSR_EFER:
            *value = x86->msr_efer;
            break;
        case MSR_STAR:
            *value = x86->msr_star;
            break;
        default:
            dbprint(VMI_DEBUG_DRIVER, "--libmicrovmi: register %"PRIu64" is not available\n", reg);
            return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

static void *
microvmi_read_page(vmi_instance_t vmi, addr_t page)
{
    return memory_cache_insert(vmi, page << vmi->page_shift);
}

static status_t
microvmi_write(vmi_instance_t vmi, addr_t paddr, void *buf, uint32_t length)
{
    if (!microvmi_write_physical(microvmi_get_instance(vmi)->ctx, paddr, buf, length))
        return VMI_FAILURE;

    // the memory cache holds copies: drop every page the write touched
    addr_t page_mask = ~((addr_t) vmi->page_size - 1);
    for (addr_t page = paddr & page_mask; page < paddr + length; page += vmi->page_size)
        memory_cache_remove(vmi, page);
    return VMI_SUCCESS;
}

static int
microvmi_is_pv(vmi_instance_t UNUSED(vmi))
{
    return 0;
}

static status_t
microvmi_pause_vm(vmi_instance_t vmi)
{
    return microvmi_pause(microvmi_get_instance(vmi)->ctx) ? VMI_SUCCESS : VMI_FAILURE;
}

static status_t
microvmi_resume_vm(vmi_instance_t vmi)
{
    return microvmi_resume(microvmi_get_instance(vmi)->ctx) ? VMI_SUCCESS : VMI_FAILURE;
}

/*
 * VMI events, modelled on LibVMI's KVM driver: INT3, single step, CR0/CR3/CR4 and MSR writes.
 * Events-pending stays unimplemented: LibVMI then drains with a zero-timeout listen.
 * Register Intercepts need no driver state: LibVMI's reg_events/msr_events tables hold exactly
 * the events whose Intercepts are set (an event whose clear failed stays there for shutdown).
 */

static status_t
microvmi_set_intr_access(vmi_instance_t vmi, interrupt_event_t *event, bool enabled)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    InterceptType breakpoint = { .tag = InterceptType_Breakpoint };

    if (event->intr != INT3) {
        errprint("libmicrovmi driver does not support enabling events for interrupt: %"PRIu8"\n", event->intr);
        return VMI_FAILURE;
    }

    bool failed = false;
    unsigned int vcpu = 0;
    for (; vcpu < vmi->num_vcpus; vcpu++) {
        if (!microvmi_toggle_intercept(microvmi->ctx, (uint16_t) vcpu, breakpoint, enabled)) {
            errprint("libmicrovmi: failed to %s the breakpoint intercept on vCPU %u\n", enabled ? "set" : "clear", vcpu);
            failed = true;
            if (enabled)
                break;
        }
    }
    if (failed && enabled) {
        // Revert partial registration; retain state for destruction if a clear fails.
        microvmi->intr_on = false;
        for (unsigned int i = 0; i < vcpu; i++)
            if (!microvmi_toggle_intercept(microvmi->ctx, (uint16_t) i, breakpoint, false))
                microvmi->intr_on = true;
    } else {
        microvmi->intr_on = failed || enabled;
    }
    return failed ? VMI_FAILURE : VMI_SUCCESS;
}

static status_t
microvmi_set_single_step(vmi_instance_t vmi, uint32_t vcpu, bool enabled)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    InterceptType singlestep = { .tag = InterceptType_Singlestep };

    if (vcpu >= vmi->num_vcpus || !microvmi_toggle_intercept(microvmi->ctx, (uint16_t) vcpu, singlestep, enabled)) {
        errprint("libmicrovmi: failed to %s single step on vCPU %"PRIu32"\n", enabled ? "start" : "stop", vcpu);
        return VMI_FAILURE;
    }
    microvmi->sstep_on[vcpu] = enabled;
    return VMI_SUCCESS;
}

static status_t
microvmi_stop_single_step(vmi_instance_t vmi, uint32_t vcpu)
{
    return microvmi_set_single_step(vmi, vcpu, false);
}

static status_t
microvmi_start_single_step(vmi_instance_t vmi, single_step_event_t *event)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);

    if (!event->vcpus || (vmi->num_vcpus < 32 && (event->vcpus >> vmi->num_vcpus))) {
        errprint("libmicrovmi: invalid single-step vCPU mask\n");
        return VMI_FAILURE;
    }

    for (uint32_t vcpu = 0; vcpu < vmi->num_vcpus && vcpu < 32; vcpu++) {
        if (!CHECK_VCPU_SINGLESTEP(*event, vcpu))
            continue;
        if (event->enable) {
            if (VMI_FAILURE == microvmi_set_single_step(vmi, vcpu, true)) {
                for (uint32_t i = 0; i < vcpu; i++)
                    if (CHECK_VCPU_SINGLESTEP(*event, i))
                        microvmi_stop_single_step(vmi, i);
                return VMI_FAILURE;
            }
        } else if (!microvmi->sstep_on[vcpu] && VMI_FAILURE == microvmi_set_single_step(vmi, vcpu, false)) {
            // registered disabled, like KVM nothing starts, but an access method without events fails here;
            // vCPUs already stepping for another event are left alone
            return VMI_FAILURE;
        }
    }
    return VMI_SUCCESS;
}

static status_t
microvmi_shutdown_single_step(vmi_instance_t vmi)
{
    status_t status = VMI_SUCCESS;
    for (uint32_t vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
        if (VMI_FAILURE == microvmi_stop_single_step(vmi, vcpu))
            status = VMI_FAILURE;
    return status;
}

// set or clear an Intercept on every vCPU; a failed set clears the vCPUs already set
static status_t
microvmi_toggle_intercept_all(vmi_instance_t vmi, InterceptType intercept, bool enabled)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    status_t status = VMI_SUCCESS;

    for (unsigned int vcpu = 0; vcpu < vmi->num_vcpus; vcpu++) {
        if (microvmi_toggle_intercept(microvmi->ctx, (uint16_t) vcpu, intercept, enabled))
            continue;
        errprint("libmicrovmi: failed to %s the %s intercept on vCPU %u\n", enabled ? "set" : "clear",
                 intercept.tag == InterceptType_Cr ? "CR" : "MSR", vcpu);
        status = VMI_FAILURE;
        if (!enabled)
            continue;
        while (vcpu--)
            microvmi_toggle_intercept(microvmi->ctx, (uint16_t) vcpu, intercept, false);
        break;
    }
    return status;
}

// MSR index also intercepted for the other kind of MSR event (MSR_ANY vs MSR_ALL): leave it alone
static bool
microvmi_msr_shared(vmi_instance_t vmi, uint32_t msr, bool from_msr_all)
{
    if (vmi->shutting_down)
        return false;
    if (from_msr_all)
        return g_hash_table_contains(vmi->msr_events, GSIZE_TO_POINTER(msr));
    if (!g_hash_table_contains(vmi->reg_events, GSIZE_TO_POINTER(MSR_ALL)))
        return false;
    for (unsigned int i = 0; i < msr_all_len; i++)
        if (msr_index[msr_all[i]] == msr)
            return true;
    return false;
}

static status_t
microvmi_set_reg_access(vmi_instance_t vmi, reg_event_t *event)
{
    InterceptType intercept = { .tag = InterceptType_Cr };
    bool enabled;

    switch (event->reg) {
        case CR0:
            intercept.cr = Cr0;
            break;
        case CR3:
            intercept.cr = Cr3;
            break;
        case CR4:
            intercept.cr = Cr4;
            break;
        case MSR_ANY:
            if (!event->msr) {
                errprint("libmicrovmi driver: MSR_ANY needs a nonzero MSR index\n");
                return VMI_FAILURE;
            }
            intercept.tag = InterceptType_Msr;
            intercept.msr = event->msr;
            break;
        case MSR_ALL:
            intercept.tag = InterceptType_Msr;
            break;
        default:
            errprint("libmicrovmi driver does not support events on register %"PRIu64" (MSRs: MSR_ANY with an index, or MSR_ALL)\n",
                     event->reg);
            return VMI_FAILURE;
    }

    switch (event->in_access) {
        case VMI_REGACCESS_N:
            enabled = false;
            break;
        case VMI_REGACCESS_W:
            enabled = true;
            break;
        default:
            errprint("libmicrovmi driver only supports register write events, not access mode %d\n", event->in_access);
            return VMI_FAILURE;
    }

    if (event->reg == MSR_ANY && microvmi_msr_shared(vmi, event->msr, false))
        return VMI_SUCCESS;
    if (event->reg != MSR_ALL)
        return microvmi_toggle_intercept_all(vmi, intercept, enabled);

    // MSR_ALL: LibVMI's MSR list, as the KVM driver
    status_t status = VMI_SUCCESS;
    for (unsigned int i = 0; i < msr_all_len; i++) {
        intercept.msr = msr_index[msr_all[i]];
        if (microvmi_msr_shared(vmi, intercept.msr, true)
                || VMI_SUCCESS == microvmi_toggle_intercept_all(vmi, intercept, enabled))
            continue;
        status = VMI_FAILURE;
        if (!enabled)
            continue;
        while (i--) {
            intercept.msr = msr_index[msr_all[i]];
            if (!microvmi_msr_shared(vmi, intercept.msr, true))
                microvmi_toggle_intercept_all(vmi, intercept, false);
        }
        break;
    }
    return status;
}

// reply and release the event's vCPU; consumes event
static status_t
microvmi_reply(microvmi_instance_t *microvmi, Event *event, bool reinject)
{
    EventReplyType reply = { .tag = EventReplyType_Continue, .continue_ = { .reinject = reinject } };
    uint16_t vcpu = event->vcpu;

    if (!microvmi_reply_event(microvmi->ctx, event, reply)) {
        errprint("libmicrovmi: failed to reply to the event on vCPU %"PRIu16"\n", vcpu);
        return VMI_FAILURE;
    }
    return VMI_SUCCESS;
}

static status_t
microvmi_process_event(vmi_instance_t vmi, Event *event)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    static const reg_t cr_regs[] = { [Cr0] = CR0, [Cr3] = CR3, [Cr4] = CR4 };
    uint16_t vcpu = event->vcpu;
    bool breakpoint = event->kind.tag == EventType_Breakpoint;
    bool reg = event->kind.tag == EventType_Cr || event->kind.tag == EventType_Msr;
    vmi_event_t *libvmi_event = NULL;

    switch (event->kind.tag) {
        case EventType_Breakpoint:
            libvmi_event = g_hash_table_lookup(vmi->interrupt_events, GUINT_TO_POINTER(INT3));
            break;
        case EventType_Singlestep:
            libvmi_event = g_hash_table_lookup(vmi->ss_events, GUINT_TO_POINTER(vcpu));
            break;
        case EventType_Cr:
            libvmi_event = g_hash_table_lookup(vmi->reg_events, GSIZE_TO_POINTER(cr_regs[event->kind.cr.cr_type]));
            break;
        case EventType_Msr:
            libvmi_event = g_hash_table_lookup(vmi->msr_events, GSIZE_TO_POINTER(event->kind.msr.msr_type));
            if (!libvmi_event) {
                libvmi_event = g_hash_table_lookup(vmi->reg_events, GSIZE_TO_POINTER(MSR_ALL));
                if (libvmi_event)
                    libvmi_event->reg_event.msr = event->kind.msr.msr_type;
            }
            break;
        default:
            break;
    }

    if (!libvmi_event) {
        // raised before its LibVMI event was cleared: let the guest run as if it was not intercepted
        dbprint(VMI_DEBUG_DRIVER, "--libmicrovmi: no LibVMI event for event kind %d on vCPU %"PRIu16"\n",
                (int) event->kind.tag, vcpu);
        return microvmi_reply(microvmi, event, breakpoint);
    }

    registers_t regs;
    if (VMI_FAILURE == microvmi_get_vcpuregs(vmi, &regs, vcpu)) {
        errprint("libmicrovmi: failed to read the registers of vCPU %"PRIu16" at an event\n", vcpu);
        // no reinjection: the vCPU re-executes and raises the event again (a CR/MSR write proceeds unseen)
        microvmi_reply(microvmi, event, false);
        return VMI_FAILURE;
    }

    libvmi_event->x86_regs = &regs.x86;
    libvmi_event->vcpu_id = vcpu;
    libvmi_event->slat_id = 0;
    if (breakpoint) {
        libvmi_event->interrupt_event.gfn = event->kind.breakpoint.gpa >> vmi->page_shift;
        libvmi_event->interrupt_event.offset = regs.x86.rip & VMI_BIT_MASK(0, 11);
        libvmi_event->interrupt_event.gla = regs.x86.rip;
        libvmi_event->interrupt_event.insn_length = event->kind.breakpoint.insn_len;
        // default reinject behavior: invalid, only 1 reinjects
        libvmi_event->interrupt_event.reinject = -1;
    } else if (event->kind.tag == EventType_Cr) {
        libvmi_event->reg_event.out_access = VMI_REGACCESS_W;
        libvmi_event->reg_event.value = event->kind.cr.new_;
        libvmi_event->reg_event.previous = event->kind.cr.old;
    } else if (event->kind.tag == EventType_Msr) {
        libvmi_event->reg_event.out_access = VMI_REGACCESS_W;
        libvmi_event->reg_event.value = event->kind.msr.value;
        libvmi_event->reg_event.previous = event->kind.msr.old;
    } else {
        libvmi_event->ss_event.gfn = event->kind.singlestep.gpa >> vmi->page_shift;
        libvmi_event->ss_event.offset = regs.x86.rip & VMI_BIT_MASK(0, 11);
        libvmi_event->ss_event.gla = regs.x86.rip;
    }

    vmi->event_callback = 1;
    event_response_t response = libvmi_event->callback(vmi, libvmi_event);
    vmi->event_callback = 0;

    status_t status = VMI_SUCCESS;
    // a register write cannot be denied: like KVM, DENY is ignored and the write proceeds
    event_response_t handled = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | (reg ? VMI_EVENT_RESPONSE_DENY : 0);
    if (response & ~handled)
        errprint("libmicrovmi driver: unhandled event responses 0x%"PRIx32"\n", (uint32_t) (response & ~handled));
    if (response & VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP) {
        vmi_event_t *step_event = g_hash_table_lookup(vmi->ss_events, GUINT_TO_POINTER(vcpu));
        if (step_event && !g_hash_table_lookup_extended(vmi->clear_events, step_event, NULL, NULL))
            status = microvmi_set_single_step(vmi, vcpu, !microvmi->sstep_on[vcpu]);
        else
            status = VMI_FAILURE;
    }

    bool reinject = breakpoint && libvmi_event->interrupt_event.reinject == 1;
    libvmi_event->x86_regs = NULL;
    // reply even if toggling failed: the vCPU must not stay parked
    if (VMI_FAILURE == microvmi_reply(microvmi, event, reinject))
        status = VMI_FAILURE;
    return status;
}

static status_t
microvmi_events_listen(vmi_instance_t vmi, uint32_t timeout)
{
    Event *event = NULL;

    if (!microvmi_listen(microvmi_get_instance(vmi)->ctx, timeout, &event)) {
        errprint("libmicrovmi: failed to listen for events\n");
        return VMI_FAILURE;
    }
    if (!event)
        return VMI_SUCCESS;

    status_t status = microvmi_process_event(vmi, event);

    // vmi_clear_event() calls from a callback were deferred until the event was replied
    if (vmi->clear_events && g_hash_table_size(vmi->clear_events))
        g_hash_table_foreach_remove(vmi->clear_events, clear_events_full, vmi);
    return status;
}

// clear a register event's Intercepts, the event stays registered in LibVMI
static void
microvmi_clear_reg_event(gpointer UNUSED(key), gpointer value, gpointer data)
{
    reg_event_t reg_event = ((vmi_event_t *) value)->reg_event;
    reg_event.in_access = VMI_REGACCESS_N;
    microvmi_set_reg_access((vmi_instance_t) data, &reg_event);
}

// the guest runs normally after vmi_destroy, even without vmi_clear_event
static void
microvmi_events_destroy(vmi_instance_t vmi)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    interrupt_event_t int3 = { .intr = INT3 };

    // all log their failures
    if (microvmi->intr_on)
        microvmi_set_intr_access(vmi, &int3, false);
    for (uint32_t vcpu = 0; vcpu < vmi->num_vcpus; vcpu++)
        if (microvmi->sstep_on[vcpu])
            microvmi_stop_single_step(vmi, vcpu);
    if (vmi->reg_events)
        g_hash_table_foreach(vmi->reg_events, microvmi_clear_reg_event, vmi);
    if (vmi->msr_events)
        g_hash_table_foreach(vmi->msr_events, microvmi_clear_reg_event, vmi);
}

status_t
driver_libmicrovmi_setup(vmi_instance_t vmi)
{
    driver_interface_t driver = { 0 };
    driver.initialized = true;
    driver.init_ptr = &microvmi_init_driver;
    driver.init_vmi_ptr = &microvmi_init_vmi;
    driver.destroy_ptr = &microvmi_destroy_driver;
    driver.get_id_from_name_ptr = &microvmi_get_id_from_name;
    driver.check_id_ptr = &microvmi_check_id;
    driver.set_id_ptr = &microvmi_set_id;
    driver.get_name_ptr = &microvmi_get_name;
    driver.set_name_ptr = &microvmi_set_name;
    driver.get_memsize_ptr = &microvmi_get_memsize;
    driver.get_vcpureg_ptr = &microvmi_get_vcpureg;
    driver.get_vcpuregs_ptr = &microvmi_get_vcpuregs;
    driver.read_page_ptr = &microvmi_read_page;
    driver.write_ptr = &microvmi_write;
    driver.is_pv_ptr = &microvmi_is_pv;
    driver.pause_vm_ptr = &microvmi_pause_vm;
    driver.resume_vm_ptr = &microvmi_resume_vm;
    driver.events_listen_ptr = &microvmi_events_listen;
    driver.set_intr_access_ptr = &microvmi_set_intr_access;
    driver.set_reg_access_ptr = &microvmi_set_reg_access;
    driver.start_single_step_ptr = &microvmi_start_single_step;
    driver.stop_single_step_ptr = &microvmi_stop_single_step;
    driver.shutdown_single_step_ptr = &microvmi_shutdown_single_step;
    vmi->driver = driver;
    return VMI_SUCCESS;
}
