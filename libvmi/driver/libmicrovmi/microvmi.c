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
#include <sys/mman.h>

#include <libmicrovmi.h>

#include "private.h"
#include "arch/intel.h"
#include "driver/driver_interface.h"
#include "driver/memory_cache.h"
#include "driver/libmicrovmi/microvmi.h"
#include "msr-index.h"

// memflow connector without VMI_INIT_DATA_MEMFLOW_CONNECTOR
#define DEFAULT_MEMFLOW_CONNECTOR "qemu_procfs"

typedef struct microvmi_instance {
    void *ctx;
    char *name;
    bool intr_on;    // Breakpoint intercept set on every vCPU
    bool *sstep_on;  // per vCPU: Singlestep intercept set, toggled by VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP
    bool pf_on;      // Pagefault (page-access) intercept set on every vCPU, while pages are restricted
    bool cpuid_on;   // CPUID intercept set on every vCPU
    bool debug_on;   // Debug exception intercept set on every vCPU
    bool views_on;   // Memory views enabled (LibVMI's alternate SLAT)
    GHashTable *restricted;  // (view, GFN) pages whose access this client restricted, restored at shutdown
    GHashTable *converting;  // (view, GFN) restricted pages set W2X or RWX2N: their access changes at the first fault
    unsigned int pauses;     // vmi_pause_vm calls not yet resumed: VBoxVMI's pause is not counted
    registers_t *cached_regs;  // per-vCPU cached registers for parked vCPUs
    bool *regs_cached;         // per-vCPU: registers are cached
} microvmi_instance_t;

// restricted table key: the Memory view above bit 48, the GFN below
#define RESTRICTED_KEY(view, gfn) GSIZE_TO_POINTER(((gsize) (view) << 48) | (gfn))
#define RESTRICTED_VIEW(key) ((uint16_t) (GPOINTER_TO_SIZE(key) >> 48))
#define RESTRICTED_GFN(key) (GPOINTER_TO_SIZE(key) & VMI_BIT_MASK(0, 47))

static inline microvmi_instance_t *
microvmi_get_instance(vmi_instance_t vmi)
{
    return (microvmi_instance_t *) vmi->driver.driver_data;
}

static inline void
microvmi_invalidate_vcpu_regs_cache(microvmi_instance_t *microvmi, unsigned long vcpu)
{
    if (microvmi->regs_cached && vcpu < 256)
        microvmi->regs_cached[vcpu] = false;
}

static inline void
microvmi_invalidate_all_regs_cache(microvmi_instance_t *microvmi, unsigned long num_vcpus)
{
    if (microvmi->regs_cached) {
        for (unsigned long i = 0; i < num_vcpus; i++)
            microvmi->regs_cached[i] = false;
    }
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
                case VMI_INIT_DATA_MEMFLOW_CONNECTOR:
                    params.memflow.connector_name = (char *) init_data->entry[i].data;
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

// Unlike Xen's shared mapping, these pages are a snapshot; writes do not reach the guest.
static void *
microvmi_mmap_guest(vmi_instance_t vmi, unsigned long *pfns, unsigned int count, int prot)
{
    const size_t page_size = vmi->page_size;
    if (!count || !page_size || page_size > 65536 || count > SIZE_MAX / page_size)
        return NULL;

    size_t length = (size_t) count * page_size;
    uint8_t *mapping = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return NULL;

    for (unsigned int i = 0; i < count;) {
        if ((uint64_t) pfns[i] > (UINT64_MAX >> vmi->page_shift))
            goto failed;
        unsigned int pages = 1;
        while (pages < count - i && pages < 65536 / page_size
                && pfns[i + pages] > pfns[i] && pfns[i + pages] - pfns[i] == pages)
            pages++;

        size_t bytes = pages * page_size;
        uint64_t bytes_read = 0;
        if (!microvmi_read_physical(microvmi_get_instance(vmi)->ctx,
                                    (uint64_t) pfns[i] << vmi->page_shift,
                                    mapping + (size_t) i * page_size, bytes, &bytes_read)
                || bytes_read != bytes)
            goto failed;
        i += pages;
    }

    if (mprotect(mapping, length, prot) != 0)
        goto failed;
    return mapping;

failed:
    munmap(mapping, length);
    return NULL;
}

static status_t
microvmi_init_driver(vmi_instance_t vmi, uint32_t init_flags, vmi_init_data_t *UNUSED(init_data))
{
    if (init_flags & VMI_INIT_DOMAINWATCH) {
        errprint("libmicrovmi cannot watch for VMs (VMI_INIT_DOMAINWATCH)\n");
        return VMI_FAILURE;
    }
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
    microvmi->cached_regs = g_try_new0(registers_t, vcpu_count);
    microvmi->regs_cached = g_try_new0(bool, vcpu_count);
    if (!microvmi->sstep_on || !microvmi->cached_regs || !microvmi->regs_cached)
        return VMI_FAILURE;
    microvmi->restricted = g_hash_table_new(g_direct_hash, g_direct_equal);
    microvmi->converting = g_hash_table_new(g_direct_hash, g_direct_equal);

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
    g_free(microvmi->cached_regs);
    g_free(microvmi->regs_cached);
    if (microvmi->restricted)
        g_hash_table_destroy(microvmi->restricted);
    if (microvmi->converting)
        g_hash_table_destroy(microvmi->converting);
    g_free(microvmi->name);
    g_free(microvmi);
    vmi->driver.driver_data = NULL;
}

// libmicrovmi addresses VMs by name, which has no numeric id: a hash of it, stable across runs,
// never 0 nor VMI_INVALID_DOMID
static uint64_t
microvmi_get_id_from_name(vmi_instance_t UNUSED(vmi), const char *name)
{
    return name ? (uint64_t) g_str_hash(name) + 1 : VMI_INVALID_DOMID;
}

static uint64_t
microvmi_get_id(vmi_instance_t vmi)
{
    return microvmi_get_id_from_name(vmi, microvmi_get_instance(vmi)->name);
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
    void *ctx = microvmi_get_instance(vmi)->ctx;
    if (!microvmi_get_max_physical_addr(ctx, max_physical_address))
        return VMI_FAILURE;
    // shortcut: drivers without a RAM size (all but VBoxVMI) report the max physical address
    if (!microvmi_get_ram_size(ctx, allocated_ram_size))
        *allocated_ram_size = *max_physical_address;
    return VMI_SUCCESS;
}

static status_t
microvmi_request_pf(vmi_instance_t vmi, unsigned long vcpu, uint64_t virtual_address, uint32_t error_code)
{
    if (vcpu > UINT16_MAX || vcpu >= vmi->num_vcpus)
        return VMI_FAILURE;

    return microvmi_request_page_fault(microvmi_get_instance(vmi)->ctx, (uint16_t) vcpu,
                                      virtual_address, error_code) ? VMI_SUCCESS : VMI_FAILURE;
}

static void
microvmi_to_x86(const X86Registers *r, x86_registers_t *x86)
{
    memset(x86, 0, sizeof(*x86));
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
    x86->msr_cstar = r->msr_cstar;
    x86->shadow_gs = r->shadow_gs_base;
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
}

static status_t
microvmi_get_vcpuregs(vmi_instance_t vmi, registers_t *regs, unsigned long vcpu)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
   
    if (vcpu < vmi->num_vcpus && microvmi->regs_cached[vcpu]) {
        *regs = microvmi->cached_regs[vcpu];
        return VMI_SUCCESS;
    }

    Registers microvmi_regs;
    if (vcpu > UINT16_MAX || !microvmi_read_registers(microvmi->ctx, (uint16_t) vcpu, &microvmi_regs))
        return VMI_FAILURE;

    memset(regs, 0, sizeof(*regs));
    microvmi_to_x86(&microvmi_regs.x86, &regs->x86);
    return VMI_SUCCESS;
}

/* The x86_registers_t fields microvmi_to_x86 fills, NULL for the others */
static uint64_t *
x86_reg_field(x86_registers_t *x86, reg_t reg)
{
    switch (reg) {
        case RAX:
            return &x86->rax;
        case RBX:
            return &x86->rbx;
        case RCX:
            return &x86->rcx;
        case RDX:
            return &x86->rdx;
        case RBP:
            return &x86->rbp;
        case RSI:
            return &x86->rsi;
        case RDI:
            return &x86->rdi;
        case RSP:
            return &x86->rsp;
        case R8:
            return &x86->r8;
        case R9:
            return &x86->r9;
        case R10:
            return &x86->r10;
        case R11:
            return &x86->r11;
        case R12:
            return &x86->r12;
        case R13:
            return &x86->r13;
        case R14:
            return &x86->r14;
        case R15:
            return &x86->r15;
        case RIP:
            return &x86->rip;
        case RFLAGS:
            return &x86->rflags;
        case CR0:
            return &x86->cr0;
        case CR2:
            return &x86->cr2;
        case CR3:
            return &x86->cr3;
        case CR4:
            return &x86->cr4;
        case CS_SEL:
            return &x86->cs_sel;
        case DS_SEL:
            return &x86->ds_sel;
        case ES_SEL:
            return &x86->es_sel;
        case FS_SEL:
            return &x86->fs_sel;
        case GS_SEL:
            return &x86->gs_sel;
        case SS_SEL:
            return &x86->ss_sel;
        case TR_SEL:
            return &x86->tr_sel;
        case LDTR_SEL:
            return &x86->ldt_sel;
        case CS_LIMIT:
            return &x86->cs_limit;
        case DS_LIMIT:
            return &x86->ds_limit;
        case ES_LIMIT:
            return &x86->es_limit;
        case FS_LIMIT:
            return &x86->fs_limit;
        case GS_LIMIT:
            return &x86->gs_limit;
        case SS_LIMIT:
            return &x86->ss_limit;
        case TR_LIMIT:
            return &x86->tr_limit;
        case LDTR_LIMIT:
            return &x86->ldt_limit;
        case IDTR_LIMIT:
            return &x86->idtr_limit;
        case GDTR_LIMIT:
            return &x86->gdtr_limit;
        case CS_BASE:
            return &x86->cs_base;
        case DS_BASE:
            return &x86->ds_base;
        case ES_BASE:
            return &x86->es_base;
        case FS_BASE:
            return &x86->fs_base;
        case GS_BASE:
            return &x86->gs_base;
        case SS_BASE:
            return &x86->ss_base;
        case TR_BASE:
            return &x86->tr_base;
        case LDTR_BASE:
            return &x86->ldt_base;
        case IDTR_BASE:
            return &x86->idtr_base;
        case GDTR_BASE:
            return &x86->gdtr_base;
        case SYSENTER_CS:
            return &x86->sysenter_cs;
        case SYSENTER_ESP:
            return &x86->sysenter_esp;
        case SYSENTER_EIP:
            return &x86->sysenter_eip;
        case MSR_LSTAR:
            return &x86->msr_lstar;
        case MSR_EFER:
            return &x86->msr_efer;
        case MSR_STAR:
            return &x86->msr_star;
        case MSR_CSTAR:
            return &x86->msr_cstar;
        case MSR_SHADOW_GS_BASE:
            return &x86->shadow_gs;
        default:
            dbprint(VMI_DEBUG_DRIVER, "--libmicrovmi: register %"PRIu64" is not available\n", reg);
            return NULL;
    }
}

static status_t
microvmi_get_vcpureg(vmi_instance_t vmi, uint64_t *value, reg_t reg, unsigned long vcpu)
{
    registers_t regs;
    if (VMI_FAILURE == microvmi_get_vcpuregs(vmi, &regs, vcpu))
        return VMI_FAILURE;

    const uint64_t *field = x86_reg_field(&regs.x86, reg);
    if (!field)
        return VMI_FAILURE;
    *value = *field;
    return VMI_SUCCESS;
}

/* What Xen and KVM apply from an event's SET_REGISTERS reply */
static void
gprs_to_microvmi(const x86_registers_t *x86, X86Registers *r)
{
    r->rax = x86->rax;
    r->rbx = x86->rbx;
    r->rcx = x86->rcx;
    r->rdx = x86->rdx;
    r->rsi = x86->rsi;
    r->rdi = x86->rdi;
    r->rsp = x86->rsp;
    r->rbp = x86->rbp;
    r->r8 = x86->r8;
    r->r9 = x86->r9;
    r->r10 = x86->r10;
    r->r11 = x86->r11;
    r->r12 = x86->r12;
    r->r13 = x86->r13;
    r->r14 = x86->r14;
    r->r15 = x86->r15;
    r->rip = x86->rip;
    r->rflags = x86->rflags;
}

/*
 * Writes the fields microvmi_to_x86 fills over current, the vCPU's registers read just before, and
 * writes the result: segment attributes and the APIC base keep their value. Fails on a selector
 * or limit wider than libmicrovmi's.
 */
static status_t
microvmi_write_x86(vmi_instance_t vmi, Registers *current, const x86_registers_t *x86, uint16_t vcpu)
{
    X86Registers *r = &current->x86;
    gprs_to_microvmi(x86, r);
    r->cr0 = x86->cr0;
    r->cr2 = x86->cr2;
    r->cr3 = x86->cr3;
    r->cr4 = x86->cr4;
    r->sysenter_cs = x86->sysenter_cs;
    r->sysenter_esp = x86->sysenter_esp;
    r->sysenter_eip = x86->sysenter_eip;
    // libmicrovmi has EFER twice and refuses a write where they differ
    r->msr_efer = x86->msr_efer;
    r->efer = x86->msr_efer;
    r->msr_star = x86->msr_star;
    r->msr_lstar = x86->msr_lstar;
    r->msr_cstar = x86->msr_cstar;
    r->shadow_gs_base = x86->shadow_gs;
#define SEGMENT(lv, mv) \
    if (x86->lv##_limit > UINT32_MAX || x86->lv##_sel > UINT16_MAX) \
        return VMI_FAILURE; \
    r->mv.base = x86->lv##_base; \
    r->mv.limit = (uint32_t) x86->lv##_limit; \
    r->mv.selector = (uint16_t) x86->lv##_sel
    SEGMENT(cs, cs);
    SEGMENT(ds, ds);
    SEGMENT(es, es);
    SEGMENT(fs, fs);
    SEGMENT(gs, gs);
    SEGMENT(ss, ss);
    SEGMENT(tr, tr);
    SEGMENT(ldt, ldt);
#undef SEGMENT
    if (x86->idtr_limit > UINT16_MAX || x86->gdtr_limit > UINT16_MAX)
        return VMI_FAILURE;
    r->idt.base = x86->idtr_base;
    r->idt.limit = (uint16_t) x86->idtr_limit;
    r->gdt.base = x86->gdtr_base;
    r->gdt.limit = (uint16_t) x86->gdtr_limit;
    return microvmi_write_registers(microvmi_get_instance(vmi)->ctx, vcpu, current) ? VMI_SUCCESS : VMI_FAILURE;
}

static status_t
microvmi_set_vcpuregs(vmi_instance_t vmi, registers_t *regs, unsigned long vcpu)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    Registers current;
    if (vcpu > UINT16_MAX || !microvmi_read_registers(microvmi->ctx, (uint16_t) vcpu, &current))
        return VMI_FAILURE;
    status_t status = microvmi_write_x86(vmi, &current, &regs->x86, (uint16_t) vcpu);
    if (status == VMI_SUCCESS)
        microvmi_invalidate_vcpu_regs_cache(microvmi, vcpu);
    return status;
}

static status_t
microvmi_set_vcpureg(vmi_instance_t vmi, uint64_t value, reg_t reg, unsigned long vcpu)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    Registers current;
    if (vcpu > UINT16_MAX || !microvmi_read_registers(microvmi->ctx, (uint16_t) vcpu, &current))
        return VMI_FAILURE;

    x86_registers_t x86;
    microvmi_to_x86(&current.x86, &x86);
    uint64_t *field = x86_reg_field(&x86, reg);
    if (!field)
        return VMI_FAILURE;
    *field = value;
    status_t status = microvmi_write_x86(vmi, &current, &x86, (uint16_t) vcpu);
    if (status == VMI_SUCCESS)
        microvmi_invalidate_vcpu_regs_cache(microvmi, vcpu);
    return status;
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

// counted like Xen's pause: a VBoxVMI resume undoes any number of pauses
static status_t
microvmi_pause_vm(vmi_instance_t vmi)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    if (!microvmi->pauses && !microvmi_pause(microvmi->ctx))
        return VMI_FAILURE;
    microvmi->pauses++;
    return VMI_SUCCESS;
}

static status_t
microvmi_resume_vm(vmi_instance_t vmi)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    if (!microvmi->pauses) {
        dbprint(VMI_DEBUG_DRIVER, "--libmicrovmi: resume without a pause\n");
        return VMI_FAILURE;
    }
    if (microvmi->pauses == 1) {
        if (!microvmi_resume(microvmi->ctx))
            return VMI_FAILURE;
        microvmi_invalidate_all_regs_cache(microvmi, vmi->num_vcpus);
    }
    microvmi->pauses--;
    return VMI_SUCCESS;
}

/*
 * VMI events, modelled on LibVMI's KVM driver: INT3, single step, CPUID,
 * CR0/CR3/CR4 and MSR writes, page access (memory events).
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
                 intercept.tag == InterceptType_Cr ? "CR" : intercept.tag == InterceptType_Msr ? "MSR"
                 : intercept.tag == InterceptType_Cpuid ? "CPUID" : "page-access", vcpu);
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

static status_t
microvmi_set_cpuid_event(vmi_instance_t vmi, bool enabled)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    InterceptType cpuid = { .tag = InterceptType_Cpuid };
    status_t status = microvmi_toggle_intercept_all(vmi, cpuid, enabled);
    if (VMI_SUCCESS == status)
        microvmi->cpuid_on = enabled;
    else if (!enabled)
        microvmi->cpuid_on = true;
    return status;
}

static status_t
microvmi_set_debug_event(vmi_instance_t vmi, bool enabled)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    InterceptType debug = { .tag = InterceptType_Debug };
    status_t status = microvmi_toggle_intercept_all(vmi, debug, enabled);
    if (VMI_SUCCESS == status)
        microvmi->debug_on = enabled;
    else if (!enabled)
        microvmi->debug_on = true;
    return status;
}

// clear the page-access Intercept once no page is restricted in any view
static void
microvmi_pf_update(vmi_instance_t vmi)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    InterceptType pagefault = { .tag = InterceptType_Pagefault };

    if (microvmi->pf_on && !g_hash_table_size(microvmi->restricted)
            && VMI_SUCCESS == microvmi_toggle_intercept_all(vmi, pagefault, false))
        microvmi->pf_on = false;
}

// set a page's allowed access in a view; the page-access Intercept is set on every vCPU while pages are restricted
static status_t
microvmi_set_page(vmi_instance_t vmi, uint16_t view, addr_t gfn, Access allowed)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    InterceptType pagefault = { .tag = InterceptType_Pagefault };
    bool restricted = allowed != (Access_R | Access_W | Access_X);
    status_t status = VMI_SUCCESS;

    if (restricted && !microvmi->pf_on) {
        if (VMI_FAILURE == microvmi_toggle_intercept_all(vmi, pagefault, true))
            return VMI_FAILURE;
        microvmi->pf_on = true;
    }

    if (!microvmi_set_page_access(microvmi->ctx, view, gfn << vmi->page_shift, allowed)) {
        errprint("libmicrovmi: failed to set the access of GFN 0x%"PRIx64" in view %"PRIu16"\n", gfn, view);
        status = VMI_FAILURE;
    } else if (restricted) {
        g_hash_table_insert(microvmi->restricted, RESTRICTED_KEY(view, gfn), GUINT_TO_POINTER((unsigned int) allowed + 1));
        g_hash_table_remove(microvmi->converting, RESTRICTED_KEY(view, gfn));
    } else {
        g_hash_table_remove(microvmi->restricted, RESTRICTED_KEY(view, gfn));
        g_hash_table_remove(microvmi->converting, RESTRICTED_KEY(view, gfn));
    }

    microvmi_pf_update(vmi);
    return status;
}

// LibVMI's denied access onto libmicrovmi's allowed access, as the KVM driver; slat_id is the Memory view.
// W2X and RWX2N are Xen's rx2rw and n2rwx: the driver changes the access at the first fault
static status_t
microvmi_set_mem_access(vmi_instance_t vmi, addr_t gpfn, vmi_mem_access_t page_access_flag, uint16_t slat_id)
{
    Access allowed;

    if (gpfn > VMI_BIT_MASK(0, 47)) {
        errprint("libmicrovmi driver: GFN 0x%"PRIx64" out of range\n", gpfn);
        return VMI_FAILURE;
    }
    if (VMI_FAILURE == intel_mem_access_sanity_check(page_access_flag))
        return VMI_FAILURE;

    switch (page_access_flag) {
        case VMI_MEMACCESS_N:
            allowed = Access_R | Access_W | Access_X;
            break;
        case VMI_MEMACCESS_W:
        case VMI_MEMACCESS_W2X:
            allowed = Access_R | Access_X;
            break;
        case VMI_MEMACCESS_X:
            allowed = Access_R | Access_W;
            break;
        case VMI_MEMACCESS_RW:
            allowed = Access_X;
            break;
        case VMI_MEMACCESS_WX:
            allowed = Access_R;
            break;
        case VMI_MEMACCESS_RWX:
        case VMI_MEMACCESS_RWX2N:
            allowed = Access_NIL;
            break;
        default:
            errprint("libmicrovmi driver: invalid memaccess setting requested: %d\n", page_access_flag);
            return VMI_FAILURE;
    }
    if (VMI_FAILURE == microvmi_set_page(vmi, slat_id, gpfn, allowed))
        return VMI_FAILURE;
    if (page_access_flag == VMI_MEMACCESS_W2X || page_access_flag == VMI_MEMACCESS_RWX2N)
        g_hash_table_insert(microvmi_get_instance(vmi)->converting, RESTRICTED_KEY(slat_id, gpfn),
                            GUINT_TO_POINTER(page_access_flag));
    return VMI_SUCCESS;
}

// libmicrovmi has no range call: page by page, gpfn_end excluded as on Xen and KVM
static status_t
microvmi_set_mem_access_range(vmi_instance_t vmi, addr_t gpfn_start, addr_t gpfn_end,
                              vmi_mem_access_t page_access_flag, uint16_t slat_id)
{
    for (addr_t gfn = gpfn_start; gfn < gpfn_end; gfn++)
        if (VMI_FAILURE == microvmi_set_mem_access(vmi, gfn, page_access_flag, slat_id))
            return VMI_FAILURE;
    return VMI_SUCCESS;
}

// the page's memory event (an RWX2N one for any access), else every generic one for the access,
// as on Xen and KVM; returns how many it stored in events
static unsigned int
microvmi_mem_events(vmi_instance_t vmi, addr_t gfn, vmi_mem_access_t out_access, vmi_event_t **events, unsigned int max)
{
    vmi_event_t *event = g_hash_table_lookup(vmi->mem_events_on_gfn, GSIZE_TO_POINTER(gfn));
    if (event && (event->mem_event.in_access & (out_access | VMI_MEMACCESS_RWX2N))) {
        events[0] = event;
        return 1;
    }

    unsigned int count = 0;
    GHashTableIter i;
    vmi_mem_access_t *key = NULL;
    ghashtable_foreach(vmi->mem_events_generic, i, &key, &event)
        if ((GPOINTER_TO_UINT(key) & out_access) && count < max)
            events[count++] = event;
    return count;
}

// reply in a view (KEEP_MEMORY_VIEW: the Active view) and release the event's vCPU. A refused reply
// leaves the vCPU parked and the event ours: retry the instruction plainly, in the requested view,
// then in the Active view, so that the vCPU never stays parked
static status_t
microvmi_reply_with(microvmi_instance_t *microvmi, Event *event, EventReplyType reply, uint16_t view)
{
    uint16_t vcpu = event->vcpu, active = event->view;
    if (microvmi->regs_cached && vcpu < 256)
        microvmi->regs_cached[vcpu] = false;

    switch (reply.tag) {
        case EventReplyType_Continue:
            reply.continue_.view = view;
            break;
        case EventReplyType_FastSingleStep:
            reply.fast_single_step.immediate_view = view;
            break;
        case EventReplyType_Emulate:
            reply.emulate.view = view;
            break;
        case EventReplyType_EmulateNoWrite:
            reply.emulate_no_write.view = view;
            break;
        case EventReplyType_EmulateReadData:
            reply.emulate_read_data.view = view;
            break;
        case EventReplyType_EmulateInsn:
            reply.emulate_insn.view = view;
            break;
    }
    if (microvmi_reply_event(microvmi->ctx, event, reply))
        return VMI_SUCCESS;
    errprint("libmicrovmi: failed to reply to the event on vCPU %"PRIu16" (view %"PRIu16")\n", vcpu, view);

    EventReplyType retry = { .tag = EventReplyType_Continue, .continue_ = { .reinject = false, .view = view } };
    if (reply.tag != EventReplyType_Continue && microvmi_reply_event(microvmi->ctx, event, retry))
        return VMI_FAILURE;
    retry.continue_.view = KEEP_MEMORY_VIEW;
    if (view != KEEP_MEMORY_VIEW && microvmi_reply_event(microvmi->ctx, event, retry)) {
        errprint("libmicrovmi: vCPU %"PRIu16" stays in its Active view %"PRIu16"\n", vcpu, active);
        return VMI_FAILURE;
    }
    if (reply.tag != EventReplyType_Continue || view != KEEP_MEMORY_VIEW)
        errprint("libmicrovmi: failed to retry the instruction on vCPU %"PRIu16"\n", vcpu);
    // only on a lost connection: the vCPU stays parked, the Event is ours to free
    microvmi_free_event(event);
    return VMI_FAILURE;
}

static status_t
microvmi_reply(microvmi_instance_t *microvmi, Event *event, bool reinject)
{
    EventReplyType reply = { .tag = EventReplyType_Continue, .continue_ = { .reinject = reinject } };
    return microvmi_reply_with(microvmi, event, reply, KEEP_MEMORY_VIEW);
}

static status_t
microvmi_process_event(vmi_instance_t vmi, Event *event)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    static const reg_t cr_regs[] = { [Cr0] = CR0, [Cr3] = CR3, [Cr4] = CR4 };
    uint16_t vcpu = event->vcpu;
    bool breakpoint = event->kind.tag == EventType_Breakpoint;
    bool reg = event->kind.tag == EventType_Cr || event->kind.tag == EventType_Msr;
    bool debug = event->kind.tag == EventType_Debug;
    bool pagefault = event->kind.tag == EventType_Pagefault;
    vmi_mem_access_t out_access = VMI_MEMACCESS_INVALID;
    addr_t gfn = 0;
    vmi_event_t *libvmi_event = NULL;
    vmi_event_t *events[8];  // a page's memory event, or the generic ones: one per access mask
    unsigned int count = 0;

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
        case EventType_Cpuid:
            libvmi_event = vmi->cpuid_event;
            break;
        case EventType_Debug:
            libvmi_event = vmi->debug_event;
            break;
        case EventType_Pagefault: {
            if (event->kind.pagefault.access & Access_R)
                out_access |= VMI_MEMACCESS_R;
            if (event->kind.pagefault.access & Access_W)
                out_access |= VMI_MEMACCESS_W;
            if (event->kind.pagefault.access & Access_X)
                out_access |= VMI_MEMACCESS_X;
            gfn = event->kind.pagefault.gpa >> vmi->page_shift;
            // like Xen, a W2X page becomes RW at a write, unreported; an RWX2N one RWX at any access, reported
            vmi_mem_access_t converting = GPOINTER_TO_UINT(g_hash_table_lookup(microvmi->converting,
                                          RESTRICTED_KEY(event->view, gfn)));
            if (converting)
                microvmi_set_page(vmi, event->view, gfn, converting == VMI_MEMACCESS_W2X
                                  ? Access_R | Access_W : Access_R | Access_W | Access_X);
            if (converting != VMI_MEMACCESS_W2X)
                count = microvmi_mem_events(vmi, gfn, out_access, events, G_N_ELEMENTS(events));
            break;
        }
        default:
            break;
    }
    if (libvmi_event)
        events[count++] = libvmi_event;

    if (!count) {
        // raised before its LibVMI event was cleared: let the guest run as if it was not intercepted
        dbprint(VMI_DEBUG_DRIVER, "--libmicrovmi: no LibVMI event for event kind %d on vCPU %"PRIu16"\n",
                (int) event->kind.tag, vcpu);
        if (pagefault) {
            // the restricted table holds every restriction: no entry is RWX
            gpointer allowed = g_hash_table_lookup(microvmi->restricted, RESTRICTED_KEY(event->view, gfn));
            if (!allowed || ((GPOINTER_TO_UINT(allowed) - 1) & event->kind.pagefault.access))
                return microvmi_reply(microvmi, event, false);
            // A different event may still restrict the page: let this unmatched access through.
            EventReplyType emulate = { .tag = EventReplyType_Emulate };
            return microvmi_reply_with(microvmi, event, emulate, KEEP_MEMORY_VIEW);
        }
        return microvmi_reply(microvmi, event, breakpoint);
    }

    // onchange: only a write that changes the register, as on Xen
    if (reg && libvmi_event->reg_event.onchange
            && (event->kind.tag == EventType_Cr ? event->kind.cr.new_ == event->kind.cr.old
                : event->kind.msr.value == event->kind.msr.old))
        return microvmi_reply(microvmi, event, false);

    // Use registers from the event if available (VBoxVMI protocol v10+)
    Registers microvmi_regs;
    if (microvmi_event_get_registers(event, &microvmi_regs)) {
        memset(&microvmi->cached_regs[vcpu], 0, sizeof(microvmi->cached_regs[vcpu]));
        microvmi_to_x86(&microvmi_regs.x86, &microvmi->cached_regs[vcpu].x86);
        microvmi->regs_cached[vcpu] = true;
    } else {
        microvmi->regs_cached[vcpu] = false;
        if (VMI_FAILURE == microvmi_get_vcpuregs(vmi, &microvmi->cached_regs[vcpu], vcpu)) {
            errprint("libmicrovmi: failed to read the registers of vCPU %"PRIu16" at an event\n", vcpu);
            microvmi_reply(microvmi, event, false);
            return VMI_FAILURE;
        }
        microvmi->regs_cached[vcpu] = true;
    }

    event_response_t response = 0, own = 0;  // all callbacks' responses, the libvmi_event's own
    libvmi_event = NULL;
    vmi->event_callback = 1;
    for (unsigned int i = 0; i < count; i++) {
        vmi_event_t *e = events[i];
        e->x86_regs = &microvmi->cached_regs[vcpu].x86;
        e->vcpu_id = vcpu;
        e->slat_id = event->view;
        if (breakpoint) {
            e->interrupt_event.gfn = event->kind.breakpoint.gpa >> vmi->page_shift;
            e->interrupt_event.offset = microvmi->cached_regs[vcpu].x86.rip & VMI_BIT_MASK(0, 11);
            e->interrupt_event.gla = microvmi->cached_regs[vcpu].x86.rip;
            e->interrupt_event.insn_length = event->kind.breakpoint.insn_len;
            // default reinject behavior: invalid, only 1 reinjects
            e->interrupt_event.reinject = -1;
        } else if (event->kind.tag == EventType_Cr) {
            // only write Intercepts exist
            e->reg_event.out_access = VMI_REGACCESS_W;
            e->reg_event.value = event->kind.cr.new_;
            e->reg_event.previous = event->kind.cr.old;
        } else if (event->kind.tag == EventType_Msr) {
            e->reg_event.out_access = VMI_REGACCESS_W;
            e->reg_event.value = event->kind.msr.value;
            e->reg_event.previous = event->kind.msr.old;
        } else if (event->kind.tag == EventType_Cpuid) {
            e->cpuid_event.leaf = event->kind.cpuid.leaf;
            e->cpuid_event.subleaf = event->kind.cpuid.subleaf;
            e->cpuid_event.insn_length = event->kind.cpuid.insn_len;
        } else if (event->kind.tag == EventType_Debug) {
            e->debug_event.gfn = microvmi->cached_regs[vcpu].x86.rip >> vmi->page_shift;
            e->debug_event.offset = microvmi->cached_regs[vcpu].x86.rip & VMI_BIT_MASK(0, 11);
            e->debug_event.gla = microvmi->cached_regs[vcpu].x86.rip;
            e->debug_event.insn_length = 0;  // Unknown at the event
            e->debug_event.type = 3;  // HVMOP_TRAP_hw_exc for #DB
            e->debug_event.reinject = 1;  // Reinject by default
        } else if (pagefault) {
            e->mem_event.gfn = gfn;
            e->mem_event.offset = event->kind.pagefault.gpa & VMI_BIT_MASK(0, 11);
            e->mem_event.gla = event->kind.pagefault.gva;
            // VBoxVMI reports a zero gva without a linear address; gptw is not reported, stays 0
            e->mem_event.gla_valid = event->kind.pagefault.gva != 0;
            e->mem_event.out_access = out_access;
        } else {
            e->ss_event.gfn = event->kind.singlestep.gpa >> vmi->page_shift;
            e->ss_event.offset = microvmi->cached_regs[vcpu].x86.rip & VMI_BIT_MASK(0, 11);
            e->ss_event.gla = microvmi->cached_regs[vcpu].x86.rip;
        }
        event_response_t r = e->callback(vmi, e);
        // shortcut: of several generic memory events, the last one responding supplies the
        // response's data (view, emulation data); merge per flag if two ever need different data
        if (r || !libvmi_event) {
            libvmi_event = e;
            own = r;
        }
        response |= r;
    }
    vmi->event_callback = 0;

    status_t status = VMI_SUCCESS;
    // a register write cannot be denied: like KVM, DENY is ignored and the write proceeds.
    event_response_t handled = VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP | VMI_EVENT_RESPONSE_SLAT_ID
                               | VMI_EVENT_RESPONSE_NEXT_SLAT_ID
                               | VMI_EVENT_RESPONSE_SET_REGISTERS
                               | (reg ? VMI_EVENT_RESPONSE_DENY : 0)
                               | (breakpoint ? VMI_EVENT_RESPONSE_SET_EMUL_INSN : 0)
                               | (pagefault ? VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_EMULATE_NOWRITE | VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA : 0);
    if (response & ~handled)
        errprint("libmicrovmi driver: unhandled event responses 0x%"PRIx32"\n", (uint32_t) (response & ~handled));
    if (response & VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP) {
        vmi_event_t *step_event = g_hash_table_lookup(vmi->ss_events, GUINT_TO_POINTER(vcpu));
        if (step_event && !g_hash_table_lookup_extended(vmi->clear_events, step_event, NULL, NULL))
            status = microvmi_set_single_step(vmi, vcpu, !microvmi->sstep_on[vcpu]);
        else
            status = VMI_FAILURE;
    }
    // Like Xen and KVM, only the GPRs, RIP and RFLAGS: injectors reply with full snapshots taken
    // earlier, maybe on another vCPU, whose per-CPU state (TR base, CR3) must not be loaded.
    // microvmi->cached_regs[vcpu].x86, not libvmi_event->x86_regs: SET_EMUL_* responses overwrite that pointer
    if (response & VMI_EVENT_RESPONSE_SET_REGISTERS) {
        Registers current;
        bool written = microvmi_read_registers(microvmi->ctx, vcpu, &current);
        if (written) {
            gprs_to_microvmi(&microvmi->cached_regs[vcpu].x86, &current.x86);
            written = microvmi_write_registers(microvmi->ctx, vcpu, &current);
            if (written)
                microvmi_invalidate_vcpu_regs_cache(microvmi, vcpu);
        }
        if (!written) {
            errprint("libmicrovmi: failed to write the registers of vCPU %"PRIu16" at an event\n", vcpu);
            status = VMI_FAILURE;
        }
    }

    // emul_insn and emul_read share a union with x86_regs: read them before clearing it
    bool reinject = false;
    if (breakpoint)
        reinject = libvmi_event->interrupt_event.reinject == 1;
    else if (debug)
        reinject = libvmi_event->debug_event.reinject == 1;
    EventReplyType reply = {
        .tag = EventReplyType_Continue,
        .continue_ = { .reinject = reinject }
    };
    if (breakpoint && (own & VMI_EVENT_RESPONSE_SET_EMUL_INSN) && libvmi_event->emul_insn) {
        // the supplied instruction replaces the int3: reinject is dropped
        reply.tag = EventReplyType_EmulateInsn;
        memcpy(reply.emulate_insn.data, libvmi_event->emul_insn->data, sizeof(reply.emulate_insn.data));
        if (!libvmi_event->emul_insn->dont_free)
            free(libvmi_event->emul_insn);
    } else if (pagefault && (own & VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA) && libvmi_event->emul_read) {
        // like Xen, a size over the buffer is capped
        reply.tag = EventReplyType_EmulateReadData;
        reply.emulate_read_data.size = libvmi_event->emul_read->size < sizeof(reply.emulate_read_data.data)
                                       ? libvmi_event->emul_read->size : sizeof(reply.emulate_read_data.data);
        memcpy(reply.emulate_read_data.data, libvmi_event->emul_read->data, reply.emulate_read_data.size);
        if (!libvmi_event->emul_read->dont_free)
            free(libvmi_event->emul_read);
    } else if (pagefault && (response & VMI_EVENT_RESPONSE_EMULATE)) {
        reply.tag = EventReplyType_Emulate;
    } else if (pagefault && (response & VMI_EVENT_RESPONSE_EMULATE_NOWRITE)) {
        reply.tag = EventReplyType_EmulateNoWrite;
    }
    uint16_t view = (own & VMI_EVENT_RESPONSE_SLAT_ID) ? libvmi_event->slat_id : KEEP_MEMORY_VIEW;
    if (own & VMI_EVENT_RESPONSE_NEXT_SLAT_ID) {
        if (response & (VMI_EVENT_RESPONSE_SET_EMUL_INSN | VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA
                        | VMI_EVENT_RESPONSE_EMULATE | VMI_EVENT_RESPONSE_EMULATE_NOWRITE)) {
            errprint("libmicrovmi: fast single-step cannot be combined with emulation\n");
            status = VMI_FAILURE;
        } else {
            reply.tag = EventReplyType_FastSingleStep;
            reply.fast_single_step.next_view = libvmi_event->next_slat_id;
            if (!(own & VMI_EVENT_RESPONSE_SLAT_ID))
                view = event->view;
        }
    }
    for (unsigned int i = 0; i < count; i++)
        events[i]->x86_regs = NULL;
    // reply even if toggling failed: the vCPU must not stay parked
    if (VMI_FAILURE == microvmi_reply_with(microvmi, event, reply, view))
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

    // the guest ran since the last event: the cached pages are copies, not mappings as on Xen
    memory_cache_flush(vmi);
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

// lift a restricted page's restriction; kept in the table if that fails
static gboolean
microvmi_restore_page(gpointer key, gpointer UNUSED(value), gpointer data)
{
    vmi_instance_t vmi = data;
    uint16_t view = RESTRICTED_VIEW(key);
    addr_t gfn = RESTRICTED_GFN(key);

    if (microvmi_set_page_access(microvmi_get_instance(vmi)->ctx, view, gfn << vmi->page_shift, Access_R | Access_W | Access_X))
        return TRUE;
    errprint("libmicrovmi: failed to restore the access of GFN 0x%"PRIx64" in view %"PRIu16"\n", gfn, view);
    return FALSE;
}

// Keep the original restrictions until every page and the intercept transition succeed.
static status_t
microvmi_clear_generic_mem_access(vmi_instance_t vmi, vmi_mem_access_t removed)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    GHashTableIter iter;
    gpointer key, value;
    vmi_event_t *event;
    vmi_mem_access_t *access;
    Access remaining = Access_NIL;
    Access full = Access_R | Access_W | Access_X;
    bool restricted_left = false;
    GPtrArray *changed = g_ptr_array_new();
    InterceptType pagefault = { .tag = InterceptType_Pagefault };

    ghashtable_foreach(vmi->mem_events_generic, iter, &access, &event) {
        vmi_mem_access_t mask = GPOINTER_TO_UINT(access);
        if (mask == removed)
            continue;
        if (mask & VMI_MEMACCESS_R)
            remaining |= Access_R;
        if (mask & VMI_MEMACCESS_W)
            remaining |= Access_W;
        if (mask & VMI_MEMACCESS_X)
            remaining |= Access_X;
    }

    g_hash_table_iter_init(&iter, microvmi->restricted);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        addr_t gfn = RESTRICTED_GFN(key);
        Access original = (Access) (GPOINTER_TO_UINT(value) - 1);
        Access allowed = original | (full & ~remaining);
        if (allowed != full)
            restricted_left = true;
        if (allowed == original)
            continue;
        if (!microvmi_set_page_access(microvmi->ctx, RESTRICTED_VIEW(key), gfn << vmi->page_shift, allowed)) {
            errprint("libmicrovmi: failed to update the access of GFN 0x%"PRIx64"\n", gfn);
            goto rollback;
        }
        g_ptr_array_add(changed, key);
    }
    if (microvmi->pf_on && !restricted_left
            && VMI_FAILURE == microvmi_toggle_intercept_all(vmi, pagefault, false)) {
        microvmi_toggle_intercept_all(vmi, pagefault, true);
        goto rollback;
    }

    if (!restricted_left)
        microvmi->pf_on = false;
    g_hash_table_iter_init(&iter, microvmi->restricted);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        Access original = (Access) (GPOINTER_TO_UINT(value) - 1);
        Access allowed = original | (full & ~remaining);
        if (allowed == original)
            continue;
        g_hash_table_remove(microvmi->converting, key);
        if (allowed == full)
            g_hash_table_iter_remove(&iter);
        else
            g_hash_table_iter_replace(&iter, GUINT_TO_POINTER((unsigned int) allowed + 1));
    }
    g_ptr_array_free(changed, TRUE);
    return VMI_SUCCESS;

rollback:
    for (guint i = 0; i < changed->len; i++) {
        gpointer changed_key = g_ptr_array_index(changed, i);
        addr_t gfn = RESTRICTED_GFN(changed_key);
        Access original = (Access) (GPOINTER_TO_UINT(g_hash_table_lookup(microvmi->restricted, changed_key)) - 1);
        if (!microvmi_set_page_access(microvmi->ctx, RESTRICTED_VIEW(changed_key), gfn << vmi->page_shift, original))
            errprint("libmicrovmi: failed to re-restrict GFN 0x%"PRIx64" during rollback\n", gfn);
    }
    g_ptr_array_free(changed, TRUE);
    return VMI_FAILURE;
}

/*
 * LibVMI's alternate SLAT on libmicrovmi's Memory views (VirtualBox: VBoxVMI), view ids unchanged:
 * 0 is the Default view. Hidden pages back vmi_alloc_hidden_gfn.
 */

// drop the restricted table's entries for one view
static void
microvmi_forget_view(vmi_instance_t vmi, uint16_t view)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);
    GHashTableIter iter;
    gpointer key;

    g_hash_table_iter_init(&iter, microvmi->restricted);
    while (g_hash_table_iter_next(&iter, &key, NULL))
        if (RESTRICTED_VIEW(key) == view) {
            g_hash_table_remove(microvmi->converting, key);
            g_hash_table_iter_remove(&iter);
        }
    microvmi_pf_update(vmi);
}

static status_t
microvmi_slat_state(vmi_instance_t vmi, bool *state)
{
    *state = microvmi_get_instance(vmi)->views_on;
    return VMI_SUCCESS;
}

static status_t
microvmi_slat_control(vmi_instance_t vmi, bool state)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);

    if (!microvmi_enable_memory_views(microvmi->ctx, state))
        return VMI_FAILURE;
    microvmi->views_on = state;
    // disabling moves every vCPU to the Default view, destroys the other views and lifts every
    // restriction, the Default view's included
    if (!state) {
        g_hash_table_remove_all(microvmi->restricted);
        g_hash_table_remove_all(microvmi->converting);
        microvmi_pf_update(vmi);
    }
    return VMI_SUCCESS;
}

static status_t
microvmi_slat_create(vmi_instance_t vmi, uint16_t *view)
{
    return microvmi_create_memory_view(microvmi_get_instance(vmi)->ctx, view) ? VMI_SUCCESS : VMI_FAILURE;
}

static status_t
microvmi_slat_destroy(vmi_instance_t vmi, uint16_t view)
{
    if (!microvmi_destroy_memory_view(microvmi_get_instance(vmi)->ctx, view))
        return VMI_FAILURE;
    microvmi_forget_view(vmi, view);
    return VMI_SUCCESS;
}

static status_t
microvmi_slat_switch(vmi_instance_t vmi, uint16_t view)
{
    return microvmi_switch_memory_view(microvmi_get_instance(vmi)->ctx, view) ? VMI_SUCCESS : VMI_FAILURE;
}

// new_gfn ~0 undoes the Remap, as on Xen
static status_t
microvmi_slat_change_gfn(vmi_instance_t vmi, uint16_t view, addr_t old_gfn, addr_t new_gfn)
{
    microvmi_instance_t *microvmi = microvmi_get_instance(vmi);

    if (old_gfn > VMI_BIT_MASK(0, 47)
            || !microvmi_remap_memory_page(microvmi->ctx, view, old_gfn, new_gfn == ~0ULL ? RESTORE_PAGE : new_gfn))
        return VMI_FAILURE;
    // Match Xen: changing a GFN also resets the page's access in that view.
    return microvmi_set_page(vmi, view, old_gfn, Access_R | Access_W | Access_X);
}

static status_t
microvmi_alloc_hidden_gfn(vmi_instance_t vmi, uint64_t *gfn)
{
    return microvmi_allocate_hidden_page(microvmi_get_instance(vmi)->ctx, gfn) ? VMI_SUCCESS : VMI_FAILURE;
}

static status_t
microvmi_free_gfn(vmi_instance_t vmi, uint64_t gfn)
{
    return microvmi_free_hidden_page(microvmi_get_instance(vmi)->ctx, gfn) ? VMI_SUCCESS : VMI_FAILURE;
}

static uint32_t
microvmi_hidden_page_pool_size_fn(vmi_instance_t vmi)
{
    return microvmi_hidden_page_pool_size(microvmi_get_instance(vmi)->ctx);
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
    if (microvmi->cpuid_on)
        microvmi_set_cpuid_event(vmi, false);
    if (microvmi->debug_on)
        microvmi_set_debug_event(vmi, false);
    // Disabling Memory views lifts every restriction and returns every vCPU to the Default view
    if (microvmi->views_on && VMI_SUCCESS != microvmi_slat_control(vmi, false))
        errprint("libmicrovmi: failed to disable Memory views\n");
    // Restore restrictions left by per-page events or a failed generic clear.
    g_hash_table_foreach_remove(microvmi->restricted, microvmi_restore_page, vmi);
    InterceptType pagefault = { .tag = InterceptType_Pagefault };
    if (microvmi->pf_on && VMI_SUCCESS == microvmi_toggle_intercept_all(vmi, pagefault, false))
        microvmi->pf_on = false;
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
    driver.get_id_ptr = &microvmi_get_id;
    driver.check_id_ptr = &microvmi_check_id;
    driver.set_id_ptr = &microvmi_set_id;
    driver.get_name_ptr = &microvmi_get_name;
    driver.set_name_ptr = &microvmi_set_name;
    driver.get_memsize_ptr = &microvmi_get_memsize;
    driver.request_page_fault_ptr = &microvmi_request_pf;
    driver.get_vcpureg_ptr = &microvmi_get_vcpureg;
    driver.get_vcpuregs_ptr = &microvmi_get_vcpuregs;
    driver.set_vcpureg_ptr = &microvmi_set_vcpureg;
    driver.set_vcpuregs_ptr = &microvmi_set_vcpuregs;
    driver.read_page_ptr = &microvmi_read_page;
    driver.mmap_guest = &microvmi_mmap_guest;
    driver.write_ptr = &microvmi_write;
    driver.is_pv_ptr = &microvmi_is_pv;
    driver.pause_vm_ptr = &microvmi_pause_vm;
    driver.resume_vm_ptr = &microvmi_resume_vm;
    driver.events_listen_ptr = &microvmi_events_listen;
    driver.set_intr_access_ptr = &microvmi_set_intr_access;
    driver.set_reg_access_ptr = &microvmi_set_reg_access;
    driver.set_mem_access_ptr = &microvmi_set_mem_access;
    driver.set_cpuid_event_ptr = &microvmi_set_cpuid_event;
    driver.set_debug_event_ptr = &microvmi_set_debug_event;
    driver.set_mem_access_range_ptr = &microvmi_set_mem_access_range;
    driver.clear_generic_mem_access_ptr = &microvmi_clear_generic_mem_access;
    driver.start_single_step_ptr = &microvmi_start_single_step;
    driver.stop_single_step_ptr = &microvmi_stop_single_step;
    driver.shutdown_single_step_ptr = &microvmi_shutdown_single_step;
    driver.alloc_hidden_gfn_ptr = &microvmi_alloc_hidden_gfn;
    driver.free_gfn_ptr = &microvmi_free_gfn;
    driver.hidden_page_pool_size_ptr = &microvmi_hidden_page_pool_size_fn;
    driver.slat_state_ptr = &microvmi_slat_state;
    driver.slat_control_ptr = &microvmi_slat_control;
    driver.slat_create_ptr = &microvmi_slat_create;
    driver.slat_destroy_ptr = &microvmi_slat_destroy;
    driver.slat_switch_ptr = &microvmi_slat_switch;
    driver.slat_change_gfn_ptr = &microvmi_slat_change_gfn;
    vmi->driver = driver;
    return VMI_SUCCESS;
}
