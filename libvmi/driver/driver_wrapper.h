/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Copyright 2011 Sandia Corporation. Under the terms of Contract
 * DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government
 * retains certain rights in this software.
 *
 * Author: Bryan D. Payne (bdpayne@acm.org)
 * Author: Tamas K Lengyel (tamas.lengyel@zentific.com)
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

#ifndef DRIVER_WRAPPER_H
#define DRIVER_WRAPPER_H

#include <libmicrovmi.h>

#include "private.h"
#include "memory_cache.h"

/*
 * The following functions are safety-wrappers that should be used internally
 * instead of calling the functions directly on the driver.
 */

static inline void
driver_destroy(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized)
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_destroy function not implemented.\n");
#endif
    if (vmi->driver.microvmi_driver)
        microvmi_destroy(vmi->driver.microvmi_driver);

    bzero(&vmi->driver, sizeof(driver_interface_t));
}

static inline uint64_t
driver_get_id_from_name(
    vmi_instance_t vmi,
    const char *name)
{
    vmi->driver.name = strndup(name, 500);
    return 1;
}

static inline status_t
driver_get_name_from_id(
    vmi_instance_t vmi,
    uint64_t domid,
    char **name)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_name_from_id_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_name_from_id function not implemented.\n");
        return 0;
    }
#endif

    return vmi->driver.get_name_from_id_ptr(vmi, domid, name);
}

static inline uint64_t
driver_get_id_from_uuid(
    vmi_instance_t vmi,
    const char *uuid)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_id_from_uuid_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_id_from_uuid function not implemented.\n");
        return 0;
    }
#endif

    return vmi->driver.get_id_from_uuid_ptr(vmi, uuid);
}

static inline uint64_t
driver_get_id(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_id_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_id function not implemented.\n");
        return 0;
    }
#endif

    return vmi->driver.get_id_ptr(vmi);
}

static inline void
driver_set_id(
    vmi_instance_t vmi,
    uint64_t id)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_id_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_id function not implemented.\n");
        return;
    }
#endif

    return vmi->driver.set_id_ptr(vmi, id);
}

static inline status_t
driver_check_id(
    vmi_instance_t vmi,
    uint64_t id)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.check_id_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_check_id function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.check_id_ptr(vmi, id);
}

static inline status_t
driver_get_name(
    vmi_instance_t vmi,
    char **name)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_name_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_name function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.get_name_ptr(vmi, name);
}

static inline void
driver_set_name(
    vmi_instance_t vmi,
    const char *name)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_name_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_name function not implemented.\n");
        return;
    }
#endif

    return vmi->driver.set_name_ptr(vmi, name);
}

static inline status_t
driver_get_xsave_info(
    vmi_instance_t vmi,
    unsigned long vcpu,
    xsave_area_t *xsave_info)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_xsave_info_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_xsave_info function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.get_xsave_info_ptr(vmi, vcpu, xsave_info);
}

static inline status_t
driver_get_memsize(
    vmi_instance_t UNUSED(vmi),
    uint64_t *allocated_ram_size,
    addr_t *max_physical_address)
{
    // return fake data for now
    *allocated_ram_size = 0x59700000;
    *max_physical_address = 0x59700000;
    return VMI_SUCCESS;
}

static inline status_t
driver_request_page_fault(
    vmi_instance_t vmi,
    unsigned long vcpu,
    uint64_t virtual_address,
    uint32_t error_code)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.request_page_fault_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_request_page_fault function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.request_page_fault_ptr(vmi, vcpu, virtual_address,
            error_code);
}

static inline status_t
driver_get_tsc_info(
    vmi_instance_t vmi,
    uint32_t *tsc_mode,
    uint64_t *elapsed_nsec,
    uint32_t *gtsc_khz,
    uint32_t *incarnation)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_tsc_info_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_tsc_info function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.get_tsc_info_ptr(vmi, tsc_mode, elapsed_nsec, gtsc_khz,
                                        incarnation);
}

static inline status_t
driver_get_vcpumtrr(
    vmi_instance_t vmi,
    mtrr_regs_t *hwMtrr,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_vcpumtrr_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_vcpumtrr function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.get_vcpumtrr_ptr(vmi, hwMtrr, vcpu);
}

static inline status_t
driver_get_vcpureg(
    vmi_instance_t vmi,
    uint64_t *value,
    reg_t reg,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver is not initialized.\n");
        return VMI_FAILURE;
    }
#endif

    void *driver = vmi->driver.microvmi_driver;
    Registers regs;
    if (!microvmi_read_registers(driver, (uint16_t)vcpu, &regs))
        return VMI_FAILURE;

    switch (reg) {
        case RAX:
            *value = (reg_t) regs.x86._0.rax;
            break;
        case RBX:
            *value = (reg_t) regs.x86._0.rbx;
            break;
        case RCX:
            *value = (reg_t) regs.x86._0.rcx;
            break;
        case RDX:
            *value = (reg_t) regs.x86._0.rdx;
            break;
        case RBP:
            *value = (reg_t) regs.x86._0.rbp;
            break;
        case RSI:
            *value = (reg_t) regs.x86._0.rsi;
            break;
        case RDI:
            *value = (reg_t) regs.x86._0.rdi;
            break;
        case RSP:
            *value = (reg_t) regs.x86._0.rsp;
            break;
        case R8:
            *value = (reg_t) regs.x86._0.r8;
            break;
        case R9:
            *value = (reg_t) regs.x86._0.r9;
            break;
        case R10:
            *value = (reg_t) regs.x86._0.r10;
            break;
        case R11:
            *value = (reg_t) regs.x86._0.r11;
            break;
        case R12:
            *value = (reg_t) regs.x86._0.r12;
            break;
        case R13:
            *value = (reg_t) regs.x86._0.r13;
            break;
        case R14:
            *value = (reg_t) regs.x86._0.r14;
            break;
        case R15:
            *value = (reg_t) regs.x86._0.r15;
            break;
        case RIP:
            *value = (reg_t) regs.x86._0.rip;
            break;
        case RFLAGS:
            *value = (reg_t) regs.x86._0.rflags;
            break;
        case CR0:
            *value = (reg_t) regs.x86._0.cr0;
            break;
        case CR2:
            *value = (reg_t) regs.x86._0.cr2;
            break;
        case CR3:
            *value = (reg_t) regs.x86._0.cr3;
            break;
        case CR4:
            *value = (reg_t) regs.x86._0.cr4;
            break;
        case CS_SEL:
            *value = (reg_t) regs.x86._0.cs.selector;
            break;
        case DS_SEL:
            *value = (reg_t) regs.x86._0.ds.selector;
            break;
        case ES_SEL:
            *value = (reg_t) regs.x86._0.es.selector;
            break;
        case FS_SEL:
            *value = (reg_t) regs.x86._0.fs.selector;
            break;
        case GS_SEL:
            *value = (reg_t) regs.x86._0.gs.selector;
            break;
        case SS_SEL:
            *value = (reg_t) regs.x86._0.ss.selector;
            break;
        case TR_SEL:
            *value = (reg_t) regs.x86._0.tr.selector;
            break;
        case CS_LIMIT:
            *value = (reg_t) regs.x86._0.cs.limit;
            break;
        case DS_LIMIT:
            *value = (reg_t) regs.x86._0.ds.limit;
            break;
        case ES_LIMIT:
            *value = (reg_t) regs.x86._0.es.limit;
            break;
        case FS_LIMIT:
            *value = (reg_t) regs.x86._0.fs.limit;
            break;
        case GS_LIMIT:
            *value = (reg_t) regs.x86._0.gs.limit;
            break;
        case SS_LIMIT:
            *value = (reg_t) regs.x86._0.ss.limit;
            break;
        case TR_LIMIT:
            *value = (reg_t) regs.x86._0.tr.limit;
            break;
        case CS_BASE:
            *value = (reg_t) regs.x86._0.cs.base;
            break;
        case DS_BASE:
            *value = (reg_t) regs.x86._0.ds.base;
            break;
        case ES_BASE:
            *value = (reg_t) regs.x86._0.es.base;
            break;
        case FS_BASE:
            *value = (reg_t) regs.x86._0.fs.base;
            break;
        case GS_BASE:
            *value = (reg_t) regs.x86._0.gs.base;
            break;
        case SS_BASE:
            *value = (reg_t) regs.x86._0.ss.base;
            break;
        case TR_BASE:
            *value = (reg_t) regs.x86._0.tr.base;
            break;
        case SYSENTER_CS:
            *value = (reg_t) regs.x86._0.sysenter_cs;
            break;
        case SYSENTER_ESP:
            *value = (reg_t) regs.x86._0.sysenter_esp;
            break;
        case SYSENTER_EIP:
            *value = (reg_t) regs.x86._0.sysenter_eip;
            break;
        case MSR_LSTAR:
            *value = (reg_t) regs.x86._0.msr_lstar;
            break;
        case MSR_EFER:
            *value = (reg_t) regs.x86._0.msr_efer;
            break;
        case MSR_STAR:
            *value = (reg_t) regs.x86._0.msr_star;
            break;
        case IDTR_BASE:
            *value = (reg_t) regs.x86._0.idt.base;
            break;
        case IDTR_LIMIT:
            *value = (reg_t) regs.x86._0.idt.limit;
            break;
        case GDTR_BASE:
            *value = (reg_t) regs.x86._0.gdt.base;
            break;
        case GDTR_LIMIT:
            *value = (reg_t) regs.x86._0.gdt.limit;
            break;
        default:
            errprint("Unimplemented register %ld\n", reg);
            return VMI_FAILURE;
    }

    return VMI_SUCCESS;
}

static inline status_t
driver_get_vcpuregs(
    vmi_instance_t vmi,
    registers_t* regs,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.get_vcpuregs_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_get_vcpuregs function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.get_vcpuregs_ptr(vmi, regs, vcpu);
}

static inline status_t
driver_set_vcpureg(
    vmi_instance_t vmi,
    uint64_t value,
    reg_t reg,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_vcpureg_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_vcpureg function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_vcpureg_ptr(vmi, value, reg, vcpu);
}

static inline status_t
driver_set_vcpuregs(
    vmi_instance_t vmi,
    registers_t *regs,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_vcpuregs_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_vcpuregs function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_vcpuregs_ptr(vmi, regs, vcpu);
}

static inline void *
driver_read_page(
    vmi_instance_t vmi,
    addr_t page)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver is not initialized\n");
        return NULL;
    }
#endif

    addr_t paddr = page << vmi->page_shift;
    return memory_cache_insert(vmi, paddr);
}

static inline void *
driver_mmap_guest(
    vmi_instance_t vmi,
    unsigned long *pfns,
    unsigned int size)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.mmap_guest) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_mmap_guest function not implemented.\n");
        return NULL;
    }
#endif

    return vmi->driver.mmap_guest(vmi, pfns, size);
}

static inline status_t
driver_write(
    vmi_instance_t vmi,
    addr_t paddr,
    void *buf,
    uint32_t length)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.write_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_write function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.write_ptr(vmi, paddr, buf, length);
}

static inline int
driver_is_pv(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.is_pv_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_is_pv function not implemented.\n");
        return 0;
    }
#endif

    return vmi->driver.is_pv_ptr(vmi);
}

static inline status_t
driver_pause_vm(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver not initialized\n");
        return VMI_FAILURE;
    }
#endif

    void* driver = vmi->driver.microvmi_driver;
    if (!microvmi_pause(driver))
        return VMI_FAILURE;
    return VMI_SUCCESS;
}

static inline status_t
driver_resume_vm(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver not initialized\n");
        return VMI_FAILURE;
    }
#endif

    void* driver = vmi->driver.microvmi_driver;
    if (microvmi_resume(driver))
        return VMI_FAILURE;
    return VMI_SUCCESS;
}

static inline status_t
driver_events_listen(
    vmi_instance_t vmi,
    uint32_t timeout)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.events_listen_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_events_listen function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.events_listen_ptr(vmi, timeout);
}

static inline int
driver_are_events_pending(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.are_events_pending_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_are_events_pending function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.are_events_pending_ptr(vmi);
}

static inline status_t
driver_set_reg_access(
    vmi_instance_t vmi,
    reg_event_t *event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_reg_access_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_reg_w_access function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_reg_access_ptr(vmi, event);
}

static inline status_t
driver_set_intr_access(
    vmi_instance_t vmi,
    interrupt_event_t *event,
    uint8_t enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_intr_access_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_intr_access function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_intr_access_ptr(vmi, event, enabled);
}

static inline status_t
driver_set_mem_access(
    vmi_instance_t vmi,
    addr_t gpfn,
    vmi_mem_access_t page_access_flag,
    uint16_t vmm_pagetable_id)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_mem_access_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_mem_access function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_mem_access_ptr(vmi, gpfn, page_access_flag, vmm_pagetable_id);
}

static inline status_t
driver_start_single_step(
    vmi_instance_t vmi,
    single_step_event_t *event)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.start_single_step_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_start_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.start_single_step_ptr(vmi, event);
}

static inline status_t
driver_stop_single_step(
    vmi_instance_t vmi,
    unsigned long vcpu)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.stop_single_step_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_stop_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.stop_single_step_ptr(vmi, vcpu);
}

static inline status_t
driver_shutdown_single_step(
    vmi_instance_t vmi)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.shutdown_single_step_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_shutdown_single_step function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.shutdown_single_step_ptr(vmi);
}

static inline status_t
driver_set_guest_requested_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_guest_requested_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_guest_requested function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_guest_requested_ptr(vmi, enabled);
}

static inline status_t
driver_set_cpuid_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_cpuid_event_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_cpuid_event function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_cpuid_event_ptr(vmi, enabled);
}

static inline status_t
driver_set_debug_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_debug_event_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_debug_event function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_debug_event_ptr(vmi, enabled);
}

static inline status_t
driver_set_privcall_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_privcall_event_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_privcall_event function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_privcall_event_ptr(vmi, enabled);
}

static inline status_t
driver_set_desc_access_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_desc_access_event_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_desc_access_event function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_desc_access_event_ptr(vmi, enabled);
}

static inline status_t
driver_set_failed_emulation_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_failed_emulation_event_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_failed_emulation_event function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_failed_emulation_event_ptr(vmi, enabled);
}

static inline status_t
driver_set_watch_domain_event(
    vmi_instance_t vmi,
    bool enabled)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_domain_watch_event_ptr) {
        dbprint(VMI_DEBUG_DRIVER, "WARNING: driver_set_watch_domain_event function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_domain_watch_event_ptr(vmi, enabled);
}

static inline status_t
driver_slat_get_domain_state (
    vmi_instance_t vmi,
    bool *state )
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.slat_get_domain_state_ptr ) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_get_domain_state function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.slat_get_domain_state_ptr (vmi, state);
}

static inline status_t
driver_slat_set_domain_state (
    vmi_instance_t vmi,
    bool state )
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.slat_set_domain_state_ptr ) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_set_domain_state function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.slat_set_domain_state_ptr (vmi, state);
}

static inline status_t
driver_slat_create (
    vmi_instance_t vmi,
    uint16_t *slat_idx )
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.slat_create_ptr) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_create function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.slat_create_ptr (vmi, slat_idx);
}

static inline status_t
driver_slat_destroy (
    vmi_instance_t vmi,
    uint16_t slat_idx )
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.slat_destroy_ptr) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_destroy function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.slat_destroy_ptr (vmi, slat_idx);
}

static inline status_t
driver_slat_switch (
    vmi_instance_t vmi,
    uint16_t slat_idx )
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.slat_switch_ptr) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_switch function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.slat_switch_ptr (vmi, slat_idx);
}

static inline status_t
driver_slat_change_gfn (
    vmi_instance_t vmi,
    uint16_t slat_idx,
    addr_t old_gfn,
    addr_t new_gfn)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.slat_change_gfn_ptr) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_change_gfn function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.slat_change_gfn_ptr (vmi, slat_idx, old_gfn, new_gfn);
}

static inline status_t
driver_set_access_listener_required(
    vmi_instance_t vmi,
    bool required)
{
#ifdef ENABLE_SAFETY_CHECKS
    if (!vmi->driver.initialized || !vmi->driver.set_access_required_ptr) {
        dbprint (VMI_DEBUG_DRIVER, "WARNING: driver_slat_change_gfn function not implemented.\n");
        return VMI_FAILURE;
    }
#endif

    return vmi->driver.set_access_required_ptr (vmi, required);
}

#endif /* DRIVER_WRAPPER_H */

