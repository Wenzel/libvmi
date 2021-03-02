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

#include <stdlib.h>
#include <string.h>

#include <libmicrovmi.h>

#include "private.h"
#include "memory_cache.h"
#include "driver/driver_interface.h"

// get data memory cache callback
static void*
get_data(vmi_instance_t vmi, addr_t paddr, uint32_t len)
{
    void *buffer = g_try_malloc0(len);
    if (!buffer)
        return NULL;

    void *driver = vmi->driver.microvmi_driver;
    if (!microvmi_read_physical(driver, (uint64_t)paddr, buffer, (size_t)len)) {
        g_free(buffer);
        return NULL;
    }
    return buffer;
}

// release data memory cache callback
static void
release_data(
    vmi_instance_t UNUSED(vmi),
    void *memory,
    size_t UNUSED(length))
{
    if (memory)
        g_free(memory);
}


status_t driver_init_mode(const char *UNUSED(name),
                          uint64_t UNUSED(domainid),
                          uint64_t UNUSED(init_flags),
                          vmi_init_data_t *UNUSED(init_data),
                          vmi_mode_t *mode)
{

    // /* if we didn't see exactly one system, report error */
    // if (count == 0) {
    //     errprint("Could not find a live guest VM or file to use.\n");
    //     errprint("Opening a live guest VM requires root access.\n");
    //     return VMI_FAILURE;
    // } else if (count > 1) {
    //     errprint
    //     ("Found more than one VMM or file to use,\nplease specify what you want instead of using VMI_AUTO.\n");
    //     return VMI_FAILURE;
    // } else { // count == 1

    // driver detection is not supported in libmicrovmi yet
    // assume Xen for now
    *mode = VMI_XEN;
    return VMI_SUCCESS;
}

status_t driver_init(vmi_instance_t vmi,
                     uint32_t UNUSED(init_flags),
                     vmi_init_data_t *UNUSED(init_data))
{
    status_t rc = VMI_FAILURE;
    if (vmi->driver.initialized) {
        errprint("Driver is already initialized.\n");
        return rc;
    }

    bzero(&vmi->driver, sizeof(driver_interface_t));

    rc = VMI_SUCCESS;

    return rc;
}

status_t driver_init_vmi(vmi_instance_t vmi,
                         uint32_t UNUSED(init_flags),
                         vmi_init_data_t *UNUSED(init_data))
{
    status_t rc = VMI_FAILURE;

    // initialize libmicrovmi logger
    microvmi_envlogger_init();
    // initialize libmicrovmi
    const char *name = vmi->driver.name;

    const char* init_error = NULL;
    // hardcode Xen
    const DriverType drv_type = Xen;
    void *driver = microvmi_init(name, &drv_type, NULL, &init_error);
    if (!driver) {
        errprint((char*)init_error);
        rs_cstring_free((char*)init_error);
        return rc;
    }

    // (re)init cache
    memory_cache_destroy(vmi);
    memory_cache_init(vmi, get_data, release_data, 0);
    vmi->driver.microvmi_driver = driver;
    vmi->driver.initialized = true;
    rc = VMI_SUCCESS;

    return rc;
}

status_t driver_domainwatch_init(vmi_instance_t vmi,
                                 uint32_t init_flags)
{
    status_t rc = VMI_FAILURE;
    if (vmi->driver.domainwatch_init_ptr)
        rc = vmi->driver.domainwatch_init_ptr(vmi, init_flags);

    return rc;
}
