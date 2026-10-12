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

#include "private.h"
#include "driver/driver_interface.h"

status_t driver_init_mode(const char *UNUSED(name),
                          uint64_t UNUSED(domainid),
                          uint64_t UNUSED(init_flags),
                          vmi_init_data_t *UNUSED(init_data),
                          vmi_mode_t *UNUSED(mode))
{
    errprint("No hypervisor driver available.\n");
    return VMI_FAILURE;
}

status_t driver_init(vmi_instance_t vmi,
                     uint32_t init_flags,
                     vmi_init_data_t *init_data)
{
    status_t rc = VMI_FAILURE;
    if (vmi->driver.initialized) {
        errprint("Driver is already initialized.\n");
        return rc;
    }

    bzero(&vmi->driver, sizeof(driver_interface_t));

    if (rc == VMI_SUCCESS && vmi->driver.init_ptr)
        rc = vmi->driver.init_ptr(vmi, init_flags, init_data);

    return rc;
}

status_t driver_init_vmi(vmi_instance_t vmi,
                         uint32_t init_flags,
                         vmi_init_data_t *init_data)
{
    status_t rc = VMI_FAILURE;
    if (vmi->driver.init_vmi_ptr)
        rc = vmi->driver.init_vmi_ptr(vmi, init_flags, init_data);

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
