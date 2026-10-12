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

/*
 * Lets every example select the VirtualBox access method without its own
 * command-line flags. examples/CMakeLists.txt force-includes this header, which
 * wraps vmi_init(), vmi_init_complete() and vmi_get_access_mode() so that
 * their init data gets these entries appended:
 *
 *   LIBVMI_VBOX_ACCESS_METHOD=machine-debugger|vboxvmi -> VMI_INIT_DATA_VBOX_ACCESS_METHOD
 *   LIBVMI_VBOX_SOCKET=<path>                          -> VMI_INIT_DATA_VBOX_SOCKET
 *
 * Neither set: the init data is passed unchanged (libmicrovmi default method).
 */

#ifndef VBOX_INIT_DATA_H
#define VBOX_INIT_DATA_H
/* force-included before the examples' own feature macros, which want GNU */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* declare the wrapped functions before the macros below can touch their prototypes */
#include <libvmi/libvmi.h>

static inline vmi_init_data_t *
vbox_init_data(vmi_init_data_t *init_data)
{
    const char *method = getenv("LIBVMI_VBOX_ACCESS_METHOD");
    const char *socket_path = getenv("LIBVMI_VBOX_SOCKET");
    if (!method && !socket_path)
        return init_data;

    uint64_t count = init_data ? init_data->count : 0;
    // shortcut: never freed, examples init once per run
    vmi_init_data_t *merged = calloc(1, sizeof(vmi_init_data_t) + (count + 2) * sizeof(vmi_init_data_entry_t));
    if (!merged) {
        fprintf(stderr, "Failed to allocate init data\n");
        exit(1);
    }
    if (count)
        memcpy(merged->entry, init_data->entry, count * sizeof(vmi_init_data_entry_t));
    merged->count = count;

    if (method) {
        uintptr_t value;
        if (!strcmp(method, "machine-debugger"))
            value = VMI_VBOX_ACCESS_METHOD_MACHINE_DEBUGGER;
        else if (!strcmp(method, "vboxvmi"))
            value = VMI_VBOX_ACCESS_METHOD_VBOXVMI;
        else {
            fprintf(stderr, "LIBVMI_VBOX_ACCESS_METHOD must be machine-debugger or vboxvmi, not '%s'\n", method);
            exit(1);
        }
        merged->entry[merged->count].type = VMI_INIT_DATA_VBOX_ACCESS_METHOD;
        merged->entry[merged->count].data = (void *) value;
        merged->count++;
    }
    if (socket_path) {
        merged->entry[merged->count].type = VMI_INIT_DATA_VBOX_SOCKET;
        merged->entry[merged->count].data = (void *) socket_path;
        merged->count++;
    }
    return merged;
}

/* a function-like macro does not expand itself again: these call the real functions */
#define vmi_init(vmi, mode, domain, init_flags, init_data, error) \
    vmi_init(vmi, mode, domain, init_flags, vbox_init_data(init_data), error)
#define vmi_init_complete(vmi, domain, init_flags, init_data, config_mode, config, error) \
    vmi_init_complete(vmi, domain, init_flags, vbox_init_data(init_data), config_mode, config, error)
#define vmi_get_access_mode(vmi, domain, init_flags, init_data, mode) \
    vmi_get_access_mode(vmi, domain, init_flags, vbox_init_data(init_data), mode)

#endif /* VBOX_INIT_DATA_H */
