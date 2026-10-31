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

/* Print the access mode, the vCPU count, the max physical address and CR3/RIP of each vCPU */

#include <stdio.h>
#include <inttypes.h>

#include <libvmi/libvmi.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <vmname>\n", argv[0]);
        return 1;
    }

    char *name = argv[1];
    vmi_instance_t vmi = NULL;
    vmi_mode_t mode;
    int retcode = 1;

    if (VMI_FAILURE == vmi_get_access_mode(NULL, name, VMI_INIT_DOMAINNAME, NULL, &mode) ||
            VMI_FAILURE == vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME, NULL, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        return retcode;
    }

    if (mode == VMI_VIRTUALBOX)
        printf("Access mode: VirtualBox\n");
    else
        printf("Access mode: %d\n", mode);
    unsigned int num_vcpus = vmi_get_num_vcpus(vmi);
    printf("vCPUs: %u\n", num_vcpus);
    printf("Max physical address: 0x%"PRIx64"\n", vmi_get_max_physical_address(vmi));

    for (unsigned int vcpu = 0; vcpu < num_vcpus; vcpu++) {
        uint64_t cr3, rip;
        if (VMI_FAILURE == vmi_get_vcpureg(vmi, &cr3, CR3, vcpu) ||
                VMI_FAILURE == vmi_get_vcpureg(vmi, &rip, RIP, vcpu)) {
            fprintf(stderr, "Failed to read registers of vCPU %u\n", vcpu);
            goto done;
        }
        printf("vCPU %u: CR3=0x%"PRIx64" RIP=0x%"PRIx64"\n", vcpu, cr3, rip);
    }
    retcode = 0;

done:
    vmi_destroy(vmi);
    return retcode;
}
