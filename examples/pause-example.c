/* The LibVMI Library is an introspection library that simplifies access to
 * memory in a target virtual machine or in a file containing a dump of
 * a system's physical memory.  LibVMI is based on the XenAccess Library.
 *
 * Author: Mathieu Tarral (mathieu.tarral@ssi.gouv.fr)
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
#include <errno.h>
#include <sys/mman.h>
#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>

#include <libvmi/libvmi.h>

static int interrupted = 0;
static void close_handler(int sig)
{
    interrupted = sig;
}

int main (int argc, char **argv)
{
    vmi_instance_t vmi = {0};
    vmi_mode_t mode = {0};
    vmi_init_data_t *init_data = NULL;
    int retcode = 1;
    int sleep_time = 10;

    /* this is the VM or file that we are looking at */
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <vmname> [<socket>]\n", argv[0]);
        return retcode;
    }

    char *name = argv[1];

    if (argc == 3) {
        char *path = argv[2];

        // fill init_data
        init_data = malloc(sizeof(vmi_init_data_t) + sizeof(vmi_init_data_entry_t));
        init_data->count = 1;
        init_data->entry[0].type = VMI_INIT_DATA_KVMI_SOCKET;
        init_data->entry[0].data = strdup(path);
    }

    if (VMI_FAILURE == vmi_get_access_mode(NULL, (void*)name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, &mode)) {
        fprintf(stderr, "Failed to get access mode\n");
        goto error_exit;
    }

    if (VMI_FAILURE ==
            vmi_init(&vmi, mode, name, VMI_INIT_DOMAINNAME | VMI_INIT_EVENTS, init_data, NULL)) {
        fprintf(stderr, "Failed to init LibVMI library.\n");
        goto error_exit;
    }

    struct sigaction act;
    /* for a clean exit */
    act.sa_handler = close_handler;
    act.sa_flags = 0;
    sigemptyset(&act.sa_mask);
    sigaction(SIGHUP,  &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT,  &act, NULL);
    sigaction(SIGALRM, &act, NULL);

    /* pause the vm */
    printf("Pausing VM for %d seconds...\n", sleep_time);
    if (vmi_pause_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to pause VM\n");
        goto error_exit;
    }

    sleep(sleep_time);

    /* resume vm */
    printf("Resuming VM\n");
    if (vmi_resume_vm(vmi) != VMI_SUCCESS) {
        printf("Failed to resume VM\n");
        goto error_exit;
    }
    retcode = 0;
error_exit:

    /* cleanup any memory associated with the LibVMI instance */
    vmi_destroy(vmi);

    if (init_data) {
        free(init_data->entry[0].data);
        free(init_data);
    }

    return retcode;
}
