# examples

This folder contains a few examples of code using the LibVMI library.

Note: some of them take an optional `[<socket>]` parameter. This refers to the
`KVMi socket`, which needs to be specified when using the KVM driver.

LibVMI talks to the hypervisor through libmicrovmi; VMI events are not
supported, so the event examples fail at `vmi_init`.

Every example selects the VirtualBox access method from the environment
(`vbox-init-data.h`, force-included by `CMakeLists.txt`, turns these into
`vmi_init` init data):

| variable | value | init data |
|---|---|---|
| `LIBVMI_VBOX_ACCESS_METHOD` | `machine-debugger` or `vboxvmi` | `VMI_INIT_DATA_VBOX_ACCESS_METHOD` |
| `LIBVMI_VBOX_SOCKET` | VBoxVMI socket path | `VMI_INIT_DATA_VBOX_SOCKET` |

Neither set: libmicrovmi's default (VBoxVMI at the VM's default socket,
MachineDebugger when that socket does not exist). For example:

    LIBVMI_VBOX_ACCESS_METHOD=machine-debugger ./vcpu-info myvm

## pause-example

Pauses the VM for 10 seconds, then resumes it.

## map-paddr

Reads and prints the physical page at the given (hexadecimal) address.

## vcpu-info

Prints the vCPU count, the max physical address and CR3/RIP of each vCPU.

## breakpoint-emulate-example

Recoiling on a software breakpoint via instruction emulation.

Reads the opcode at the specified location in memory (using the `opcode_size`
parameter) and sets a software breakpoint by writing `int3` interrupt.

When the breakpoint is hit, use the `VMI_EVENT_RESPONSE_SET_EMUL_INSN` event response
to emulate the instruction stored in `event->emul_insn`.

## breakpoint-recoil-example

Recoiling on a software breakpoint like a traditional debugger.

Reads the opcode at the specified symbol location and writes a software breakpoint `int3`, then
waits for interrupt events

When the breakpoint is hit, use the checks if it's our breakpoint, and recoil over it
by writing back the original opcode and enabling singlestep with `VMI_EVENT_RESPONSE_TOGGLE_SINGLESTEP`.

The singlestep callback will handle the second step of the recoil by writing back the breakoint
and disabling the singlestep for this VCPU.

## cr3-event-example

Intercepts and displays `CR3` events.

## descriptor-event-example

Intercepts descriptor register accesss events. (`IDTR`, `GDTR`, `LDTR`, `TR`)

## vmi-dump-memory

Dumps the VM's physical memory to the given filepath.

## event-example

A demo of the event API using `MSRs`, `memory access` and `CR3` events.

## fool-patchguard

Finds the index of `nt!NtLoadDriver` routine in the `SSDT`, and corrupts the entry.

Then it waits for a Patchguard check to return fake data.

Demonstrates how to use

- `event->emul_read`
- `VMI_EVENT_RESPONSE_SET_EMUL_READ_DATA`

## interrupt-event-example

A simple interrupt interception example that will display `int3` events.

## map-addr

Display a page in hexadecimal at the given virtual address.

## map-symbol

Display a page in hexadecimal at the given symbol.

_Note: Not compatible with the new KVM driver_

## mem-event-example

A simple execute memory access interception, configured on the current RIP.

## vmi-module-list

Displays the list of loaded modules, for Windows and linux.

## msr-event-example

A simple MSR event interception.

## read-disk-example

Example reads bootable disk zero sector (MBR) and saves to file

## io-event-example

Example set breakpoint on I/O (in, out instrutions) events

## vmi-process-list

Displays the VM's process list.

## singlestep-event-example

A simple singlestep event interception. Also demonstrate how to manually toggle the singlestep once enabled.

## switch-view-example

A simple example demonstrating how to use Second Level Address Translation (EPT/RVI) via LibVMI.

## va-pages

Displays the current process page tables upon each `CR3` load.

## wait-for-domain-example

A Simple example monitoring for domain creation and deletion.

## vmi-win-guid

Print the `GUID` and the `PE_HEADER` of the Windows kernel.

## vmi-win-offsets

Displays Windows kernel offsets based on a Rekall profile.

## xen-emulate-response

Sets an execute memory access trap on a virtual address and emulate the instruction to continue execution.
