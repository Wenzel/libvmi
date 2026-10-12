LibVMI: Simplified Virtual Machine Introspection
================================================

LibVMI is a virtual machine introspection library.  This means that it helps
you access the memory of a running virtual machine.  LibVMI provides primitives
for accessing this memory using physical or virtual addresses and kernel
symbols.

This branch of LibVMI talks to the hypervisor through libmicrovmi_ instead of
its own drivers: Xen, KVM, VirtualBox and memflow guests are reached through
the matching libmicrovmi driver (``VMI_XEN``, ``VMI_KVM``, ``VMI_VIRTUALBOX``,
``VMI_MEMFLOW`` modes). Memory snapshot files (``VMI_FILE``), Bareflank and
VMI events are not supported. LibVMI can provide access to physical memory for
any operating system, and access to virtual memory and kernel symbols from
Windows and Linux.

.. _libmicrovmi: https://github.com/Wenzel/libmicrovmi

If you would like higher level semantic information, then we suggest using the
LibVMI Python bindings and Volatility.  Volatility
(https://github.com/volatilityfoundation/volatility/) is a forensic memory
analysis framework supporting both Linux and Windows systems that can aid
significantly in performing useful memory analysis tasks.  The LibVMI Python
bindings includes a Volatility address space plugin that enables you to use
Volatility on a live virtual machine.

This file contains very basic instructions to get you up and running.  If you
want more details about installation, or programming with LibVMI, then see
the documentation included in the doc/ subdirectory of LibVMI, or view the
documentation online at https://libvmi.com.

.. image:: https://badges.gitter.im/Join%20Chat.svg
   :alt: Join the chat at https://gitter.im/libvmi/Lobby
   :target: https://gitter.im/libvmi/Lobby?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge

.. image:: https://github.com/Wenzel/libvmi/actions/workflows/build.yml/badge.svg?branch=libmicrovmi
    :target: https://github.com/Wenzel/libvmi/actions/workflows/build.yml

.. image:: https://scan.coverity.com/projects/14159/badge.svg
    :target: https://scan.coverity.com/projects/libvmi-libvmi

Dependencies
------------
The following libraries are used in building this code:

- ``CMake`` (``>= 3.1``)

- libmicrovmi_ (see below)

- ``yacc`` OR ``bison`` (optional, for reading the configuration file)

- ``lex`` OR ``flex`` (optional, for reading the configuration file)

- ``glib`` (``>= 2.22``)

- ``libjson-c`` (optional, for JSON profiles)

Installing the dependencies on Ubuntu::

    $ sudo apt-get install cmake flex bison libglib2.0-dev libjson-c-dev

libmicrovmi
~~~~~~~~~~~
LibVMI needs libmicrovmi's ``dev`` branch at the commit CI pins
(``LIBMICROVMI_REV`` in ``.github/workflows/build.yml``), built from source with
the VirtualBox driver (add ``xen``, ``kvm`` or ``mflow`` to ``--features`` for
the other drivers) and a Rust toolchain:

.. code::

   git clone https://github.com/Wenzel/libmicrovmi
   cd libmicrovmi
   git checkout <LIBMICROVMI_REV>
   cargo build --release --features virtualbox
   sudo install -m 644 target/release/capi/libmicrovmi.h /usr/local/include/
   sudo install -m 755 target/release/libmicrovmi.so /usr/local/lib/
   sudo ldconfig

To use another install prefix, pass it to LibVMI's CMake with
``-DCMAKE_PREFIX_PATH=<prefix>`` (it looks for ``<prefix>/include/libmicrovmi.h``
and ``<prefix>/lib/libmicrovmi.so``) and add ``<prefix>/lib`` to ``LD_LIBRARY_PATH``.

Building
--------
LibVMI uses the [CMake](https://cmake.org/) build system.  To compile this library, simply
follow the steps below:

.. code::

   mkdir build
   cd build
   cmake ..
   make

The example code will work without installing LibVMI.

You can specify a different install prefix with
``cmake -DCMAKE_INSTALL_PREFIX=/usr ..``

The default installation prefix is ``/usr/local``.  You may need to run
``ldconfig`` after performing a ``make install``.

For a complete view of the build options, using ``ccmake`` tool is prefered if
available.

Otherwise, look at ``CMakeLists.txt`` ``option()`` commands.

Installation and Configuration
------------------------------
For complete details on installation and configuration, please see the
related online documentation:

http://libvmi.com/docs/gcode-install.html

VirtualBox support
~~~~~~~~~~~~~~~~~~
Open a VirtualBox VM by name (``VMI_INIT_DOMAINNAME``): ``vmi_get_access_mode``
reports ``VMI_VIRTUALBOX``. libmicrovmi reaches the VM with one of two access
methods, selected through ``vmi_init`` init data:

- no init data: VBoxVMI at the VM's default socket, falling back to
  MachineDebugger only when that socket does not exist (run with
  ``RUST_LOG=info`` to see which one was picked)
- ``VMI_INIT_DATA_VBOX_ACCESS_METHOD`` with ``(void *)(uintptr_t)VMI_VBOX_ACCESS_METHOD_MACHINE_DEBUGGER``:
  the VirtualBox ``IMachineDebugger`` API, never falls back
- ``VMI_INIT_DATA_VBOX_ACCESS_METHOD`` with ``(void *)(uintptr_t)VMI_VBOX_ACCESS_METHOD_VBOXVMI``:
  the VBoxVMI socket, never falls back; ``VMI_INIT_DATA_VBOX_SOCKET`` (a ``char *`` path)
  overrides the VM's default socket

.. code::

   vmi_init_data_t *init_data = malloc(sizeof(vmi_init_data_t) + 2 * sizeof(vmi_init_data_entry_t));
   init_data->count = 2;
   init_data->entry[0].type = VMI_INIT_DATA_VBOX_ACCESS_METHOD;
   init_data->entry[0].data = (void *)(uintptr_t)VMI_VBOX_ACCESS_METHOD_VBOXVMI;
   init_data->entry[1].type = VMI_INIT_DATA_VBOX_SOCKET;
   init_data->entry[1].data = "/path/to/vm.sock";

The examples take the same selection from the environment
(``LIBVMI_VBOX_ACCESS_METHOD=machine-debugger|vboxvmi`` and ``LIBVMI_VBOX_SOCKET``),
see ``examples/README.md``::

    LIBVMI_VBOX_ACCESS_METHOD=machine-debugger ./build/examples/vcpu-info myvm

KVM support
~~~~~~~~~~~
The KVMi socket goes to libmicrovmi's KVM driver with ``VMI_INIT_DATA_KVMI_SOCKET``.

Python bindings
----------------
LibVMI is written in C.  If you would rather work with Python, then look at the
``libvmi/python``` repository. They provide an almost feature complete python
interface to LibVMI with a relatively small performance overhead.

https://github.com/libvmi/python

Volatility3 Intermediate Symbol Table (IST) Format
------------------------------
LibVMI supports the use of Volatility3's IST JSONs for introspecting Windows and Linux. By using
these jsons, LibVMI is able to bypass the use if the in-memory KdDebuggerData (KDBG)
structure normally used by memory forensics tools and thus allows introspecting domains
where this structure is either corrupted, or encoded (like in the case of Windows 8 x64).
However, these ISTs have to be created for each kernel version, and therefore if an
update is made to the kernel, the JSON file has to be re-generated, thus it's a bit less stable
as the standard LibVMI configuration entries.

Volatility3 is available at https://github.com/volatilityfoundation/volatility3.

To read about how to generate the IST see: https://volatility3.readthedocs.io/en/latest/symbol-tables.html.

Note: To support Linux profiles generated by dwarf2json you'll need libjson-c version 0.15 or newer installed.

Rekall profiles
------------------------------
Note: Rekall is no longer maintained. Support for Rekall profiles will be deprecated.

LibVMI also supports the use of Rekall profiles for introspecting Windows and Linux. By using
Rekall profiles, LibVMI is able to bypass the use if the in-memory KdDebuggerData (KDBG)
structure normally used by memory forensics tools and thus allows introspecting domains
where this structure is either corrupted, or encoded (like in the case of Windows 8 x64).
However, Rekall profiles have to be created for each kernel version, and therefore if an
update is made to the kernel, the profile has to be re-generated, thus it's a bit less stable
as the standard LibVMI configuration entries.

Rekall is available at https://github.com/google/rekall.

To create a Rekall profile for Windows you can use the rekall_offset_finder.py script that ships
with LibVMI. See https://github.com/libvmi/libvmi/blob/master/tools/windows-offset-finder for more
details. If you need to examine an on-disk version of the kernel (or any other PE executable), you
can run the following the Rekall command:

.. code::

    rekall peinfo -f <path/to/ntoskrnl.exe>


Once the PDB filename and GUID is known, creating the Rekall profile is done in two steps:

.. code::

    rekall fetch_pdb <PDB filename> <GUID>
    rekall parse_pdb <PDB filename> > rekall-profile.json

The PDB filename should not have the .pdb extension in the above commands.

To create a Rekall profile for Linux follow the instructions at https://github.com/google/rekall/tree/master/tools/linux

The Rekall profile can be used directly in the LibVMI config via an additional rekall_profile entry
pointing to this file with an absolute path. There is no need to specify any of the offsets normally
required as those offsets will be available via the profile itself.

Debugging
---------
To enable LibVMI debug output, look at the ``libvmi/debug.h`` header file,
and set the CMake ``VMI_DEBUG`` option accordingly.

Example to enable all debug output:

.. code::

    cmake -DVMI_DEBUG=__VMI_DEBUG_ALL ..

Example to enable selective output (DRIVER and CORE)

.. code::

    cmake -DVMI_DEBUG='(VMI_DEBUG_DRIVER | VMI_DEBUG_CORE)' ..

Community
---------
The LibVMI forums are available at https://groups.google.com/forum/#!forum/vmitools
