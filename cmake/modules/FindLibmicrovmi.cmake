# Try to find libmicrovmi library
# Libmicrovmi_FOUND - if libvirt is found
# Libmicrovmi_INCLUDE_DIRS - libvirt include directories
# Libmicrovmi_LIBRARIES - libvirt libraries

find_path(Libmicrovmi_INCLUDE_DIR
    NAMES libmicrovmi.h)

find_library(Libmicrovmi_LIBRARY
    NAMES libmicrovmi.so)

include(FindPackageHandleStandardArgs)

find_package_handle_standard_args(Libmicrovmi
    DEFAULT_MSG
    Libmicrovmi_LIBRARY
    Libmicrovmi_INCLUDE_DIR)

if (Libmicrovmi_FOUND)
    set(Libmicrovmi_INCLUDE_DIRS ${Libmicrovmi_INCLUDE_DIR})
    set(Libmicrovmi_LIBRARIES ${Libmicrovmi_LIBRARY})
endif ()

mark_as_advanced(Libmicrovmi_INCLUDE_DIR Libmicrovmi_LIBRARY)

set_package_properties(Libmicrovmi PROPERTIES
    DESCRIPTION "Cross-platform unified low-level VMI interface"
    URL "https://github.com/Wenzel/libmicrovmi"
    PURPOSE "Dependency for LibVMI drivers"
    TYPE REQUIRED)

