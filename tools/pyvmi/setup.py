#!/usr/bin/env python
import subprocess
from distutils.core import setup, Extension

pkgconfig_cflags = subprocess.getoutput ("pkg-config --cflags glib-2.0 libvmi")
pkgconfig_include_flags = subprocess.getoutput ("pkg-config --cflags-only-I glib-2.0 libvmi")
pkgconfig_include_dirs = [ t[2:] for t in pkgconfig_include_flags.split() ]
pkgconfig_lflags = subprocess.getoutput ("pkg-config --libs-only-l glib-2.0 libvmi")
pkgconfig_libs = [ t[2:] for t in pkgconfig_lflags.split() ]
pkgconfig_biglflags = subprocess.getoutput ("pkg-config --libs-only-L glib-2.0 libvmi")
pkgconfig_ldirs = [ t[2:] for t in pkgconfig_biglflags.split() ]

pyvmimod = Extension('pyvmi', sources=['pyvmi.c'],
                    include_dirs = pkgconfig_include_dirs,
                    library_dirs = pkgconfig_ldirs,
                    libraries = pkgconfig_libs,
                    extra_compile_args=[pkgconfig_cflags])

setup(name='PyVmi', version='1.1',
      description = 'Python interface to LibVMI',
      ext_modules = [pyvmimod])
