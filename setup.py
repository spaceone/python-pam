#! /usr/bin/env python

"""Setup script for the Python-PAM module distribution."""

import distutils
from distutils.core import setup
from distutils.extension import Extension

ext = Extension(
    name="PAM",
    libraries=["pam","pam_misc"],
    sources=["PAMmodule.c"]
)
##print ext.__dict__; sys.exit(1)

setup (name = 'PAM',
       version = '0.4.2',
       description = 'Python bindings for PAM',
       ext_modules = [ext])
