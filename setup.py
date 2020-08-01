#!/usr/bin/env python

from distutils.core import setup, Extension

setup(
    name='PyPAM',
    version='0.5.0',
    description='PAM (Pluggable Authentication Module) bindings for Python',
    author='Rob Riggs',
    author_email='rob+pypam@pangalactic.org',
    url='http://www.pangalactic.org/PyPAM',
    license='LGPL',
    ext_modules=[
        Extension(
            'PAMmodule',
            ['PAMmodule.c'],
            libraries=['pam', 'pam_misc'],
            extra_compile_args = ['-std=c99'],
        )
    ],
)

