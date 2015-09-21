# -*- coding: utf-8 -*-
import sys

# from setuptools import setup, Extension
# from setuptools.command.test import test
from distutils.core import setup, Extension
class test(): pass

class Tox(test):
    def initialize_options(self):
        test.initialize_options(self)
        self.tox_args = None

    def finalize_options(self):
        test.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        import tox
        sys.exit(tox.cmdline())

httpparser_extension = Extension('httpparser', sources = ['httpparser/httpparser.c'])

setup(
    name='httpparser.py',
    version='0.1',
    description='HTTP/1.1 parser library',
    url='https://github.com/hackaugusto/httpparser.py',
    author='Augusto F. Hack',
    author_email='hack.augusto@gmail.com',
    license='MIT',

    py_modules=['httpparser'],
    ext_modules=[httpparser_extension],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
    ],
    keywords=['http', 'parser'],
    tests_require=['tox'],
    # cmdclass={'test': Tox},
)
