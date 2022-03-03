# -*- coding: utf-8 -*-

#MIT License
#
#Copyright (c) 2017-2022 Valve Software inc., Collabora Ltd
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

# Creates exe of python script and puts dependent modules in lib folder
# run from the virtualenv, top level:
# C:\steamos-devkit> python .\setup\cxfreeze-windows.py build

import sys
import os
from cx_Freeze import setup, Executable

assert sys.platform == 'win32'

module_map = {
    'PySDL2': 'sdl2',
    'PyOpenGL': 'OpenGL',
    'PyNaCl': 'nacl',
}

# explicitly include all top level modules, extracted from requirements.txt
# it's likely they don't all need to be explicitly listed, but this protects us from missing dependencies a little
# hand rolled parser is a little fragile, but if you are going to touch requirements.txt you better know what you're doing anyway
modules = []
for req in open('requirements.txt').readlines():
    if req[0] == '#':
        continue
    # those platform specific packages are all support packages that do not need to be bundled
    if req.find('sys_platform') != -1:
        continue
    req = req.strip('\n')
    if req in module_map:
        modules.append(module_map[req])
    else:
        modules.append(req)
modules.append('imgui')

print(f'modules: {modules!r}')

build_exe_options = {
    'packages': modules, # this actually takes a list of module names
    'excludes': ['tkinter'],
    'path': ['client'] + sys.path,
    # Add vcredist dlls
    'include_msvcr': True,
}

base = 'Win32GUI'

setup(
    name='steamos-devkit',
    description='SteamOS Devkit Client',
    options={'build_exe': build_exe_options},
    executables=[
        Executable('client/devkit-gui.py', base=base),
    ],
    package_dir={'': 'client'},
)
