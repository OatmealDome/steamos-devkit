# -*- coding: utf-8 -*-

import sys
import os
import platform

def setup_pysdl2_dll_path():
    if platform.system() != 'Windows':
        return
    if 'PYSDL2_DLL_PATH' in os.environ:
        return
    if getattr(sys, 'frozen', False):
        # Running frozen
        dir_ = os.path.dirname(sys.executable)
        os.environ['PYSDL2_DLL_PATH'] = os.path.join(dir_, 'lib', 'devkit_client', 'gui2')
    else:
        # Running from script
        dir_ = os.path.dirname(__file__)
        os.environ['PYSDL2_DLL_PATH'] = dir_
    print('Setting PYSDL2_DLL_PATH: {!r}'.format(os.environ['PYSDL2_DLL_PATH']))
    if sys.stdout:
        sys.stdout.flush()

setup_pysdl2_dll_path()

from .gui2 import main

