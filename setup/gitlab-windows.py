#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import shutil

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

assert sys.platform == 'win32'
assert sys.prefix == sys.base_prefix    # executed at build VM OS level

def call(cmd):
    print(f'BEGIN CMD: {cmd}')
    subprocess.check_call(cmd, cwd=ROOT_DIR, shell=True)
    print(f'END CMD: {cmd}')

if __name__ == '__main__':
    call(f'python -m venv .')
    interpreter = os.path.join(ROOT_DIR, r'Scripts\python.exe')
    call(f'{interpreter} -m pip install --upgrade pip')
    pip = os.path.join(ROOT_DIR, r'Scripts\pip.exe')
    call(f'{pip} install --upgrade setuptools')
    call(f'{pip} install -r requirements.txt')
    call(rf'{pip} install .\pyimgui-wheels\imgui-2.0.0-cp310-cp310-win_amd64.whl')
    call(rf'{interpreter} .\setup\package-windows.py')