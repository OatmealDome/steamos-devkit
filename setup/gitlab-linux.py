#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import tempfile
import shutil
import glob

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ARTIFACTS_DIR = os.path.join(ROOT_DIR, 'artifacts')

assert sys.platform == 'linux'
assert sys.prefix == sys.base_prefix    # executed at build VM OS level

def call(cmd, cwd):
    print(f'BEGIN CMD: {cmd}')
    output = subprocess.check_output(cmd, cwd=cwd, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
    sys.stdout.write(output)
    print(f'END CMD: {cmd}')

if __name__ == '__main__':
    os.makedirs(ARTIFACTS_DIR, exist_ok=True)
    for python_minor in (9, 10):
        build_dir = os.path.abspath(os.path.join(ROOT_DIR, f'../steamos-devkit-py3{python_minor}'))
        interpreter = f'python3.{python_minor}'
        # using pipenv wasn't the best idea for CI, it leaves it's files in ~/.local/share/virtualenvs/,
        # and we need to wipe that too to try our best to be reproductible and idempotent
        if os.path.exists(build_dir):
            cmd = f'{interpreter} -m pipenv --python 3.{python_minor} --venv'
            print(f'Check if {build_dir} has a leftover virtualenv')
            cp = subprocess.run(cmd, cwd=build_dir, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=True, universal_newlines=True)
            if cp.returncode == 0:
                venv_dir = cp.stdout.strip('\n')
                if os.path.exists(venv_dir):
                    print(f'rmtree {venv_dir}')
                    shutil.rmtree(venv_dir)
            else:
                print(f'no virtualenv for {build_dir} to delete')
            print(f'rmtree {build_dir}')
            shutil.rmtree(build_dir)
        print(f'copytree {ROOT_DIR} -> {build_dir}')
        shutil.copytree(ROOT_DIR, build_dir)
        pipenv_cmd = f'{interpreter} -m pipenv --python 3.{python_minor} run'
        call(f'{pipenv_cmd} pip install -r requirements.txt', build_dir)
        pipenv_cmd = f'{interpreter} -m pipenv run'
        call(f'{pipenv_cmd} pip install pyimgui-wheels/imgui-2.0.0-cp3{python_minor}-cp3{python_minor}-linux_x86_64.whl', build_dir)
        call(f'{pipenv_cmd} {interpreter} ./setup/package-linux.py', build_dir)
        g = glob.glob(f'{build_dir}/devkit-gui*.pyz')
        if len(g) != 1:
            raise Exception('No .pyz build artifact produced? Aborting')
        artifact = g[0]
        print(f'copy {artifact} -> {ARTIFACTS_DIR}')
        shutil.copyfile(artifact, os.path.join(ARTIFACTS_DIR, os.path.basename(artifact)))

