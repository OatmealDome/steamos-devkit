# -*- coding: utf-8 -*-

import sys
import os
import shutil
import subprocess
import argparse
import zipfile

assert sys.platform == 'win32'          # windows only
assert sys.prefix != sys.base_prefix    # must be executed in the virtualenv

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SETUP_DIR = os.path.abspath(os.path.dirname(__file__))
CLIENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), r'..\client'))
BUILD_DIR = os.path.join(ROOT_DIR, 'build')
DIST_DIR = os.path.join(ROOT_DIR, 'dist')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Prepare a package of the devkit client for Windows')
    parser.add_argument('--refresh', required=False, action='store_true', default='.', help='Refresh only')
    conf = parser.parse_args()

    if not conf.refresh:
        for dir_path in (BUILD_DIR, DIST_DIR):
            if os.path.exists(dir_path):
                assert os.path.isdir(dir_path)
                print(f'Delete {dir_path}')
                shutil.rmtree(dir_path)

    version_tag = subprocess.check_output(['git', 'describe'], cwd=CLIENT_DIR, universal_newlines=True).strip()
    print(f'Refresh version: {version_tag}')
    open(os.path.join(CLIENT_DIR, r'devkit_client\version.py'), 'wt').write(f'__version__ = "{version_tag}"')

    print(f'Build the package')
    subprocess.check_call([r'.\Scripts\python.exe', r'.\setup\cxfreeze-windows.py', 'build'], cwd=ROOT_DIR)

    shutil.copytree(os.path.join(BUILD_DIR, 'exe.win-amd64-3.10'), DIST_DIR, dirs_exist_ok=True)

    for name in ('devkit-msvsmon', 'devkit-utils', 'gpuvis'):
        dir_path = os.path.join(CLIENT_DIR, name)
        shutil.copytree(dir_path, os.path.join(DIST_DIR, name), dirs_exist_ok=True)

    cygroot = r'C:\cygwin64\bin'
    assert os.path.isdir(cygroot)
    for name in [
        'cygpath.exe',
        'rsync.exe',
        'ssh.exe',
        'cygcrypto-1.1.dll',
        'cygwin1.dll',
        'cygz.dll',
        'cygiconv-2.dll',
        'cygcom_err-2.dll',
        'cyggcc_s-seh-1.dll',
        'cyggssapi_krb5-2.dll',
        'cygintl-8.dll',
        'cygk5crypto-3.dll',
        'cygkrb5-3.dll',
        'cygkrb5support-0.dll',
        'cyglz4-1.dll',
        'cygzstd-1.dll',
        'cygxxhash-0.dll'
        ]:
        shutil.copy(os.path.join(cygroot, name), DIST_DIR)

    shutil.copytree(os.path.join(ROOT_DIR, 'third-party-licenses'), os.path.join(DIST_DIR, 'third-party-licenses'), dirs_exist_ok=True)

    shutil.copy(os.path.join(ROOT_DIR, 'ChangeLog'), DIST_DIR)

    zippath = os.path.join(ROOT_DIR, 'devkit-gui-win64.zip')
    print(f'Creating archive: {zippath}')
    subprocess.check_call(['7z', 'a', zippath, '.'], cwd=DIST_DIR)
