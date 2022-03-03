#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import subprocess
import argparse
import tempfile
import zipfile
import shutil
import zipapp

assert sys.platform == 'linux'
assert sys.prefix != sys.base_prefix    # must be executed in the virtualenv

SETUP_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CLIENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '../client'))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Prepare a shiv package of the devkit client for Linux')
    parser.add_argument('--output-directory', required=False, action='store', default='.', help='Output directory')
    conf = parser.parse_args()

    version_tag = subprocess.check_output(['git', 'describe'], cwd=CLIENT_DIR, universal_newlines=True).strip()
    print(f'Refresh version: {version_tag}')
    open(os.path.join(CLIENT_DIR, 'devkit_client/version.py'), 'wt').write(f'__version__ = "{version_tag}"')

    print(f'Prepare shiv package for {CLIENT_DIR}')
    setup_path = os.path.join(CLIENT_DIR, 'setup.py')
    if not os.path.islink(setup_path):
        assert not os.path.exists(setup_path)
        dst_path = os.path.join(SETUP_DIR, 'shiv-linux-setup.py')
        print(f'Create symlink {setup_path} -> {dst_path}')
        os.symlink(dst_path, setup_path)
    venv_dir = subprocess.check_output('python -m pipenv --venv', shell=True, universal_newlines=True).strip()
    assert sys.version_info[0] == 3
    python_minor = sys.version_info[1]
    site_packages_dir = os.path.join(venv_dir, f'lib/python3.{python_minor}/site-packages')
    interpreter = f'/usr/bin/env python3.{python_minor}'
    output_name = f'devkit-gui-cp3{python_minor}.pyz'
    with tempfile.TemporaryDirectory() as tmpdirname:
        intermediate_path = os.path.join(tmpdirname, output_name)
        cmd=[ 'shiv',
            '--site-packages', site_packages_dir,
            '--python', interpreter,
            '--entry-point', 'devkit_client.gui2.main',
            '--output-file', intermediate_path,
            '.'
            ]
        print(f"{' '.join(cmd)}")
        subprocess.check_call(cmd, cwd=CLIENT_DIR)
        # rebuild the .pyz with the devkit-utils/ folder inserted
        with tempfile.TemporaryDirectory() as zipappdirname:
            src_dir = os.path.join(CLIENT_DIR, 'devkit-utils')
            print(f'Adding {src_dir} to the .pyz')
            z = zipfile.ZipFile(intermediate_path)
            z.extractall(zipappdirname)
            shutil.copytree(
                src_dir,
                os.path.join(zipappdirname, 'site-packages/devkit-utils')
                )
            shutil.copy(os.path.join(ROOT_DIR, 'ChangeLog'), zipappdirname)
            output_path = os.path.abspath(os.path.join(conf.output_directory, output_name))
            zipapp.create_archive(
                zipappdirname,
                output_path,
                interpreter=interpreter
            )
            print(f'Wrote {output_path}')
