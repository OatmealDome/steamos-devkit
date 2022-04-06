#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import stat
import subprocess
import glob

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

STEAMOS_DEVKIT_CI_UPLOAD_HOST=os.environ.get('STEAMOS_DEVKIT_CI_UPLOAD_HOST')
STEAMOS_DEVKIT_CI_UPLOAD_PATH=os.environ.get('STEAMOS_DEVKIT_CI_UPLOAD_PATH')
STEAMOS_DEVKIT_CI_UPLOAD_SSH_PRIVATE_KEY_FILE=os.environ.get('STEAMOS_DEVKIT_CI_UPLOAD_SSH_PRIVATE_KEY_FILE')
STEAMOS_DEVKIT_CI_UPLOAD_USER=os.environ.get('STEAMOS_DEVKIT_CI_UPLOAD_USER')

if __name__ == '__main__':
    os.chmod(STEAMOS_DEVKIT_CI_UPLOAD_SSH_PRIVATE_KEY_FILE, stat.S_IREAD)

    version_tag = subprocess.check_output(['git', 'describe'], cwd=ROOT_DIR, universal_newlines=True).strip()
    print(f'Deploy version: {version_tag}')

    src_dir = os.path.join(ROOT_DIR, 'artifacts')
    dst_dir = os.path.join(STEAMOS_DEVKIT_CI_UPLOAD_PATH, version_tag)
    latest = 'latest'
    if version_tag.find('internal') != -1:
        latest = 'latest-internal'
    latest_dir = os.path.join(STEAMOS_DEVKIT_CI_UPLOAD_PATH, latest)
    cmd = f'rsync -rv -e "ssh -o StrictHostKeyChecking=no -i {STEAMOS_DEVKIT_CI_UPLOAD_SSH_PRIVATE_KEY_FILE}" {src_dir}/ {STEAMOS_DEVKIT_CI_UPLOAD_USER}@{STEAMOS_DEVKIT_CI_UPLOAD_HOST}:{dst_dir}'
    print(cmd)
    subprocess.check_call(cmd, shell=True)

    cmd = f'ssh -o StrictHostKeyChecking=no -i {STEAMOS_DEVKIT_CI_UPLOAD_SSH_PRIVATE_KEY_FILE} {STEAMOS_DEVKIT_CI_UPLOAD_USER}@{STEAMOS_DEVKIT_CI_UPLOAD_HOST} "cd {STEAMOS_DEVKIT_CI_UPLOAD_PATH} ; ln -f -s {version_tag} {latest}"'
    print(cmd)
    subprocess.check_call(cmd, shell=True)
