#!/usr/bin/env python3
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


import contextlib
from dataclasses import dataclass
from genericpath import exists
import glob
import sys
import os
import platform
import traceback
import enum
import getpass
from io import StringIO
import json
import logging
from pathlib import Path
import queue
import shlex
import shutil
import socket
import string
import subprocess
import time
from threading import Thread
import unicodedata
import urllib
import urllib.parse
import urllib.request
import urllib.error
import webbrowser
import tempfile
import pathlib
import re

import appdirs

import paramiko
import devkit_client.zeroconf as zeroconf

try:
    import devkit_client.version
    __version__ = devkit_client.version.__version__
except:
    __version__ = '<undefined>'

# Must match Steam client ESteamPlayDebug
class SteamPlayDebug(enum.IntEnum):
    Disabled = 0
    Start = 1
    Wait = 2

STEAMOS_DEVKIT_SERVICE = "_steamos-devkit._tcp"
LOCAL_DOMAIN = "local"
DEFAULT_DEVKIT_SERVICE_HTTP = 32000

STEAM_DEVKIT_TYPE = STEAMOS_DEVKIT_SERVICE + '.' + LOCAL_DOMAIN + '.'
ZEROCONF_TIMEOUT = 10000

# Format version number for TXT record. Increment if we make an
# incompatible change that would cause current clients to parse it
# incorrectly (hopefully we will never need this). See
# https://tools.ietf.org/html/rfc6763#section-6.7
CURRENT_TXTVERS = b'1'

# A translation table that case-folds ASCII, while leaving non-ASCII
# unaltered
ASCII_LOWERCASE = str.maketrans(string.ascii_uppercase,
                                string.ascii_lowercase)

# Default urllib timeout is way too long for LAN hosts
REQUEST_TIMEOUT = 2

# Root of the installation - do not use getcwd!
if getattr(sys, 'frozen', False):
    ROOT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    ROOT_DIR = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__), '..'
        )
    )

RESTART_SDDM = '/usr/bin/steamos-polkit-helpers/steamos-restart-sddm'
REBOOT_NOW = '/usr/bin/steamos-polkit-helpers/steamos-reboot-now'

import devkit_client.proxy

logger = logging.getLogger(__name__)

SUBPROCESS_CREATION_FLAGS = 0
if platform.system() == 'Windows':
    SUBPROCESS_CREATION_FLAGS = subprocess.CREATE_NO_WINDOW


g_remote_debuggers = None
g_external_tools = None


class ResolveMachineArgs:
    def __init__(self, devkit):
        self.machine, self.machine_name_type = devkit.machine_command_args
        self.login = None
        self.http_port = devkit.http_port


@dataclass
class RemoteDebugger:
    directory: str
    year: str

def _locate_vswhere():
    assert sys.platform == 'win32'
    if 'PROGRAMFILES(X86)' in os.environ:
        # 64-bit
        program_files_path = Path(os.environ['PROGRAMFILES(X86)'])
    elif 'PROGRAMFILES' in os.environ:
        # 32-bit
        program_files_path = Path(os.environ['PROGRAMFILES'])
    else:
        logger.warning('Unable to locate the program files directory')
        return None
    vswhere_path = program_files_path / 'Microsoft Visual Studio' / 'Installer' / 'vswhere.exe'
    if not vswhere_path.is_file():
        logger.info('Unable to locate vswhere.exe, probably Visual Studio '
                    'has not been installed')
        return None
    return vswhere_path

def _locate_remote_debugger(vswhere_path, version):
    # Starting from Visual Studio 2017, the official way to locate a VS
    # installation path is by using the provided "vswhere" executable.
    assert sys.platform == 'win32'
    if not vswhere_path:
        return
    # E.g. if version is 15, we will end up with "[15,16)",
    # meaning that we start looking from the version 15 up to
    # version 16, excluded.
    version_range = f"[{version},{version+1})"
    vs_install_path = subprocess.check_output(
        [str(vswhere_path), '-latest', '-version', version_range, '-prerelease', '-property', 'installationPath'],
        universal_newlines=True,
        creationflags=SUBPROCESS_CREATION_FLAGS,
    ).strip('\n')
    if not vs_install_path:
        logger.info(f'Unable to locate the installation path of Visual Studio {version}')
        return None
    remote_debugger = Path(vs_install_path) / 'Common7' / 'IDE' / 'Remote Debugger'
    return str(remote_debugger) if remote_debugger.is_dir() else None

def get_remote_debuggers():
    assert sys.platform == 'win32'
    global g_remote_debuggers
    if g_remote_debuggers is not None:
        return g_remote_debuggers
    ret = []
    vswhere_path = _locate_vswhere()
    # Look for Visual Studio 15 (2017) and 16 (2019)
    for version, year in [[15, 2017], [16, 2019], [17, 2022]]:
        debugger_dir = _locate_remote_debugger(vswhere_path, version)
        if debugger_dir:
            ret.append(RemoteDebugger(debugger_dir, year))

    g_remote_debuggers = ret
    return g_remote_debuggers


def _locate_external_tool(name):
    assert sys.platform == 'win32'
    if getattr(sys, 'frozen', False):
        # Scripts that were frozen into a standalone executable via cx_freeze are expected to package the binaries
        tools_path = os.path.dirname(sys.executable)
        ret = os.path.join(tools_path, 'cygroot/bin', name)
        assert os.path.exists(ret)
        return ret
    # Running from source:
    # Locate a cygwin version. That's what we package. Windows ssh.exe isn't a compatible transport for rsync for instance
    # NOTE: we could do better at locating the cygwin install
    ret = os.path.join(r'C:\cygwin64\bin', name)
    if os.path.exists(ret):
        return ret
    # Last ditch attempt, look for the first thing in PATH
    ret = shutil.which(name)
    if ret is not None:
        return ret
    raise Exception('Required external tool not found: {!r}'.format(name))

def locate_external_tools():
    '''Returns a tuple of paths (cygpath, ssh, rsync, ssh_know_hosts)'''
    global g_external_tools
    if g_external_tools is not None:
        return g_external_tools
    if sys.platform != 'win32':
        g_external_tools = (None, 'ssh', 'rsync', None)
        return g_external_tools

    cygpath = _locate_external_tool('cygpath.exe')
    ssh = _locate_external_tool('ssh.exe')
    rsync = _locate_external_tool('rsync.exe')

    # we used to require USERNAME being set - but not anymore
    # still, since I don't know of legitimate Window configurations where USERNAME wouldn't be set,
    # I'm leaving this check so there is at least a warning about this
    USERNAME = os.getenv('USERNAME')
    if USERNAME is None:
        try:
            # I don't trust this module, especially under cx_Freeze, so only do a late import
            logger.warning('USERNAME is empty, trying from win32api')
            import win32api
            USERNAME = win32api.GetUserName()
            logger.warning(f'Obtained USERNAME from win32api: {USERNAME}')
        except Exception as e:
            log_exception(e)
            logger.error(f'USERNAME environment variable is not set on this system.')

    USERPROFILE = os.getenv('USERPROFILE')
    if USERPROFILE is None:
        # said system has USERPROFILE though .. smh
        import pprint
        logger.error(pprint.pformat(dict(os.environ)))
        raise Exception(f'Unexpected: no USERPROFILE in your environment variables - please fix.')

    # cygwin's ssh.exe (which we wrap and distribute in the frozen build) seems to ignore the HOME environment
    # and expands ~/.ssh/known_hosts (for instance) relative to the location of the .exe,
    # which ends up putting it in some really odd locations, and sometimes even paths that it does not have write permissions to
    # for us this is only a problem with ~/.ssh/known_hosts although it could bleed to other configuration files
    # to avoid problems, we explicitly set UserKnownHostsFile

    dotssh_path = str(pathlib.PureWindowsPath(USERPROFILE, '.ssh'))
    if not os.path.isdir(dotssh_path):
        logger.info(f'creating "~/.ssh" path (based on USERPROFILE): {dotssh_path!r}')
        try:
            os.makedirs(dotssh_path)
        except Exception as e:
            log_exception(e)
            raise Exception(f'Unexpected: cannot create {dotssh_path!r} based on your USERPROFILE environment variable -- please fix.')

    ssh_known_hosts = str(pathlib.PureWindowsPath(USERPROFILE, '.ssh', 'known_hosts'))
    logger.info(f'Forcing ssh known_hosts path to {ssh_known_hosts!r}')
    g_external_tools = (cygpath, ssh, rsync, ssh_known_hosts)
    return g_external_tools


def parse_settings_arguments(jsonobject, args):
    if getattr(args, 'clear_settings', False):
        jsonobject['clear_settings'] = True

    for settings_file in getattr(args, 'settings_file', []):
        logger.info("settings-file given, reading %s", settings_file)

        try:
            with open(settings_file, "r") as f:
                jsonobject['settings'].update(json.load(f))
        except (IOError, FileNotFoundError):
            raise ValueError("Unable to read json settings file %s",
                             settings_file)

    for value in getattr(args, 'set_json', []):
        logger.info("set-json used, adding json string to settings")
        pair = value.split('=', 1)
        if len(pair) != 2:
            raise ValueError("set-json arguments require name=value,"
                             " %s is invalid", value)

        jsonobject['settings'][pair[0]] = json.loads(pair[1])

    for value in getattr(args, 'set', []):
        logger.info("set used, adding given settings")
        pair = value.split('=', 1)
        if len(pair) != 2:
            raise ValueError("set arguments must be name=value, %s is invalid",
                             value)

        jsonobject['settings'][pair[0]] = pair[1]

    deps = getattr(args, 'deps')
    if deps:
        logger.info("deps used, adding given dependencies")
        jsonobject['settings']['deps'] = deps


def log_exception(e):
    # https://stackoverflow.com/a/11415140/1043757
    lines = [l.strip('\n') for l in traceback.format_exception(type(e), e, e.__traceback__)]
    for l in lines:
        logger.error(l)


def stream_byte_copy_thread(source, dest):
    buf = source.read()

    while buf:
        try:
            dest.write(buf)
        except TypeError:
            dest.write(str(buf))
        buf = source.read()


def stream_copy_logger(source, dest):
    buf = source.readline()

    while buf:
        dest.info(buf)
        buf = source.readline()


class MachineNotFoundError(Exception):
    def __init__(self, message, *, name=None):
        super().__init__(message)
        self.name = name


class MachineNameType(enum.Enum):
    GUESS = 0
    ADDRESS = 1
    SERVICE_NAME = 2

    def __repr__(self):
        return '<{}.{}>'.format(self.__class__.__name__, self.name)


class ServiceListener(object):
    def __init__(self, quiet=False):
        self.r = zeroconf.Zeroconf()
        self.devkits = {}
        self.devkit_events = queue.Queue()
        self.quiet = quiet

    def __del__(self):
        if self.r is not None:
            self.r.close()
            self.r = None

    def remove_service(self, zeroconf, type, name):
        # Called from the zeroconf thread
        assert type == STEAM_DEVKIT_TYPE, (name, type)
        assert name.endswith('.' + type), (name, type)
        service_name = name[:-len('.' + type)]
        if (not self.quiet):
            logger.info("Service %r removed", service_name)
        if not service_name in self.devkits:
            logger.warning("Service %r not found", service_name)
            return
        del self.devkits[service_name]
        self.devkit_events.put(('del', service_name))

    def add_service(self, zeroconf, type, name):
        # Called from the zeroconf thread
        assert type == STEAM_DEVKIT_TYPE, (name, type)
        assert name.endswith('.' + type), (name, type)
        service_name = name[:-len('.' + type)]
        if (not self.quiet):
            logger.info("Service %r found", service_name)
        get_service_delay = time.perf_counter()
        info = self.r.get_service_info(type, name, timeout=ZEROCONF_TIMEOUT)
        get_service_delay = time.perf_counter() - get_service_delay
        if not self.quiet:
            logger.debug(f'zeroconf.get_service_info: {get_service_delay:.1f}')
        if info:
            if not self.quiet:
                logger.info(
                    "  Address is %s:%d",
                    socket.inet_ntoa(info.addresses[0]), info.port)
                logger.info(
                    "  Weight is %d, Priority is %d",
                    info.weight, info.priority)
                logger.info("  Server is %s", info.server)
            prop = info.properties
            if prop:
                if not self.quiet:
                    logger.info("  Properties are:")
                    for key, value in prop.items():
                        logger.info("    %s: %s", key, value)

                if b'txtvers' in prop and prop[b'txtvers'] != CURRENT_TXTVERS:
                    logger.warning(
                        'Incompatible txtvers %r, ignoring %s',
                        prop[b'txtvers'], service_name)
                    return

            self.devkits[service_name] = info
            self.devkit_events.put(('add', service_name))

    def address_for_service(self, name):
        if not name in self.devkits:
            return None
        info = self.devkits[name]
        return socket.inet_ntoa(info.addresses[0])

    def port_for_service(self, name):
        if not name in self.devkits:
            return DEFAULT_DEVKIT_SERVICE_HTTP
        info = self.devkits[name]
        return info.port

    def update_service(self, *args):
        pass


def get_public_key_comment():
    return ' devkit-client:{}@{}'.format(
        getpass.getuser(),
        socket.gethostname(),
    )


def get_public_key(key):
    public_key = (
        'ssh-rsa ' + key.get_base64() + get_public_key_comment() + '\n')
    return public_key


def ensure_devkit_key():
    key_folder = appdirs.user_config_dir('steamos-devkit')
    key_path = os.path.join(key_folder, 'devkit_rsa')
    pubkey_path = os.path.join(key_folder, 'devkit_rsa.pub')
    try:
        key = paramiko.RSAKey.from_private_key_file(key_path)
    except (IOError, FileNotFoundError):
        try:
            os.makedirs(key_folder)
        except (FileExistsError):
            pass
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(key_path)
        o = open(pubkey_path, 'w')
        o.write(get_public_key(key))
    if platform.system() == 'Linux':
        # enforce/fix file permissions
        os.chmod(key_path, 0o400)
        os.chmod(pubkey_path, 0o400)
    return (key, key_path, pubkey_path)


class DevkitClient(object):
    def __init__(self, quiet=True):
        self.keypath = os.path.join(
            appdirs.user_config_dir('steamos-devkit'),
            'devkit_rsa',
        )
        (self.cygpath, self.ssh, self.rsync, self.ssh_known_hosts) = locate_external_tools()
        self.ssh_result = {}
        self.last_device_list_time = 0
        self.rsync_process = None

    def machine_readable_command_reader_thread(self, command_stdout):
        json_output = str(command_stdout.read(), 'utf-8')
        try:
            self.ssh_result = json.loads(json_output)
        except Exception as e:
            logger.error('output does not parse as json:')
            logger.error('%s', json_output)
            self.ssh_result = e

    def remote_shell_command(self, username, ipaddress):
        cmd = [
            # NOTE: this is the path to the ssh client, and may contain spaces (especially likely on windows)
            self.ssh
        ]
        if self.ssh_known_hosts is not None:
            cmd += [
                '-o', f'UserKnownHostsFile={self.ssh_known_hosts}',
            ]
        cmd += [
            '-o', 'StrictHostKeyChecking=no',
            '-o', 'IdentitiesOnly=yes',
            '-t',
            '-i', self.keypath,
            '{}@{}'.format(username, ipaddress),
        ]
        return cmd

    def live_ssh_command(self, username, ipaddress, command):
        logger.debug('%s@%s: %s', username, ipaddress, command)
        cmd = self.remote_shell_command(username, ipaddress)
        cmd.append(command)
        exit_status = subprocess.call(
            cmd,
            creationflags = SUBPROCESS_CREATION_FLAGS
        )

        logger.info("exit status is %d", exit_status)

        if exit_status != 0:
            raise subprocess.CalledProcessError(exit_status, command)

    def ssh_command(
            self, username, ipaddress, command, stdindata,
            stream_output_to=None
        ):
        logger.debug('%s@%s: %s', username, ipaddress, command)
        ssh = paramiko.SSHClient()
        key, key_path, _ = ensure_devkit_key()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        logger.debug(f'Connecting to {username}@{ipaddress} with private key {key_path!r}')

        ssh.connect(
            ipaddress,
            username=username,
            pkey=key,
            timeout=REQUEST_TIMEOUT
            )

        stdin, stdout, stderr = ssh.exec_command(command)
        chan = stdout.channel

        stderr_thread = Thread(target=stream_copy_logger,
                               args=(stderr, logger))
        stderr_thread.start()
        if stream_output_to is not None:
            stdout_thread = Thread(
                target=stream_byte_copy_thread,
                args=(stdout, stream_output_to))
        else:
            # stdout will be json data
            stdout_thread = Thread(
                target=self.machine_readable_command_reader_thread,
                args=(stdout,))

        stdout_thread.start()

        # Send stdin data if there is any
        if stdindata is not None:
            logger.info("Writing stdin data to command input: %r", stdindata)
            stdin.write(stdindata)
            stdin.flush()
            stdin.channel.shutdown_write()
        stdin.close()

        exit_status = chan.recv_exit_status()

        stdout_thread.join()
        stderr_thread.join()

        if stream_output_to is not None:
            # output is not None, so just return since output went to it already
            return

        json_or_exception = self.ssh_result

        logger.info("exit status: %d", exit_status)

        ssh.close()

        if exit_status != 0:
            raise subprocess.CalledProcessError(exit_status, command)

        if isinstance(json_or_exception, Exception):
            raise json_or_exception
        else:
            # json_or_exception is stdout output
            return json_or_exception

    def on_cancel_transfer(self, **kwargs):
        if self.rsync_process:
            self.rsync_process.terminate()

    def rsync_transfer(
        self,
        localdir,
        user,
        ipaddress,
        remotedir,
        delete_extraneous = False, # delete extraneous files on the remote
        skip_newer_files = False, # leave files with a newer modification time untouched, allows local changes on the remote
        verify_checksums = False, # force checksum content verification
        upload = True, # uploading to remote by default
        extra_cmdline = [], # additional command line parms, typically content filtering
    ):
        '''Folder transfers. Either direction, controlled by the upload parm'''

        if not os.path.isdir(localdir):
            raise Exception(f'Source directory does not exist: {localdir}')
        if sys.platform == 'win32':
            localdir = self.native_to_cygwin_path(localdir)

        cmd = [
            self.rsync,
            "-av",
            "--chmod=Du=rwx,Dgo=rx,Fu=rwx,Fog=rx",
            "-e", '{} {} -o StrictHostKeyChecking=no -i {}'.format(
                shlex.quote(self.ssh),
                '-o UserKnownHostsFile={}'.format(shlex.quote(self.ssh_known_hosts)) if self.ssh_known_hosts else '',
                shlex.quote(self.keypath),
            )
        ]
        if delete_extraneous:
            cmd += ['--delete', '--delete-excluded', '--delete-delay']
        if skip_newer_files:
            cmd += ['--update']
        if verify_checksums:
            if skip_newer_files:
                # UI expected to prevent this
                logger.warning('WARNING: combining --update and --checksum in rsync command line - may cause unexpected behavior.')
            cmd += ['--checksum']
        cmd += extra_cmdline
        # NOTE: we force folder to folder here with the trailing /
        # makes the function easier to use but limits our ability to pull remote patterns..
        upload_cmd = [
            '{}/'.format(localdir.rstrip('/')),
            '{}@{}:{}/'.format(user, ipaddress, remotedir.rstrip('/')),
        ]
        if not upload:
            upload_cmd.reverse()
        cmd += upload_cmd
        logger.info(shlex.join(cmd))
        self.rsync_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            creationflags=SUBPROCESS_CREATION_FLAGS,
            )
        while True:
            output = self.rsync_process.stdout.readline()
            if output == b'' and self.rsync_process.poll() is not None:
                break
            if output:
                logger.info(output.decode('utf-8').strip())
        retcode = self.rsync_process.wait()
        self.rsync_process = None
        if retcode != 0:
            raise subprocess.CalledProcessError(retcode, cmd)
        return retcode

    def test_cygpath(self, _path):
        # had to move the cygpath.exe under cygroot/bin/ to avoid the path above the binary to get interpreted as '/' (root)
        logger.info('DBG: testing cygpath.exe behavior, see https://cygwin.com/pipermail/cygwin/2022-June/251750.html')
        wp = pathlib.WindowsPath(_path)
        for i in range(1, len(wp.parts)+1):
            cwp = pathlib.WindowsPath(*wp.parts[:i])
            path = str(cwp)
            cmd=[self.cygpath, path]
            p = subprocess.Popen(
                cmd,
                creationflags=SUBPROCESS_CREATION_FLAGS,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            output = str(p.communicate()[0], 'utf-8')
            s_cmd = ' '.join(cmd)
            logger.info(f'DBG: {s_cmd!r}: {p.returncode} {output!r}')

    def native_to_cygwin_path(self, path):
        p = subprocess.Popen(
            [
                self.cygpath,
                path,
            ],
            creationflags=SUBPROCESS_CREATION_FLAGS,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        output = str(p.communicate()[0], 'utf-8')
        logger.debug(output)
        assert p.returncode == 0
        return output.split('\n')[0]


class Machine:
    def __init__(self, name, devkit1=(), login=None, http_port=DEFAULT_DEVKIT_SERVICE_HTTP):
        self.address = name
        self.name = name
        self.normalized_name = name
        self.login = login
        self.devkit1 = devkit1
        self.settings = {}
        self._http_port = http_port

    @property
    def http_port(self):
        return self._http_port


@contextlib.contextmanager
def zeroconf_context():
    zc = zeroconf.Zeroconf()
    try:
        yield zc
    finally:
        zc.close()


def resolve_machine(name, devkit1=(), login=None, need_login=True,
                    need_devkit1=True, name_type=MachineNameType.GUESS,
                    http_port=DEFAULT_DEVKIT_SERVICE_HTTP):
    machine = Machine(name, devkit1=devkit1, login=login, http_port=http_port)

    if name_type is MachineNameType.SERVICE_NAME:
        # Make .local. equivalent to .local
        name = name.rstrip('.')

        # Make .local optional
        if name.endswith('.' + LOCAL_DOMAIN):
            name = name[:-len('.' + LOCAL_DOMAIN)]

        # Make ._steamos-devkit._tcp optional
        if name.endswith('.' + STEAMOS_DEVKIT_SERVICE):
            name = name[:-len('.' + STEAMOS_DEVKIT_SERVICE)]

        machine.name = name
        instance_name = name + '.' + STEAM_DEVKIT_TYPE

        logger.info("Looking for machine with service name: %s", machine.name)
        logger.debug("DNS-SD instance name: %s", instance_name)

        with zeroconf_context() as zc:
            get_service_delay = time.perf_counter()
            info = zc.get_service_info(STEAM_DEVKIT_TYPE, instance_name, timeout=ZEROCONF_TIMEOUT)
            get_service_delay = time.perf_counter() - get_service_delay
            logger.debug(f'zeroconf.get_service_info: {get_service_delay:.1f}')

            if info:
                logger.debug("Machine found")
                if len(info.addresses) <= 0:
                    raise MachineNotFoundError(
                        'DNS-SD instance did not publish an IP address yet: {!r}'.format(instance_name),
                        name=machine.name
                    )
                machine.address = socket.inet_ntoa(info.addresses[0])
                logger.info("Machine IP: %s", machine.address)

                if info.properties:
                    settings = info.properties.get(b'settings')
                    if settings is not None:
                        machine.settings = json.loads(settings)

                    if machine.login is None:
                        login = info.properties.get(b'login')
                        if login is not None:
                            machine.login = login.decode('utf-8')
                            logger.debug("Machine login: %s", machine.login)

                        devkit1 = info.properties.get(b'devkit1')
                        if devkit1 is not None:
                            machine.devkit1 = shlex.split(devkit1.decode('utf-8'))
                            logger.debug("devkit-1 entry point: %s", machine.devkit1)
            else:
                raise MachineNotFoundError(
                    'Unable to find a devkit named "{}"'.format(machine.name),
                    name=machine.name)

            # mDNS is ASCII-case-insensitive, like normal DNS, and defines
            # UTF-8 to be fully composed.
            machine.normalized_name = unicodedata.normalize(
                'NFC', machine.name.translate(ASCII_LOWERCASE).rstrip('.'))

    elif name_type is MachineNameType.ADDRESS:
        # name is (assumed to be) a resolvable DNS hostname.
        # Normalize by squashing to lower case (DNS is case-insensitive
        # for ASCII) and stripping any trailing '.', but continue to use
        # what the user typed on the command-line as machine.address
        machine.normalized_name = machine.name.translate(
            ASCII_LOWERCASE).rstrip('.')

    else:
        assert name_type is MachineNameType.GUESS

        if name.endswith((  # any of:
            '.' + STEAM_DEVKIT_TYPE,
            '.' + STEAMOS_DEVKIT_SERVICE + '.' + LOCAL_DOMAIN,
            '.' + STEAMOS_DEVKIT_SERVICE + '.',
            '.' + STEAMOS_DEVKIT_SERVICE,
        )):
            return resolve_machine(
                name, devkit1=devkit1, login=login, need_login=need_login,
                need_devkit1=need_devkit1,
                name_type=MachineNameType.SERVICE_NAME,
                http_port=machine.http_port
            )
        elif '.' in name:
            return resolve_machine(
                name, devkit1=devkit1, login=login, need_login=need_login,
                need_devkit1=need_devkit1,
                name_type=MachineNameType.ADDRESS,
                http_port=machine.http_port
            )
        else:
            try:
                return resolve_machine(
                    name, devkit1=devkit1, login=login, need_login=need_login,
                    need_devkit1=need_devkit1,
                    name_type=MachineNameType.SERVICE_NAME,
                    http_port=machine.http_port
                )
            except MachineNotFoundError as e:
                # treat as if it was an ADDRESS, and fall through to looking
                # up the login name if necessary
                logger.warning('%s; assuming resolvable address instead', e)

    # If necessary, ask the server which user to log in as
    if ((machine.login is None or not machine.devkit1) and
            (need_login or need_devkit1)):
        logger.debug('Requesting /properties.json')
        request = urllib.request.Request(f'http://{machine.address}:{machine.http_port}/properties.json')
        try:
            result = urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT
                )
        except socket.error as e:
            pass
        else:
            json_object = json.load(result)
            logger.debug('-> %r', json_object)

            if 'settings' in json_object:
                machine.settings = json.loads(json_object['settings'])

            if 'devkit1' in json_object:
                devkit1 = json_object['devkit1']

                if isinstance(devkit1, str):
                    machine.devkit1 = (devkit1,)
                else:
                    machine.devkit1 = tuple(devkit1)

            if 'login' in json_object:
                machine.login = json_object['login']

    # Backwards compatibility
    if machine.login is None and need_login:
        logger.debug('Requesting /login-name')
        request = urllib.request.Request(f'http://{machine.address}:{machine.http_port}/login-name')
        try:
            result = urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT
                )
        except urllib.error.HTTPError as e:
            logger.error(
                "The devkit returned HTTP error %d",
                e.code)
            logger.error(
                "Additional output: %s",
                e.file.read().decode('utf-8', 'replace'))
        except socket.error as e:
            logger.error(
                "Unable to connect to devkit on that address. "
                "Check the devkit is running: %s", e)
        else:
            machine.login = result.read().decode('utf-8', 'strict').strip()

    return machine


MAGIC_PHRASE = '900b919520e4cf601998a71eec318fec'

def register(args):
    key, _, _ = ensure_devkit_key()

    machine = resolve_machine(
        args.machine,
        name_type=args.machine_name_type,
        # we will not be executing a ssh command, so this can be skipped
        need_login=False,
        need_devkit1=False,
        http_port=getattr(args, 'http_port', DEFAULT_DEVKIT_SERVICE_HTTP),
    )

    logger.info("Registering with devkit at ip: %s", machine.address)

    data = get_public_key(key)
    # Right now we don't have a pairing dialog mechanism in place on the target machines
    # Someone discovering this port open in the wild could get lucky, pass a key and get registered
    # Add some random 'signature' token to reduce the luck factor a little bit
    # Of course if someone is eavesdropping on the traffic, or gains access to either this source or the approve-ssh-key, this falls apart too
    data = data.strip('\n') + ' ' + MAGIC_PHRASE + '\n'

    # Now that we have a key, register it
    request = urllib.request.Request(
        f'http://{machine.address}:{machine.http_port}/register',
        data=data.encode('ascii'),
        headers={'Content-Type': 'text/plain'},
        method='POST'
        )
    return urllib.request.urlopen(
        request,
        # If there is a prompt in the Steam client, this may take a while
        timeout=30
        )


def read_game_details(machine, gamename):
    game_folder = os.path.join(
        appdirs.user_config_dir('steamos-devkit'), "games")

    path = os.path.join(game_folder, gamename + ".json")
    jsondata = '{}'

    try:
        with open(path, "r") as f:
            jsondata = f.read()
    except (IOError, FileNotFoundError):
        return None

    json_object = json.loads(jsondata)
    if machine in json_object:
        return json_object[machine]
    else:
        return None


def save_game_details(name, machine, username, gameid, destdir):
    game_folder = os.path.join(
        appdirs.user_config_dir('steamos-devkit'), "games")
    try:
        os.makedirs(game_folder)
    except (FileExistsError):
        pass

    path = os.path.join(game_folder, name + ".json")
    jsondata = '{}'
    try:
        with open(path, "r") as f:
            jsondata = f.read()
    except (IOError, FileNotFoundError):
        pass

    # parse json data
    json_object = json.loads(jsondata)

    json_object[machine] = {
        "destdir": destdir,
        "gameid": gameid,
        "username": username,
    }

    try:
        with open(path + ".new", "w") as f:
            json.dump(json_object, f)
        os.replace(path + '.new', path)
    except (IOError):
        logger.error("Unable to write settings for game data to %s", path)


def list_games(args):
    logger.info(f'List games on {args.machine}')

    (ssh, client, machine) = _open_ssh_for_args_all(args)

    (out_text, _, _) = _simple_ssh(ssh, f'python3 ~/devkit-utils/steamos-list-games', check_status=True)
    json_output = json.loads(out_text)
    return json_output


def new_or_ensure_game(args):
    logger.info(f'Create/update {args.name} on {args.machine}')

    (ssh, client, machine) = _open_ssh_for_args_all(args)

    gameid = args.name
    (out_text, _, _) = _simple_ssh(ssh, f'python3 ~/devkit-utils/steamos-prepare-upload --gameid {gameid}', check_status=True)
    #logger.debug(f'steamos-prepare-upload: {out_text}')
    json_output = json.loads(out_text)

    user = json_output['user']
    destdir = json_output['directory']

    logger.info("Performing rsync of files")
    args.cancel_signal.connect(client.on_cancel_transfer)
    client.rsync_transfer(
        args.directory,
        user,
        machine.address,
        destdir,
        delete_extraneous = args.delete_extraneous,
        skip_newer_files = args.skip_newer_files,
        verify_checksums = args.verify_checksums,
        upload = True,
        extra_cmdline = args.filter_args
    )

    if args.steam_play_debug != SteamPlayDebug.Disabled:
        if get_remote_debuggers() is not None:
            ssh = _open_ssh_for_args(args)
            sftp = ssh.open_sftp()

            remote_home, _, _ = _simple_ssh(ssh, f'realpath ~', silent=True, check_status=True)
            remote_home = remote_home.strip('\n')

            # Transfer the bundled devkit-msvsmon content: patch and remote setup script
            msvsmon_devkit_local_path = os.path.join(ROOT_DIR, 'devkit-msvsmon')
            assert os.path.exists(msvsmon_devkit_local_path)
            msvsmon_remote_path = f'{remote_home}/devkit-msvsmon'
            client.rsync_transfer(
                msvsmon_devkit_local_path,
                user,
                machine.address,
                msvsmon_remote_path
            )

            # Transfer the remote debugging tools that will be deployed
            for remote_debugger in get_remote_debuggers():
                msvsmon_remote_path_sub = f'{remote_home}/devkit-msvsmon/msvsmon{remote_debugger.year}'
                client.rsync_transfer(
                    remote_debugger.directory,
                    user,
                    machine.address,
                    msvsmon_remote_path_sub
                )

            # Drop in additional webservices.dll to work around a bug in current Proton release
            webservices_x86 = r'C:\Windows\SysWOW64\webservices.dll'
            webservices_x64 = r'C:\Windows\System32\webservices.dll'
            assert os.path.exists(webservices_x86) and os.path.exists(webservices_x64)
            for remote_debugger in get_remote_debuggers():
                sftp.put(webservices_x86, f'{remote_home}/devkit-msvsmon/msvsmon{remote_debugger.year}/x86/webservices.dll')
                sftp.put(webservices_x64, f'{remote_home}/devkit-msvsmon/msvsmon{remote_debugger.year}/x64/webservices.dll')

            if args.steam_play_debug == SteamPlayDebug.Wait:
                # Locate and copy the backend DLLs that support the follow child process functionality
                logger.info('Locate and copy child process extension DLL:')
                success = False
                extensions_root = os.path.join(appdirs.user_data_dir(), r'microsoft\visualstudio')
                for extension_dir in os.listdir(extensions_root):
                    if extension_dir.startswith('15.0_'):
                        year = '2017'
                    elif extension_dir.startswith('16.0_'):
                        year = '2019'
                    elif extension_dir.startswith('17.0_'):
                        year = '2022'
                    else:
                        continue
                    glob_pattern = os.path.join(extensions_root, extension_dir, 'Extensions')
                    glob_pattern += r'\**\ChildProcessDebuggerBackend.dll'
                    # logger.debug(f'glob pattern: {glob_pattern!r}')
                    for srcpath in glob.glob(glob_pattern, recursive=True):
                        bitness = os.path.split(os.path.split(srcpath)[0])[1]
                        # logger.debug(bitness)
                        if not bitness in ('x86', 'x64'):
                            continue
                        dstpath = f'{remote_home}/devkit-msvsmon/msvsmon{year}/{bitness}/ChildProcessDebuggerBackend.dll'
                        logger.info(f'Transfer {srcpath} -> {dstpath}')
                        sftp.put(srcpath, dstpath)
                        # good enough: let's assume we're fine as soon as we see something
                        # things could still be bad, extension installed for the wrong visual studio, bitness missing etc. .. oh well
                        success = True
                if not success:
                    raise Exception('The Microsoft Child Process Debugging Power Tool extension could not be located.\nThis is required in order to enable the wait for attach feature.\nPlease check documentation on partner site.\n')

            # NOTE: we specify the python interpreter, so even though msvsmoninstall.py is CRLF it gets executed correctly
            command = 'python3 ~/devkit-msvsmon/msvsmoninstall.py'
            _simple_ssh(ssh, command, check_status=True)
        else:
            raise Exception('Cannot setup the remote debug tools. Please install the Visual Studio remote debugging tools on your development system.')

    jsonobject = {
        'gameid': gameid,
        'directory': destdir,
        'argv': args.argv,
        'settings': {},
    }

    parse_settings_arguments(jsonobject, args)

    if gameid.lower() != 'steam':
        # the parameter generation is too convoluted for flat command line arguments, so we just pass a json blob
        (out_text, _, _) = _simple_ssh(ssh, f'python3 ~/devkit-utils/steam-client-create-shortcut --parms {shlex.quote(json.dumps(jsonobject))}', check_status=True)
        #logger.debug(f'steam-client-create-shortcut: {out_text}')
        json_output = json.loads(out_text)
        if 'error' in json_output:
            # Does that work to bring a popup?
            raise Exception(json_output['error'])
        logger.info(json_output['success'])
    else:
        # if the steam side loaded client was already running, then we just paved over it with our upload!
        # under those conditions, the game-updated hook often gets stuck or throws exceptions
        # (because the steam process is still running, but badly mangled and unresponsive)
        # really, we should stop steam and keep gamescope in a holding pattern before we upload ..
        # we still need to write a few critical files though, let's reproduce the useful bits of game-updated here:

        remote_path, _, _ = _simple_ssh(ssh, f'realpath ~/devkit-game', silent=True, check_status=True)
        remote_path = remote_path.strip('\n')

        argv_fd, argv_path = tempfile.mkstemp(prefix=f'{gameid}-argv.json', text=True)
        json.dump(jsonobject['argv'], open(argv_path, 'wt'))
        settings_fd, settings_path = tempfile.mkstemp(prefix=f'{gameid}-settings.json', text=True)
        json.dump(jsonobject['settings'], open(settings_path, 'wt'))

        sftp = ssh.open_sftp()
        sftp.put(argv_path, str(pathlib.PurePosixPath(remote_path, f'{gameid}-argv.json')))
        sftp.put(settings_path, str(pathlib.PurePosixPath(remote_path, f'{gameid}-settings.json')))

        os.close(argv_fd)
        os.unlink(argv_path)
        os.close(settings_fd)
        os.unlink(settings_path)

    return True


def set_steam_client(args):
    # Supported incoming args.name values:
    # None, 'default' or 'SteamStatus.OS': reset to the default OS client
    # 'SteamStatus.OS_DEV': setup the default OS client in 'dev mode'
    # 'steam' or 'SteamStatus.SIDE': setup the side loaded Steam client
    if args.name is None or args.name == 'default':
        args.name = 'SteamStatus.OS'
    elif args.name == 'steam':
        args.name = 'SteamStatus.SIDE'
    logger.info(
        "Setting the steam client for the main session to %r on machine %r",
        args.name,
        args.machine
    )
    command = f'python3 ~/devkit-utils/steamos-set-steam-client --client {args.name}'
    if args.command is not None:
        command += f' --command {shlex.quote(args.command)}'
    if args.args is not None:
        command += f' --args {shlex.quote(args.args)}'
    if args.gdbserver:
        command += ' --gdbserver'
    ssh = _open_ssh_for_args(args)
    (_, _, exit_status) = _simple_ssh(ssh, command)
    if exit_status != 0:
        raise Exception('Failed to set steam client, please see status window.')

def sync_logs(args):
    client = DevkitClient()
    logger.info(
        "Sync logs files from machine %s to %s",
        args.machine, args.local_folder)

    machine = resolve_machine(
        args.machine, name_type=args.machine_name_type,
        http_port=getattr(args, 'http_port', DEFAULT_DEVKIT_SERVICE_HTTP),
    )

    local_steamlogs_folder = os.path.join(args.local_folder, 'steam_logs')
    os.makedirs(local_steamlogs_folder, exist_ok=True)

    client.rsync_transfer(
        local_steamlogs_folder,
        machine.login,
        machine.address,
        f'/home/{machine.login}/.local/share/Steam/logs',
        delete_extraneous = False,
        skip_newer_files = False,
        verify_checksums = False,
        upload = False,
    )

    local_minidump_folder = os.path.join(args.local_folder, 'minidump')
    os.makedirs(local_minidump_folder, exist_ok=True)

    client.rsync_transfer(
        local_minidump_folder,
        machine.login,
        machine.address,
        '/tmp/dumps',
        delete_extraneous = False,
        skip_newer_files = False,
        verify_checksums = False,
        upload = False,
    )


# Open a remote shell, or execute a command interactively against a device
# This is handy for privileged operations (sudo) and remote CLI interactions
def remote_shell(args, remote_commands=None):
    client = DevkitClient()
    logger.info(
        "Open remote shell to %s", args.machine
    )
    machine = resolve_machine(
        args.machine,
        login=args.login,
        need_login=True, need_devkit1=True,
        name_type=args.machine_name_type,
        http_port=getattr(args, 'http_port', DEFAULT_DEVKIT_SERVICE_HTTP),
    )
    ssh_command = client.remote_shell_command(
        machine.login,
        machine.address
    )
    if remote_commands is not None:
        assert type(remote_commands) is list
        ssh_command += remote_commands
    return run_in_terminal(ssh_command)

# Returns the child process
def run_in_terminal(commands):
    cwd = os.getcwd()
    creationflags=0
    if platform.system() == 'Windows':
        # After a bunch of iteration, writing a ps1 script and running it from the ssh.exe directory seems the most reliable
        # trying to pass all command line parameters with a direct powershell.exe invocation runs into a nightmare of path escaping business
        # this also enables us to provide better error handling and diagnostics
        ssh_path = commands[0]
        cwd = os.path.dirname(ssh_path)
        ssh_exe = rf'.\{os.path.basename(ssh_path)}'
        with tempfile.NamedTemporaryFile(
            mode='wt',
            prefix='devkit-remote-shell',
            suffix='.ps1',
            delete=False, # we just leak those .. whatever
        ) as batch:
            logging.info(f'Writing and executing {batch.name}:')
            args_list = ','.join(f'"{c}"' for c in commands[1:])
            # NOTE: exit codes from the remote command script/shell are not propagated back out .. maybe force a pause when debug is on?
            cmd = f"""
# All errors are Terminating errors
$ErrorActionPreference = 'Stop'
try {{
    cd "{cwd}"
    Start-Process -NoNewWindow -Wait -FilePath {ssh_exe} -ArgumentList {args_list}
}} catch {{
    pause
    Exit -1
}}
# Bit of a catch-all since we don't have good error propagation, maybe remove once this proves reliable?
Start-Sleep -Seconds 3
"""
            batch.write(cmd)
            batch.flush()
            commands = ['powershell.exe', '-ExecutionPolicy', 'Bypass', batch.name]
        # ensures we get a separate console when running out of a shell with pipenv
        creationflags=subprocess.CREATE_NEW_CONSOLE
    else:
        matched = False
        for terminal_prefix in (
            ['konsole', '-e'],
            ['gnome-terminal', '--'],
            ['xterm', '-e'],
        ):
            if shutil.which(terminal_prefix[0]) is not None:
                commands = terminal_prefix + commands
                logger.info(f'Open terminal: {commands!r}')
                matched = True
                break
        if not matched:
            raise Exception('Could not find a suitable terminal to run command!')
    logger.info(f'Run in terminal, cwd {cwd!r}: {" ".join(commands)}')
    p = subprocess.Popen(
        commands,
        creationflags=creationflags,
        cwd=cwd,
    )
    return p


def set_password(args):
    return remote_shell(args, ['~/devkit-utils/steamos-set-password.sh'])


def cef_console(args):
    client = DevkitClient()
    logger.info(
        "Open CEF dev console to %s", args.machine
    )
    machine = resolve_machine(
        args.machine,
        login=args.login,
        need_login=False, need_devkit1=False,
        name_type=args.machine_name_type,
        http_port=getattr(args, 'http_port', DEFAULT_DEVKIT_SERVICE_HTTP),
    )
    webbrowser.open(f'http://{machine.address}:8081', new=2, autoraise=True)


def _simple_ssh(ssh, cmd, silent=False, check_status=False):
    if not silent:
        logger.info(cmd)
    _, stdout, stderr = ssh.exec_command(cmd)
    exit_status = stdout.channel.recv_exit_status()
    out_text = stdout.read().decode('UTF-8', 'replace')
    err_text = stderr.read().decode('UTF-8', 'replace')
    if not silent or (check_status and exit_status != 0):
        if len(out_text) > 0:
            logger.info(out_text)
        if len(err_text) > 0:
            logger.info(err_text)
    if check_status and exit_status != 0:
        raise Exception('command failed, check console')
    return (out_text, err_text, exit_status)


def _open_ssh_for_args_all(args, machine=None):
    client = DevkitClient()
    if machine is None:
        machine = resolve_machine(
            args.machine,
            login=args.login,
            need_login=True, need_devkit1=False,
            name_type=args.machine_name_type,
            http_port=getattr(args, 'http_port', DEFAULT_DEVKIT_SERVICE_HTTP),
        )
    ssh = paramiko.SSHClient()
    key, key_path, _ = ensure_devkit_key()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    logger.debug(f'Connecting to {machine.login}@{machine.address} with private key {key_path!r}')

    ssh.connect(
        machine.address,
        username=machine.login,
        pkey=key,
        timeout=REQUEST_TIMEOUT
    )
    return (ssh, client, machine)

def open_ssh_for_args_all(name, name_type, machine):
    class ArgWrap:
        def __init__(self, name, name_type):
            self.machine = name
            self.machine_name_type = name_type
            self.login = None
    return _open_ssh_for_args_all(ArgWrap(name, name_type), machine)

def _open_ssh_for_args(args):
    return _open_ssh_for_args_all(args)[0]


def _obtain_trace(ssh, sftp, args):
    local_trace_file = args.local_filename
    # technically unsecure .. we obtain a unique temp file, delete it and let the gpu-trace service write it out again (tm)
    out_text, _, _ = _simple_ssh(ssh, f'mktemp -p /tmp XXXXXXXXX-gpu-trace.zip', silent=True, check_status=True)
    remote_trace_file = out_text.strip('\n')
    _simple_ssh(ssh, f'rm {remote_trace_file}', silent=True, check_status=True)

    capture_cmd = f'gpu-trace --capture --no-gpuvis -o {remote_trace_file}'
    _, err_text, exit_status = _simple_ssh(ssh, capture_cmd)

    if err_text.find('Capture request failed') != -1 or err_text.find('Failed to capture a perf trace.') != -1:
        # recognize this error, tell the daemon to start tracing and try again
        # (assuming that tracing mode not enabled is the cause .. this is fragile unfortunately)
        logger.info('start tracing and try again')
        start_cmd = 'gpu-trace --start'
        _simple_ssh(ssh, start_cmd)
        _, err_text, exit_status = _simple_ssh(ssh, capture_cmd)

    if exit_status != 0:
        # will catch 'command not found' at least (gpu-trace not installed)
        raise Exception('command failed, check console')

    sftp.get(remote_trace_file, local_trace_file)
    # keep /tmp clean - limited space that will quickly fill up otherwise
    # old gpu-trace uses a permission mask that prevents the deletion - will be fixed soon (9/20/2022)
    _simple_ssh(ssh, f'rm {remote_trace_file}', silent=True)

    return local_trace_file


def gpu_trace(args):
    ssh = _open_ssh_for_args(args)
    sftp = ssh.open_sftp()

    local_trace_file = _obtain_trace(ssh, sftp, args)

    if args.launch:
        if not os.path.exists(args.gpuvis_path):
            raise Exception(f'Invalid GPU Vis path - does not exist: {args.gpuvis_path}')
        gpuvis_cmd = [args.gpuvis_path, local_trace_file]
        logger.info(' '.join(gpuvis_cmd))
        subprocess.Popen(gpuvis_cmd)


def rgp_capture(args):
    ssh = _open_ssh_for_args(args)

    _simple_ssh(ssh, 'rm /tmp/*.rgp', silent=True)
    _simple_ssh(ssh, 'touch /tmp/rgp.trigger', silent=True)
    attempts = 10
    while attempts > 0:
        time.sleep(.1)
        attempts -= 1
        out_text, err_text, exit_status = _simple_ssh(ssh, 'ls -1t /tmp/*.rgp', silent=True)
        if exit_status == 0:
            remote_path = out_text.split('\n')[0]
            remote_filename = pathlib.PurePosixPath(remote_path).parts[-1]
            os.makedirs(args.local_folder, exist_ok = True)
            local_path = os.path.join(args.local_folder, remote_filename)
            sftp = ssh.open_sftp()
            sftp.get(remote_path, local_path)
            logger.info(f'Downloaded to {local_path}')
            break
    if attempts <= 0:
        raise Exception('Could not obtain a RGP capture: timeout. Have you enabled RGP capture in the Steam client, are you running a Vulkan title?')

    if args.launch:
        if not os.path.exists(args.rgp_path):
            raise Exception(f'Invalid Radeon GPU Profiler path - does not exist: {args.rgp_path}')
        profiler_cmd = [args.rgp_path, local_path]
        subprocess.Popen(profiler_cmd)


def config_steam_wrapper_flags(devkit, enable, disable):
    ssh = _open_ssh_for_args(ResolveMachineArgs(devkit))
    _simple_ssh(ssh, 'mkdir -p $XDG_RUNTIME_DIR/steam/env', silent=True, check_status=True)
    if disable:
        for env in disable:
            logger.info(f'Turn off Steam launch flag: {env}')
            _simple_ssh(ssh, f'rm -f $XDG_RUNTIME_DIR/steam/env/{env}', silent=True, check_status=True)
    if enable:
        for (k,v) in enable.items():
            logger.info(f'Set Steam launch flag: {k}={v}')
            _simple_ssh(ssh, f'echo {v} > $XDG_RUNTIME_DIR/steam/env/{k}', silent=True, check_status=True)
    return (enable, disable)


def restart_sddm(args):
    ssh = _open_ssh_for_args(args)
    (_, _, exit_status) = _simple_ssh(ssh, RESTART_SDDM, check_status=True)


def screenshot(args):
    ssh = _open_ssh_for_args(args)
    # gamescope takes a screenshot asynchronously - we have to wait after signaling
    # wipe any existing screenshot first:
    # - so they don't accumulate in tmpfs
    # - so we can wait and confirm a new screenshot was delivered
    _simple_ssh(ssh, 'rm /tmp/gamescope_*.png', silent=True)
    _simple_ssh(ssh, 'kill -USR2 `pidof gamescope`', silent=True, check_status=True)
    attempts = 50
    while attempts > 0:
        time.sleep(.1)
        attempts -= 1
        out_text, err_text, exit_status = _simple_ssh(ssh, 'find /tmp -maxdepth 1 -type f -name "gamescope*.png"', silent=True)
        #logger.debug(f'{out_text!r} {err_text!r} {exit_status}')
        if exit_status == 0 and len(out_text) > 0:
            remote_path = out_text.split('\n')[0]
            remote_filename = pathlib.PurePosixPath(remote_path).parts[-1]

            if args.filename is None or len(args.filename) == 0:
                local_path = str(pathlib.Path(args.folder, remote_filename))
            else:
                suffix = pathlib.Path(remote_filename).suffix
                filename = str(pathlib.Path(args.filename).with_suffix(''))
                if args.do_timestamp:
                    # use the timestamp of the incoming file, but use the file prefix that has been set
                    m = re.search('_[0-9-_]*', remote_filename)
                    timestamp = ''
                    if m is not None:
                        timestamp = m.group(0)
                    local_path = str(pathlib.Path(args.folder, filename + timestamp)) + suffix
                else:
                    # this will silently overwrite since we were not asked to put a timestamp
                    local_path = str(pathlib.Path(args.folder, filename)) + suffix

            os.makedirs(os.path.dirname(local_path), exist_ok=True)

            sftp = ssh.open_sftp()
            sftp.get(remote_path, local_path)
            logger.info(f'Downloaded to {local_path}')
            break
    if attempts <= 0:
        raise Exception('Could not retrieve screenshot: timeout.')

def sync_utils(args, machine=None):
    client = DevkitClient()
    if machine is None:
        machine = resolve_machine(
            args.machine, login=args.login, need_login=True, need_devkit1=True,
            name_type=args.machine_name_type,
            http_port=getattr(args, 'http_port', DEFAULT_DEVKIT_SERVICE_HTTP),
        )
    user = machine.login or 'root'

    utils_local_path = os.path.join(ROOT_DIR, 'devkit-utils')
    assert os.path.exists(utils_local_path)
    utils_remote_path = '~/devkit-utils'
    logger.info(f'Sync utility scripts to {args.machine}')
    client.rsync_transfer(
        utils_local_path,
        user,
        machine.address,
        utils_remote_path
    )

# Returns None to indicate a failure
def steamos_get_status(args):
    ssh = _open_ssh_for_args(args)
    (out_text, err_text, exit_status) = _simple_ssh(ssh, 'python3 ~/devkit-utils/steamos-get-status --json', silent=True, check_status=False)
    if exit_status != 0:
        logger.warning(err_text)
        return
    try:
        ret = json.loads(out_text)
    except json.JSONDecodeError as e:
        log_exception(e)
        logger.warning('Could not parse steamos-get-status --json output')
        return
    return ret

# Returns None to indicate a failure
def set_session(args):
    ssh = _open_ssh_for_args(args)
    _simple_ssh(ssh, f'steamos-session-select {args.session}')
    if args.wait:
        count = 0
        while count < 5:
            count += 1
            time.sleep(1)
            steamos_status = steamos_get_status(args)
            if steamos_status is None:
                continue
            if steamos_status['session_status'] == args.session:
                if steamos_status['session_status'] != 'gamescope':
                    return steamos_status
                # give a bit extra for the steam client to start when in gamescope
                if steamos_status['steam_status'] != 'SteamStatus.NOT_RUNNING':
                    return steamos_status
        logger.warning(f'timeout waiting for requested session change')
        return steamos_status # return the last status anyway

def dump_controller_config(args):
    (ssh, client, machine) = _open_ssh_for_args_all(args)
    # wipe any old data from /tmp first
    _simple_ssh(ssh, 'rm -f /tmp/config_*.tmp')
    cmd = ['python3', '~/devkit-utils/steamos-dump-controller-config']
    #cmd.append('--verbose')
    if args.appid:
        cmd += ['--appid', args.appid]
    elif args.gameid:
        cmd += ['--gameid', args.gameid]
    (out_text, _, _) = _simple_ssh(ssh, ' '.join(cmd), check_status=True)
    json_output = json.loads(out_text)
    if 'error' in json_output:
        # Does that work to bring a popup?
        raise Exception(json_output['error'])
    logger.info(json_output['success'])
    # retrieve files
    client = DevkitClient()
    client.rsync_transfer(
        args.folder,
        machine.login,
        machine.address,
        '/tmp',
        delete_extraneous = False,
        skip_newer_files = False,
        verify_checksums = False,
        upload = False,
        # doing this way because rsync_transfer only takes in directories
        extra_cmdline = [ '--include=config_*.vdf', '--exclude=*' ]
    )
    return json_output['success']

def delete_title(args):
    ssh = _open_ssh_for_args(args)
    cmd = ['python3', '~/devkit-utils/steamos-delete']
    if args.gameid:
        cmd += ['--delete-title', args.gameid]
    if args.delete_all:
        cmd += ['--delete-all-titles']
    if args.reset_steam_client:
        cmd += ['--reset-steam-client']
    (out_text, _, exit_status) = _simple_ssh(ssh, ' '.join(cmd))
    if exit_status != 0:
        raise Exception(out_text)
    return out_text

def simple_command(devkit, cmd):
    (ssh, client, machine) = _open_ssh_for_args_all(ResolveMachineArgs(devkit))
    if type(cmd) is list:
        cmd = shlex.join(cmd)
    _simple_ssh(ssh, cmd)

def sync_pattern(devkit, host_folder, pattern):
    os.makedirs(host_folder, exist_ok=True)
    (_, client, machine) = _open_ssh_for_args_all(ResolveMachineArgs(devkit))
    client.rsync_transfer(
        host_folder,
        machine.login,
        machine.address,
        f'/home/{machine.login}',
        delete_extraneous = False,
        skip_newer_files = False,
        verify_checksums = False,
        upload = False,
        extra_cmdline = pattern,
    )

def set_renderdoc_replay(devkit, enable):
    (ssh, _, machine) = _open_ssh_for_args_all(ResolveMachineArgs(devkit))
    _simple_ssh(ssh, 'killall -9 renderdoccmd', silent=True, check_status=False)
    if enable:
        # renderdoccmd adds a 'RenderDoc/' subfolder..
        _simple_ssh(ssh, f'RENDERDOC_TEMP=/home/{machine.login} renderdoccmd remoteserver -d', silent=True, check_status=True)
