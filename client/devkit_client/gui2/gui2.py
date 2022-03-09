import sys
import os
import atexit
import pickle
import argparse
import enum
import ctypes
import collections
import concurrent.futures
import logging
import shlex
import json
import socketserver
import http.server
import threading
import time
from pathlib import Path
import platform
import re
import enum
import socket
import webbrowser
import pathlib
import shutil
import urllib.error
import subprocess
import functools

if platform.system() == 'Windows':
    import winreg

import signalslot
import OpenGL.GL as gl
import sdl2
import imgui
import imgui.integrations.sdl2

import devkit_client
from devkit_client import SteamPlayDebug
import paramiko
import devkit_client.zeroconf as zeroconf

CHARACTER_WIDTH = 8
CHARACTER_HEIGHT = 14 # e.g. a line of text

GAMEID_ALLOWED_PATTERN = '^[A-Za-z_][A-Za-z0-9_.]+$'

GUEST_LAN_LIMITED_CONNECTIVITY = 'WARNING: DEVICE IS ON GUEST LAN - no network connectivity, cannot be used.'
GUEST_LAN_PATTERN = 'DISABLE'

logger = logging.getLogger(__name__)


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'on', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'off', 'false', 'f', 'n', '0'):
        return False
    else:
        raise Exception('Boolean value expected.')


def imgui_calc_text_size(text):
    lines = text.split('\n')
    max_char = max([len(l) for l in lines])
    return (max_char*CHARACTER_WIDTH, len(lines)*CHARACTER_HEIGHT)


class DevkitCommands:
    '''Wrap an async API around devkit command execution via the cli modules.
    This is very crufty because reasons. Could be massively simplified now.
    '''

    def __init__(self):
        self.executor = None
        self.signal_steamos_status = signalslot.Signal(args = ['devkit'])

    def setup(self):
        self.executor = concurrent.futures.ThreadPoolExecutor()

    def _identify(self, devkit):
        machine = self._check_connectivity(devkit)

        assert devkit.limited_connectivity is not None

        # If the service cannot be reached, ssh connectivity is irrelevant, we cannot do anything with the kit
        # Also catches no connectivity situations (wrong IP, fully firewalled, etc.)
        if not devkit.http_connectivity:
            logger.info(f'No connectivity with kit: {machine.address}')
            raise DevkitNoConnectivity

        if not devkit.ssh_connectivity:
            # assume we are seeing an unregistered devkit that does not have sshd running yet
            logger.info(f'sshd may not be running yet - kit needs registration: {machine.address}')
            raise DevkitNotRegistered

        try:
            # check if the kit is registered - by opening a ssh to it with our devkit key
            devkit_client.open_ssh_for_args_all(devkit.machine_command_args[0], devkit.machine_command_args[1], machine)
        except paramiko.AuthenticationException as e:
            logger.info(f'ssh connection check failed: {e}')
            raise DevkitNotRegistered

        # looking good, deploy/refresh the utility scripts
        class SyncUtilsArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
        devkit_client.sync_utils(SyncUtilsArgs(devkit), machine)
        # get general status info
        class GetStatusArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
        steamos_status = devkit_client.steamos_get_status(GetStatusArgs(devkit))
        if steamos_status is None:
            steamos_status = {}
        return (machine, steamos_status)

    def identify(self, *args):
        return self.executor.submit(self._identify, *args)

    def _steamos_get_status(self, devkit):
        class GetStatusArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
        # on the UI side, we default steamos_status to empty dict
        devkit.steamos_status = {}
        try:
            devkit.steamos_status = devkit_client.steamos_get_status(GetStatusArgs(devkit))
        except Exception as e:
            raise e
        if devkit.steamos_status is None:
            devkit.steamos_status = {}
            raise Exception('SteamOS get status failed, check status window')
        self.signal_steamos_status.emit(devkit=devkit)
        return devkit.steamos_status

    def steamos_get_status(self, *args):
        return self.executor.submit(self._steamos_get_status, *args)

    def _list_games(self, devkit):
        class ListGamesArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
        return devkit_client.list_games(ListGamesArgs(devkit))

    def list_games(self, *args):
        return self.executor.submit(self._list_games, *args)

    def _register(self, devkit):
        class RegisterArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
        return devkit_client.register(RegisterArgs(devkit))

    def register(self, *args):
        return self.executor.submit(self._register, *args)

    def _update_game(self, devkit, restart_steam, gdbserver, steam_play, steam_play_debug, steam_play_debug_version, *args):

        class NewGameArgs:
            def __init__(self, devkit, title_name, local_folder, delete_remote_files, verify_checksums, start_command, filter_args, dependencies, cancel_signal):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.name = title_name
                self.directory = local_folder
                assert type(start_command) is list
                self.argv = start_command
                self.login = None
                self.update = not delete_remote_files
                self.verify_checksums = verify_checksums
                self.filter_args = filter_args
                self.steam_play_debug = SteamPlayDebug.Disabled
                self.deps = dependencies
                self.cancel_signal = cancel_signal

        new_game_args = NewGameArgs(devkit, *args)
        if steam_play:
            # access via getattr in the low level
            new_game_args.set = [
                'steam_play=1',
                f'steam_play_debug={int(steam_play_debug)}',
                f'steam_play_debug_version={steam_play_debug_version}'
            ]
            new_game_args.steam_play_debug = steam_play_debug
        else:
            new_game_args.set = ['steam_play=0']
        result = devkit_client.new_or_ensure_game(new_game_args)
        if not result:
            raise Exception("new_or_ensure_game command failed, check console")
        if restart_steam:
            # side loaded Steam client:
            # new_game_args.argv is a single string wrapped in a list (one element), and is the full command to execute
            command = ' '.join(new_game_args.argv)
            self._set_steam_client(devkit, 'SteamStatus.SIDE', command, None, True, gdbserver)
        return True

    def update_game(self, *args):
        return self.executor.submit(self._update_game, *args)

    def _restart_steam(self, devkit):
        class RestartArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args

        restart_args = RestartArgs(devkit)
        devkit_client.restart_steam_client(restart_args)
        return True

    def restart_steam(self, devkit):
        return self.executor.submit(self._restart_steam, devkit)

    def _set_steam_client(self, devkit, title_name, command, args, wait, gdbserver):
        class SetSteamClientArgs:
            def __init__(self, devkit, title_name, command, args, gdbserver):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.login = None
                self.http_port = devkit.http_port
                self.name = title_name
                self.command = command
                self.args = args
                self.gdbserver = gdbserver

        set_steam_client_args = SetSteamClientArgs(devkit, title_name, command, args, gdbserver)
        devkit_client.set_steam_client(set_steam_client_args)
        self._restart_sddm(devkit)
        if wait:
            class GetStatusArgs:
                def __init__(self, devkit):
                    self.machine, self.machine_name_type = devkit.machine_command_args
                    self.http_port = devkit.http_port
                    self.login = None
            get_status_args = GetStatusArgs(devkit)
            count = 0
            while count < 10:
                count += 1
                time.sleep(1)
                try:
                    steamos_status = devkit_client.steamos_get_status(get_status_args)
                except Exception as e:
                    devkit_client.log_exception(e)
                    logger.error('SteamOS get status failed during set steam client, wait and retry')
                    continue
                if steamos_status is None:
                    continue # is also error condition on the status
                devkit.steamos_status = steamos_status
                self.signal_steamos_status.emit(devkit=devkit)
                if devkit.steam_client_status != 'SteamStatus.NOT_RUNNING':
                    return True # reached the other side
        return True

    def set_steam_client(self, *args):
        return self.executor.submit(self._set_steam_client, *args)

    def _sync_logs(self, devkit, logs_folder):
        class SyncLogsArgs:
            def __init__(self, devkit, logs_folder):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.local_folder = logs_folder

        # check that the Steam client is in a configuration that writes out logs
        if devkit.steam_client_status == 'SteamStatus.OS':
            raise Exception("Steam is not configured to write logs on the device - please use the Devkits tab to switch to 'OS Client dev mode'")

        sync_logs_args = SyncLogsArgs(devkit, logs_folder)
        devkit_client.sync_logs(sync_logs_args)
        return True

    def sync_logs(self, devkit, logs_folder):
        return self.executor.submit(self._sync_logs, devkit, logs_folder)

    def _open_remote_shell(self, devkit):
        remote_shell_args = devkit_client.RemoteShellArgs(devkit)
        devkit_client.remote_shell(remote_shell_args)
        return True

    def open_remote_shell(self, devkit):
        return self.executor.submit(self._open_remote_shell, devkit)

    def _open_cef_console(self, devkit):

        class CEFConsoleArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
        cef_console_args = CEFConsoleArgs(devkit)
        devkit_client.cef_console(cef_console_args)
        return True

    def open_cef_console(self, devkit):
        return self.executor.submit(self._open_cef_console, devkit)

    def _gpu_trace(self, *args):
        class GPUTraceArgs:
            def __init__(self, devkit, local_filename, launch, gpuvis_path):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
                self.local_filename = local_filename
                self.launch = launch
                self.gpuvis_path = gpuvis_path
        gpu_trace_args = GPUTraceArgs(*args)
        devkit_client.gpu_trace(gpu_trace_args)

    def gpu_trace(self, *args):
        return self.executor.submit(self._gpu_trace, *args)

    def _rgp_capture(self, *args):
        class RGPCaptureArgs:
            def __init__(self, devkit, local_folder, launch, rgp_path):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
                self.local_folder = local_folder
                self.launch = launch
                self.rgp_path = rgp_path
        rgp_capture_args = RGPCaptureArgs(*args)
        devkit_client.rgp_capture(rgp_capture_args)

    def rgp_capture(self, *args):
        return self.executor.submit(self._rgp_capture, *args)

    def _restart_sddm(self, devkit):
        class RestartSDDMArgs:
            def __init__(self, devkit):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
        sddm_restart_args = RestartSDDMArgs(devkit)
        devkit_client.restart_sddm(sddm_restart_args)

    def restart_sddm(self, devkit):
        return self.executor.submit(self._restart_sddm, devkit)

    def _screenshot(self, *args):

        class ScreenshotArgs:
            def __init__(self, devkit, folder, filename, do_timestamp):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
                self.folder = folder
                self.filename = filename
                self.do_timestamp = do_timestamp
        screenshot_args = ScreenshotArgs(*args)
        devkit_client.screenshot(screenshot_args)

    def screenshot(self, *args):
        return self.executor.submit(self._screenshot, *args)

    def _check_port(self, host, port):
        try:
            logger.debug(f'Checking if {host}:{port} is open.')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            ret = s.connect_ex((host, port))
        except Exception as e:
            devkit_client.log_exception(e)
            logger.warning(f'Port {port} on host {host} is unreachable.')
            return False
        if ret != 0:
            logger.error(f'socket.connect_ex errno: {ret}')
            logger.warning(f'Port {port} on host {host} is unreachable.')
            return False
        logger.info(f'Port {port} on host {host} is open.')
        return True

    def _check_connectivity(self, devkit):
        machine = devkit_client.resolve_machine(
            devkit.machine_command_args[0],
            name_type=devkit.machine_command_args[1],
            http_port=devkit.http_port
        )

        if platform.system() == 'Windows' and machine.address in ('127.0.0.1', 'localhost'):
            # Valve specific: devkits may be accessed via a portforwarding over the local interface,
            # both the ssh and http service ports are forwarded
            # ssh is always forwarded to 22 atm
            # but http is forwarded to 32001, because some Valve devs have an unrelated service already using 32000
            # so we check 32001 first, then 32000 as a fallback (although that last one really shouldn't happen in our forwarding setups)
            # additionally, the devkit client is started before the tunnels are in place, so give ourselves plenty of extra time to retry
            attempts = 1
            max_attempts = 5
            while attempts < max_attempts:
                assert devkit.service_name is None # mDNS not relevant here, this is for 'add by IP' only
                devkit.http_connectivity = False
                for test_port in (devkit_client.DEFAULT_DEVKIT_SERVICE_HTTP+1, devkit_client.DEFAULT_DEVKIT_SERVICE_HTTP):
                    if self._check_port(machine.address, test_port):
                        devkit.http_port = test_port
                        logger.info(f'Possible devkit service responding on {machine.address}:{devkit.http_port}')
                        devkit.http_connectivity = True
                if not devkit.http_connectivity:
                    logger.warning('devkit service on portforwarded local ports is not responding, wait and try again')
                    time.sleep(5)
                    attempts += 1
                else:
                    # if we had to do loop and wait for the tunnel, the machine info is incomplete and causes problems, so refresh
                    machine = devkit_client.resolve_machine(
                        devkit.machine_command_args[0],
                        name_type=devkit.machine_command_args[1],
                        http_port=devkit.http_port
                    )
                    # continue on to the ssh port check
                    break
            if attempts >= max_attempts:
                logger.warning(f'Timed out waiting for the service on {machine.address}:{devkit.http_port}')
        else:
            # NOTE: http_port may already be a non standard port through the mDNS properties
            devkit.http_connectivity = self._check_port(machine.address, devkit.http_port)
            if not devkit.http_connectivity:
                if machine.address.startswith(GUEST_LAN_PATTERN):
                    devkit.guest_lan = True

        if devkit.http_connectivity:
            # Pull the properties from the service
            request = urllib.request.Request(f'http://{machine.address}:{devkit.http_port}/properties.json')
            try:
                result = urllib.request.urlopen(request)
            except Exception as e:
                devkit_client.log_exception(e)
                # Doesn't look like a devkit service, or some other problem
                devkit.http_connectivity = False
            else:
                properties_payload = result.read().decode('utf-8', 'replace')
                logger.debug(f'properties payload: {properties_payload!r}')
                # we are seeing a situation where strict parsing fails, but not much details on what's going on
                decoder = json.JSONDecoder(strict=False)
                devkit.service_properties = decoder.decode(properties_payload)
                # unwrap some more
                devkit.service_properties['settings'] = decoder.decode(devkit.service_properties['settings'])

        devkit.ssh_connectivity = self._check_port(machine.address, 22)
        return machine

    # some network setups let mDNS through but block other traffic
    # the future will return a bool response indicating wether the important devkit ports are reachable
    def check_connectivity(self, devkit):
        return self.executor.submit(self._check_connectivity, devkit)

    def _set_session(self, devkit, *args):
        class SetSessionArgs:
            def __init__(self, devkit, session, wait):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
                self.session = session
                # will force a wait and return of a steamos_status
                self.wait = wait
        devkit.steamos_status = devkit_client.set_session(SetSessionArgs(devkit, *args))
        if devkit.steamos_status is None:
            devkit.steamos_status = {}

    def set_session(self, *args):
        return self.executor.submit(self._set_session, *args)

    def _dump_controller_config(self, *args):
        class DumpControllerConfigArgs:
            def __init__(self, devkit, appid, gameid, folder):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
                self.appid = appid if ( appid is not None and len(appid) > 0 ) else None
                self.gameid = gameid if ( gameid is not None and len(gameid) > 0 ) else None
                self.folder = folder
                assert self.appid or self.gameid # at least one of these is required
        return devkit_client.dump_controller_config(DumpControllerConfigArgs(*args))

    def dump_controller_config(self, *args):
        return self.executor.submit(self._dump_controller_config, *args)

    def _delete_title(self, *args):
        class DeleteTitleArgs:
            def __init__(self, devkit, gameid, delete_all, reset_steam_client):
                self.machine, self.machine_name_type = devkit.machine_command_args
                self.http_port = devkit.http_port
                self.login = None
                self.gameid = gameid if ( gameid is not None and len(gameid) > 0 ) else None
                self.delete_all = delete_all
                self.reset_steam_client = reset_steam_client
        return devkit_client.delete_title(DeleteTitleArgs(*args))

    def delete_title(self, *args):
        return self.executor.submit(self._delete_title, *args)

    def _simple_command(self, *args):
        return devkit_client.simple_command(*args)

    def simple_command(self, *args):
        return self.executor.submit(self._simple_command, *args)

    def _sync_perf_logs(self, *args):
        return devkit_client.sync_perf_logs(*args)

    def sync_perf_logs(self, *args):
        return self.executor.submit(self._sync_perf_logs, *args)

    def _browse_files(self, devkit):
        filezilla = None
        if platform.system() == 'Windows':
            try:
                key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Wow6432Node\FileZilla Client')
            except OSError as e:
                logger.info('FileZilla not found in registry')
            else:
                filezilla = os.path.join(winreg.QueryValue(key, None), 'filezilla.exe')
        if filezilla is None:
            filezilla = shutil.which('filezilla')
        if filezilla is None or not os.path.exists(filezilla):
            raise Exception('FileZilla not found. Please install in order to use this feature.')
        cmd = [filezilla, '-l', 'ask', f'sftp://{devkit.machine.login}@{devkit.machine.address}']
        subprocess.Popen(cmd)

    def browse_files(self, *args):
        return self.executor.submit(self._browse_files, *args)

    def _set_password(self, devkit):
        remote_shell_args = devkit_client.RemoteShellArgs(devkit)
        return devkit_client.set_password(remote_shell_args)

    def set_password(self, *args):
        return self.executor.submit(self._set_password, *args)

class DevkitState(enum.Enum):
    devkit_init = enum.auto()
    devkit_registering = enum.auto()
    devkit_init_failed = enum.auto()
    devkit_not_registered = enum.auto()
    devkit_online = enum.auto()

class DevkitNotRegistered(Exception):
    pass

class DevkitNoConnectivity(Exception):
    pass

class Devkit:
    ADDED_BY_IP_KEY = 'Devkit.AddedByIP'

    def __init__(self, devkit_commands, settings, zc_listener=None, service_name=None, address=None):
        self.devkit_commands = devkit_commands
        self.settings = settings
        # both set if added as a service (None otherwise)
        self.zc_listener = zc_listener
        self.service_name = service_name
        # set if added by address (None otherwise)
        self.address = address
        assert self.service_name is not None or self.address is not None
        assert ( self.service_name is None ) == ( self.zc_listener is None )
        self.state = DevkitState.devkit_init
        # set once state reaches devkit_online (None otherwise)
        self.machine = None
        self.init_future = None
        self.register_future = None
        self.register_done_future = None
        # connectivity checks - tri-state
        self.ssh_connectivity = None
        self.http_connectivity = None
        self.service_properties = None # filled with the devkit service properties.json after a successful connectivity check
        self.guest_lan = False
        # dictionary representing the steamos device status obtained via the devkit-utils/steamos-get-status command
        self.steamos_status = {}
        if self.zc_listener:
            self._http_port = self.zc_listener.port_for_service(self.service_name)
        else:
            self._http_port = devkit_client.DEFAULT_DEVKIT_SERVICE_HTTP

    # returns a tri-state as well
    @property
    def limited_connectivity(self):
        if self.ssh_connectivity is None or self.http_connectivity is None:
            return None
        return (not self.ssh_connectivity) or (not self.http_connectivity)

    @property
    def added_by_ip(self):
        return self.address is not None

    @property
    def name(self):
        # Human friendly name, either the service or the address
        if self.service_name is not None:
            return self.service_name
        assert self.address is not None
        return self.address

    @property
    def full_name(self):
        # Add the IP address when appropriate
        if self.service_name is not None:
            return '{} ({})'.format(self.service_name, self.zc_listener.address_for_service(self.service_name))
        return self.address

    @property
    def machine_command_args(self):
        if self.service_name is not None:
            return (self.service_name, devkit_client.MachineNameType.SERVICE_NAME)
        return (self.address, devkit_client.MachineNameType.ADDRESS)

    # Uploading and debugging a side loaded Steam client - only relevant to Valve
    @property
    def is_jupiter(self):
        return self.steamos_status.get('jupiter', False)

    @property
    def http_port(self):
        return self._http_port

    @http_port.setter
    def http_port(self, value):
        self._http_port = value

    @property
    def steam_client_status(self):
        '''Status of the Steam client on the device'''
        return self.steamos_status.get('steam_status', 'SteamStatus.ERROR')

    @property
    def steam_configuration(self):
        '''Intended configuration of the Steam client on the device'''
        return self.steamos_status.get('steam_configuration', 'SteamStatus.ERROR')

    @property
    def cef_debugging_enabled(self):
        return self.steamos_status.get('cef_debugging_enabled', False)

    @property
    def osclient_steam_version(self):
        return self.steamos_status.get('steam_osclient_version', None)

    @property
    def os_name(self):
        return self.steamos_status.get('os_name', None)

    @property
    def os_version(self):
        return self.steamos_status.get('os_version', None)

    @property
    def foxnet_connectivity(self):
        return self.steamos_status.get('has_foxnet_connectivity', False)

    @property
    def user_password_is_set(self):
        return self.steamos_status.get('user_password_is_set', False)

    def has_mdns_service(self):
        return self.service_name is not None

    def setup(self):
        assert self.state == DevkitState.devkit_init
        self.init_future = self.devkit_commands.identify(self)
        self.init_future.add_done_callback(self.on_init_done)
        if self.added_by_ip:
            ip_set = self.settings.get(self.ADDED_BY_IP_KEY, set())
            ip_set.add(self.address)
            self.settings[self.ADDED_BY_IP_KEY] = ip_set
            self.settings.save_settings()

    def forget_added_by_ip(self):
        assert self.added_by_ip
        ip_set = self.settings.get(self.ADDED_BY_IP_KEY, set())
        ip_set.remove(self.address)
        self.settings[self.ADDED_BY_IP_KEY] = ip_set
        self.settings.save_settings()

    def register(self):
        assert self.state == DevkitState.devkit_not_registered
        self.state = DevkitState.devkit_registering
        self.register_future = self.devkit_commands.register(self)
        self.register_future.add_done_callback(self.on_register_done)
        self.register_done_future = concurrent.futures.Future()
        self.register_done_future.set_running_or_notify_cancel()
        return self.register_done_future

    def on_init_done(self, f):
        assert f is self.init_future
        try:
            (machine, steamos_status) = f.result()
        except DevkitNotRegistered as e:
            self.state = DevkitState.devkit_not_registered
        except DevkitNoConnectivity as e:
            self.state = DevkitState.devkit_init_failed
        except Exception as e:
            devkit_client.log_exception(e)
            logger.error('%r: identify command failed', self.name)
            self.state = DevkitState.devkit_init_failed
        else:
            self.state = DevkitState.devkit_online
            self.machine = machine
            self.steamos_status = steamos_status

    def on_register_done(self, f):
        # We process register_future and fire register_done_future for the UI
        assert f is self.register_future
        assert f.done()
        e = f.exception()
        if not e is None:
            logger.error('%r: register command failed', self.name)
            if type(e) is urllib.error.HTTPError and e.code == 403:
                # Pull more useful information from the error
                error_report = e.fp.read().decode('utf-8')
                # We get a very loosely structured text response, but with newer devkit service releases we can hope to get the json error payload from ssh-approve-key
                found_error = False
                for line in error_report.split('\n'):
                    try:
                        ret = json.loads(line)
                    except:
                        # write out the text lines
                        logger.error(line)
                    else:
                        # raise a propagated error from ssh-approve-key as a modal error
                        self.register_done_future.set_exception(Exception(ret['error']))
                        found_error = True
                        break
                # If no error json was obtained, raise a generic error
                if not found_error:
                    self.register_done_future.set_exception(Exception('Registration failed, see console'))
            else:
                # Push the exception as is, it's not a type that we know how to process
                self.register_done_future.set_exception(e)
            self.state = DevkitState.devkit_not_registered
            return
        self.state = DevkitState.devkit_init
        self.register_done_future.set_result(True)
        self.setup()


class Toolbar:
    '''Command toolbar, toggling tool windows and executing commands.'''

    def __init__(self, viewport):
        self.viewport = viewport
        self.height = 35
        self.signal_pressed = signalslot.Signal(args = ['name'])
        self.selected_devkit = None

    @property
    def is_devkit_selected(self):
        return self.selected_devkit is not None

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)

    def on_draw(self, **kwargs):
        pressed_buttons = []
        imgui.begin('Toolbar', False, imgui.WINDOW_NO_MOVE | imgui.WINDOW_NO_COLLAPSE | imgui.WINDOW_NO_TITLE_BAR | imgui.WINDOW_NO_RESIZE)
        for button_name in (
            DevkitsWindow.BUTTON_NAME,
            ConsoleWindow.BUTTON_NAME,
        ):
            if imgui.button(button_name):
                pressed_buttons.append(button_name)
            imgui.same_line()
        if self.is_devkit_selected:
            active_buttons = [
                UpdateTitle.BUTTON_NAME,
                DeviceLogs.BUTTON_NAME,
            ]
            for button_name in active_buttons:
                if imgui.button(button_name):
                    pressed_buttons.append(button_name)
                imgui.same_line()
        imgui.set_window_position(0, 0)
        imgui.set_window_size(self.viewport.width, self.height)
        imgui.end()
        for button_name in pressed_buttons:
            # Signal needs to be fired outside of imgui begin/end blocks so draws can be done in the handlers
            self.signal_pressed.emit(name=button_name, selected_devkit=self.selected_devkit)

    def focus_console(self):
        self.signal_pressed.emit(name=ConsoleWindow.BUTTON_NAME, selected_devkit=self.selected_devkit)


class ToolWindow:
    '''Manage layout and visibility for tool windows.'''

    def __init__(self, name, viewport, toolbar):
        self.name = name
        self.viewport = viewport
        self.toolbar = toolbar
        self.visible = False
        self.focus_trigger = True
        # By default a ToolWindow is only ticked when it's visible
        self.always_tick = False
        # By default a ToolWindow does not tick if there is no devkit selected
        self.tick_without_devkit = False

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name, **kwargs):
        if name != self.name:
            return
        self.visible = True
        self.focus_trigger = True

    def on_draw(self, **kwargs):
        if not self.visible:
            if self.always_tick:
                self.tick(visible=False)
            return
        if not self.toolbar.is_devkit_selected and not self.tick_without_devkit:
            return
        # Size up the window to fill the viewport on the first draw
        imgui.set_next_window_position(0, self.toolbar.height, imgui.ONCE)
        imgui.set_next_window_size(self.viewport.width, self.viewport.height - self.toolbar.height, imgui.ONCE)
        if self.focus_trigger:
            imgui.set_next_window_focus()
            self.focus_trigger = False
        # NOTE: draw is only called if the window is visible!
        self.tick(visible=True)

    def tick(self, visible):
        '''Customize in child classes'''
        pass


class ModalWait:
    '''A modal dialog to wrap slow devkit operations'''
    def __init__(
        self, viewport, toolbar, title, task_future,
        exit_on_success=False,
        cancel_signal=False,
        ):
        self.viewport = viewport
        self.toolbar = toolbar
        self.title = title
        self.task_future = task_future
        self.exit_on_success = exit_on_success

        self.output_text = ''
        self.dialog_width = 0
        self.dialog_height = 0
        self.user_resized = False   # If the user manipulates the dialog size, stop our auto size updates

        self._result = None
        self._error = None
        self.signal_task_done = signalslot.Signal()
        # Replace the output text:
        # - replaces 'Please Wait...' while waiting
        # - replaces the final message after completion
        self._override_output_text = None
        self.cancel_signal = signalslot.Signal() if cancel_signal else None

    @property
    def result(self):
        return self._result

    @property
    def error(self):
        return self._error

    @property
    def override_output_text(self):
        return self._override_output_text

    @override_output_text.setter
    def override_output_text(self, value):
        self._override_output_text = value

    def draw(self):
        # This would be a lot more simple if I had found a way to have imgui auto resize the layout based on content
        # But either I'm too dumb to figure it out, or it's not possible in 1.77
        output_text = self._override_output_text if self._override_output_text is not None else 'Please wait..'
        in_progress = True      # Abort/OK button
        trigger_resize = False  # Force a dialog resize to fit additional text
        if self.task_future.done():
            in_progress = False
            if self._result is None and self._error is None:
                # Reset output text override, so we can override the wait and the final message independently
                self._override_output_text = None
                # Collect the result of error - (runs once)
                try:
                    self._result = self.task_future.result()
                    if self.exit_on_success:
                        return False
                except Exception as e:
                    self._error = e
                    devkit_client.log_exception(e)
                    # Bring up the status window whenever a modal dialog hits an error
                    self.toolbar.focus_console()
                self.signal_task_done.emit()
            if not self._override_output_text is None:
                # Output text was set externally
                output_text = self._override_output_text
            else:
                # Default output text rules
                if not self._error is None:
                    output_text = 'ERROR: {}'.format(self._error)
                else:
                    output_text = str(self._result)
        if output_text != self.output_text:
            trigger_resize = True
            self.output_text = output_text

        button_offset = 58 # account for button vertical space when going from text size to dialog size

        if trigger_resize and not self.user_resized:
            # ideal text area size to in the dialog
            (text_width, text_height) = imgui_calc_text_size(self.output_text)
            # minimum dimensions, only increase dimensions on auto-resize, never exceed viewport size
            self.dialog_width = min(self.viewport.width, max(15*CHARACTER_WIDTH, len(self.title)*CHARACTER_WIDTH, text_width, self.dialog_width))
            # account for the button vertical space at the bottom
            self.dialog_height = min(self.viewport.height, max(3*CHARACTER_HEIGHT+button_offset, text_height+button_offset, self.dialog_height))
            #logger.info('set dialog size to %dx%d', self.dialog_width, self.dialog_height)
            imgui.set_next_window_size(self.dialog_width, self.dialog_height)
            x = ( self.viewport.width - self.dialog_width ) / 2
            y = ( self.viewport.height - self.dialog_height ) / 2
            imgui.set_next_window_position(x, y)

        imgui.open_popup(self.title)
        # Note: tried imgui.WINDOW_ALWAYS_AUTO_RESIZE but could not get a useful behavior out of it
        if imgui.begin_popup_modal(self.title):
            imgui.begin_child('message', imgui.get_window_width(), imgui.get_window_height()-button_offset)
            imgui.input_text_multiline('', self.output_text, len(self.output_text)+1, imgui.get_window_width(), imgui.get_window_height(), imgui.INPUT_TEXT_READ_ONLY)
            imgui.end_child()

            if in_progress:
                if self.cancel_signal:
                    if imgui.button('Cancel'):
                        self.cancel_signal.emit()
            else:
                dismiss = False
                if self._error is None:
                    dismiss = imgui.button('OK')
                else:
                    imgui.push_style_color(imgui.COLOR_BUTTON, 1, 0, 0)
                    dismiss = imgui.button('ERROR')
                    imgui.pop_style_color()

                # Press OK button, or hit escape/enter to dismiss once the task is complete
                keyboard_state = sdl2.SDL_GetKeyboardState(None)
                dismiss |= keyboard_state[sdl2.SDL_SCANCODE_ESCAPE] or keyboard_state[sdl2.SDL_SCANCODE_RETURN] or keyboard_state[sdl2.SDL_SCANCODE_KP_ENTER]
                if dismiss:
                    imgui.close_current_popup()
                    imgui.end_popup()
                    return False

            if not self.user_resized:
                s = imgui.get_window_size()
                if s.x != self.dialog_width or s.y != self.dialog_height:
                    logger.info('user resized the modal dialog - disabling further size auto updates')
                    self.user_resized = True

            imgui.end_popup()
        return True


class DevkitsWindow(ToolWindow):
    '''List online devkits, support registration against a kit and selection for operations.'''

    BUTTON_NAME = 'Devkits'

    def __init__(self,
                 conf,
                 devkit_commands,
                 settings,
                 screenshot,
                 perf_overlay,
                 gpu_trace,
                 rgp_capture,
                 controller_configs,
                 delete_title,
                 *args):
        super(DevkitsWindow, self).__init__(self.BUTTON_NAME, *args)
        self.conf = conf
        self.devkit_commands = devkit_commands
        self.settings = settings
        self.screenshot = screenshot
        self.perf_overlay = perf_overlay
        self.gpu_trace = gpu_trace
        self.rgp_capture = rgp_capture
        self.controller_configs = controller_configs
        self.delete_title = delete_title
        # Visible by default
        self.visible = True
        # Tick every frame regardless of visibility for zeroconf browser
        self.always_tick = True
        # Draw even when no kit is active
        self.tick_without_devkit = True
        self.zc = None
        self.zc_listener = None
        self.devkits = collections.OrderedDict()
        self._selected_devkit_name = None
        # Keep the same devkit selected across application restarts
        self.preferred_devkit_name = None
        self.modal_wait = None
        self.signal_selected_devkit = signalslot.Signal(args=['devkit'])
        self.add_by_ip_text = ''
        self.steam_client_args = None
        # Hook into status updates to refresh the command line arguments
        self.devkit_commands.signal_steamos_status.connect(self.on_steamos_status)
        # Indicates whether Valve internal services are available
        self.valve_mode = False

    def setup(self):
        super(DevkitsWindow, self).setup()
        self.zc = zeroconf.Zeroconf()
        self.zc_listener = devkit_client.ServiceListener(quiet=False)
        zeroconf.ServiceBrowser(
            self.zc,
            devkit_client.STEAM_DEVKIT_TYPE,
            self.zc_listener
        )
        self.preferred_devkit_name = self.settings.get('DevkitsWindow.preferred_devkit_name', None)
        devkits_by_ip = self.settings.get(Devkit.ADDED_BY_IP_KEY, set())
        for address in devkits_by_ip:
            logger.info(f'Attempt to initialize a devkit previously added by IP: {address}')
            devkit = Devkit(self.devkit_commands, self.settings, address=address)
            devkit.setup()
            self.devkits[devkit.name] = devkit
        self._valve_setup()

    def _valve_setup(self):
        pass

    def __del__(self):
        if self.zc is not None:
            self.zc.close()
            self.zc = None

    # TODO: support multi select
    @property
    def selected_devkit(self):
        if self._selected_devkit_name is None:
            return None
        if not self._selected_devkit_name in self.devkits:
            logger.warning('Selected devkit is no longer available: %r', self._selected_devkit_name)
            self._selected_devkit_name = None
            self.signal_selected_devkit.emit(kit=None)
            return None
        devkit = self.devkits[self._selected_devkit_name]
        if devkit.state != DevkitState.devkit_online:
            logger.warning('Selected devkit is not in online state: %r', devkit.state)
            self._selected_devkit_name = None
            self.signal_selected_devkit.emit(kit=None)
            return None
        return devkit

    def _set_steam_client(self, target_steam_client):
        set_steam_client_future = self.devkit_commands.set_steam_client(
            self.selected_devkit,
            target_steam_client,
            None,                   # no command
            self.steam_client_args,    # we have command line arguments instead
            True, # wait
            False, # gdbserver - default off here, use 'Title Upload' for the feature
        )
        self.modal_wait = ModalWait(
            self.viewport,
            self.toolbar,
            f'Changing the Steam client config on {self.selected_devkit.name!r}',
            set_steam_client_future,
            exit_on_success=True,
        )

    def on_steamos_status(self, devkit, **kwargs):
        # Let the next tick pull the latest arguments from the selected devkit again (hopefully, the one we got a status for)
        self.steam_client_args = None

    def _valve_mode_draw(self, ljust):
        pass

    def tick(self, visible):
        # === logic tick ===============================================================
        while not self.zc_listener.devkit_events.empty():
            op, service_name = self.zc_listener.devkit_events.get()
            if op == 'add':
                assert service_name not in self.devkits
                devkit = Devkit(self.devkit_commands, self.settings, zc_listener=self.zc_listener, service_name=service_name)
                devkit.setup()
                self.devkits[devkit.name] = devkit
            else:
                assert op == 'del'
                del self.devkits[service_name]

        online_kits = [k for k in self.devkits.values() if k.state == DevkitState.devkit_online]

        # Maintain selected devkit
        self.selected_devkit # Makes sure the selected devkit remains valid internally
        emit = None
        for kit in online_kits:
            # Trying to always maintain a kit selected
            if self._selected_devkit_name is None:
                self._selected_devkit_name = kit.name
                emit = kit
            # Restore the preferred kit if we see it
            if self._selected_devkit_name != kit.name and kit.name == self.preferred_devkit_name:
                self._selected_devkit_name = kit.name
                emit = kit
        if not emit is None:
            self.signal_selected_devkit.emit(kit=emit)

        if not visible:
            return

        # === draw =========================================================================
        (_, opened) = imgui.begin(self.BUTTON_NAME, True, imgui.WINDOW_NO_COLLAPSE)
        if not opened:
            self.visible = False
            imgui.end()
            return

        imgui.text('Add devkit by IP:')
        imgui.same_line()
        imgui.push_item_width(20*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##add_by_ip', self.add_by_ip_text, 128, imgui.INPUT_TEXT_ENTER_RETURNS_TRUE)
        if changed:
            self.add_by_ip_text = s
            logger.info('Adding devkit at address %r', self.add_by_ip_text)
            devkit = Devkit(self.devkit_commands, self.settings, address=self.add_by_ip_text)
            devkit.setup()
            self.devkits[devkit.name] = devkit

        # list non registered devkits (discovered, registering, failed etc.)
        other_kits = [k for k in self.devkits.values() if k not in online_kits]
        if len(other_kits) > 0:
            imgui.text('Add a devkit:')
            buttons_index = 0
            for kit in other_kits:
                imgui.text(kit.full_name)
                imgui.same_line()
                if kit.state == DevkitState.devkit_init:
                    imgui.text('Initializing...')
                elif kit.state == DevkitState.devkit_registering:
                    imgui.text('Registering...')
                elif kit.state == DevkitState.devkit_not_registered:
                    if imgui.button(f'Register##{buttons_index}'):
                        register_future = kit.register()
                        self.modal_wait = ModalWait(
                            self.viewport,
                            self.toolbar,
                            'Registering with devkit {!r}'.format(kit.name),
                            register_future,
                            exit_on_success=True
                        )
                        self.modal_wait.override_output_text = 'Please approve pairing on the device...'
                    limited_connectivity = kit.limited_connectivity
                    # we check for this first thing in _identify, shouldn't be possible to come here without it anymore
                    assert not limited_connectivity is None
                    if limited_connectivity:
                        if kit.guest_lan:
                            imgui.same_line()
                            imgui.text(GUEST_LAN_LIMITED_CONNECTIVITY)
                        else:
                            running_sshd = True
                            if kit.http_connectivity:
                                # only obtained if http connectivity was confirmed
                                settings = kit.service_properties['settings']
                                # old services will not report the flag and have sshd running by default
                                running_sshd = ( settings.get('sshd', '1') == '1' )
                            # a device that was never registered as a devkit will not have sshd running yet,
                            # in that case we do not say anything about limited connectivity to avoid confusion
                            if running_sshd:
                                imgui.same_line()
                                ssh_status = 'open' if kit.ssh_connectivity else 'closed'
                                http_status = 'open' if kit.http_connectivity else 'closed'
                                imgui.text(f'WARNING: The device is visible over mDNS, but some network ports are unreachable (22 {ssh_status}, {kit.http_port} {http_status}): cannot use this kit')
                else:
                    assert kit.state == DevkitState.devkit_init_failed
                    imgui.text('Init failed')
                    imgui.same_line()
                    if imgui.button(f'Retry##{buttons_index}'):
                        kit.state = DevkitState.devkit_init
                        kit.setup()
                    if kit.added_by_ip:
                        imgui.same_line()
                        if imgui.button(f'Forget IP kit##failed_{buttons_index}'):
                            kit.forget_added_by_ip()
                            del self.devkits[kit.name]

                    limited_connectivity = kit.limited_connectivity
                    # we check for this first thing in _identify, shouldn't be possible to come here without it anymore
                    assert not limited_connectivity is None
                    if limited_connectivity:
                        if kit.guest_lan:
                            imgui.same_line()
                            imgui.text(GUEST_LAN_LIMITED_CONNECTIVITY)
                        else:
                            imgui.same_line()
                            ssh_status = 'open' if kit.ssh_connectivity else 'closed'
                            http_status = 'open' if kit.http_connectivity else 'closed'
                            if kit.added_by_ip:
                                if not kit.ssh_connectivity and not kit.http_connectivity:
                                    imgui.text(f'WARNING: device added by IP, did not respond.')
                                else:
                                    imgui.text(f'WARNING: device added by IP, some network ports are unreachable (22 {ssh_status}, {kit.http_port} {http_status}): cannot use this kit')
                            else:
                                imgui.text(f'WARNING: device discovered over mDNS, but some network ports are unreachable (22 {ssh_status}, {kit.http_port} {http_status}): cannot use this kit')
                buttons_index += 1

        if len(online_kits) == 0 and len(other_kits) == 0:
            imgui.text('No devkit discovered on the network (mDNS). If your devkit is running, please add by IP.')

        if len(online_kits) == 0:
            imgui.text('No registered devkits online! Add a devkit to start.')
        else:
            imgui.separator()
            imgui.text('Select target devkit:')
            counter = 0
            for kit in online_kits:
                description = kit.full_name
                if kit.is_jupiter:
                    description += f' Jupiter OS: {kit.os_version}'
                else:
                    description += f' OS: {kit.os_name}'
                if not kit.user_password_is_set:
                    description += f' - user password is not set'
                clicked, _ = imgui.checkbox(description, kit.name == self._selected_devkit_name)
                # TODO: list installed titles
                if clicked:
                    self._selected_devkit_name = kit.name
                    self.signal_selected_devkit.emit(kit=kit)
                    # Mark as the new preferred devkit
                    self.preferred_devkit_name = self._selected_devkit_name
                    self.settings['DevkitsWindow.preferred_devkit_name'] = self.preferred_devkit_name
                if kit.added_by_ip:
                    imgui.same_line()
                    if imgui.button('Forget IP kit##online_{counter}'):
                        kit.forget_added_by_ip()
                        del self.devkits[kit.name]
                        # end the draw frame early in case we invalidated the active devkit
                        imgui.end()
                        return
                counter += 1
            if self.selected_devkit is not None:
                if self.selected_devkit.is_jupiter:
                    active_buttons = [
                        RefreshStatus.BUTTON_NAME,
                        ListTitles.BUTTON_NAME,
                        ChangePassword.BUTTON_NAME,
                        RemoteShell.BUTTON_NAME,
                        RestartSDDM.BUTTON_NAME,
                        BrowseFiles.BUTTON_NAME,
                    ]
                    if self.selected_devkit.cef_debugging_enabled or self.valve_mode:
                        active_buttons.append(CEFConsole.BUTTON_NAME)
                else:
                    # The non-jupiter code path is likely bitrotting fast atm
                    active_buttons = [
                        RefreshStatus.BUTTON_NAME,
                        ListTitles.BUTTON_NAME,
                        RemoteShell.BUTTON_NAME,
                    ]
                same_line = False
                for button_name in active_buttons:
                    if same_line:
                        imgui.same_line()
                    if imgui.button(button_name):
                        self.toolbar.signal_pressed.emit(name=button_name, selected_devkit=self.selected_devkit)
                    same_line = True

            steamos_status = self.selected_devkit.steamos_status
            assert steamos_status is not None
            if self.selected_devkit.is_jupiter:
                # === gamescope / plasma session select ========================================
                ljust=24
                if self.valve_mode:
                    self._valve_mode_draw(ljust)
                imgui.text(f'{"Set session":<{ljust}}:')
                imgui.same_line()
                imgui.push_item_width(25*CHARACTER_WIDTH)
                combo_options = steamos_status['session_options'].copy()
                session_status = steamos_status['session_status']
                try:
                    session_status_index = steamos_status['session_options'].index(steamos_status['session_status'])
                except:
                    combo_options.append(session_status)
                    session_status_index = len(combo_options)-1
                clicked, selected_out = imgui.combo(
                    '##Session',
                    session_status_index,
                    combo_options,
                )
                if clicked:
                    # apply immediately
                    if selected_out < len(steamos_status['session_options']):
                        apply_session = steamos_status['session_options'][selected_out]
                        logger.info(f'apply {apply_session}')
                        set_session_future = self.devkit_commands.set_session(
                            self.selected_devkit,
                            apply_session,
                            True # wait
                        )
                        self.modal_wait = ModalWait(
                            self.viewport,
                            self.toolbar,
                            f'Changing session on {self.selected_devkit.name!r}',
                            set_session_future,
                            exit_on_success=True,
                        )

                # === Steam client config ========================================================
                imgui.text(f'{"Steam client is":<{ljust}}:')
                imgui.same_line()
                imgui.push_item_width(30*CHARACTER_WIDTH)
                imgui.text(steamos_status['steam_status_description'])
                imgui.pop_item_width()
                imgui.text(f'{"Change to":<{ljust}}:')
                imgui.same_line()
                config_options = [
                    ( 'OS client', 'SteamStatus.OS' ),
                    ( 'OS client dev mode (logging+cmdline)', 'SteamStatus.OS_DEV' ),
                ]
                if steamos_status['has_side_loaded_client']:
                    config_options.append( ( 'side loaded client', 'SteamStatus.SIDE' ) )
                status_lookup = steamos_status['steam_status']
                if status_lookup == 'SteamStatus.VSCODE':
                    status_lookup = 'SteamStatus.SIDE' # don't distinguish, just say 'side loaded client'
                steam_config_index = 0
                try:
                    steam_config_index = [ v[1] for v in config_options ].index(status_lookup)
                except:
                    pass # unknown status, we'll just use 0
                clicked, selected_config_index = imgui.combo(
                    '##ConfigSteam',
                    steam_config_index,
                    [ v[0] for v in config_options ],
                )
                if clicked:
                    target_steam_client = config_options[selected_config_index][1]
                    self._set_steam_client(target_steam_client)
                if status_lookup in ('SteamStatus.OS_DEV', 'SteamStatus.SIDE'):
                    # Enable setting the command line from here, for both OS client and side-loaded client
                    if self.steam_client_args is None:
                        if 'steam_current_args' in steamos_status:
                            self.steam_client_args = ' '.join(steamos_status['steam_current_args'])
                        else:
                            logger.warning('Current command line arguments for the Steam client not available, falling back to default arguments.')
                            self.steam_client_args = ' '.join(steamos_status['steam_default_args'])
                    imgui.text(f'{"Arguments":<{ljust}}:')
                    imgui.same_line()
                    imgui.push_item_width(60*CHARACTER_WIDTH)
                    changed, s = imgui.input_text('##CommandLine', self.steam_client_args, 1000)
                    imgui.pop_item_width()
                    if changed:
                        self.steam_client_args = s
                    imgui.same_line()
                    if imgui.button('Reset'):
                        # Reset to the default arguments out of gamescope-session
                        self.steam_client_args = ' '.join(steamos_status['steam_default_args'])
                    current_args = ' '.join(steamos_status['steam_current_args']) if steamos_status['steam_current_args'] is not None else None
                    dirty = self.steam_client_args != current_args
                    if dirty:
                        imgui.same_line()
                        if imgui.button('Apply'):
                            self._set_steam_client(status_lookup)
                imgui.separator()

            subtool_list = []
            if self.selected_devkit.is_jupiter:
                subtool_list += [
                    self.screenshot,
                    self.perf_overlay,
                    self.gpu_trace,
                    self.rgp_capture,
                ]
            subtool_list += [
                self.controller_configs,
                self.delete_title,
            ]

            # sub tools do their own drawing in the devkits window and have their own trigger buttons
            for subtool in subtool_list:
                subtool.devkits_window_draw(self.selected_devkit)

        imgui.end()

        if self.modal_wait is None:
            return
        if not self.modal_wait.draw():
            self.modal_wait = None


class ConsoleHandler(logging.Handler):
    MAX_LINES = 500

    def __init__(self, logger, formatter, *args):
        super(ConsoleHandler, self).__init__()
        self.logger = logger
        self.formatter = formatter
        self.log_lines = collections.deque(maxlen=ConsoleHandler.MAX_LINES)
        self.dirty = True
        self._text = None
        self._text_len = None

    def setup(self):
        self.logger.addHandler(self)

    @property
    def text_and_len(self):
        if self.dirty:
            self._text = '\n'.join(self.log_lines) + '\n'
            self._text_len = len(self._text)
            self.dirty = False
        return (self._text, self._text_len)

    def emit(self, record):
        self.add_line(self.formatter.format(record))

    def add_line(self, line):
        self.log_lines.extend(line.split('\n'))
        self.dirty = True


class FileToConsoleHandlerAdapter:
    '''Adapt a file object API to push logging records to a ConsoleHandler'''

    def __init__(self, handler):
        self.handler = handler

    def write(self, buf):
        # Do we get partial line writes? Assuming no..
        for line in buf.splitlines(False):
            self.handler.add_line(line.rstrip('\n'))

    def flush(self):
        pass


class ConsoleWindow(ToolWindow):
    '''All purpose logging window.'''

    BUTTON_NAME = 'Status'
    SETTINGS_NAME = 'ConsoleWindow.autoscroll'

    def __init__(self, conf, handler, settings, *args):
        super(ConsoleWindow, self).__init__(self.BUTTON_NAME, *args)
        self.conf = conf
        self.handler = handler
        self.settings = settings
        # Draw even when no kit is active
        self.tick_without_devkit = True
        self.autoscroll = self.settings.get(ConsoleWindow.SETTINGS_NAME, True)
        self.autoscroll_y = 0

    def tick(self, visible):
        (_, opened) = imgui.begin(self.BUTTON_NAME, True, imgui.WINDOW_NO_COLLAPSE)
        if not opened:
            self.visible = False
            imgui.end()
            return
        clicked, v = imgui.checkbox('Auto-scroll on output', self.autoscroll)
        if clicked:
            self.autoscroll = v
            self.settings[ConsoleWindow.SETTINGS_NAME] = v
        imgui.begin_child('console')
        text, text_len = self.handler.text_and_len
        # the +1 fixes flickering memory garbage text appearing at the end of the log,
        # I suspect there's an off-by-one somewhere with the terminating \0, maybe that's an imgui fix (core.pyx)
        imgui.input_text_multiline('', text, text_len+1, imgui.get_window_width(), imgui.get_window_height(), imgui.INPUT_TEXT_READ_ONLY)
        if self.autoscroll:
            imgui.begin_child('')
            max_y = imgui.get_scroll_max_y()
            if max_y != self.autoscroll_y:
                imgui.set_scroll_y(max_y)
                self.autoscroll_y = max_y
            imgui.end_child()
        imgui.end_child()
        imgui.end()


class SubTool:
    def __init__(self, devkit_commands, viewport, toolbar, settings):
        self.devkit_commands = devkit_commands
        self.viewport = viewport
        self.toolbar = toolbar
        self.settings = settings
        self.list_games_future = None
        self.modal_wait = None

    def on_draw(self, **kwargs):
        if self.modal_wait is None:
            return
        if not self.modal_wait.draw():
            self.modal_wait = None


class ListTitles(SubTool):
    BUTTON_NAME = 'List Titles'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name, selected_devkit, **kwargs):
        if name != self.BUTTON_NAME:
            return
        self.list_games_future = self.devkit_commands.list_games(selected_devkit)
        self.modal_wait = ModalWait(
            self.viewport,
            self.toolbar,
            'Titles deployed on {!r}:'.format(selected_devkit.name),
            self.list_games_future
            )
        self.modal_wait.signal_task_done.connect(self.on_list_done)

    def on_list_done(self, **kwargs):
        if self.modal_wait.result is None:
            # failed, let the exception be displayed using ModalWait's defaults
            return
        # parse the json response for presentation
        output = '\n'.join(game['gameid'] for game in self.modal_wait.result)
        self.modal_wait.override_output_text = output


class UpdateTitle(ToolWindow):
    BUTTON_NAME = 'Title Upload'
    STEAM_DEFAULT_EXCLUDE_PATTERNS_V1 = '*.exe *.dll *.pdb Steam.AppBundle *.dylib.dSYM ios64 tvos64 ubuntu12_32/steam-runtime'
    STEAM_DEFAULT_EXCLUDE_PATTERNS_V2 = '*.exe *.dll *.pdb Steam.AppBundle *.dylib.dSYM ios64 tvos64 ubuntu12_32/steam-runtime package* steamapp* workshop* android* appcache* depotcache* bin/cef dumps* logs* userdata*'
    STEAM_DEFAULT_EXCLUDE_PATTERNS_V3 = '+_legacycompat/* +_steamclient*.dll +_GameOverlayRenderer64.dll *.exe *.dll *.pdb Steam.AppBundle *.dylib.dSYM ios64 tvos64 ubuntu12_32/steam-runtime package* steamapp* workshop* android* appcache* depotcache* bin/cef dumps* logs* userdata*'
    STEAM_DEFAULT_EXCLUDE_PATTERNS_V4 = '+_legacycompat/* +_bin/d3ddriverquery64.exe +_steamclient*.dll +_GameOverlayRenderer64.dll *.exe *.dll *.pdb Steam.AppBundle *.dylib.dSYM ios64 tvos64 ubuntu12_32/steam-runtime package* steamapp* workshop* android* appcache* depotcache* bin/cef dumps* logs* userdata*'
    STEAM_DEFAULT_EXCLUDE_PATTERNS = '+_legacycompat/* +_bin/d3ddriverquery64.exe +_steamclient*.dll +_GameOverlayRenderer64.dll libcef.so.dbg *.exe *.dll *.pdb Steam.AppBundle *.dylib.dSYM ios64 tvos64 ubuntu12_32/steam-runtime package* steamapp* workshop* android* appcache* depotcache* bin/cef dumps* logs* userdata*'
    STEAM_DEFAULT_START_COMMAND_V1 = './steam.sh -steampal -steamos3'
    STEAM_DEFAULT_START_COMMAND = './steam.sh -steamdeck -steamos3'
    SELECTED_CONFIG_LIST = 'UpdateTitleConfigs'
    SELECTED_CONFIG_KEY = 'UpdateTitleSelectedConfig'

    POSSIBLE_DEPS = [{"name":"DirectX", "items": [{"id": "directx", "name": "June 2010"}]},
                     {"name": "Visual C++ Redist", "items": [{"id": "vs2019", "name": "2019 (also includes 2017 & 2015)"},
                                                             {"id": "vs2017", "name": "2017 (deprecated)"},
                                                             {"id": "vs2015", "name": "2015 (deprecated)"},
                                                             {"id": "vs2013", "name": "2013"},
                                                             {"id": "vs2012", "name": "2012"},
                                                             {"id": "vs2010", "name": "2010"},
                                                             {"id": "vs2008", "name": "2008"},
                                                             {"id": "vs2004", "name": "2005"}]},
                     {"name": "OpenAL", "items": [{"id": "openal", "name": "2.0.7.0"}]},
                     {"name": ".NET", "items": [{"id": "dotnet48", "name": "4.8"},
                                                {"id": "dotnet47", "name": "4.7.2"},
                                                {"id": "dotnet46", "name": "4.6.2"},
                                                {"id": "dotnet45", "name": "4.5.2"},
                                                {"id": "dotnet40client", "name": "4.0 Client Profile"},
                                                {"id": "dotnet40", "name": "4.0"},
                                                {"id": "dotnet35client", "name": "3.5 Client Profile"},
                                                {"id": "dotnet35", "name": "3.5"}]},
                     {"name": "XNA", "items": [{"id": "xna40", "name": "4.0"},
                                               {"id": "xna31", "name": "3.1"},
                                               {"id": "xna30", "name": "3.0"}]},
                     {"name": "PhysX", "items": [{"id": "physx8", "name": "8.09.04"},
                                                 {"id": "physx912", "name": "9.12.1031"},
                                                 {"id": "physx913", "name": "9.13.1220"},
                                                 {"id": "physx914", "name": "9.14.0702"}]}]

    def __init__(self, devkit_commands, devkits_window, settings, *args):
        super(UpdateTitle, self).__init__(self.BUTTON_NAME, *args)
        self.devkit_commands = devkit_commands
        self.devkits_window = devkits_window
        self.settings = settings
        self.apply_default_settings()
        self.available_configs = self.settings.get(UpdateTitle.SELECTED_CONFIG_LIST, [])
        forbbiden_steam_config_names = [ v for v in self.available_configs if v.lower() == 'steam' and v != 'steam' ]
        if len(forbbiden_steam_config_names) > 0:
            logger.error(f'only "steam" all-lowercase configs - skipping {forbbiden_steam_config_names}')
            for v in forbbiden_steam_config_names:
                self.available_configs.remove(v)
        self.selected_config = self.settings.get(UpdateTitle.SELECTED_CONFIG_KEY, '')
        self.restore_settings(self.selected_config)
        self.update_future = None
        self.modal_wait = None
        self.deps = {}
        # cancel signal emitted to the low level execution if we want to cancel the rsync transfer
        self.cancel_signal = signalslot.Signal()

    def save_settings(self, prefix, dict):
        dict[f'{prefix}title_name'] = self.title_name
        dict[f'{prefix}local_folder'] = self.local_folder
        dict[f'{prefix}filter_mode'] = self.filter_mode
        dict[f'{prefix}filter_patterns'] = self.filter_patterns
        dict[f'{prefix}delete_remote_files'] = self.delete_remote_files
        dict[f'{prefix}verify_checksums'] = self.verify_checksums
        dict[f'{prefix}start_command'] = self.start_command
        dict[f'{prefix}restart_steam'] = self.restart_steam
        dict[f'{prefix}steam_play'] = self.steam_play
        dict[f'{prefix}steam_play_debug'] = self.steam_play_debug
        dict[f'{prefix}steam_play_debug_wait'] = self.steam_play_debug_wait
        dict[f'{prefix}steam_play_debug_version'] = self.steam_play_debug_version
        dict[f'{prefix}auto_upload'] = self.auto_upload
        dict[f'{prefix}gdbserver'] = self.gdbserver
        dict[f'{prefix}dependencies'] = self.deps

    def restore_settings(self, gameid):
        if gameid is None or len(gameid) == 0:
            return
        try:
            # make the defaults match apply_default_settings
            self.title_name = self.settings.get(f'UpdateTitle.{gameid}.title_name', '')
            self.local_folder = self.settings.get(f'UpdateTitle.{gameid}.local_folder', '')
            self.filter_mode = self.settings.get(f'UpdateTitle.{gameid}.filter_mode', 0)
            # this is a bit nasty, we have to copy the list when retrieving from the Settings object, otherwise it's the same pattern for all title configurations
            self.filter_patterns = self.settings.get(f'UpdateTitle.{gameid}.filter_patterns', ['', '', '']).copy()
            self.delete_remote_files = self.settings.get(f'UpdateTitle.{gameid}.delete_remote_files', False)
            self.verify_checksums = self.settings.get(f'UpdateTitle.{gameid}.verify_checksums', False)
            self.start_command = self.settings.get(f'UpdateTitle.{gameid}.start_command', '')
            self.restart_steam = self.settings.get(f'UpdateTitle.{gameid}.restart_steam', False)
            self.steam_play = self.settings.get(f'UpdateTitle.{gameid}.steam_play', False)
            self.steam_play_debug = self.settings.get(f'UpdateTitle.{gameid}.steam_play_debug', False)
            self.steam_play_debug_wait = self.settings.get(f'UpdateTitle.{gameid}.steam_play_debug_wait', False)
            self.steam_play_debug_version = self.settings.get(f'UpdateTitle.{gameid}.steam_play_debug_version', '2019')
            self.auto_upload = self.settings.get(f'UpdateTitle.{gameid}.auto_upload', False)
            self.gdbserver = self.settings.get(f'UpdateTitle.{gameid}.gdbserver', False)
            self.deps = self.settings.get(f'UpdateTitle.{gameid}.dependencies', {})
        except Exception as e:
            # used to be a sort of valid code path, shouldn't happen anymore
            devkit_client.log_exception(e)

        exclude_patterns = self.settings.get(f'UpdateTitle.{gameid}.exclude_patterns', '')
        if len(exclude_patterns) > 0:
            logger.info(f'Converting obsolete exclude_patterns setting for game {gameid} to the new filter settings')
            self.filter_mode = 0
            self.filter_patterns[0] = exclude_patterns
            # one time: write back an empty string
            self.settings[f'UpdateTitle.{gameid}.exclude_patterns'] = ''

        if gameid == 'steam' and self.filter_mode == 0:
            # transparently update the exclude filter pattern to the new version if it was set to the old default
            if len(self.filter_patterns[0]) == 0 or self.filter_patterns[0] in (
                self.STEAM_DEFAULT_EXCLUDE_PATTERNS_V1,
                self.STEAM_DEFAULT_EXCLUDE_PATTERNS_V2,
                self.STEAM_DEFAULT_EXCLUDE_PATTERNS_V3,
                self.STEAM_DEFAULT_EXCLUDE_PATTERNS_V4,
            ):
                logger.info(f'Update default steam exclude pattern to latest version')
                self.filter_patterns[0] = self.STEAM_DEFAULT_EXCLUDE_PATTERNS
        if gameid == 'steam':
            # transparently update the start command
            if len(self.start_command) == 0 or self.start_command in (
                self.STEAM_DEFAULT_START_COMMAND_V1,
            ):
                logger.info(f'Update default steam start command to latest version')
                self.start_command = self.STEAM_DEFAULT_START_COMMAND

    def apply_default_settings(self):
        self.title_name = ''
        self.local_folder = ''
        # If true, filter with an exclude pattern (default). Otherwise use an include pattern.
        self.filter_mode = 0
        # track the patterns for all three filter modes, only one applies at upload time though
        self.filter_patterns = ['', '', '']
        self.delete_remote_files = False
        self.verify_checksums = False
        self.start_command = ''
        self.restart_steam = False
        self.steam_play = False
        self.steam_play_debug = False
        self.steam_play_debug_wait = False
        self.steam_play_debug_version = '2019'
        self.auto_upload = False
        self.gdbserver = False
        self.deps = {}

    def _select_title(self, gameid):
        if gameid is None:
            self.apply_default_settings()
            self.selected_config = ''
            return
        self.selected_config = gameid
        self.settings[UpdateTitle.SELECTED_CONFIG_KEY] = gameid
        self.restore_settings(gameid)

    def tick(self, visible):
        (_, opened) = imgui.begin(self.BUTTON_NAME, True, imgui.WINDOW_NO_COLLAPSE)
        if not opened:
            self.visible = False
            imgui.end()
            return

        imgui.columns(2)
        imgui.set_column_width(0, 170)

        imgui.text('Load config:')
        imgui.next_column()
        selected_index = 0
        if self.selected_config in self.available_configs:
            selected_index = self.available_configs.index(self.selected_config) + 1
        clicked, selected_out = imgui.combo(
            "##Restore", selected_index, ['default'] + self.available_configs
        )
        if clicked:
            if selected_out == 0:
                self._select_title(None)
            else:
                self._select_title(self.available_configs[selected_out-1])
        imgui.next_column()
        imgui.next_column()
        save_config = imgui.button('Save config')
        imgui.same_line()
        if imgui.button('Delete config'):
            if self.selected_config in self.available_configs:
                logger.info(f'Delete config {self.selected_config!r}')
                self.available_configs.remove(self.selected_config)
            else:
                logger.warning(f'Cannot delete config {self.selected_config!r}: not found')
        imgui.next_column()
        imgui.separator()

        imgui.text('Name:')
        imgui.next_column()
        imgui.push_item_width(-1)
        changed, s = imgui.input_text('##Name', self.title_name, 1000)
        imgui.pop_item_width()
        if changed:
            if s.lower() == 'steam':
                # only all lowercase 'steam' is admissible - 'Steam' causes problems with the devkit scripts
                s = 'steam'
            self.title_name = s
            if self.title_name == 'steam':
                # Set the default exclude pattern for steam
                self.filter_patterns[0] = self.STEAM_DEFAULT_EXCLUDE_PATTERNS
                self.start_command = self.STEAM_DEFAULT_START_COMMAND
            else:
                if self.filter_patterns[0] == self.STEAM_DEFAULT_EXCLUDE_PATTERNS:
                    # Do not drag the Steam client exclude pattern into all title names that start with 'steam'
                    self.filter_patterns[0] = ''
                if self.start_command == self.STEAM_DEFAULT_START_COMMAND:
                    # Do not drag the Steam client start command into all title names that start with 'steam'
                    self.start_command = ''
        imgui.next_column()
        imgui.text('Local Folder:')
        imgui.next_column()
        imgui.push_item_width(-1)
        changed, s = imgui.input_text('##LocalFolder', self.local_folder, 1000)
        imgui.pop_item_width()
        if changed:
            self.local_folder = s
        imgui.next_column()
        imgui.text('Upload filtering:')
        imgui.next_column()

        imgui.push_item_width(16*CHARACTER_WIDTH)
        changed, v = imgui.combo(
            '##FilterPatternSelect',
            self.filter_mode,
            ['Exclude only', 'Include only', 'Rsync args'],
            )
        if changed:
            self.filter_mode = v
        imgui.pop_item_width()
        imgui.same_line()
        imgui.push_item_width(-1)
        changed, s = imgui.input_text('##FilterPattern', self.filter_patterns[self.filter_mode], 1000)
        imgui.pop_item_width()
        if changed:
            self.filter_patterns[self.filter_mode] = s
        imgui.next_column()

        imgui.text('Clean upload:')
        imgui.next_column()
        clicked, v = imgui.checkbox('Delete remote files not present in local folder', self.delete_remote_files)
        if clicked:
            self.delete_remote_files = v
        imgui.same_line()
        clicked, v = imgui.checkbox('Verify checksums', self.verify_checksums)
        if clicked:
            self.verify_checksums = v
        imgui.next_column()
        imgui.text('Start Command:')
        imgui.next_column()
        imgui.push_item_width(-1)
        changed, s = imgui.input_text('##StartCommand', self.start_command, 1000)
        imgui.next_column()
        imgui.pop_item_width()
        if changed:
            self.start_command = s

        if self.title_name.lower() != 'steam':
            imgui.text('Steam Play:')
            imgui.next_column()
            clicked, v = imgui.checkbox('This title requires Steam Play', self.steam_play)
            imgui.next_column()
            if clicked:
                self.steam_play = v

            if self.steam_play:
                imgui.next_column()

                # keeping this off until the Steam side is ready for support
                #if imgui.button('Set dependencies'):
                #    imgui.open_popup('Set dependencies')

                if imgui.begin_popup_modal('Set dependencies')[0]:
                    imgui.columns(2)
                    imgui.set_column_width(0,170)
                    imgui.text('Common redistributables')
                    imgui.next_column()
                    for dep in UpdateTitle.POSSIBLE_DEPS:
                        imgui.next_column()
                        imgui.text(dep["name"])
                        for depitem in dep["items"]:
                            depclicked, depchecked = imgui.checkbox(depitem["name"], depitem["id"] in self.deps)

                            if depclicked:
                                if depchecked:
                                    self.deps[depitem["id"]] = True
                                else:
                                    del self.deps[depitem["id"]]
 
                    dismiss = imgui.button('OK')

                    # Press OK button, or hit escape/enter to dismiss once the task is complete
                    keyboard_state = sdl2.SDL_GetKeyboardState(None)
                    dismiss |= keyboard_state[sdl2.SDL_SCANCODE_ESCAPE] or keyboard_state[sdl2.SDL_SCANCODE_RETURN] or keyboard_state[sdl2.SDL_SCANCODE_KP_ENTER]
                    if dismiss:
                        imgui.close_current_popup()
                    imgui.end_popup()

                imgui.next_column()
                imgui.text('Steam Play debug:')
                imgui.next_column()
                clicked, v = imgui.checkbox('Start Visual Studio C++ debugger service on launch', self.steam_play_debug != SteamPlayDebug.Disabled)
                imgui.next_column()
                if clicked:
                    self.steam_play_debug = v
                if self.steam_play_debug:
                    remote_debuggers = devkit_client.get_remote_debuggers()
                    if len(remote_debuggers) == 0:
                        imgui.next_column()
                        imgui.text('ERROR: Please install the Visual Studio Remote Tools on your Windows system first.')
                        imgui.same_line()
                        if imgui.button('Help'):
                            webbrowser.open('https://partner.steamgames.com/doc/steamdeck/devkits/debugging')
                        imgui.next_column()
                    else:
                        imgui.text('Wait for attach:')
                        imgui.next_column()
                        clicked, v = imgui.checkbox('Wait for a debug client to attach', self.steam_play_debug_wait)
                        imgui.next_column()
                        if clicked:
                            self.steam_play_debug_wait = v
                        imgui.text('Remote debugger:')
                        imgui.next_column()
                        version_options = [ str(dbg.year) for dbg in remote_debuggers ]
                        try:
                            version_index = version_options.index(self.steam_play_debug_version)
                        except:
                            logger.warning(f'Invalid remote debug tool version {self.steam_play_debug_version}, resetting')
                            version_index = 0
                            self.steam_play_debug_version = version_options[0]
                        imgui.push_item_width(8*CHARACTER_WIDTH)
                        clicked, selected_index = imgui.combo(
                            '##MSVSMonVersion', version_index, version_options
                        )
                        imgui.pop_item_width()
                        if clicked:
                            self.steam_play_debug_version = version_options[selected_index]
                        imgui.next_column()
        else:
            self.steam_play = False

        if self.devkits_window.selected_devkit.is_jupiter and self.title_name.lower() == 'steam':
            imgui.text('Restart:')
            imgui.next_column()
            clicked, v = imgui.checkbox('Restart Steam side loaded client on upload', self.restart_steam)
            imgui.next_column()
            if clicked:
                self.restart_steam = v
            imgui.text('gdbserver:')
            imgui.next_column()
            clicked, v = imgui.checkbox('Use gdbserver (will wait with no rendering for a remote attach, check documentation)', self.gdbserver)
            imgui.next_column()
            if clicked:
                self.gdbserver = v
        else:
            self.restart_steam = False

        imgui.text('Auto upload:')
        imgui.next_column()
        clicked, v = imgui.checkbox('Auto upload upon build success notification', self.auto_upload)
        imgui.next_column()
        if clicked:
            self.auto_upload = v

        imgui.columns(1)

        do_upload = imgui.button('Upload')

        if save_config or do_upload:
            if re.fullmatch(GAMEID_ALLOWED_PATTERN, self.title_name) is None:
                failed_future = concurrent.futures.Future()
                failed_future.set_exception(Exception(f'Title name {self.title_name!r} must match pattern {GAMEID_ALLOWED_PATTERN}'))
                self.modal_wait = ModalWait(
                    self.viewport,
                    self.toolbar,
                    'ERROR',
                    failed_future
                )
                save_config = False
                do_upload = False
            else:
                logger.info(f'Saving config for {self.title_name!r}')
                self.save_settings(f'UpdateTitle.{self.title_name}.', self.settings)
                if not self.title_name in self.available_configs:
                    self.available_configs.append(self.title_name)
                    self.available_configs = sorted(self.available_configs)
                    self.settings[UpdateTitle.SELECTED_CONFIG_LIST] = self.available_configs
                    self.settings[UpdateTitle.SELECTED_CONFIG_KEY] = self.title_name
                # This is an important enough operation, force a flush to disk
                self.settings.save_settings()

        imgui.end()

        if do_upload:
            self.do_upload()

        if self.modal_wait is None:
            return
        # updating
        if not self.modal_wait.draw():
            if self.modal_wait.error is None:
                # the update was a success, bring the focus back to this window, otherwise leave at the status window
                self.on_pressed(UpdateTitle.BUTTON_NAME)
            self.modal_wait = None

    def on_ui_cancel_upload(self, **kwargs):
        # signal emitted by the UI to request transfer cancel, emit back to the low level
        logger.info('Cancelling upload operation')
        self.cancel_signal.emit()

    def do_upload(self):
        # build the rsync command line args for filtering upload content
        filter_args = []
        filter_tokens = shlex.split(self.filter_patterns[self.filter_mode])
        if self.filter_mode == 0:
            # a set of exclude patterns, this was the only implementation originally
            for token in filter_tokens:
                if token.startswith('+_'):
                    # this was a legacy hack, we keep it in
                    filter_args.append(f'--include={token[2:]}')
                else:
                    filter_args.append(f'--exclude={token}')
        elif self.filter_mode == 1:
            filter_args += [ f'--include={token}' for token in filter_tokens ]
            # visit all directories, skip all files
            # see https://unix.stackexchange.com/questions/2161/rsync-filter-copying-one-pattern-only
            filter_args += ['--include=*/', '--exclude=*', '--prune-empty-dirs']
        else:
            # just take the tokens directly as rsync args
            # this allows for more custom options, such as --copy-links etc.
            filter_args += filter_tokens
        steam_play_debug_enum = SteamPlayDebug.Disabled
        if self.steam_play and self.steam_play_debug:
            steam_play_debug_enum = SteamPlayDebug.Wait if self.steam_play_debug_wait else SteamPlayDebug.Start
        self.update_future = self.devkit_commands.update_game(
            self.devkits_window.selected_devkit,
            self.restart_steam,
            self.gdbserver,
            self.steam_play,
            steam_play_debug_enum,
            self.steam_play_debug_version,
            self.title_name,
            self.local_folder,
            self.delete_remote_files,
            self.verify_checksums,
            [self.start_command],
            filter_args,
            self.deps,
            self.cancel_signal
            )
        self.result_message = None
        self.modal_wait = ModalWait(
            self.viewport,
            self.toolbar,
            'Updating {!r} on {!r}'.format(
                self.title_name,
                self.devkits_window.selected_devkit.name
            ),
            self.update_future,
            exit_on_success=True,
            cancel_signal=True,
            )
        self.modal_wait.cancel_signal.connect(self.on_ui_cancel_upload)
        self.toolbar.focus_console()

    def on_build_success(self, name):
        auto_upload_pref = f'UpdateTitle.{name}.auto_upload'
        if not ( auto_upload_pref in self.settings ):
            raise Exception(f'No such title: {name}')
        if not self.settings.get(f'UpdateTitle.{name}.auto_upload', False):
            # title is not configured to do uploads
            logger.info(f'Received a build success notification for {name!r}. Auto upload is not enabled, stopping.')
            return
        if name == 'steam':
            client_config = self.devkits_window.selected_devkit.steam_configuration
            if client_config != 'SteamConfig.SIDE':
                # Valve developers found it confusing that the side-loaded client would be refreshed
                # and switched over to if the kit is running the OS client
                # In order to avoid creating confusion the other way though, about builds getting done but no uploads happening,
                # let's abuse the modal system and pop an obnoxious message
                failed_future = concurrent.futures.Future()
                failed_future.set_exception(Exception(f'Received a build success notification for {name!r}, but the device is not configured to run a side loaded Steam client ({client_config}), stopping.'))
                self.modal_wait = ModalWait(
                    self.viewport,
                    self.toolbar,
                    'Build success notifications',
                    failed_future,
                )
                return
        # bring to the foreground in case some other title was selected
        self._select_title(name)
        self.do_upload()


class RefreshStatus:
    BUTTON_NAME = 'Refresh Status'

    def __init__(self, devkit_commands, devkits_window, viewport, toolbar):
        self.devkit_commands = devkit_commands
        self.devkits_window = devkits_window
        self.viewport = viewport
        self.toolbar = toolbar
        self.modal_wait = None

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name , **kwargs):
        if name != self.BUTTON_NAME:
            return
        # Refresh a devkit passed in the signal, or the default selected
        kwargs.get('selected_devkit', self.devkits_window.selected_devkit)
        devkit = self.devkits_window.selected_devkit
        status_future = self.devkit_commands.steamos_get_status(devkit)
        self.modal_wait = ModalWait(
            self.viewport,
            self.toolbar,
            f'Refresh SteamOS status on {devkit.name!r}',
            status_future,
            exit_on_success=True
        )

    def on_draw(self, **kwargs):
        if self.modal_wait is None:
            return
        if not self.modal_wait.draw():
            self.modal_wait = None

class DeviceLogs(ToolWindow):
    BUTTON_NAME = 'Device Logs'
    LOGS_FOLDER_KEY = 'DeviceLogs.logs_folder'

    def __init__(self, devkit_commands, devkits_window, settings, *args):
        super(DeviceLogs, self).__init__(self.BUTTON_NAME, *args)
        self.devkit_commands = devkit_commands
        self.devkits_window = devkits_window
        self.settings = settings
        self.logs_folder = None
        self.sync_future = None
        self.modal_wait = None
        self.steam_log = ''
        self.scroll_down = False

    def setup(self):
        super(DeviceLogs, self).setup()
        if self.LOGS_FOLDER_KEY in self.settings:
            self.logs_folder = self.settings[self.LOGS_FOLDER_KEY]
        else:
            self.logs_folder = str(pathlib.Path(os.path.expanduser('~/.devkit-client-gui/logs')))

    def tick(self, visible):
        (_, opened) = imgui.begin(self.BUTTON_NAME, True, imgui.WINDOW_NO_COLLAPSE)
        if not opened:
            self.visible = False
            imgui.end()
            return
        imgui.columns(2)
        imgui.set_column_width(0, 170)
        imgui.text('Download logs to:')
        imgui.next_column()
        imgui.push_item_width(-1)
        changed, s = imgui.input_text(' ', self.logs_folder, 1000)
        if changed:
            self.logs_folder = s
        imgui.pop_item_width()
        imgui.columns(1)
        if imgui.button('Refresh'):
            self.settings[self.LOGS_FOLDER_KEY] = self.logs_folder
            self.sync_future = self.devkit_commands.sync_logs(
                self.devkits_window.selected_devkit,
                self.logs_folder
            )
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                'Retrieving logs from {!r}'.format(self.devkits_window.selected_devkit.name),
                self.sync_future,
                exit_on_success=True,
            )
        imgui.begin_child('logs')
        imgui.input_text_multiline('', self.steam_log, len(self.steam_log)+1, imgui.get_window_width(), imgui.get_window_height(), imgui.INPUT_TEXT_READ_ONLY)
        if self.scroll_down:
            imgui.set_scroll_y(imgui.get_scroll_max_y())
            self.scroll_down = False
        imgui.end_child()
        imgui.end()

        if self.modal_wait is None:
            return
        if not self.modal_wait.draw():
            self.modal_wait = None
            self.reload_logs()

    def reload_logs(self):
        steam_log_path = os.path.join(self.logs_folder, 'steam_logs', 'output.log')
        if not os.path.exists(steam_log_path):
            logger.warning('Devkit log does not exist: %r', steam_log_path)
            return
        self.steam_log = open(steam_log_path, 'rt', errors='replace').read()
        self.scroll_down = True


class RemoteShell:
    BUTTON_NAME = 'Remote Shell'

    def __init__(self, devkit_commands, devkits_window, toolbar):
        self.devkit_commands = devkit_commands
        self.devkits_window = devkits_window
        self.toolbar = toolbar

    def setup(self):
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name , **kwargs):
        if name != self.BUTTON_NAME:
            return
        f = self.devkit_commands.open_remote_shell(self.devkits_window.selected_devkit)
        # fires when the shell closes, so could be a while
        f.add_done_callback(self.on_open_remote_shell_done)

    def on_open_remote_shell_done(self, f):
        try:
            f.result()
        except Exception as e:
            devkit_client.log_exception(e)


class CEFConsole:
    BUTTON_NAME = 'CEF console'

    def __init__(self, devkit_commands, devkits_window, toolbar):
        self.devkit_commands = devkit_commands
        self.devkits_window = devkits_window
        self.toolbar = toolbar

    def setup(self):
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name, **kwargs):
        if name != self.BUTTON_NAME:
            return
        f = self.devkit_commands.open_cef_console(self.devkits_window.selected_devkit)
        f.add_done_callback(self.on_open_cef_console_done)

    def on_open_cef_console_done(self, f):
        try:
            f.result()
        except Exception as e:
            devkit_client.log_exception(e)


class Screenshot(SubTool):
    BUTTON_NAME = 'Take Screenshot'
    FOLDER_KEY = 'Screenshot.folder'
    FILENAME_KEY = 'Screenshot.filename'
    TIMESTAMP_KEY = 'Screenshot.timestamp'

    def setup(self):
        if not self.FOLDER_KEY in self.settings:
            self.settings[self.FOLDER_KEY] = str(pathlib.Path(os.path.expanduser('~/Pictures')))
        if not self.FILENAME_KEY in self.settings:
            self.settings[self.FILENAME_KEY] = ''
        if not self.TIMESTAMP_KEY in self.settings:
            self.settings[self.TIMESTAMP_KEY] = True
        self.viewport.signal_draw.connect(self.on_draw)

    def devkits_window_draw(self, selected_devkit):
        imgui.text('Folder:')
        imgui.same_line()
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##screenshot_folder', self.settings[self.FOLDER_KEY], 260)
        if changed:
            self.settings[self.FOLDER_KEY] = s

        imgui.same_line()
        imgui.text('Filename (optional):')
        imgui.same_line()
        imgui.set_next_item_width(32*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##screenshot_filename', self.settings[self.FILENAME_KEY], 128)
        if changed:
            self.settings[self.FILENAME_KEY] = s

        imgui.same_line()
        clicked, v = imgui.checkbox('timestamp', self.settings[self.TIMESTAMP_KEY])
        if clicked:
            self.settings[self.TIMESTAMP_KEY] = v

        imgui.same_line()
        # gross - plz halp with layout
        imgui.set_cursor_pos_x(1100)
        if imgui.button(Screenshot.BUTTON_NAME):
            task_future = self.devkit_commands.screenshot(
                selected_devkit,
                self.settings[self.FOLDER_KEY],
                self.settings[self.FILENAME_KEY],
                self.settings[self.TIMESTAMP_KEY],
                )
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                f'Capturing Screenshot from {selected_devkit.name}',
                task_future,
                exit_on_success=True,
            )


class PerfOverlay(SubTool):
    FOLDER_KEY = 'PerfOverlay.folder'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        if not self.FOLDER_KEY in self.settings:
            self.settings[self.FOLDER_KEY] = str(pathlib.Path(os.path.expanduser('~/.devkit-client-gui/perf_logs')))
        # tri-states
        self.draw_perf_overlay = None
        self.log_perf_data = None

    def on_selected_devkit(self, kit, **kwargs):
        # When switching kits, the state of the overlay buttons goes back to undefined
        self.draw_perf_overlay = None
        self.log_perf_data = None

    def devkits_window_draw(self, selected_devkit):
        imgui.set_cursor_pos_x(8*CHARACTER_WIDTH)
        if self.draw_perf_overlay is None:
            imgui.internal.push_item_flag(imgui.internal.ITEM_MIXED_VALUE, True)
            clicked, v = imgui.checkbox('Draw performance overlay', False)
            imgui.internal.push_item_flag(imgui.internal.ITEM_MIXED_VALUE, False)
        else:
            clicked, v = imgui.checkbox('Draw performance overlay', self.draw_perf_overlay)
        if clicked:
            self.draw_perf_overlay = v
            cmd_future = self.devkit_commands.simple_command(selected_devkit, ['mangohudctl', 'set', 'no_display', 'false' if self.draw_perf_overlay else 'true'])
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                f'Change performance overlay drawing',
                cmd_future,
                exit_on_success=True,
            )

        imgui.same_line()
        imgui.set_cursor_pos_x(57*CHARACTER_WIDTH)
        imgui.text('frametime folder:')
        imgui.same_line()
        imgui.set_cursor_pos_x(74*CHARACTER_WIDTH)
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##PerfDataFolder', self.settings[self.FOLDER_KEY], 260)
        if changed:
            self.settings[self.FOLDER_KEY] = s

        imgui.same_line()
        imgui.set_cursor_pos_x(1100)
        perf_log_button = 'Stop Capture' if self.log_perf_data else 'Start Frametime Capture'
        if imgui.button(perf_log_button):
            if self.log_perf_data:
                stop_log_future = self.devkit_commands.simple_command(selected_devkit, ['mangohudctl', 'set', 'log_session', 'false'])
                def download_logs(f):
                    self.log_perf_data = False
                    download_logs_future = self.devkit_commands.sync_perf_logs(selected_devkit, self.settings[self.FOLDER_KEY])
                    self.modal_wait = ModalWait(
                        self.viewport,
                        self.toolbar,
                        f'Downloading performance data',
                        download_logs_future,
                        exit_on_success=True,
                    )
                stop_log_future.add_done_callback(download_logs)
                self.modal_wait = ModalWait(
                    self.viewport,
                    self.toolbar,
                    f'Turn off perf logging',
                    stop_log_future,
                    exit_on_success=True,
                )
            else:
                start_log_future = self.devkit_commands.simple_command(selected_devkit, ['mangohudctl', 'set', 'log_session', 'true'])
                self.log_perf_data = True


class GPUTrace(SubTool):
    BUTTON_NAME = 'System trace'
    FILEPATH_KEY = 'GPUTrace.filepath.2'
    LAUNCH_KEY = 'GPUTrace.launch'
    GPUVIS_KEY = 'GPUTrace.gpuvis_path.3'

    def setup(self):
        if not self.FILEPATH_KEY in self.settings:
            self.settings[self.FILEPATH_KEY] = str(pathlib.Path(os.path.expanduser('~/Downloads/gpu-trace.zip')))
        if not self.LAUNCH_KEY in self.settings:
            self.settings[self.LAUNCH_KEY] = True
        self.refresh_gpuvis_path()
        self.viewport.signal_draw.connect(self.on_draw)

    def refresh_gpuvis_path(self):
        if ( self.GPUVIS_KEY in self.settings ) and os.path.exists( self.settings[self.GPUVIS_KEY] ):
            # gpuvis may be tethered to an OS installed version
            return

        gpuvis_bin = 'gpuvis.exe' if platform.system() == 'Windows' else 'gpuvis'

        # search in PATH first
        gpuvis_path = shutil.which(gpuvis_bin)
        if gpuvis_path is not None:
            self.settings[self.GPUVIS_KEY] = gpuvis_path
            return

        if platform.system() != 'Windows':
            # we only bundle gpuvis in the Windows build, so if we didn't find it .. we're done
            self.settings[self.GPUVIS_KEY] = 'NOT SET'
            self.settings[self.LAUNCH_KEY] = False
            return

        # check for a bundled gpuvis
        gpuvis_path = os.path.join( devkit_client.ROOT_DIR, r'gpuvis\gpuvis.exe' )
        if os.path.exists( gpuvis_path ):
            logger.info(f'Found bundled gpuvis: {gpuvis_path}')
            self.settings[self.GPUVIS_KEY] = gpuvis_path
            return

        # not found
        self.settings[self.GPUVIS_KEY] = 'NOT SET'
        self.settings[self.LAUNCH_KEY] = False

    def devkits_window_draw(self, selected_devkit):
        imgui.text('  File:')
        imgui.same_line()
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##gpu_trace_filepath', self.settings[self.FILEPATH_KEY], 260)
        if changed:
            self.settings[self.FILEPATH_KEY] = s
        imgui.same_line()
        clicked, v = imgui.checkbox('Launch GPUVis:', self.settings[self.LAUNCH_KEY])
        if clicked:
            self.settings[self.LAUNCH_KEY] = v
        imgui.same_line()
        imgui.set_cursor_pos_x(74*CHARACTER_WIDTH)
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##gpu_trace_gpuvis_path', self.settings[self.GPUVIS_KEY], 260)
        if changed:
            self.settings[self.GPUVIS_KEY] = s
        imgui.same_line()
        imgui.set_cursor_pos_x(1100)
        if imgui.button(GPUTrace.BUTTON_NAME):
            task_future = self.devkit_commands.gpu_trace(
                selected_devkit,
                self.settings[self.FILEPATH_KEY],
                self.settings[self.LAUNCH_KEY],
                self.settings[self.GPUVIS_KEY]
                )
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                f'Capturing System trace from {selected_devkit.name}',
                task_future,
                exit_on_success=True,
            )


class RGPCapture(SubTool):
    BUTTON_NAME = 'RGP Capture'
    FOLDER_KEY = 'RGPCapture.folder'
    LAUNCH_KEY = 'RGPCapture.launch'
    RGP_KEY = 'RGPCapture.RGP_path'

    def setup(self):
        if not self.FOLDER_KEY in self.settings:
            self.settings[self.FOLDER_KEY] = str(pathlib.Path(os.path.expanduser('~/Downloads/RGP')))
        if not self.LAUNCH_KEY in self.settings:
            self.settings[self.LAUNCH_KEY] = True
        if not self.RGP_KEY in self.settings:
            rgp_bin = 'RadeonGPUProfiler.exe' if platform.system() == 'Windows' else 'RadeonGPUProfiler'
            rgp_path = shutil.which(rgp_bin)
            if rgp_path is None:
                rgp_path = 'NOT SET'
            self.settings[self.RGP_KEY] = rgp_path
        self.viewport.signal_draw.connect(self.on_draw)

    def devkits_window_draw(self, selected_devkit):
        imgui.text('Folder:')
        imgui.same_line()
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##rgp_capture_folder', self.settings[self.FOLDER_KEY], 260)
        if changed:
            self.settings[self.FOLDER_KEY] = s
        imgui.same_line()
        clicked, v = imgui.checkbox('Launch RGP:', self.settings[self.LAUNCH_KEY])
        if clicked:
            self.settings[self.LAUNCH_KEY] = v
        imgui.same_line()
        imgui.set_cursor_pos_x(74*CHARACTER_WIDTH)
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text('##rgp_path', self.settings[self.RGP_KEY], 260)
        if changed:
            self.settings[self.RGP_KEY] = s
        imgui.same_line()
        imgui.set_cursor_pos_x(1100)
        if imgui.button(RGPCapture.BUTTON_NAME):
            task_future = self.devkit_commands.rgp_capture(selected_devkit, self.settings[self.FOLDER_KEY], self.settings[self.LAUNCH_KEY], self.settings[self.RGP_KEY])
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                f'Capturing RGP frame from {selected_devkit.name}',
                task_future,
                exit_on_success=True,
            )


class ControllerConfigs(SubTool):
    BUTTON_NAME = 'Get Controller Config'
    FOLDER_KEY = 'ControllerConfigs.folder'
    APPID_KEY = 'ControllerConfigs.appid'
    GAMEID_KEY = 'ControllerConfigs.gameid'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        if not self.FOLDER_KEY in self.settings:
            self.settings[self.FOLDER_KEY] = str(pathlib.Path(os.path.expanduser('~/SteamDeck_ControllerConfigs')))
        if not self.APPID_KEY in self.settings:
            self.settings[self.APPID_KEY] = ''
        if not self.GAMEID_KEY in self.settings:
            self.settings[self.GAMEID_KEY] = ''

    def devkits_window_draw(self, selected_devkit):
        # gate on a recent enough Steam client - remove this eventually
        if (selected_devkit.osclient_steam_version is not None) and (selected_devkit.osclient_steam_version < 1632434294):
            return

        imgui.text(' appid:')
        imgui.same_line()
        imgui.set_next_item_width(16*CHARACTER_WIDTH)
        changed, s = imgui.input_text(
            '##controller_config_appid',
            self.settings[self.APPID_KEY],
            64
        )
        if changed:
            self.settings[self.APPID_KEY] = s
        imgui.same_line()
        imgui.text('(or) title name:')
        imgui.same_line()
        imgui.set_next_item_width(16*CHARACTER_WIDTH)
        changed, s = imgui.input_text(
            '##controller_config_gameid',
            self.settings[self.GAMEID_KEY],
            64
        )
        if changed:
            self.settings[self.GAMEID_KEY] = s
        imgui.same_line()
        imgui.text('to folder:')
        imgui.same_line()
        imgui.set_cursor_pos_x(67*CHARACTER_WIDTH)
        imgui.set_next_item_width(55*CHARACTER_WIDTH)
        changed, s = imgui.input_text(
            '##controller_config_folder',
            self.settings[self.FOLDER_KEY],
            260
        )
        if changed:
            self.settings[self.FOLDER_KEY] = s
        imgui.same_line()
        imgui.set_cursor_pos_x(1100)
        if imgui.button(self.BUTTON_NAME):
            task_future = self.devkit_commands.dump_controller_config(
                selected_devkit,
                self.settings[self.APPID_KEY],
                self.settings[self.GAMEID_KEY],
                self.settings[self.FOLDER_KEY],
            )
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                'Retrieving controller configuration from {}'.format(selected_devkit.name),
                task_future,
                exit_on_success=False,
            )


class DeleteTitle(SubTool):
    BUTTON_NAME = 'Delete Title(s)'
    GAMEID_KEY = 'DeleteTitle.gameid'
    DELETE_ALL_KEY = 'DeleteTitle.delete_all'
    RESET_STEAM_KEY = 'DeleteTitle.reset_steam_client'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        if not self.GAMEID_KEY in self.settings:
            self.settings[self.GAMEID_KEY] = ''
        if not self.DELETE_ALL_KEY in self.settings:
            self.settings[self.DELETE_ALL_KEY] = False
        if not self.RESET_STEAM_KEY in self.settings:
            self.settings[self.RESET_STEAM_KEY] = False

    def devkits_window_draw(self, selected_devkit):
        imgui.text(' Title:')
        imgui.same_line()
        imgui.set_next_item_width(48*CHARACTER_WIDTH)
        changed, s = imgui.input_text(
            '##delete_title_gameid',
            self.settings[self.GAMEID_KEY],
            128
        )
        if changed:
            self.settings[self.GAMEID_KEY] = s
        imgui.same_line()
        changed, v = imgui.checkbox('Delete all devkit titles', self.settings[self.DELETE_ALL_KEY])
        if changed:
            self.settings[self.DELETE_ALL_KEY] = v
        if selected_devkit.is_jupiter:
            imgui.same_line()
            changed, v = imgui.checkbox('Delete local Steam content + reset client', self.settings[self.RESET_STEAM_KEY])
            if changed:
                self.settings[self.RESET_STEAM_KEY] = v
        else:
            self.settings[self.RESET_STEAM_KEY] = False
        imgui.same_line()
        imgui.set_cursor_pos_x(1100)
        if imgui.button(self.BUTTON_NAME):
            if len(self.settings[self.GAMEID_KEY]) > 0:
                if re.fullmatch(GAMEID_ALLOWED_PATTERN, s) is None:
                    # bit of an odd pattern for showing an error, could be factored into a utility
                    failed_future = concurrent.futures.Future()
                    failed_future.set_exception(Exception(f'Title name {s!r} must match {GAMEID_ALLOWED_PATTERN}'))
                    self.modal_wait = ModalWait(
                        self.viewport,
                        self.toolbar,
                        'ERROR',
                        failed_future
                    )
                    return
            task_future = self.devkit_commands.delete_title(
                selected_devkit,
                self.settings[self.GAMEID_KEY],
                self.settings[self.DELETE_ALL_KEY],
                self.settings[self.RESET_STEAM_KEY],
            )
            self.modal_wait = ModalWait(
                self.viewport,
                self.toolbar,
                f'Deleting uploaded titles from {selected_devkit.name}',
                task_future,
                exit_on_success=True,
            )

class RestartSDDM(SubTool):
    BUTTON_NAME = 'Restart Steam/SDDM'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name, selected_devkit, **kwargs):
        if name != self.BUTTON_NAME:
            return
        task_future = self.devkit_commands.restart_sddm(selected_devkit)
        self.modal_wait = ModalWait(
            self.viewport,
            self.toolbar,
            f'Restarting SDDM on {selected_devkit.name}',
            task_future,
            exit_on_success=True,
        )


class BrowseFiles(SubTool):
    BUTTON_NAME = 'Browse Device Files'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name, selected_devkit, **kwargs):
        if name != self.BUTTON_NAME:
            return
        spawn_future = self.devkit_commands.browse_files(selected_devkit)
        self.modal_wait = ModalWait(
            self.viewport,
            self.toolbar,
            f'Starting FileZilla',
            spawn_future,
            exit_on_success=True,
        )


class ChangePassword(SubTool):
    BUTTON_NAME = 'Set or Change Password'

    def setup(self):
        self.viewport.signal_draw.connect(self.on_draw)
        self.toolbar.signal_pressed.connect(self.on_pressed)

    def on_pressed(self, name, selected_devkit, **kwars):
        if name != self.BUTTON_NAME:
            return
        f = self.devkit_commands.set_password(selected_devkit)
        # fires once the operation completes
        f.add_done_callback(functools.partial(self.on_set_password_done, selected_devkit))

    def on_set_password_done(self, selected_devkit, f):
        try:
            f.result()
        except Exception as e:
            devkit_client.log_exception(e)
        self.toolbar.signal_pressed.emit(name=RefreshStatus.BUTTON_NAME, selected_devkit=selected_devkit)


class ImGui_SDL2_Viewport:
    '''Create a SDL2 window, GL context and run frames.'''

    def __init__(self, width, height, window_name):
        self.default_width = width
        self.default_height = height
        self.window_name = window_name
        self.sdl_window = None
        self.gl_context = None
        self.sdl_width = ctypes.c_int(0)
        self.sdl_height = ctypes.c_int(0)
        self.running = False

        # enable/disable
        self.verbose_fps = False
        # perf verbose state
        self.avg_frametime = None
        self.avg_swaptime = None
        self.perf_count = 0
        self.verbose_last = None

        # set to None for no limiter
        self.fps_limiter = 60.

        self.signal_draw = signalslot.Signal()

    @property
    def width(self):
        return self.sdl_width.value

    @property
    def height(self):
        return self.sdl_height.value

    def _create_gl_window(self, best_settings=True):
        sdl2.SDL_GL_ResetAttributes()

        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_DOUBLEBUFFER, 1)
        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_DEPTH_SIZE, 24)
        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_STENCIL_SIZE, 8)
        if best_settings:
            sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_ACCELERATED_VISUAL, 1)
            # Multisample looks ok on Linux, but is blurry on Windows
            sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_MULTISAMPLEBUFFERS, 0 if platform.system() == 'Windows' else 1)
            sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_MULTISAMPLESAMPLES, 0 if platform.system() == 'Windows' else 16)
        else:
            sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_ACCELERATED_VISUAL, 1)
            sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_MULTISAMPLEBUFFERS, 0)
            sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_MULTISAMPLESAMPLES, 0)
        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_CONTEXT_FLAGS, sdl2.SDL_GL_CONTEXT_FORWARD_COMPATIBLE_FLAG)
        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_CONTEXT_MAJOR_VERSION, 4 if best_settings else 3)
        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_CONTEXT_MINOR_VERSION, 1)
        sdl2.SDL_GL_SetAttribute(sdl2.SDL_GL_CONTEXT_PROFILE_MASK, sdl2.SDL_GL_CONTEXT_PROFILE_CORE)

        sdl2.SDL_SetHint(sdl2.SDL_HINT_MAC_CTRL_CLICK_EMULATE_RIGHT_CLICK, b"1")
        sdl2.SDL_SetHint(sdl2.SDL_HINT_VIDEO_HIGHDPI_DISABLED, b"1")
        # Do not disable system composition, which in turn would disable transparent windows in CEF
        sdl2.SDL_SetHint(sdl2.SDL_HINT_VIDEO_X11_NET_WM_BYPASS_COMPOSITOR, b"0")

        self.sdl_window = sdl2.SDL_CreateWindow(self.window_name.encode('utf-8'),
                                    sdl2.SDL_WINDOWPOS_CENTERED, sdl2.SDL_WINDOWPOS_CENTERED,
                                    self.default_width, self.default_height,
                                    sdl2.SDL_WINDOW_OPENGL|sdl2.SDL_WINDOW_RESIZABLE
                                        )

        if self.sdl_window is None:
            logger.warning('SDL_CreateWindow failed: {}'.format(sdl2.SDL_GetError()))
            return False

        self.gl_context = sdl2.SDL_GL_CreateContext(self.sdl_window)
        if self.gl_context is None:
            logger.warning('SDL_GL_CreateContext failed: {}'.format(sdl2.SDL_GetError()))
            return False

        sdl2.SDL_GL_MakeCurrent(self.sdl_window, self.gl_context)

        if sdl2.SDL_GL_SetSwapInterval(1) < 0:
            # not worth an abort or settings degrade, we have a frame limiter too
            logger.warning('SDL_GL_SetSwapInterval failed: {}'.format(sdl2.SDL_GetError()))

        return True

    def report_versions(self):
        logger.info('Valve devkit client UI %s', devkit_client.__version__)
        logger.info('Using pyimgui %s', imgui.__version__)
        logger.info('Using imgui %s', imgui.get_version())
        version = sdl2.SDL_version()
        sdl2.SDL_GetVersion(version)
        logger.info('Using SDL2 %s.%s.%s', version.major, version.minor, version.patch)

    def setup(self):
        self.report_versions()

        if sdl2.SDL_Init(sdl2.SDL_INIT_EVERYTHING) < 0:
            raise Exception('SDL_Init failed: %d'.format(sdl2.SDL_GetError()))

        if self._create_gl_window(best_settings=True):
            return
        logger.info('Try GL context creation with more conservative settings')
        if not self._create_gl_window(best_settings=False):
            raise Exception('Could not create OpenGL window')

    def main(self):
        imgui.create_context()
        impl = imgui.integrations.sdl2.SDL2Renderer(self.sdl_window)

        event = sdl2.SDL_Event()
        self.running = True
        while self.running:
            frame_time = time.perf_counter()
            while sdl2.SDL_PollEvent(ctypes.byref(event)) != 0:
                if event.type == sdl2.SDL_QUIT:
                    self.running = False
                    break
                impl.process_event(event)
            impl.process_inputs()

            sdl2.SDL_GetWindowSize(self.sdl_window, ctypes.byref(self.sdl_width), ctypes.byref(self.sdl_height))

            imgui.new_frame()

            self.signal_draw.emit()

            gl.glClearColor(.2, .2, .2, 1)
            gl.glClear(gl.GL_COLOR_BUFFER_BIT)

            imgui.render()
            impl.render(imgui.get_draw_data())

            swap_time = time.perf_counter()
            sdl2.SDL_GL_SwapWindow(self.sdl_window)

            t = time.perf_counter()
            swap_time = t - swap_time
            frame_time = t - frame_time

            # crude fps limiter, when vsync is silently broken, or too high
            if self.fps_limiter is not None:
                early = 1./self.fps_limiter - frame_time
                early -= swap_time
                if early > 0.001:
                    limiter_sleep = time.perf_counter()
                    time.sleep(early)
                    limiter_sleep = time.perf_counter() - limiter_sleep
                    # so verbose reports the corrected (limited) fps
                    frame_time += limiter_sleep

            if self.verbose_fps:
                self.perf_count += 1
                if self.perf_count == 1:
                    self.avg_swaptime = swap_time
                    self.avg_frametime = frame_time
                else:
                    self.avg_swaptime += (swap_time - self.avg_swaptime) / self.perf_count
                    self.avg_frametime += (frame_time - self.avg_frametime) / self.perf_count

                if self.verbose_last is None:
                    self.verbose_last = time.perf_counter()
                if t - self.verbose_last > 1.: # every second
                    logger.info(f'fps: {1./self.avg_frametime:4.1f} Hz' )
                    logger.info(f'swap delay: {self.avg_swaptime*1000.:4.1f} ms')
                    self.perf_count = 0
                    self.verbose_last = t

        impl.shutdown()
        sdl2.SDL_GL_DeleteContext(self.gl_context)
        sdl2.SDL_DestroyWindow(self.sdl_window)
        sdl2.SDL_Quit()


class Settings(collections.abc.MutableMapping):
    def __init__(self):
        self.is_shutdown = True
        self.settings_path = os.path.expanduser(os.path.join('~', '.devkit-client-gui', 'settings.pickle'))
        self.settings = {}
        if os.path.exists(self.settings_path):
            try:
                self.settings = pickle.load(open(self.settings_path, 'rb'))
            except Exception as e:
                # it is best to hard abort, in case this is a 'transient' error
                # if we continue with empty settings, the destructor will write out an empty file and wipe saved settings
                # this happens before the main window is up, but the exception dialog will still come up (even though it's not easy to parse)
                devkit_client.log_exception(e)
                raise Exception(f'Failed to load settings from {self.settings_path} - delete or move the file out of the way.')
            logger.info('Loaded settings: %r', self.settings_path)
        # destructor won't attempt to serialize settings again, any further changes will be lost
        self.is_shutdown = False

    def save_settings(self):
        # Settings are normally saved through an atexit handler, but in some cases an explicit save is useful
        os.makedirs(os.path.dirname(self.settings_path), exist_ok=True)
        pickle.dump(self.settings, open(self.settings_path, 'wb'))
        # because of atexit - trying to maximize the chances this gets printed somewhere
        sys.stderr.write('Saved settings {!r}\n'.format(self.settings_path))
        sys.stderr.flush()

    def shutdown(self):
        '''Use this to save settings and avoid problems due to interpreter shutting down in the destructor.'''
        self.save_settings()
        self.is_shutdown = True

    def __del__(self):
        if self.is_shutdown:
            return
        if sys.is_finalizing():
            sys.stderr.write('Settings.__del__: interpreter is shutting down, cannot serialize settings!\n')
            sys.stderr.flush()
            return
        self.shutdown()

    def __getitem__(self, key):
        return self.settings.__getitem__(key)

    def __setitem__(self, key, value):
        return self.settings.__setitem__(key, value)

    def __delitem__(self, key):
        return self.settings.__delitem__(key)

    def __iter__(self):
        return self.settings.__iter__()

    def __len__(self):
        return self.settings.__len__()


class APIHandler(http.server.BaseHTTPRequestHandler):
    def _respond(self, d):
        self.send_response(http.HTTPStatus.OK)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(d).encode('UTF-8', 'replace'))

    def do_GET(self):
        client_api = self.server.client_api
        if self.path == '/selected_devkit':
            ret = {}
            selected_devkit = client_api.devkits_window.selected_devkit
            if selected_devkit is not None:
                ret = selected_devkit.machine.__dict__
            self._respond(ret)
            return
        if self.path == '/ssh_key_path':
            key, key_path = devkit_client.ensure_devkit_key()
            self._respond({'key_path':key_path})
            return
        if self.path == '/title_settings':
            d = {}
            client_api.update_title.save_settings('', d)
            self._respond(d)
            return
        self.send_error(http.HTTPStatus.NOT_FOUND)

    def do_POST(self):
        client_api = self.server.client_api
        if self.path == '/post_event':
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            event = json.loads(post_data)
            logger.info('received an event: %r', event)
            name = None
            try:
                if (event['type'] == 'build' and event['status'] == 'success'):
                    name = event['name']
            except:
                pass
            if name is None:
                msg = f'malformed event: {event!r}'
                logger.error(msg)
                self.send_error(http.HTTPStatus.BAD_REQUEST, msg)
                return
            try:
                client_api.update_title.on_build_success(name)
            except Exception as e:
                msg = f'processing failed: {e!r}'
                logger.error(msg)
                self.send_error(http.HTTPStatus.INTERNAL_SERVER_ERROR, msg)
            self._respond({})
            return
        self.send_error(http.HTTPStatus.NOT_FOUND)


class ClientAPI(threading.Thread):
    """Primitive REST API server to expose information and basic commands to other local tools."""

    # devkit service listens on 32000 (all interfaces), so we're staying close for now
    HOST = '127.0.0.1'
    PORT = 32010

    def __init__(self, devkits_window, update_title):
        super(ClientAPI, self).__init__(daemon=True)
        self.devkits_window = devkits_window
        self.update_title = update_title

    def setup(self):
        self.start()

    def run(self):
        logger.info('Starting client API server')
        httpd = http.server.HTTPServer((ClientAPI.HOST, ClientAPI.PORT), APIHandler)
        httpd.client_api = self
        httpd.serve_forever()


def setup_console_handler(conf):
    # Setup the console handler as early as possible to catch early messages
    # Messages are collected, but may still be lost if an error happens before we get a chance to display the console
    root_logger = logging.getLogger()
    root_logger.setLevel(conf.verbose)
    console_handler = ConsoleHandler(
        root_logger,
        logging.Formatter('%(message)s')
    )
    console_handler.setup()
    if conf.logfile is not None:
        root_logger.addHandler(logging.FileHandler(conf.logfile))
    return console_handler


def main():
    parser = argparse.ArgumentParser(
        description='Steam Devkit Management Tool'
    )
    parser.add_argument(
        '--verbose', required=False, action='store',
        default='INFO', const='DEBUG', nargs='?',
        help='Logging verbosity'
    )
    parser.add_argument(
        '--logfile', required=False, action='store',
        help='Log to file'
    )
    parser.add_argument(
        '--valve', required=False, action='store_true',
        help='Force Valve mode features (default: auto detect)'
    )

    conf = parser.parse_args()

    if not getattr(sys, 'frozen', False) and sys.stderr is not None:
        # This sets up a default logging to stderr, unrelated to the console logging path
        logging.basicConfig(format='%(message)s', level=conf.verbose)
        console_handler = setup_console_handler(conf)
    else:
        # We are frozen, and sys.stderr is None (e.g. Windows)
        console_handler = setup_console_handler(conf)
        adapter = FileToConsoleHandlerAdapter(console_handler)
        sys.stderr = adapter
        sys.stdout = adapter
        logger.info('Running frozen - stdout/stderr redirectors are setup')

    # uncomment to enable zeroconf DEBUG verbose
    #zeroconf.log.setLevel(conf.verbose)

    # paramiko's default INFO verbose is too much traffic already
    if conf.verbose != 'DEBUG':
        logging.getLogger('paramiko').setLevel(logging.WARNING)

    devkit_client.proxy.disable_proxy()

    settings = Settings()
    atexit.register(settings.shutdown)

    devkit_commands = DevkitCommands()
    devkit_commands.setup()

    viewport = ImGui_SDL2_Viewport(1280, 720, "Steam Devkit Management Tool")
    viewport.setup()

    # All of these hooks into the draw signal of the viewport
    toolbar = Toolbar(viewport)
    toolbar.setup()

    screenshot = Screenshot(devkit_commands, viewport, toolbar, settings)
    screenshot.setup()
    perf_overlay = PerfOverlay(devkit_commands, viewport, toolbar, settings)
    perf_overlay.setup()
    gpu_trace = GPUTrace(devkit_commands, viewport, toolbar, settings)
    gpu_trace.setup()
    rgp_capture = RGPCapture(devkit_commands,  viewport, toolbar, settings)
    rgp_capture.setup()
    controller_configs = ControllerConfigs(devkit_commands, viewport, toolbar, settings)
    controller_configs.setup()
    delete_title = DeleteTitle(devkit_commands, viewport, toolbar, settings)
    delete_title.setup()
    list_titles = ListTitles(devkit_commands, viewport, toolbar, settings)
    list_titles.setup()
    restart_sddm = RestartSDDM(devkit_commands, viewport, toolbar, settings)
    restart_sddm.setup()
    browse_files = BrowseFiles(devkit_commands, viewport, toolbar, settings)
    browse_files.setup()
    change_password = ChangePassword(devkit_commands, viewport, toolbar, settings)
    change_password.setup()

    devkits_window = DevkitsWindow(
        conf,
        devkit_commands,
        settings,
        screenshot,
        perf_overlay,
        gpu_trace,
        rgp_capture,
        controller_configs,
        delete_title,
        viewport,
        toolbar
    )
    devkits_window.setup()
    def on_selected_devkit(kit, **kwargs):
        # Notify the toolbar so it can enable/disable buttons that require a kit selected
        toolbar.selected_devkit = kit
    devkits_window.signal_selected_devkit.connect(on_selected_devkit)

    devkits_window.signal_selected_devkit.connect(perf_overlay.on_selected_devkit)

    console_window = ConsoleWindow(conf, console_handler, settings, viewport, toolbar)
    console_window.setup()
    refresh_status = RefreshStatus(devkit_commands, devkits_window, viewport, toolbar)
    refresh_status.setup()
    update_title = UpdateTitle(devkit_commands, devkits_window, settings, viewport, toolbar)
    update_title.setup()
    view_steam_logs = DeviceLogs(devkit_commands, devkits_window, settings, viewport, toolbar)
    view_steam_logs.setup()
    cef_console = CEFConsole(devkit_commands, devkits_window, toolbar)
    cef_console.setup()
    remote_shell = RemoteShell(devkit_commands, devkits_window, toolbar)
    remote_shell.setup()

    client_api = ClientAPI(devkits_window, update_title)
    client_api.setup()

    viewport.main()
