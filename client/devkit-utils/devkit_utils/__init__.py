#!/usr/bin/env python
# encoding: utf-8
"""Utility functions for the Steam client hook scripts"""

import sys
import os
import traceback
import tempfile
import json
import logging
import fcntl
import errno
import contextlib
import time
import fcntl


import logging as logging_module
logger = logging_module.getLogger(__name__)


@contextlib.contextmanager
def wrap_outputs(stderr_prefix):
    # capture stderr to file to support debugging
    stderr_fd = sys.stderr.fileno()
    tf = tempfile.NamedTemporaryFile(
        mode='w+',
        prefix=stderr_prefix,
        delete=True)
    if sys.version_info >= (3, 4):
        # this API in the os module is only available for python3
        # but it does not seem to work with subprocess anyway
        os.set_inheritable(tf.file.fileno(), True)
        assert os.get_inheritable(tf.file.fileno())
    sys.stderr = tf.file

    # we can only write out a json response to stdout,
    # so redirect stdout to stderr,
    # and keep a handle on the original stdout for the response
    stdout_fd = os.dup(sys.stdout.fileno())
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())

    ctx = {}
    try:
        yield ctx
    except:
        logger.error(traceback.format_exc())
    finally:
        tf.flush()
        tf.seek(0)
        os.write(stderr_fd, tf.read().encode('utf-8'))
        if 'ret' in ctx:
            os.write(stdout_fd, json.dumps(ctx['ret']).encode('utf-8'))


class SteamClientNotRunningException(Exception):
    def __init__(self, error_message):
        self.error_message = error_message

    def __str__(self):
        return self.error_message


def validate_steam_client():
    """Verify that the steam client is running, and permissions are adequate"""
    pid_path = os.path.normpath(
        os.path.realpath(
            os.path.expanduser('~/.steam/steam.pid')))
    if not os.path.exists(pid_path):
        raise SteamClientNotRunningException('{0} does not exist'.format(pid_path))
    try:
        pid = int(open(pid_path, 'rt').read())
    except Exception:
        raise SteamClientNotRunningException('{0} is invalid'.format(pid_path))
    try:
        os.kill(pid, 0)
    except OSError:
        raise SteamClientNotRunningException('{0} does not refer to a valid process'.format(pid_path))
    logger.info('Found steam client pid %s', pid)


def execute_steam_client_command(cmd):
    """Send a command to the steam client over the IPC pipe"""
    pipe_path = os.path.normpath(
        os.path.realpath(
            os.path.expanduser('~/.steam/steam.pipe')))
    try:
        pipe = open(pipe_path, 'wb+', 0)
    except IOError:
        raise Exception('cannot open steam client pipe')
    session_token = open(os.path.expanduser('~/.steam/steam.token')).read()
    pipe_cmd = 'devkit-1 steam://devkit-1/{0}/{1}'.format(
        session_token,
        cmd
    )
    logger.debug('Sending command line:')
    logger.debug(pipe_cmd)
    pipe.write('{0}\n'.format(pipe_cmd).encode('utf-8'))
    pipe.close()


def save_argv(gameid, argv):
    """Save command line and arguments if provided"""

    if argv is None:
        return

    argvfile = os.path.join(os.getenv("HOME"), "devkit-game",
                            gameid + "-argv.json")
    try:
        with open(argvfile, "w") as argvf:
            fcntl.flock(argvf, fcntl.LOCK_EX)
            json.dump(argv, argvf)
            fcntl.flock(argvf, fcntl.LOCK_UN)
    except IOError:
        raise Exception(
            "Unable to open argv file for writing: {0}".format(argvfile))


def obtain_argv(gameid, argv):
    """Obtain command line with arguments"""

    # If present and not None or [], just return the local arguments
    if argv:
        return argv

    # From here, expect arguments to have been saved previously
    argvfile = os.path.join(os.getenv("HOME"), "devkit-game",
                            gameid + "-argv.json")
    try:
        with open(argvfile, "r") as argvf:
            fcntl.flock(argvf, fcntl.LOCK_EX)
            argv = json.load(argvf)
            fcntl.flock(argvf, fcntl.LOCK_UN)
    except IOError:
        raise Exception(
            "Unable to open argv file for reading: {0}".format(argvfile))
    return argv


def save_settings(gameid, data):
    """Save settings"""
    settingsfile = os.path.join(os.getenv("HOME"), "devkit-game",
                                gameid + "-settings.json")
    settings = dict()

    if data.get('clear_settings', False):
        settings = {}
    else:
        try:
            with open(settingsfile, "r") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                settings = json.load(f)
                fcntl.flock(f, fcntl.LOCK_UN)
        except IOError as e:
            if (e.errno != errno.ENOENT):
                raise

    # Merge settings from new json
    if 'settings' in data:
        settings.update(data['settings'])

    try:
        with open(settingsfile, "w") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            json.dump(settings, f)
            fcntl.flock(f, fcntl.LOCK_UN)
    except (IOError):
        raise Exception(
            "Unable to open settings file for writing: {0}".format(
                settingsfile
            ))

    return settings


def load_settings(gameid):
    settingsfile = os.path.join(os.getenv("HOME"), "devkit-game", gameid + '-settings.json')

    if not os.path.isfile(settingsfile):
        return None

    with open(settingsfile, "r") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        settings = json.load(f)
        fcntl.flock(f, fcntl.LOCK_UN)

    return settings


class SteamResponse_Timeout(Exception):
    pass


class SteamResponse_Error(Exception):
    def __init__(self, error_response):
        self.error_response = error_response

    def __str__(self):
        return self.error_response


@contextlib.contextmanager
def wait_on_file_response(path, timeout=5):
    """
The pipe to the Steam Client is one way.
Responses from the Steam Client are written to filesystem.
Protocol is as follows:
- Steam Client creates a 'path.lock' file
- Steam Client writes either 'path' or 'path.error' to indicate a problem
- Steam Client deletes 'path.lock'
- Caller (us) can then read the response

NOTE 1: this function is used as a context manager and will block until a response comes in or timeout.

NOTE 2: the files are created by Steam when responding to a command. If the files already exist the response protocol will break.
    """
    lock_path = '{0}.lock'.format(path)
    error_path = '{0}.error'.format(path)
    max_count = timeout
    while True:
        time.sleep(1)
        if os.path.exists(error_path) or os.path.exists(path) and not os.path.exists(lock_path):
            if os.path.exists(error_path):
                with open(error_path, 'r') as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    error_response = f.read()
                    fcntl.flock(f, fcntl.LOCK_UN)
                    raise SteamResponse_Error(error_response)
            with open(path, 'r') as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                success_response = f.read()
                yield success_response
                fcntl.flock(f, fcntl.LOCK_UN)
                return
        max_count -= 1
        if max_count > 0:
            continue
        raise SteamResponse_Timeout()


# Setting up as a context manager so we never miss the deletion
# Creating a temporary .lock file to guard the create operation
@contextlib.contextmanager
def create_pid(pid_path):
    os.makedirs(os.path.dirname(pid_path), exist_ok=True)
    lock_path = '{0}.lock'.format(pid_path)
    try:
        lock_file = os.open(lock_path, os.O_CREAT | os.O_EXCL)
    except IOError as e:
        logger.error('cannot create lock file %s for pid file %s', lock_path, pid_path)
        logger.error('remove the lock file manually and run again if you are confident no other instance is active')
        raise

    pid_file = open(pid_path,'w')
    pid_file.write(str(os.getpid()))
    pid_file.flush()
    os.close(lock_file)
    os.unlink(lock_path)
    try:
        yield pid_file
    finally:
        pid_file.close()
        # Assume that's atomic and all is well, no need for another .lock
        os.unlink(pid_path)
