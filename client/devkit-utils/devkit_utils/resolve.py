#!/usr/bin/env python3

import sys
import os
import logging
from urllib.parse import quote_plus as urllib_quote_plus
import json
import tempfile

from . import validate_steam_client
from . import execute_steam_client_command
from . import wait_on_file_response

import logging as logging_module
logger = logging_module.getLogger(__name__)


def resolve_shortcuts():
    # make sure there is a steam client online that we can talk to before doing anything
    validate_steam_client()

    # scan the devkit games
    installed_gameids = set([])
    devkit_game_path = os.path.expanduser('~/devkit-game')
    if not os.path.exists(devkit_game_path):
        logger.info('%r does not exist, creating', devkit_game_path)
        os.mkdir(devkit_game_path)
    entries = sorted(os.scandir(devkit_game_path), key=lambda entry: entry.name)
    directories = [e for e in entries if e.is_dir()]
    for d in directories:
        gameid = d.name
        file_names = [f.name for f in entries if f.is_file() and f.name.startswith(gameid)]
        has_argv = '{0}-argv.json'.format(gameid) in file_names
        has_settings = '{0}-settings.json'.format(gameid) in file_names
        if (not has_argv and not has_settings):
            logger.info('Subfolder %r in %r is not accompanied by devkit configuration files, ignoring', d.name, devkit_game_path)
            continue
        logger.info('Found installed Devkit Game: %r', gameid)
        installed_gameids.add(gameid)

    # ask the Steam Client which Devkit Games are registered
    with tempfile.TemporaryDirectory(prefix='list-shortcuts') as tempdir:
        response = os.path.join(tempdir, 'shortcuts.json')
        cmd = 'list-shortcuts?response={}'.format(
            urllib_quote_plus(os.path.join(response))
        )
        # send the request
        execute_steam_client_command(cmd)
        with wait_on_file_response(response) as response:
            client_shortcuts = json.loads(response)
    logger.debug(client_shortcuts)
    assert client_shortcuts['version'] == 2
    registered_gameids = set([])
    logger.info('Steam Client has %d registered devkit game(s)', len(client_shortcuts['gameids']))
    for gameid in client_shortcuts['gameids']:
        logger.info('Found Devkit Game registered with Steam Client: %r', gameid)
        registered_gameids.add(gameid)

    # any registered game that is not found installed on disk needs to be removed
    for remove_gameid in registered_gameids - installed_gameids:
        with tempfile.TemporaryDirectory(prefix='delete-shortcut') as tempdir:
            logger.info('Removing stale registered Devkit Game: %r', remove_gameid)
            response = os.path.join(tempdir, 'shortcut-deleted')
            cmd = 'delete-shortcut?response={}&gameid={}'.format(
                urllib_quote_plus(response),
                remove_gameid
            )
            execute_steam_client_command(cmd)
            with wait_on_file_response(response) as response:
                logger.info('from Steam Client: %s', response.strip())

    # any installed game that is not found registered needs to be added
    for add_gameid in installed_gameids - registered_gameids:
        with tempfile.TemporaryDirectory(prefix='create-shortcut') as tempdir:
            logger.info('Registering installed Dekit Game: %r', add_gameid)
            response = os.path.join(tempdir, 'registered')
            cmd = 'create-shortcut?response={}&gameid={}&directory={}'.format(
                urllib_quote_plus(response),
                add_gameid,
                urllib_quote_plus(devkit_game_path)
            )
            execute_steam_client_command(cmd)
            with wait_on_file_response(response) as response:
                logger.info('from Steam Client: %s', response.strip())

if __name__ == '__main__':
    resolve_shortcuts()
