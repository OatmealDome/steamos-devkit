import os
import logging

logger = logging.getLogger(__name__)

def disable_proxy():
    # Prevent urllib from picking up proxy settings, always connect directly
    for del_env_var in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
        if not del_env_var in os.environ:
            continue
        logger.info('Ignoring proxy environment variable: %s', del_env_var)
        del os.environ[del_env_var]
    if not 'no_proxy' in os.environ:
        # somehow we have one system where this needs to be set (was trying to reach a portforwarded kit on 127.0.0.1)
        # should we be explicitly setting no_proxy to '*' for everyone then ?? wtf..
        os.environ['no_proxy'] = 'localhost,127.0.0.0/8'
        logger.info(f'Force no_proxy: {os.environ["no_proxy"]}')
