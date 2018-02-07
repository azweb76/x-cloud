import requests
import os
from xcloud import utils
import logging

from xcloud.SensuClient import SensuClient

LOG = logging.getLogger(__name__)

class Plugin(object):
    def __init__(self, options):
        if 'sensu' in options:
            default_options = {
                'authentication': {
                    'username': options['username'],
                    'password': options['password']
                }
            }
            sensu_options = utils.extend(default_options, options['sensu'])
            self._sensu_client = SensuClient(sensu_options)
        else:
            self._sensu_client = None

    def on_before_server_pulled(self, server):
        self.on_silence(server)

    def on_silence(self, server):
        if self._sensu_client:
            LOG.info('silencing %s', server.name)
            self._sensu_client.silence_client(server.name, reason='pulling server')

    def on_server_deleted(self, server):
        if self._sensu_client:
            LOG.info('deleting client %s', server.name)
            self._sensu_client.delete_client(server.name)

    def on_server_pushed(self, server):
        self.on_unsilence(server)

    def on_unsilence(self, server):
        if self._sensu_client:
            LOG.info('unsilencing %s', server.name)
            self._sensu_client.unsilence_client(server.name)

    def on_describe(self, server, info):
        if self._sensu_client:
            client = self._sensu_client.get_client(server.name)
            info['has_sensu'] = client is not None