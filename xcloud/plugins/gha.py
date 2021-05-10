import requests
import os
from xcloud import utils
import logging

from xcloud.SensuClient import SensuClient

LOG = logging.getLogger(__name__)

class Plugin(object):
    def __init__(self, options):
        pass

    def get_runner_token(self, options):
        git_opts = options.get('gha', {})
        username = git_opts['username']
        pat = os.environ['GITHUB_TOKEN']
        git_org = git_opts.get('org')
        resp = requests.post(
            "https://api.github.com/orgs/{}/actions/runners/registration-token".format(git_org),
            auth=(username, pat))
        if resp.status_code == 201:
            return resp.json()['token']
        print('Failed to create token. Response code {}'.format(resp.status_code))
        exit(resp.status_code)

    def on_before_server_created(self, server, options):
        if 'gha' in options:
            server['gha'] = {
                'token': self.get_runner_token(options)
            }