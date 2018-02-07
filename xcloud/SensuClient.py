import requests
import utils
import time
from RequestClient import RequestClient
import os

class SensuClient(RequestClient):
    def __init__(self, options):
        RequestClient.__init__(self, options)

    def get_client(self, client_name):
        return RequestClient._get(self, 'clients/%s' % client_name)

    def get_silenced(self):
        return RequestClient._get(self, 'silenced')

    def silence_client(self, client_name, expire=3600, reason='unknown', creator='x-cloud'):
        entry = self.get_silenced_client(client_name)
        if entry is None:
            resp = RequestClient._post(self, 'silenced', {
                "subscription": 'client:%s' % client_name,
                "expire": expire,
                "reason": reason,
                "creator": creator
            })
            duration = utils.tdelta(self.options.get('silence_wait', '15s'))
            time.sleep(duration.total_seconds())
            return resp
        return entry
        

    def get_silenced_client(self, client_name):
        silenced = self.get_silenced()
        subscription = 'client:%s' % client_name
        entry = [x for x in silenced if x['subscription'] == subscription]

        if entry:
            return entry[0]
        return None

    def unsilence_client(self, client_name):
        silenced = self.get_silenced()
        subscription = 'client:%s' % client_name
        entry = [x for x in silenced if x['subscription'] == subscription]
        if entry:
            data = {
                'id': entry[0]['id']
            }
            return RequestClient._post(self, 'silenced/clear', data)
        return None

    def delete_client(self, client_name):
        return RequestClient._delete(self, 'clients/%s' % client_name)
