import requests
import json
from requests.auth import HTTPBasicAuth


class RequestClient(object):
    def __init__(self, options):
        self.options = self._init(options)

    def _init(self, options):
        auth = options.get('authentication', None)
        if auth:
            self._auth = HTTPBasicAuth(auth['username'], auth['password'])
        self._headers = {}
        self._certs = None

        return options

    def _resolve(self, path):
        return self.options['url'] + path

    def _get(self, path):
        url = self._resolve(path)
        resp = requests.get(url, auth=self._auth, headers=self._headers, cert=self._certs)
        if resp.status_code == 404:
            return None
        elif resp.status_code == 200:
            return resp.json()
        else:
            raise RuntimeError('unable to GET %s [status_code=%s] %s' % (path, resp.status_code, resp.text))

    def _post(self, path, data):
        url = self._resolve(path)
        resp = requests.post(url, data=json.dumps(data), auth=self._auth, headers=self._headers, cert=self._certs)
        if resp.status_code == 200:
            return True
        else:
            raise RuntimeError('unable to POST %s [status_code=%s] %s' % (path, resp.status_code, resp.text))

    def _delete(self, path):
        url = self._resolve(path)
        resp = requests.delete(url, auth=self._auth, headers=self._headers, cert=self._certs)
        if resp.status_code == 200 or resp.status_code == 202 or resp.status_code == 404:
            return True
        else:
            raise RuntimeError('unable to DELETE %s [status_code=%s] %s' % (path, resp.status_code, resp.text))