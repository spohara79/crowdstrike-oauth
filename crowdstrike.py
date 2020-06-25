import requests
import sys
import warnings
from pprint import pprint
from datetime import datetime, timedelta


class CSMethodNotSupported(Exception):
    pass

class CrowdStrike():

    def __init__(self, base_url='https://api.crowdstrike.com'):
        self.base_url = base_url
        self.headers = {
            'accept': 'application/json',
        }
        self.oauth_token = None
        self.build_urls()

    def build_urls(self):
        self.oauth_url = '{0}/oauth2/token'.format(self.base_url)
        self.get_putfiles_url = '{0}/real-time-response/entities/put-files/v1'.format(self.base_url)
        self.list_putfiles_url = '{0}/real-time-response/queries/put-files/v1'.format(self.base_url)
        self.list_scripts_url = '{0}/real-time-response/queries/scripts/v1'.format(self.base_url)
        self.get_scripts_url = '{0}/real-time-response/entities/scripts/v1'.format(self.base_url)
        self.init_session_url = '{0}/real-time-response/combined/batch-init-session/v1'.format(self.base_url)
        self.admincommand_url = '{0}/real-time-response/entities/admin-command/v1'.format(self.base_url)
        self.batch_cmd_url = '{0}/real-time-response/combined/batch-command/v1'.format(self.base_url)
        self.admin_cmd_url = '{0}/real-time-response/combined/batch-admin-command/v1'.format(self.base_url)
        self.responder_cmd_url = '{0}/real-time-response/combined/batch-active-responder-command/v1'.format(self.base_url)
        self.list_devices_url = '{0}/devices/queries/devices/v1'.format(self.base_url)
        self.get_devices_url = '{0}/devices/entities/devices/v1'.format(self.base_url)

    def get_oauth2_token(self):
        data = {
            'client_id': '',
            'client_secret': '',
            'grant_type': "client_credentials"
        }
        self.headers['Content-Type'] = 'application/x-www-form-urlencoded'
        resp = self.make_request(self.oauth_url,'POST',data=data)
        oauth2_token = resp['access_token']
        self.headers["authorization"] = "bearer {0}".format(oauth2_token)
        self.headers.pop('Content-Type', None)

    def init_session(self, host_ids):
        self.headers['Content-Type'] = 'application/json'
        data = {
            'host_ids': host_ids
        }
        resp = self.make_request(self.init_session_url, 'POST', json=data)
        self.headers.pop('Content-Type', None)
        return resp['batch_id']

    def run_cmd(self, batch_id, cmd, cmd_line, hosts):
        self.headers['Content-Type'] = 'application/json'
        admin_cmds = ['put', 'run', 'runscript']
        responder_cmds = ['cp', 'encrypt', 'kill', 'map', 'memdump', 'mkdir', 'mv', 'reg delete',
                          'reg load', 'reg unload', 'reg set', 'restart', 'rm', 'shutdown', 'unmap',
                          'xmemdump', 'zip']
        cmd_uri = self.admin_cmd_url if cmd in admin_cmds else self.responder_cmd_url if cmd in responder_cmds else self.batch_cmd_url
        cmd_string = '{0} {1}'.format(cmd, cmd_line)
        data = {
            'base_command': cmd,
            'command_string': cmd_string,
            'batch_id': batch_id,
            'optional_hosts': hosts
        }
        resp = self.make_request(cmd_uri, 'POST', json=data)
        self.headers.pop('Content-Type', None)
        return resp

    def list_devices(self):
        api_limit = 5000
        api_offset = 0
        devices = []
        last_seen = datetime.utcnow() - timedelta(hours=24, minutes=0) # 24 hours (to go.. i wanna be sedated)  
        while True:
            params = {
                'filter': "last_seen:>='{0}'".format(last_seen.strftime('%Y-%m-%dT%H:%M:%SZ')),
                'limit': api_limit,
                'offset': api_offset
            }
            resp = self.make_request(self.list_devices_url, 'GET', params=params)
            resource_total = resp['meta']['pagination']['total']
            devices += resp['resources']
            if len(devices) == resource_total:
                break
            else:
                api_offset += api_limit
        return devices

    def __chunk__(self, chunk_list, n):
        for i in xrange(0, len(chunk_list), n):
            yield chunk_list[i:i+n]

    def get_devices(self, devices):
        chunks = 100
        device_list = []
        for device_chunk in self.__chunk__(devices, chunks):
            params = {'ids': device_chunk}
            resp = self.make_request(self.get_devices_url, 'GET', params=params)
            device_list += resp['resources']
        return device_list

    def list_putfiles(self):
        resp = self.make_request(self.list_putfiles_url, 'GET')
        return resp

    def get_putfiles(self, putfiless):
        params = {'ids': putfiles}
        resp = self.make_request(self.get_putfiles_url, 'GET', params=params)
        return resp

    def list_scripts(self):
        resp = self.make_request(self.list_scripts_url, 'GET')
        return resp

    def get_scripts(self, scripts):
        params = {'ids': scripts}
        resp = self.make_request(self.get_scripts_url, 'GET', params=params)
        return resp

    def make_request(self, url, method, headers=None, params=None, data=None, json=None, verify=False):
        if not self.oauth_token and url != self.oauth_url:
            self.get_oauth2_token()
        if not headers:
            headers = self.headers
        try:
            if method not in ['GET', 'POST']:
                raise CSMethodNotSupported
        except CSMethodNotSupported:
            print('{0} method is not supported'.format(method))
        resp = requests.request(method, url, headers=headers, params=params, data=data, json=json, verify=verify)
        if resp.ok:
            return resp.json()
        else:
            resp.raise_for_status()
