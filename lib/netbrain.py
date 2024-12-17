# lib/netbrain.py
"""
NetBrain API Client
"""

import logging
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

class NetBrainClient:
    def __init__(self, host: str, username: str, password: str, tenant: str):
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.tenant = tenant
        self.session = requests.Session()
        self.token = None
        
    def authenticate(self) -> None:
        """Authenticate with NetBrain and get token"""
        url = urljoin(self.host, '/ServicesAPI/API/V1/Session')
        data = {
            'username': self.username,
            'password': self.password,
            'tenant': self.tenant
        }
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        self.token = response.json()['token']
        self.session.headers.update({'token': self.token})

    def get_sites(self) -> List[Dict[str, Any]]:
        """Get all NetBrain sites"""
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/ChildSites')
        params = {'sitePath': 'My Network'}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()['sites']

    def get_site_devices(self, site_path: str) -> List[Dict[str, Any]]:
        """Get all devices in a site"""
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/Devices')
        params = {'sitePath': site_path}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()['devices']

    def get_device_attributes(self, hostname: str) -> Dict[str, Any]:
        """Get device attributes"""
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices/Attributes')
        params = {'hostname': hostname}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()['attributes']

    def get_device_configs(self, device_id: str) -> Dict[str, Any]:
        """Get device configuration data"""
        # First get available configs
        url = urljoin(self.host, '/ServicesAPI/DeDeviceData/CliCommandSummary')
        data = {
            'devId': device_id,
            'folderType': 0,
            'withData': False
        }
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        configs = {}
        summary = response.json()['data']['summary']
        
        # Get most recent execution
        if summary and summary[0]['commands']:
            latest = summary[0]
            
            # Get content for each command
            for cmd, location in zip(latest['commands'], latest['locations']):
                content_url = urljoin(self.host, '/ServicesAPI/DeDeviceData/CliCommand')
                content_data = {
                    'sourceType': location['sourceType'],
                    'id': location['id'],
                    'md5': location['md5'],
                    'location': location['location']
                }
                
                content_response = self.session.post(content_url, json=content_data)
                content_response.raise_for_status()
                
                configs[cmd] = content_response.json()['data']['content']

        return configs

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an authenticated request to NetBrain API"""
        if not self.token:
            self.authenticate()

        url = urljoin(self.host, endpoint)
        response = self.session.request(method, url, **kwargs)
        
        if response.status_code == 401:  # Token expired
            self.authenticate()
            response = self.session.request(method, url, **kwargs)
        
        response.raise_for_status()
        return response.json()