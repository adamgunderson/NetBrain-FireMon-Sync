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
            'password': self.password
        }
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            
            self.token = response.json()['token']
            self.session.headers.update({'token': self.token})
            logging.info("Successfully authenticated with NetBrain")
        except Exception as e:
            logging.error(f"Failed to authenticate with NetBrain: {str(e)}")
            raise

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """Get all devices from NetBrain"""
        all_devices = []
        sites = self.get_sites()
        
        for site in sites:
            try:
                site_devices = self.get_site_devices(site['sitePath'])
                all_devices.extend(site_devices)
            except Exception as e:
                logging.error(f"Error getting devices for site {site['sitePath']}: {str(e)}")
                continue
                
        return all_devices

    def get_sites(self) -> List[Dict[str, Any]]:
        """Get all NetBrain sites"""
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/ChildSites')
        params = {'sitePath': 'My Network'}
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        return response.json()['sites']

    def get_site_devices(self, site_path: str) -> List[Dict[str, Any]]:
        """Get all devices in a site"""
        logging.debug(f"Getting devices for site: {site_path}")
        try:
            url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/Devices')
            params = {'sitePath': site_path}
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            devices = response.json().get('devices', [])
            logging.debug(f"Retrieved {len(devices)} devices from site {site_path}")
            return devices
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                logging.warning(f"Site path '{site_path}' not found or invalid")
                return []
            raise
        except Exception as e:
            logging.error(f"Error getting devices for site {site_path}: {str(e)}")
            raise

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

    def get_device_config_time(self, device_id: str) -> Optional[str]:
        """Get last configuration time for a device"""
        logging.debug(f"Getting config time for device ID: {device_id}")
        try:
            # Get device configs summary
            url = urljoin(self.host, '/ServicesAPI/DeDeviceData/CliCommandSummary')
            data = {
                'devId': device_id,
                'folderType': 0,
                'withData': False
            }
            
            response = self.session.post(url, json=data)
            response.raise_for_status()
            
            summary = response.json().get('data', {}).get('summary', [])
            if summary:
                # Return the most recent execution time
                latest_time = summary[0].get('executeTime')
                logging.debug(f"Latest config time for device {device_id}: {latest_time}")
                return latest_time
                
            logging.debug(f"No config time found for device {device_id}")
            return None
            
        except Exception as e:
            logging.error(f"Error getting config time for device {device_id}: {str(e)}")
            return None

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