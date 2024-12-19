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

    def validate_token(self) -> bool:
        """Check if current token is valid"""
        if not self.token:
            return False
            
        try:
            # Make a test API call
            response = self.session.get(urljoin(self.host, self.test_endpoint))
            return response.status_code != 401
        except:
            return False

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
        """
        Get all NetBrain sites starting from root 'My Network'
        Handles site hierarchy traversal and error conditions
        
        Returns:
            List of site dictionaries containing site information and hierarchy
        """
        logging.debug("Getting NetBrain sites")
        all_sites = []
        
        try:
            # Ensure we're authenticated
            if not self.token:
                self.authenticate()
            
            # First get root level sites
            url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/ChildSites')
            params = {'sitePath': 'My Network'}
            
            response = self.session.get(url, params=params)
            
            # Handle token expiration
            if response.status_code == 401:
                logging.debug("Token expired, re-authenticating...")
                self.authenticate()
                response = self.session.get(url, params=params)
                
            response.raise_for_status()
            
            root_sites = response.json().get('sites', [])
            all_sites.extend(root_sites)
            
            # Process container sites to get full hierarchy
            for site in root_sites:
                if site.get('isContainer'):
                    child_sites = self._get_child_sites(site['sitePath'])
                    all_sites.extend(child_sites)
            
            logging.debug(f"Retrieved total of {len(all_sites)} sites from NetBrain")
            return all_sites
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                logging.warning(f"Invalid site path 'My Network'. API Response: {e.response.text}")
                return []
            logging.error(f"HTTP error getting NetBrain sites: {str(e)}")
            raise
        except Exception as e:
            logging.error(f"Error getting NetBrain sites: {str(e)}")
            raise

    def _get_child_sites(self, parent_path: str) -> List[Dict[str, Any]]:
        """
        Recursively get child sites for a given parent path
        
        Args:
            parent_path: Full site path of parent site
            
        Returns:
            List of child site dictionaries
        """
        child_sites = []
        try:
            url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/ChildSites')
            params = {'sitePath': parent_path}
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            sites = response.json().get('sites', [])
            child_sites.extend(sites)
            
            # Recursively get children of container sites
            for site in sites:
                if site.get('isContainer'):
                    grandchildren = self._get_child_sites(site['sitePath'])
                    child_sites.extend(grandchildren)
                    
            return child_sites
            
        except Exception as e:
            logging.error(f"Error getting child sites for {parent_path}: {str(e)}")
            return []

    def get_site_devices(self, site_path: str) -> List[Dict[str, Any]]:
        """
        Get all devices in a site
        
        Args:
            site_path: Full path of the site to get devices from
            
        Returns:
            List of device dictionaries
        """
        logging.debug(f"Getting devices for site: {site_path}")
        
        try:
            if not self.token:
                self.authenticate()
                
            url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/Devices')
            
            # URL encode the site path properly
            encoded_path = quote(site_path, safe='')
            params = {'sitePath': encoded_path}
            
            response = self.session.get(url, params=params)
            
            # Handle token expiration
            if response.status_code == 401:
                logging.debug("Token expired, re-authenticating...")
                self.authenticate()
                response = self.session.get(url, params=params)
                
            if response.status_code == 400:
                logging.warning(f"Site path '{site_path}' not found or invalid. Response: {response.text}")
                return []
                
            response.raise_for_status()
            
            devices = response.json().get('devices', [])
            logging.debug(f"Retrieved {len(devices)} devices from site {site_path}")
            return devices
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 400:
                logging.warning(f"Site path '{site_path}' not found or invalid")
                return []
            logging.error(f"HTTP error getting devices for site {site_path}: {str(e)}")
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