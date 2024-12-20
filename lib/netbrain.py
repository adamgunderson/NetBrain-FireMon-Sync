# lib/netbrain.py
"""
NetBrain API Client
Handles all interactions with the NetBrain API including authentication, site hierarchy retrieval,
device information and configuration management
"""

import logging
import requests
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin, quote
from functools import lru_cache
from datetime import datetime

class NetBrainError(Exception):
    """Base exception for NetBrain API errors"""
    pass

class NetBrainAuthError(NetBrainError):
    """Authentication related errors"""
    pass

class NetBrainAPIError(NetBrainError):
    """General API errors"""
    pass

class NetBrainClient:
    def __init__(self, host: str, username: str, password: str, tenant: str):
        """Initialize NetBrain client
        
        Args:
            host: NetBrain server hostname/URL
            username: API username
            password: API password 
            tenant: NetBrain tenant name
        """
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.tenant = tenant
        self.session = requests.Session()
        self.token = None
        self._processed_sites = set()  # Track processed sites to prevent recursion

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
            
        except requests.exceptions.HTTPError as e:
            raise NetBrainAuthError(f"Authentication failed: {str(e)}")
        except Exception as e:
            raise NetBrainError(f"Error during authentication: {str(e)}")

    def validate_token(self) -> bool:
        """Check if current token is valid"""
        if not self.token:
            return False
            
        try:
            # Make a test API call to verify token
            url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices')
            params = {'pageSize': 1}
            response = self.session.get(url, params=params)
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
        self._processed_sites.clear()  # Clear processed sites tracking
        
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
                
            if response.status_code == 400:
                logging.warning("Invalid site path 'My Network'. Attempting to retrieve all sites...")
                url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites')
                response = self.session.get(url)
                
            response.raise_for_status()
            
            root_sites = response.json().get('sites', [])
            all_sites.extend(root_sites)
            
            # Process container sites to get full hierarchy
            for site in root_sites:
                if site.get('isContainer') and site['sitePath'] not in self._processed_sites:
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

    def _get_child_sites(self, parent_path: str, depth: int = 0) -> List[Dict[str, Any]]:
        """
        Recursively get child sites for a given parent path with depth tracking
        
        Args:
            parent_path: Full site path of parent site
            depth: Current recursion depth, used to prevent infinite recursion
            
        Returns:
            List of child site dictionaries
        """
        # Prevent infinite recursion
        if depth > 10:  # Maximum depth limit
            logging.warning(f"Maximum depth reached for path: {parent_path}")
            return []
            
        if parent_path in self._processed_sites:
            return []
            
        self._processed_sites.add(parent_path)
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
                if site.get('isContainer') and site['sitePath'] not in self._processed_sites:
                    grandchildren = self._get_child_sites(site['sitePath'], depth + 1)
                    child_sites.extend(grandchildren)
                    
            return child_sites
            
        except Exception as e:
            logging.error(f"Error getting child sites for {parent_path}: {str(e)}")
            return []

    @lru_cache(maxsize=128)
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
            params = {'sitePath': site_path}
            
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
        
        try:
            response = self._request('GET', url, params=params)
            return response['attributes']
        except Exception as e:
            logging.error(f"Error getting attributes for device {hostname}: {str(e)}")
            raise

    def get_device_configs(self, device_id: str) -> Dict[str, Any]:
        """Get device configuration data"""
        configs = {}
        
        try:
            # First get available configs
            url = urljoin(self.host, '/ServicesAPI/DeDeviceData/CliCommandSummary')
            data = {
                'devId': device_id,
                'folderType': 0,
                'withData': False
            }
            
            response = self._request('POST', url, json=data)
            summary = response.get('data', {}).get('summary', [])
            
            # Get most recent execution
            if summary and summary[0].get('commands'):
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
                    
                    content_response = self._request('POST', content_url, json=content_data)
                    
                    if content_response.get('data', {}).get('content'):
                        configs[cmd] = content_response['data']['content']
                    else:
                        logging.warning(f"Config content not found for command '{cmd}' on device {device_id}")

            return configs
            
        except Exception as e:
            logging.error(f"Error getting configs for device {device_id}: {str(e)}")
            return {}

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
            
            logging.debug(f"Making API request to {url} with data: {data}")
            
            response = self._request('POST', url, json=data)
            
            logging.debug(f"API response status code: {response.get('operationResult', {}).get('ResultCode')}")
            logging.debug(f"API response content: {response}")
            
            summary = response.get('data', {}).get('summary', [])
            
            if summary:
                # Return the most recent execution time
                latest_time = summary[0].get('executeTime')
                logging.debug(f"Latest config time for device {device_id}: {latest_time}")
                return latest_time
                
            logging.warning(f"Config summary not found for device {device_id}")
            return None
            
        except Exception as e:
            logging.error(f"Error getting config time for device {device_id}: {str(e)}")
            return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an authenticated request to NetBrain API"""
        if not self.token:
            self.authenticate()

        try:
            response = self.session.request(method, endpoint, **kwargs)
            
            if response.status_code == 401:  # Token expired
                self.authenticate()
                response = self.session.request(method, endpoint, **kwargs)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            raise NetBrainAPIError(f"API request failed: {str(e)}")
        except Exception as e:
            raise NetBrainError(f"Unexpected error: {str(e)}")