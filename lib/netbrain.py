# lib/netbrain.py

"""
NetBrain API Client
Handles all interactions with the NetBrain API including:
- Authentication and token management 
- Device inventory retrieval
- Configuration management
- Site hierarchy management
- Error handling and request retries
"""

import os
import logging
import requests
import json
from typing import Dict, List, Any, Optional, Set
from urllib.parse import urljoin
from functools import lru_cache
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

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
    def __init__(self, host: str = None, username: str = None, 
                 password: str = None, tenant: str = None,
                 config_manager = None):
        """
        Initialize NetBrain client with environment variables or provided values
        
        Args:
            host: NetBrain server URL
            username: NetBrain username
            password: NetBrain password 
            tenant: NetBrain tenant name (defaults to 'Default')
            config_manager: Configuration manager instance
        """
        self.host = (host or os.getenv('NETBRAIN_HOST', '')).rstrip('/')
        self.username = username or os.getenv('NETBRAIN_USERNAME', '')
        self.password = password or os.getenv('NETBRAIN_PASSWORD', '')
        self.tenant = tenant or os.getenv('NETBRAIN_TENANT', 'Default')
        
        if not all([self.host, self.username, self.password]):
            raise ValueError("Missing required NetBrain credentials")
            
        # Setup session with retry strategy
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[401, 429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "PUT", "DELETE", "OPTIONS", "TRACE", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.token = None
        self.config_manager = config_manager
        self.last_auth_time = None
        self.token_expiry = 30  # Token expiry in minutes

    def authenticate(self) -> None:
        """
        Authenticate with NetBrain and get token
        
        Raises:
            NetBrainAuthError: If authentication fails
            NetBrainError: For other errors during authentication
        """
        url = urljoin(self.host, '/ServicesAPI/API/V1/Session')
        data = {
            'username': self.username,
            'password': self.password,
            'tenant': self.tenant
        }
        
        try:
            logging.debug("Attempting NetBrain authentication...")
            response = self.session.post(url, json=data)
            response.raise_for_status()
            
            auth_data = response.json()
            if not auth_data.get('token'):
                raise NetBrainAuthError("No token in authentication response")
                
            self.token = auth_data['token']
            self.last_auth_time = datetime.now()
            
            # Update session headers with new token
            self.session.headers.update({
                'token': self.token,
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Tenant': self.tenant
            })
            
            logging.info("Successfully authenticated with NetBrain")
            
        except requests.exceptions.HTTPError as e:
            raise NetBrainAuthError(f"Authentication failed: {str(e)}")
        except Exception as e:
            raise NetBrainError(f"Error during authentication: {str(e)}")

    def validate_token(self) -> bool:
        """
        Check if current token is valid and not expired
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.token or not self.last_auth_time:
            return False
            
        # Check token age
        token_age = datetime.now() - self.last_auth_time
        if token_age > timedelta(minutes=self.token_expiry):
            logging.debug("Token expired due to age")
            return False
            
        try:
            url = urljoin(self.host, '/ServicesAPI/API/V1/Session/CurrentDomain')
            response = self.session.get(url)
            
            if response.status_code == 200:
                return True
            elif response.status_code == 401:
                logging.debug("Token invalid according to API check")
                return False
                
            return False
            
        except Exception as e:
            logging.error(f"Error validating token: {str(e)}")
            return False

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices from NetBrain using the Inventory List API
        Filters devices based on device type mappings in config
        
        Returns:
            List of device dictionaries
            
        Raises:
            NetBrainError: If ConfigManager is not provided or API errors occur
        """
        logging.debug("Getting all devices from NetBrain inventory")
        
        if not self.config_manager:
            raise NetBrainError("ConfigManager required for device type filtering")
            
        all_devices = []
        device_types = self.config_manager.get_mapped_device_types()
        
        for device_type in device_types:
            try:
                devices = self._get_devices_by_type(device_type)
                all_devices.extend(devices)
            except Exception as e:
                logging.error(f"Error getting devices for type {device_type}: {str(e)}")
                continue
        
        total_devices = len(all_devices)        
        logging.info(f"Retrieved {total_devices} total devices from NetBrain")
        
        # Add detailed device logging if in debug mode
        from .logger import log_device_details
        log_device_details(all_devices)
        
        return all_devices

    def _get_devices_by_type(self, device_type: str, batch_size: int = 100) -> List[Dict[str, Any]]:
        """
        Get devices of a specific type using the CMDB API
        
        Args:
            device_type: Device type to search for
            batch_size: Number of records to retrieve per request
                
        Returns:
            List of device dictionaries
                
        Raises:
            NetBrainAPIError: If API request fails
        """
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices')
        devices = []
        skip = 0
        
        # Create filter for device type
        device_filter = {
            'subTypeName': device_type
        }
        
        # Keep track of total devices
        total_count = None
        
        while True:
            try:
                # Build query parameters
                params = {
                    'version': '1',
                    'limit': batch_size,
                    'skip': skip,
                    'fullattr': '1',
                    'filter': json.dumps(device_filter)
                }
                
                response = self._request('GET', url, params=params)
                
                # Get total count from response
                if total_count is None:
                    total_count = response.get('totalResultCount', 0)
                    logging.debug(f"Found {total_count} total devices of type {device_type}")
                    
                    if total_count == 0:
                        break
                
                # Process device batch
                batch_data = response.get('devices', [])
                if not batch_data:
                    break
                    
                devices.extend(self._parse_device_data(batch_data))
                
                logging.debug(f"Retrieved {len(devices)}/{total_count} devices of type {device_type}")
                
                # Check if we've retrieved all devices
                if len(devices) >= total_count:
                    break
                    
                # Increment skip for next batch
                skip += len(batch_data)
                
            except Exception as e:
                logging.error(f"Error retrieving devices of type {device_type} (skip={skip}): {str(e)}")
                break
                
        logging.info(f"Retrieved total of {len(devices)}/{total_count} devices of type {device_type}")
        
        # Verify we got all expected devices
        if total_count and len(devices) < total_count:
            logging.warning(f"Only retrieved {len(devices)} of {total_count} expected devices of type {device_type}")
            
        return devices

    def _parse_device_data(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse device data from inventory API response into standard format
        
        Args:
            devices: Raw device data from API
            
        Returns:
            List of normalized device dictionaries
        """
        parsed_devices = []
        for device in devices:
            try:
                parsed = {
                    'id': device.get('Device$_id'),
                    'hostname': device.get('Device$name'),
                    'mgmtIP': device.get('Device$mgmtIP'),
                    'site': device.get('Device$site'),
                    'attributes': {
                        'vendor': device.get('Device$vendor'),
                        'model': device.get('Device$model'), 
                        'subTypeName': device.get('Device$subTypeName'),
                        'ver': device.get('Device$ver'),
                        'sn': device.get('Device$sn'),
                        'contact': device.get('Device$contact'),
                        'loc': device.get('Device$loc'),
                        'login_alias': device.get('Device$login_alias'),
                        'mgmtIntf': device.get('Device$mgmtIntf'),
                        'lastDiscoveryTime': device.get('Device$lDiscoveryTime')
                    }
                }
                parsed_devices.append(parsed)
            except Exception as e:
                logging.error(f"Error parsing device data: {str(e)}")
                continue
                
        return parsed_devices

    def get_device_configs(self, device_id: str) -> Dict[str, str]:
        """
        Get device configuration data and parse command outputs
        
        Args:
            device_id: NetBrain device ID
            
        Returns:
            Dictionary mapping commands to their outputs
            
        Raises:
            NetBrainAPIError: If API request fails
            NetBrainError: For other errors during config retrieval
        """
        configs = {}
        
        try:
            # Ensure valid token
            if not self.validate_token():
                self.authenticate()
                
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
            raise

    def get_device_config_time(self, device_id: str) -> Optional[str]:
        """
        Get timestamp of last configuration update
        
        Args:
            device_id: NetBrain device ID
            
        Returns:
            ISO format timestamp string or None if not found
        """
        logging.debug(f"Getting config time for device ID: {device_id}")
        try:
            if not self.validate_token():
                self.authenticate()
                
            url = urljoin(self.host, '/ServicesAPI/DeDeviceData/CliCommandSummary')
            data = {
                'devId': device_id,
                'folderType': 0,
                'withData': False
            }
            
            response = self._request('POST', url, json=data)
            summary = response.get('data', {}).get('summary', [])
            
            if summary:
                latest_time = summary[0].get('executeTime')
                logging.debug(f"Latest config time for device {device_id}: {latest_time}")
                return latest_time
                
            logging.warning(f"Config summary not found for device {device_id}")
            return None
            
        except Exception as e:
            logging.error(f"Error getting config time for device {device_id}: {str(e)}")
            return None

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make an authenticated request to NetBrain API with automatic token refresh
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional request parameters
            
        Returns:
            JSON response data
            
        Raises:
            NetBrainAPIError: If request fails
            NetBrainError: For other unexpected errors
        """
        if not self.token:
            self.authenticate()

        try:
            response = self.session.request(method, endpoint, **kwargs)
            
            # Handle 401 by re-authenticating once
            if response.status_code == 401:
                logging.debug("Token expired during request, re-authenticating...")
                self.authenticate()
                response = self.session.request(method, endpoint, **kwargs)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            raise NetBrainAPIError(f"API request failed: {e.response.status_code} {e.response.reason} for url: {e.response.url}")
        except Exception as e:
            raise NetBrainError(f"Unexpected error: {str(e)}")

    def get_sites(self) -> List[Dict[str, Any]]:
        """
        Get all sites from NetBrain
        
        Returns:
            List of site dictionaries
            
        Raises:
            NetBrainAPIError: If API request fails
        """
        try:
            url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Sites/ChildSites')
            params = {'sitePath': 'My Network'}
            
            response = self._request('GET', url, params=params)
            return response.get('sites', [])
            
        except Exception as e:
            logging.error(f"Error getting sites: {str(e)}")
            raise

    def get_device_attributes(self, hostname: str) -> Dict[str, Any]:
        """
        Get detailed device attributes
        
        Args:
            hostname: Device hostname
            
        Returns:
            Dictionary of device attributes
            
        Raises:
            NetBrainAPIError: If API request fails
        """
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices/Attributes')
        params = {'hostname': hostname}
        
        try:
            response = self._request('GET', url, params=params)
            return response['attributes']
        except Exception as e:
            logging.error(f"Error getting attributes for device {hostname}: {str(e)}")
            raise