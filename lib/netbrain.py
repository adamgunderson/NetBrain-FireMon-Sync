# lib/netbrain.py

"""
NetBrain API Client
Handles all interactions with the NetBrain API including authentication, device inventory retrieval,
and configuration management
"""

import logging
import requests
import json
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
    def __init__(self, host: str = None, username: str = None, 
                 password: str = None, tenant: str = None,
                 config_manager = None):
        """
        Initialize NetBrain client with environment variables or provided values
        """
        self.host = (host or os.getenv('NETBRAIN_HOST', '')).rstrip('/')
        self.username = username or os.getenv('NETBRAIN_USERNAME', '')
        self.password = password or os.getenv('NETBRAIN_PASSWORD', '')
        self.tenant = tenant or os.getenv('NETBRAIN_TENANT', 'Default')
        
        if not all([self.host, self.username, self.password]):
            raise ValueError("Missing required NetBrain credentials")
            
        self.session = requests.Session()
        self.token = None
        self.config_manager = config_manager

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
        """
        Check if current token is valid
        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.token:
            return False
            
        try:
            url = urljoin(self.host, '/ServicesAPI/inventoryreport/data/list')
            payload = {
                "skip": 0,
                "limit": 1
            }
            response = self.session.post(url, json=payload)
            return response.status_code != 401
            
        except:
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
                
        logging.info(f"Retrieved {len(all_devices)} total devices from NetBrain")
        return all_devices

    def _get_devices_by_type(self, device_type: str, 
                           batch_size: int = 500) -> List[Dict[str, Any]]:
        """
        Get devices of a specific type using the Inventory List API
        
        Args:
            device_type: Device type to search for
            batch_size: Number of records to retrieve per request
            
        Returns:
            List of device dictionaries
            
        Raises:
            NetBrainAPIError: If API request fails
        """
        url = urljoin(self.host, '/ServicesAPI/inventoryreport/data/list')
        devices = []
        skip = 0
        
        while True:
            payload = {
                "skip": skip,
                "limit": batch_size,
                "sort": {"name": "", "asc": True},
                "match": {
                    "type": 1,
                    "value": "",
                    "search": device_type
                },
                "userNewVersion": True
            }
            
            try:
                response = self._request('POST', url, json=payload)
                
                if not response.get('data', {}).get('data'):
                    break
                    
                # Parse device data from response
                batch_data = json.loads(response['data']['data'])
                devices.extend(self._parse_device_data(batch_data))
                
                if len(batch_data) < batch_size:
                    break
                    
                skip += batch_size
                
            except Exception as e:
                logging.error(f"Error retrieving devices of type {device_type}: {str(e)}")
                break
                
        logging.debug(f"Retrieved {len(devices)} devices of type {device_type}")
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
        Make an authenticated request to NetBrain API
        
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
            
            if response.status_code == 401:  # Token expired
                self.authenticate()
                response = self.session.request(method, endpoint, **kwargs)
            
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.HTTPError as e:
            raise NetBrainAPIError(f"API request failed: {str(e)}")
        except Exception as e:
            raise NetBrainError(f"Unexpected error: {str(e)}")

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