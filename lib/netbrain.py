# lib/netbrain.py

"""
NetBrain API Client - Updated to use Attributes and Device Raw Data APIs
Handles all interactions with the NetBrain API including:
- Authentication and token management 
- Device inventory retrieval and attribute lookup
- Configuration management using Device Raw Data API
- Content processing to remove shell prompts
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
        
        # Cache for device data
        self._device_cache = {}

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
        Get all devices from NetBrain using the Devices API
        Filters devices based on device type mappings in config
        
        Returns:
            List of device dictionaries
            
        Raises:
            NetBrainError: If ConfigManager is not provided or API errors occur
        """
        logging.debug("Getting all devices from NetBrain")
        
        if not self.config_manager:
            raise NetBrainError("ConfigManager required for device type filtering")
            
        all_devices = []
        device_types = self.config_manager.get_mapped_device_types()
        logging.debug(f"Configured device types: {sorted(device_types)}")

        # Get devices by type
        for device_type in device_types:
            try:
                url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices')
                skip = 0
                limit = 50  # Use smaller batch size to avoid timeout issues

                while True:
                    # Build API query parameters
                    params = {
                        'version': '1',
                        'skip': skip,
                        'limit': limit,
                        'fullattr': '1',
                        'filter': json.dumps({"subTypeName": device_type})
                    }
                    
                    logging.debug(f"Querying devices: type={device_type}, skip={skip}, limit={limit}")
                    
                    # Make API request
                    response = self._request('GET', url, params=params)
                    if not response:
                        logging.error(f"No response received for device type {device_type}")
                        break
                        
                    # Get device batch and total count
                    devices = response.get('devices', [])
                    total_count = response.get('totalResultCount', 0)
                    
                    if not devices:
                        logging.debug(f"No devices found for type {device_type}")
                        break

                    # Normalize device data
                    normalized_devices = []
                    for device in devices:
                        try:
                            # Get additional details using hostname (not ID)
                            hostname = device.get('name')
                            if not hostname:
                                logging.warning(f"Skipping device with missing hostname: {device}")
                                continue
                                
                            device_details = self.get_device_details(hostname)
                            if not device_details:
                                logging.warning(f"Could not get details for device {hostname}")
                                continue
                                
                            normalized = {
                                'hostname': hostname,
                                'mgmtIP': device.get('mgmtIP'),
                                'site': device.get('site'),
                                'attributes': {
                                    'subTypeName': device.get('subTypeName'),
                                    'vendor': device.get('vendor'),
                                    'model': device.get('model'),
                                    'version': device.get('ver'),
                                    'serialNumber': device.get('sn'),
                                    'contact': device.get('contact'),
                                    'location': device.get('loc'),
                                    'mgmtIntf': device.get('mgmtIntf'),
                                    'description': device.get('descr'),
                                    'lastDiscoveryTime': device.get('lDiscoveryTime', {}).get('$date')
                                                       if isinstance(device.get('lDiscoveryTime'), dict) 
                                                       else device.get('lDiscoveryTime')
                                }
                            }
                            
                            # Validate required fields
                            if not normalized.get('mgmtIP'):
                                logging.warning(f"Skipping device {hostname} with missing mgmtIP")
                                continue
                                
                            if not normalized['attributes'].get('subTypeName'):
                                logging.warning(f"Skipping device {hostname} with missing subTypeName")
                                continue
                                
                            normalized_devices.append(normalized)
                            logging.debug(f"Normalized device: hostname={normalized['hostname']}, "
                                        f"IP={normalized['mgmtIP']}, type={normalized['attributes']['subTypeName']}")
                                        
                        except Exception as e:
                            logging.error(f"Error normalizing device data: {str(e)}")
                            if logging.getLogger().isEnabledFor(logging.DEBUG):
                                logging.error(f"Problem device data: {json.dumps(device, indent=2)}")
                            continue

                    # Add valid devices to result list
                    all_devices.extend(normalized_devices)
                    processed_count = skip + len(devices)
                    
                    logging.info(f"Retrieved {len(normalized_devices)} {device_type} devices. "
                               f"Progress: {processed_count}/{total_count}")
                    
                    # Check if we're done with this device type
                    if processed_count >= total_count or len(devices) < limit:
                        logging.debug(f"Completed retrieval for device type {device_type}")
                        break
                        
                    skip += len(devices)

            except Exception as e:
                logging.error(f"Error getting devices of type {device_type}: {str(e)}")
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.exception("Detailed error trace:")
                continue
        
        total_devices = len(all_devices)        
        logging.info(f"Retrieved {total_devices} total devices from NetBrain")
        
        # Log device type distribution
        type_counts = {}
        for device in all_devices:
            device_type = device['attributes'].get('subTypeName', 'Unknown')
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
        
        logging.info("Device type distribution:")
        for device_type, count in sorted(type_counts.items()):
            logging.info(f"  {device_type}: {count}")
        
        # Add detailed device logging if in debug mode
        from .logger import log_device_details
        log_device_details(all_devices)
        
        return all_devices

    def get_device_details(self, hostname: str) -> Optional[Dict[str, Any]]:
        """
        Get device details using the Attributes API endpoint
        Uses hostname for the API call as required by NetBrain API
        
        Args:
            hostname: Device hostname (not device ID)
                
        Returns:
            Device dictionary or None if not found
                
        Example response:
        {
            'name': 'device1',
            'mgmtIP': '10.0.0.1',
            'site': 'My Network/Site1',
            'attributes': {
                'subTypeName': 'Cisco IOS Switch',
                'vendor': 'Cisco',
                'model': 'Catalyst 3750',
                'ver': '12.2(55)SE',
                'mgmtIntf': 'Vlan1'
            }
        }
        """
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices/Attributes')
        
        # Ensure we're using hostname and not ID
        if not isinstance(hostname, str):
            logging.warning(f"Invalid hostname type provided: {type(hostname)}. Expected string.")
            return None
            
        # Skip UUIDs that look like device IDs
        if len(hostname) == 36 and hostname.count('-') == 4:
            logging.warning(f"Received device ID instead of hostname: {hostname}")
            return None
            
        params = {'hostname': hostname}
        
        try:
            logging.debug(f"Getting device details for hostname: {hostname}")
            response = self._request('GET', url, params=params)
            
            if response.get('statusCode') == 790200:  # Success
                # Build standardized device data structure
                device_data = {
                    'name': response.get('hostname'),
                    'mgmtIP': response.get('attributes', {}).get('mgmtIP'),
                    'site': response.get('attributes', {}).get('site', 'Unassigned'),
                    'attributes': response.get('attributes', {})
                }
                
                return device_data
                
            logging.warning(f"Device {hostname} not found: {response.get('statusDescription')}")
            return None
            
        except Exception as e:
            logging.error(f"Error getting device details for {hostname}: {str(e)}")
            return None

    def _get_device_by_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        """
        Get device details by looking up hostname in Attributes API
        Uses caching to reduce API calls
        
        Args:
            device_id: NetBrain device ID (used only for cache key)
            
        Returns:
            Device dictionary or None if not found
        """
        # Check cache first
        if device_id in self._device_cache:
            return self._device_cache[device_id]

        # First get device details from inventory to get hostname
        url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices/Inventory')
        params = {'id': device_id}
        
        try:
            inv_response = self._request('GET', url, params=params)
            if inv_response.get('statusCode') != 790200:
                logging.warning(f"Device {device_id} not found in inventory")
                return None

            hostname = inv_response.get('device', {}).get('name')
            if not hostname:
                logging.warning(f"No hostname found for device ID {device_id}")
                return None

            # Now get full device details from Attributes API
            device_data = self.get_device_details(hostname)
            if device_data:
                # Cache with device ID as key
                self._device_cache[device_id] = device_data
            return device_data
            
        except Exception as e:
            logging.error(f"Error getting device details for ID {device_id}: {str(e)}")
            return None

    def get_device_configs(self, hostname: str) -> Dict[str, str]:
        """
        Get device configuration data using the Device Raw Data API
        
        Args:
            hostname: Device hostname
            
        Returns:
            Dictionary mapping commands to their outputs
            
        Raises:
            NetBrainAPIError: If API request fails
            NetBrainError: For other errors during config retrieval
        """
        configs = {}
        
        try:
            # Get device details to get device type
            device = self.get_device_details(hostname)
            if not device:
                raise NetBrainError(f"Device not found with hostname {hostname}")

            # Get device type and command mappings
            device_type = device['attributes'].get('subTypeName')
            if not device_type:
                raise NetBrainError(f"No device type found for device {hostname}")

            command_mappings = self.config_manager.get_config_file_mapping(device_type)
            if not command_mappings:
                logging.warning(f"No command mappings found for device type {device_type}")
                return configs

            # Fetch each command using the Device Raw Data API
            for command in command_mappings.keys():
                try:
                    url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices/DeviceRawData')
                    params = {
                        'hostname': hostname,
                        'dataType': 2,  # CLI command result
                        'cmd': command
                    }

                    response = self._request('GET', url, params=params)
                    
                    if response.get('statusCode') == 790200:  # Success
                        content = response.get('content', '')
                        if content:
                            # Process the content to remove prompts and commands
                            processed_content = self._process_command_output(content, command)
                            configs[command] = processed_content
                            logging.debug(f"Successfully retrieved command '{command}' for device {hostname}")
                        else:
                            logging.warning(f"Empty content received for command '{command}' on device {hostname}")
                    else:
                        logging.warning(f"Failed to get command '{command}' for device {hostname}: {response.get('statusDescription')}")

                except Exception as e:
                    logging.error(f"Error getting command '{command}' for device {hostname}: {str(e)}")
                    continue

            return configs
            
        except Exception as e:
            error_msg = f"Error getting device configs: {str(e)}"
            logging.error(error_msg)
            raise NetBrainError(error_msg)

    def get_device_config_time(self, hostname: str) -> Optional[str]:
        """
        Get timestamp of last configuration update
        
        Args:
            hostname: Device hostname
            
        Returns:
            ISO format timestamp string or None if not found
        """
        try:
            device = self.get_device_details(hostname)
            if not device:
                return None

            last_discovery = device['attributes'].get('lDiscoveryTime')
            if last_discovery and last_discovery != '0001-01-01T00:00:00Z':
                return last_discovery

            return None

        except Exception as e:
            logging.error(f"Error getting config time for device {hostname}: {str(e)}")
            return None

    def _process_command_output(self, content: str, command: str) -> str:
        """
        Process command output to remove shell prompts and command strings
        
        Args:
            content: Raw command output
            command: Command that was executed
            
        Returns:
            Processed command output
        """
        if not content:
            return content

        # Split content into lines
        lines = content.split('\n')
        
        # Remove empty lines at start and end
        while lines and not lines[0].strip():
            lines.pop(0)
        while lines and not lines[-1].strip():
            lines.pop()
            
        if not lines:
            return ''

        # Remove prompt and command from first line
        first_line = lines[0]
        if ('>' in first_line or '#' in first_line) and command in first_line:
            # Found a prompt with command, remove first line
            lines = lines[1:]
        elif command in first_line:
            # Found the command alone, remove first line
            lines = lines[1:]

        # Remove any trailing CLI prompts or banners
        while lines and ('>' in lines[-1] or '#' in lines[-1] or 'banner' in lines[-1].lower()):
            lines.pop()

        # Rejoin lines and strip any extra whitespace
        return '\n'.join(lines).strip()

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices from NetBrain using the Devices API
        Filters devices based on device type mappings in config
        
        Returns:
            List of device dictionaries
            
        Raises:
            NetBrainError: If ConfigManager is not provided or API errors occur
        """
        logging.debug("Getting all devices from NetBrain")
        
        if not self.config_manager:
            raise NetBrainError("ConfigManager required for device type filtering")
            
        all_devices = []
        device_types = self.config_manager.get_mapped_device_types()
        logging.debug(f"Configured device types: {sorted(device_types)}")

        # Get devices by type
        for device_type in device_types:
            try:
                url = urljoin(self.host, '/ServicesAPI/API/V1/CMDB/Devices')
                skip = 0
                limit = 50  # Use smaller batch size to avoid timeout issues

                while True:
                    # Build API query parameters
                    params = {
                        'version': '1',
                        'skip': skip,
                        'limit': limit,
                        'fullattr': '1',
                        'filter': json.dumps({"subTypeName": device_type})
                    }
                    
                    logging.debug(f"Querying devices: type={device_type}, skip={skip}, limit={limit}")
                    
                    # Make API request
                    response = self._request('GET', url, params=params)
                    if not response:
                        logging.error(f"No response received for device type {device_type}")
                        break
                        
                    # Get device batch and total count
                    devices = response.get('devices', [])
                    total_count = response.get('totalResultCount', 0)
                    
                    if not devices:
                        logging.debug(f"No devices found for type {device_type}")
                        break

                    # Normalize device data
                    normalized_devices = []
                    for device in devices:
                        try:
                            normalized = {
                                'id': device.get('id'),
                                'hostname': device.get('name'),  # Map 'name' to 'hostname'
                                'mgmtIP': device.get('mgmtIP'),
                                'site': device.get('site'),
                                'attributes': {
                                    'subTypeName': device.get('subTypeName'),
                                    'vendor': device.get('vendor'),
                                    'model': device.get('model'),
                                    'version': device.get('ver'),
                                    'serialNumber': device.get('sn'),
                                    'contact': device.get('contact'),
                                    'location': device.get('loc'),
                                    'mgmtIntf': device.get('mgmtIntf'),
                                    'description': device.get('descr'),
                                    'lastDiscoveryTime': device.get('lDiscoveryTime', {}).get('$date')
                                                       if isinstance(device.get('lDiscoveryTime'), dict) 
                                                       else device.get('lDiscoveryTime')
                                }
                            }
                            
                            # Validate required fields
                            if not normalized.get('hostname'):
                                logging.warning(f"Skipping device with missing hostname: {device}")
                                continue
                                
                            if not normalized.get('mgmtIP'):
                                logging.warning(f"Skipping device {normalized['hostname']} with missing mgmtIP")
                                continue
                                
                            if not normalized['attributes'].get('subTypeName'):
                                logging.warning(f"Skipping device {normalized['hostname']} with missing subTypeName")
                                continue
                                
                            normalized_devices.append(normalized)
                            logging.debug(f"Normalized device: hostname={normalized['hostname']}, "
                                        f"IP={normalized['mgmtIP']}, type={normalized['attributes']['subTypeName']}")
                                        
                        except Exception as e:
                            logging.error(f"Error normalizing device data: {str(e)}")
                            if logging.getLogger().isEnabledFor(logging.DEBUG):
                                logging.error(f"Problem device data: {json.dumps(device, indent=2)}")
                            continue

                    # Add valid devices to result list
                    all_devices.extend(normalized_devices)
                    processed_count = skip + len(devices)
                    
                    logging.info(f"Retrieved {len(normalized_devices)} {device_type} devices. "
                               f"Progress: {processed_count}/{total_count}")
                    
                    # Check if we're done with this device type
                    if processed_count >= total_count or len(devices) < limit:
                        logging.debug(f"Completed retrieval for device type {device_type}")
                        break
                        
                    skip += len(devices)

            except Exception as e:
                logging.error(f"Error getting devices of type {device_type}: {str(e)}")
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.exception("Detailed error trace:")
                continue
        
        total_devices = len(all_devices)        
        logging.info(f"Retrieved {total_devices} total devices from NetBrain")
        
        # Log device type distribution
        type_counts = {}
        for device in all_devices:
            device_type = device['attributes'].get('subTypeName', 'Unknown')
            type_counts[device_type] = type_counts.get(device_type, 0) + 1
        
        logging.info("Device type distribution:")
        for device_type, count in sorted(type_counts.items()):
            logging.info(f"  {device_type}: {count}")
        
        # Add detailed device logging if in debug mode
        from .logger import log_device_details
        log_device_details(all_devices)
        
        return all_devices

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
            # Set up headers for NetBrain API
            headers = {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'Token': self.token,
                'Tenant': self.tenant
            }
            
            # Update session headers
            self.session.headers.update(headers)
            
            # Log request details in debug mode
            logging.debug(f"Making NetBrain API request: {method} {endpoint}")
            if 'params' in kwargs:
                logging.debug(f"Request parameters: {kwargs['params']}")
            if 'json' in kwargs:
                logging.debug(f"Request body: {kwargs['json']}")
            
            response = self.session.request(method, endpoint, verify=False, **kwargs)
            
            # Handle 401 by re-authenticating once
            if response.status_code == 401:
                logging.debug("Token expired during request, re-authenticating...")
                self.authenticate()
                # Update token in headers after re-auth
                self.session.headers.update({'Token': self.token})
                response = self.session.request(method, endpoint, verify=False, **kwargs)
            
            response.raise_for_status()
            
            # Parse response
            response_data = response.json()
            
            # Check for API-specific error responses
            if isinstance(response_data, dict):
                status_code = response_data.get('statusCode')
                if status_code != 790200 and 'error' in response_data:
                    error_msg = response_data.get('error', 'Unknown API error')
                    raise NetBrainAPIError(f"API error {status_code}: {error_msg}")
                elif status_code == 791006:  # Device Data Not Found
                    logging.warning("Device data not found - benchmark may be required")
                    return response_data
            
            logging.debug(f"API request successful: {method} {endpoint}")
            return response_data
            
        except requests.exceptions.HTTPError as e:
            error_msg = f"API request failed: {e.response.status_code} {e.response.reason} for url: {e.response.url}"
            logging.error(error_msg)
            try:
                error_detail = e.response.json()
                logging.error(f"Error details: {error_detail}")
            except:
                pass
            raise NetBrainAPIError(error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error during API request: {str(e)}"
            logging.error(error_msg)
            raise NetBrainError(error_msg)

    def clear_caches(self) -> None:
        """Clear all caches"""
        self._device_cache.clear()
        self._get_device_configs.cache_clear()
        logging.debug("Cleared all caches")

    @lru_cache(maxsize=1024)
    def _get_device_configs(self, hostname: str) -> Dict[str, str]:
        """Cached method to get device configurations"""
        return self.get_device_configs(hostname)

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - ensure cleanup"""
        self.clear_caches()
        if hasattr(self, 'session'):
            self.session.close()