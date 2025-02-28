# lib/firemon.py

"""
FireMon API Client Module
Handles all interactions with the FireMon API including:
- Authentication and token management 
- Device management (create, search, update)
- Configuration imports
- License management
- Device group operations
"""

import os
import json  # Added missing json import
import logging
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin
from datetime import datetime

class FireMonError(Exception):
    """Base exception for FireMon API errors"""
    pass

class FireMonAuthError(FireMonError):
    """Authentication related errors"""
    pass

class FireMonAPIError(FireMonError):
    """General API errors"""
    pass

class FireMonClient:
    def __init__(self, host: str = None, username: str = None,
                 password: str = None, domain_id: int = None):
        """
        Initialize FireMon client with environment variables or provided values
        
        Args:
            host: FireMon server URL 
            username: FireMon username
            password: FireMon password
            domain_id: FireMon domain ID (defaults to 1)
        """
        self.host = (host or os.getenv('FIREMON_HOST', '')).rstrip('/')
        self.username = username or os.getenv('FIREMON_USERNAME', '')
        self.password = password or os.getenv('FIREMON_PASSWORD', '')
        self.domain_id = domain_id or int(os.getenv('FIREMON_DOMAIN_ID', '1'))
        
        if not all([self.host, self.username, self.password]):
            raise ValueError("Missing required FireMon credentials")
            
        self.session = requests.Session()
        self.token = None

    def authenticate(self) -> None:
        """
        Authenticate with FireMon and get token
        
        Raises:
            FireMonAuthError: If authentication fails
            FireMonError: For other errors during authentication
        """
        url = urljoin(self.host, '/securitymanager/api/authentication/login')
        data = {
            'username': self.username,
            'password': self.password
        }
        
        try:
            response = self.session.post(url, json=data)
            response.raise_for_status()
            
            self.token = response.json()['token']
            self.session.headers.update({
                'Authorization': f'Bearer {self.token}',
                'Content-Type': 'application/json'
            })
            logging.info("Successfully authenticated with FireMon")
            
        except requests.exceptions.HTTPError as e:
            raise FireMonAuthError(f"Authentication failed: {str(e)}")
        except Exception as e:
            raise FireMonError(f"Error during authentication: {str(e)}")

    def validate_token(self) -> bool:
        """
        Check if current token is valid
        
        Returns:
            bool: True if token is valid, False otherwise
        """
        if not self.token:
            return False
            
        try:
            url = urljoin(self.host, '/securitymanager/api/domain/1/devicegroup.json')
            params = {'page': 0, 'pageSize': 1}
            response = self.session.get(url, params=params)
            return response.status_code != 401
            
        except Exception as e:
            logging.error(f"Error validating token: {str(e)}")
            return False

    def get_all_devices(self) -> List[Dict[str, Any]]:
        """
        Get all devices from FireMon
        
        Returns:
            List of device dictionaries
        """
        logging.debug("Getting all devices from FireMon")
        all_devices = []
        page = 0
        page_size = 100
        
        while True:
            try:
                url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device')
                params = {
                    'page': page,
                    'pageSize': page_size
                }
                
                response = self._request('GET', url, params=params)
                devices = response.get('results', [])

                # Log a sample device to debug the response structure
                if devices and page == 0:
                    logging.debug(f"Sample FireMon device response: {json.dumps(devices[0], indent=2)}")

                all_devices.extend(devices)
                
                if len(devices) < page_size:
                    break
                    
                page += 1
                
            except Exception as e:
                raise FireMonAPIError(f"Error retrieving devices: {str(e)}")
                    
        return all_devices

    def search_device(self, hostname: str, mgmt_ip: str) -> Optional[Dict[str, Any]]:
        """
        Search for a device by hostname and management IP
        Uses comprehensive case-insensitive search to match FireMon behavior
        
        Args:
            hostname: Device hostname
            mgmt_ip: Management IP address
                
        Returns:
            Device dictionary if found, None otherwise
        """
        if not hostname and not mgmt_ip:
            logging.warning("Both hostname and mgmt_ip are empty, cannot search for device")
            return None
            
        # First try getting all devices and doing client-side matching
        # This is more reliable than using the API's search capabilities
        try:
            # Get all devices from the domain
            url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device')
            params = {
                'page': 0,
                'pageSize': 1000  # Get a large batch to ensure we find matching devices
            }
            
            logging.debug(f"Searching for device with hostname={hostname}, IP={mgmt_ip}")
            response = self._request('GET', url, params=params)
            devices = response.get('results', [])
            
            # First try exact case-insensitive hostname match
            if hostname:
                hostname_lower = hostname.lower()
                for device in devices:
                    device_name = device.get('name', '')
                    if device_name and device_name.lower() == hostname_lower:
                        logging.info(f"Found exact case-insensitive match by name: {device_name} for {hostname}")
                        return self._format_device_result(device)
            
            # Then try exact IP match
            if mgmt_ip:
                for device in devices:
                    device_ip = device.get('managementIp')
                    if device_ip == mgmt_ip:
                        logging.info(f"Found exact match by IP: {device_ip} for device {device.get('name', 'unknown')}")
                        return self._format_device_result(device)
                        
            # If still no match, use the SIQL search as a fallback
            if hostname:
                url = urljoin(self.host, '/securitymanager/api/siql/device/paged-search')
                query = (f"domain {{ id = {self.domain_id} }} AND device {{ "
                        f"name matches '{hostname}' }}")
                
                params = {
                    'q': query,
                    'page': 0,
                    'pageSize': 50,
                    'sort': 'name'
                }
                
                response = self._request('GET', url, params=params)
                results = response.get('results', [])
                
                if results:
                    # Find exact case-insensitive match manually
                    for device in results:
                        device_name = device.get('name', '')
                        if device_name.lower() == hostname.lower():
                            logging.info(f"Found case-insensitive match via SIQL: {device_name} for {hostname}")
                            return self._format_device_result(device)
            
            logging.debug(f"No match found for {hostname} / {mgmt_ip}")
            return None
            
        except Exception as e:
            logging.error(f"Error searching for device {hostname}: {str(e)}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed search error trace:")
            return None

    def _format_device_result(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Format device search result into standard format"""
        return {
            'id': device.get('id'),
            'name': device.get('name'),
            'managementIp': device.get('managementIp'),
            'collectorGroupName': device.get('collectorGroupName'),
            'collectorGroupId': device.get('collectorGroupId'),
            'product': device.get('product'),
            'managedType': device.get('managedType'),
            'lastRevision': device.get('lastRevision'),
            'devicePack': {
                'deviceName': device.get('product'),
                'vendor': device.get('vendor')
            } if device.get('product') and device.get('vendor') else None
        }
        
    def create_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create a new device in FireMon
        
        Args:
            device_data: Device configuration dictionary
            
        Returns:
            Created device data
            
        Raises:
            FireMonAPIError: If device creation fails with detailed error information
        """
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device')
        params = {'manualRetrieval': 'false'}
        
        try:
            # Log the request details
            logging.debug(f"Creating device {device_data.get('name')} with payload: {json.dumps(device_data, indent=2)}")
            
            response = self.session.post(url, json=device_data, params=params)
            
            # If there's an error, try to get detailed error information
            if not response.ok:
                error_details = "Unknown error"
                try:
                    error_response = response.json()
                    if isinstance(error_response, dict):
                        error_details = error_response.get('message', error_response.get('error', str(error_response)))
                    else:
                        error_details = str(error_response)
                except Exception as json_err:
                    error_details = response.text or str(response.reason)
                
                error_msg = (
                    f"Failed to create device {device_data.get('name')}: "
                    f"Status {response.status_code} - {error_details}"
                )
                logging.error(error_msg)
                logging.error(f"Request URL: {url}")
                logging.error(f"Request Headers: {response.request.headers}")
                
                raise FireMonAPIError(error_msg)
            
            result = response.json()
            logging.info(f"Successfully created device {device_data.get('name')} with ID {result.get('id')}")
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = f"API request failed: {str(e)}"
            logging.error(error_msg)
            raise FireMonAPIError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error creating device: {str(e)}"
            logging.error(error_msg)
            raise FireMonError(error_msg)

    def update_device(self, device_id: int, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update an existing device in FireMon
        
        Args:
            device_id: FireMon device ID
            device_data: Updated device configuration dictionary
            
        Returns:
            Updated device data
            
        Raises:
            FireMonAPIError: If device update fails
        """
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device/{device_id}')
        
        try:
            # Log the update details
            logging.debug(f"Updating device ID {device_id} with payload: {json.dumps(device_data, indent=2)}")
            
            response = self.session.put(url, json=device_data)
            
            # Handle errors with detailed information
            if not response.ok:
                error_details = "Unknown error"
                try:
                    error_response = response.json()
                    if isinstance(error_response, dict):
                        error_details = error_response.get('message', error_response.get('error', str(error_response)))
                    else:
                        error_details = str(error_response)
                except Exception:
                    error_details = response.text or str(response.reason)
                
                error_msg = (
                    f"Failed to update device {device_id}: "
                    f"Status {response.status_code} - {error_details}"
                )
                logging.error(error_msg)
                logging.error(f"Request URL: {url}")
                
                raise FireMonAPIError(error_msg)
            
            result = response.json()
            logging.info(f"Successfully updated device ID {device_id}")
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = f"API request failed for device update: {str(e)}"
            logging.error(error_msg)
            raise FireMonAPIError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error updating device: {str(e)}"
            logging.error(error_msg)
            raise FireMonError(error_msg)

    def import_device_config(self, device_id: int, files: Dict[str, str], 
                       change_user: str = 'NetBrain') -> Dict[str, Any]:
        """
        Import device configuration files to FireMon
        
        Args:
            device_id: FireMon device ID
            files: Dictionary mapping filenames to content
            change_user: User to attribute changes to
            
        Returns:
            Import result data
        """
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/device/{device_id}/rev'
        )
        params = {
            'action': 'IMPORT',
            'changeUser': change_user
        }
        
        try:
            # Create proper multipart form data with indexed file fields
            # Each file needs to be named "file[index]" with filename attribute set correctly
            multipart_form_data = {}
            
            for i, (filename, content) in enumerate(files.items()):
                # Create a file-like object from the content string
                # The key needs to be 'file[i]' exactly as the API expects
                field_name = f'file[{i}]'
                
                # Log what we're uploading for debug purposes
                logging.debug(f"Adding file to upload: {field_name}, filename={filename}, content length={len(content)}")
                
                # Create the multipart form data entry with the proper filename
                multipart_form_data[field_name] = (filename, content, 'application/octet-stream')
            
            # Log request details
            logging.debug(f"Sending config import request to FireMon: URL={url}, params={params}, "
                         f"Uploading {len(multipart_form_data)} files")
            
            # Make the request using the requests library's files parameter
            # This properly handles the multipart/form-data encoding
            response = self.session.post(url, params=params, files=multipart_form_data)
            
            # Check response status
            if not response.ok:
                # Try to get more detailed error information
                try:
                    error_details = response.json()
                    error_msg = f"Error importing device config: {response.status_code} {response.reason} - {error_details}"
                except:
                    error_msg = f"Error importing device config: {response.status_code} {response.reason} for url: {response.url}"
                
                logging.error(error_msg)
                if logging.getLogger().isEnabledFor(logging.DEBUG):
                    logging.error(f"Response content: {response.text}")
                
                raise FireMonAPIError(error_msg)
            
            # Parse and return the response
            result = response.json()
            logging.info(f"Successfully imported configuration for device {device_id}, "
                       f"revision ID: {result.get('id')}")
            return result
            
        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed during config import: {str(e)}"
            logging.error(error_msg)
            raise FireMonAPIError(error_msg)
        except Exception as e:
            error_msg = f"Error importing device config: {str(e)}"
            logging.error(error_msg)
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace for config import:")
            raise FireMonAPIError(error_msg)

    def manage_device_license(self, device_id: int, add: bool = True, 
                            products: Optional[List[str]] = None) -> None:
        """
        Add or remove device licenses
        
        Args:
            device_id: FireMon device ID
            add: True to add licenses, False to remove
            products: List of product codes (defaults to ['SM', 'PO', 'PP'])
        """
        if products is None:
            products = ['SM', 'PO', 'PP']
            
        for product in products:
            url = urljoin(
                self.host,
                f'/securitymanager/api/domain/{self.domain_id}/device/license/'
                f'{device_id}/product/{product}'
            )
            
            try:
                if add:
                    response = self.session.post(url)
                else:
                    response = self.session.delete(url)
                    
                response.raise_for_status()
                
            except Exception as e:
                raise FireMonAPIError(
                    f"Error {'adding' if add else 'removing'} license {product}: {str(e)}"
                )

    def get_device_groups(self) -> List[Dict[str, Any]]:
        """
        Get all device groups
        
        Returns:
            List of device group dictionaries
        """
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/devicegroup.json')
        
        all_groups = []
        page = 0
        while True:
            params = {
                'page': page,
                'pageSize': 100,
                'sort': 'name'
            }
            
            try:
                response = self._request('GET', url, params=params)
                all_groups.extend(response['results'])
                
                if len(response['results']) < response['pageSize']:
                    break
                    
                page += 1
                
            except Exception as e:
                raise FireMonAPIError(f"Error getting device groups: {str(e)}")
            
        return all_groups

    def create_device_group(self, name: str, description: str = '', 
                          parent_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Create a new device group
        
        Args:
            name: Group name
            description: Group description
            parent_id: Parent group ID
            
        Returns:
            Created group data
        """
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/devicegroup.json')
        data = {
            'name': name,
            'description': description,
            'domainId': self.domain_id
        }
        
        if parent_id:
            data['parentId'] = parent_id
        
        try:
            return self._request('POST', url, json=data)
        except Exception as e:
            raise FireMonAPIError(f"Error creating device group: {str(e)}")

    def update_device_group(self, group_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update a device group
        
        Args:
            group_id: Group ID
            data: Updated group data
            
        Returns:
            Updated group data
        """
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}'
        )
        
        try:
            return self._request('PUT', url, json=data)
        except Exception as e:
            raise FireMonAPIError(f"Error updating device group: {str(e)}")

    def add_device_to_group(self, group_id: int, device_id: int) -> None:
        """
        Add a device to a group
        
        Args:
            group_id: Group ID
            device_id: Device ID
        """
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}/'
            f'device/{device_id}'
        )
        
        try:
            response = self.session.post(url)
            response.raise_for_status()
        except Exception as e:
            raise FireMonAPIError(f"Error adding device to group: {str(e)}")

    def remove_device_from_group(self, group_id: int, device_id: int) -> None:
        """
        Remove a device from a group
        
        Args:
            group_id: Group ID
            device_id: Device ID
        """
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}/'
            f'device/{device_id}'
        )
        
        try:
            response = self.session.delete(url)
            response.raise_for_status()
        except Exception as e:
            raise FireMonAPIError(f"Error removing device from group: {str(e)}")

    def get_device_revision(self, device_id: int) -> Optional[Dict[str, Any]]:
        """
        Get latest device revision details
        
        Args:
            device_id: Device ID
            
        Returns:
            Revision details if found, None otherwise
        """
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/rev/filter')
        params = {
            'filter': f'device.id = {device_id}',
            'page': 0,
            'pageSize': 1,
            'sort': '-createdate'
        }
        
        try:
            response = self._request('GET', url, params=params)
            results = response.get('results', [])
            return results[0] if results else None
        except Exception as e:
            raise FireMonAPIError(f"Error getting device revision: {str(e)}")

    def find_group_by_path(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Find a device group by its path
        
        Args:
            path: Group path (e.g., "Parent/Child")
            
        Returns:
            Group data if found, None otherwise
        """
        groups = self.get_device_groups()
        path_parts = path.split('/')
        current_group = None
        
        for part in path_parts:
            found = False
            for group in groups:
                if group['name'] == part:
                    if not current_group or group.get('parentId') == current_group['id']:
                        current_group = group
                        found = True
                        break
            
            if not found:
                return None
                
        return current_group

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make an authenticated request to FireMon API
        
        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional request parameters
            
        Returns:
            JSON response data
            
        Raises:
            FireMonAPIError: If request fails
            FireMonError: For other unexpected errors
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
            
        except requests.exceptions.RequestException as e:
            raise FireMonAPIError(f"API request failed: {str(e)}")
        except Exception as e:
            raise FireMonError(f"Unexpected error: {str(e)}")