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
    """Client for interacting with the FireMon API"""
    
    def __init__(self, host: str, username: str, password: str, domain_id: int):
        """Initialize FireMon client
        
        Args:
            host: FireMon server hostname/URL
            username: API username
            password: API password 
            domain_id: FireMon domain ID
        """
        self.host = host.rstrip('/')
        self.username = username
        self.password = password
        self.domain_id = domain_id
        self.session = requests.Session()
        self.token = None

    def authenticate(self) -> None:
        """Authenticate with FireMon and get token"""
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
        """Check if current token is valid"""
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
        """Get all devices from FireMon"""
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
                all_devices.extend(devices)
                
                if len(devices) < page_size:
                    break
                    
                page += 1
                
            except Exception as e:
                raise FireMonAPIError(f"Error retrieving devices: {str(e)}")
                
        return all_devices

    def search_device(self, hostname: str, mgmt_ip: str) -> Optional[Dict[str, Any]]:
        """Search for a device by hostname and management IP"""
        url = urljoin(self.host, '/securitymanager/api/siql/device/paged-search')
        query = (f"domain {{ id = {self.domain_id} }} AND device {{ "
                f"name = '{hostname}' AND (( managementip equals '{mgmt_ip}' )) }}")
        
        params = {
            'q': query,
            'page': 0,
            'pageSize': 1,
            'sort': 'name'
        }
        
        try:
            response = self._request('GET', url, params=params)
            results = response.get('results', [])
            return results[0] if results else None
            
        except Exception as e:
            raise FireMonAPIError(f"Error searching for device: {str(e)}")

    def create_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new device in FireMon"""
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device')
        params = {'manualRetrieval': 'false'}
        
        try:
            return self._request('POST', url, json=device_data, params=params)
        except Exception as e:
            raise FireMonAPIError(f"Error creating device: {str(e)}")

    def import_device_config(self, device_id: int, files: Dict[str, str], 
                           change_user: str = 'NetBrain') -> Dict[str, Any]:
        """Import device configuration files"""
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/device/{device_id}/rev'
        )
        params = {
            'action': 'IMPORT',
            'changeUser': change_user
        }
        
        # Prepare multipart form data
        files_data = {
            f'file[{i}]': (filename, content)
            for i, (filename, content) in enumerate(files.items())
        }
        
        try:
            response = self.session.post(url, params=params, files=files_data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            raise FireMonAPIError(f"Error importing device config: {str(e)}")

    def manage_device_license(self, device_id: int, add: bool = True, 
                            products: Optional[List[str]] = None) -> None:
        """Add or remove device licenses"""
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
        """Get all device groups"""
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
        """Create a new device group"""
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
        """Update a device group"""
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}'
        )
        
        try:
            return self._request('PUT', url, json=data)
        except Exception as e:
            raise FireMonAPIError(f"Error updating device group: {str(e)}")

    def add_device_to_group(self, group_id: int, device_id: int) -> None:
        """Add a device to a group"""
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
        """Remove a device from a group"""
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
        """Get latest device revision details"""
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

    def get_devices_in_group(self, group_id: int) -> List[Dict[str, Any]]:
        """Get all devices in a device group"""
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}/device.json'
        )
        
        all_devices = []
        page = 0
        while True:
            params = {
                'page': page,
                'pageSize': 100
            }
            
            try:
                response = self._request('GET', url, params=params)
                all_devices.extend(response['results'])
                
                if len(response['results']) < response['pageSize']:
                    break
                    
                page += 1
                
            except Exception as e:
                raise FireMonAPIError(f"Error getting devices in group: {str(e)}")
            
        return all_devices

    def delete_device_group(self, group_id: int) -> None:
        """Delete a device group"""
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}'
        )
        
        try:
            response = self.session.delete(url)
            response.raise_for_status()
        except Exception as e:
            raise FireMonAPIError(f"Error deleting device group: {str(e)}")

    def find_group_by_path(self, path: str) -> Optional[Dict[str, Any]]:
        """Find a device group by its path"""
        # Get all groups and build path mapping
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
        """Make an authenticated request to FireMon API"""
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