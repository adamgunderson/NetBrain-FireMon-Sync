# File: lib/firemon.py

"""
FireMon API Client
Handles all interactions with the FireMon API
"""

import logging
import requests
from typing import Dict, List, Any, Optional
from urllib.parse import urljoin

class FireMonClient:
    def __init__(self, host: str, username: str, password: str, domain_id: int):
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
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        self.token = response.json()['token']
        self.session.headers.update({'Authorization': f'Bearer {self.token}'})

    def search_device(self, hostname: str, mgmt_ip: str) -> Optional[Dict[str, Any]]:
        """Search for a device by hostname and management IP"""
        url = urljoin(self.host, '/securitymanager/api/siql/device/paged-search')
        query = f"domain {{ id = {self.domain_id} }}  AND device {{ name = '{hostname}' AND (( managementip equals '{mgmt_ip}' )) }}"
        
        params = {
            'q': query,
            'page': 0,
            'pageSize': 1,
            'sort': 'name'
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        results = response.json()['results']
        return results[0] if results else None

    def create_device(self, device_data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new device in FireMon"""
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device')
        params = {'manualRetrieval': 'false'}
        
        response = self.session.post(url, json=device_data, params=params)
        response.raise_for_status()
        
        return response.json()

    def import_device_config(self, device_id: int, files: Dict[str, str], change_user: str = 'NetBrain') -> Dict[str, Any]:
        """Import device configuration files"""
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/device/{device_id}/rev')
        params = {
            'action': 'IMPORT',
            'changeUser': change_user
        }
        
        # Prepare multipart form data
        files_data = {
            f'file[{i}]': (filename, content)
            for i, (filename, content) in enumerate(files.items())
        }
        
        response = self.session.post(url, params=params, files=files_data)
        response.raise_for_status()
        
        return response.json()

    def manage_device_license(self, device_id: int, add: bool = True, products: List[str] = None) -> None:
        """Add or remove device licenses"""
        if products is None:
            products = ['SM', 'PO', 'PP']  # Default products
            
        for product in products:
            url = urljoin(
                self.host,
                f'/securitymanager/api/domain/{self.domain_id}/device/license/{device_id}/product/{product}'
            )
            
            if add:
                response = self.session.post(url)
            else:
                response = self.session.delete(url)
                
            response.raise_for_status()

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
            
            response = self.session.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            all_groups.extend(data['results'])
            
            if len(data['results']) < data['pageSize']:
                break
                
            page += 1
            
        return all_groups

    def create_device_group(self, name: str, description: str = '', parent_id: Optional[int] = None) -> Dict[str, Any]:
        """Create a new device group"""
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/devicegroup.json')
        data = {
            'name': name,
            'description': description,
            'domainId': self.domain_id
        }
        
        if parent_id:
            data['parentId'] = parent_id
        
        response = self.session.post(url, json=data)
        response.raise_for_status()
        
        return response.json()

    def update_device_group(self, group_id: int, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update a device group"""
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}')
        
        response = self.session.put(url, json=data)
        response.raise_for_status()
        
        return response.json()

    def add_device_to_group(self, group_id: int, device_id: int) -> None:
        """Add a device to a group"""
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}/device/{device_id}'
        )
        
        response = self.session.post(url)
        response.raise_for_status()

    def remove_device_from_group(self, group_id: int, device_id: int) -> None:
        """Remove a device from a group"""
        url = urljoin(
            self.host,
            f'/securitymanager/api/domain/{self.domain_id}/devicegroup/{group_id}/device/{device_id}'
        )
        
        response = self.session.delete(url)
        response.raise_for_status()

    def get_device_revision(self, device_id: int) -> Optional[Dict[str, Any]]:
        """Get latest device revision details"""
        url = urljoin(self.host, f'/securitymanager/api/domain/{self.domain_id}/rev/filter')
        params = {
            'filter': f'device.id = {device_id}',
            'page': 0,
            'pageSize': 1,
            'sort': '-createdate'
        }
        
        response = self.session.get(url, params=params)
        response.raise_for_status()
        
        results = response.json()['results']
        return results[0] if results else None

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make an authenticated request to FireMon API"""
        if not self.token:
            self.authenticate()

        url = urljoin(self.host, endpoint)
        response = self.session.request(method, url, **kwargs)
        
        if response.status_code == 401:  # Token expired
            self.authenticate()
            response = self.session.request(method, url, **kwargs)
        
        response.raise_for_status()
        return response.json()