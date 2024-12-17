# lib/group_hierarchy.py

import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass

@dataclass
class GroupNode:
    id: Optional[int]
    name: str
    path: str
    parent_path: Optional[str]
    children: Set[str]
    site_id: Optional[str]
    level: int

class GroupHierarchyManager:
    def __init__(self, firemon_client):
        self.firemon = firemon_client
        self.group_cache = {}
        self.path_cache = {}
        
    def build_group_hierarchy(self, sites: List[Dict[str, Any]]) -> Dict[str, GroupNode]:
        """Build complete group hierarchy with validation"""
        hierarchy = {}
        
        # First pass: Create all nodes
        for site in sites:
            self._create_path_nodes(site['sitePath'], site['siteId'], hierarchy)
            
        # Second pass: Validate and fix hierarchy
        self._validate_and_fix_hierarchy(hierarchy)
        
        return hierarchy
        
    def _create_path_nodes(self, path: str, site_id: str, hierarchy: Dict[str, GroupNode]) -> None:
        """Create all nodes in a path"""
        parts = path.split('/')
        current_path = ''
        level = 0
        
        for part in parts:
            if current_path:
                current_path += '/'
            current_path += part
            level += 1
            
            if current_path not in hierarchy:
                parent_path = '/'.join(current_path.split('/')[:-1])
                hierarchy[current_path] = GroupNode(
                    id=None,
                    name=part,
                    path=current_path,
                    parent_path=parent_path if parent_path else None,
                    children=set(),
                    site_id=site_id if current_path == path else None,
                    level=level
                )
                
            if level > 1:
                parent = hierarchy[parent_path]
                parent.children.add(current_path)
                
    def _validate_and_fix_hierarchy(self, hierarchy: Dict[str, GroupNode]) -> None:
        """Validate hierarchy and fix any issues"""
        # Get existing FireMon groups
        fm_groups = {g['name']: g for g in self.firemon.get_device_groups()}
        self.group_cache.update(fm_groups)
        
        # Map paths to FireMon group IDs
        for path, node in hierarchy.items():
            if node.name in fm_groups:
                node.id = fm_groups[node.name]['id']
                self.path_cache[path] = node.id
                
        # Validate parent-child relationships
        issues = []
        for path, node in hierarchy.items():
            if node.parent_path:
                parent_node = hierarchy.get(node.parent_path)
                if not parent_node:
                    issues.append(f"Missing parent node for {path}")
                    continue
                    
                if parent_node.id is None:
                    issues.append(f"Parent group not found in FireMon for {path}")
                    continue
                    
                # Check if current node exists in FireMon
                if node.id is not None:
                    fm_group = fm_groups.get(node.name)
                    if fm_group and fm_group.get('parentId') != parent_node.id:
                        issues.append(f"Incorrect parent group for {path}")
                        
        if issues:
            logging.warning(f"Hierarchy issues found: {issues}")
            
    def sync_group_hierarchy(self, hierarchy: Dict[str, GroupNode], dry_run: bool = False) -> List[Dict[str, Any]]:
        """Synchronize group hierarchy to FireMon"""
        changes = []
        processed_groups = set()
        
        try:
            # Process hierarchy level by level
            max_level = max(node.level for node in hierarchy.values())
            
            for level in range(1, max_level + 1):
                level_nodes = {
                    path: node for path, node in hierarchy.items() 
                    if node.level == level
                }
                
                for path, node in level_nodes.items():
                    try:
                        change = self._process_group_node(node, hierarchy, dry_run)
                        if change:
                            changes.append(change)
                        processed_groups.add(node.name)
                        
                    except Exception as e:
                        logging.error(f"Error processing group {node.name}: {str(e)}")
                        changes.append({
                            'action': 'error',
                            'group': node.name,
                            'error': str(e),
                            'status': 'error'
                        })
                        
            # Handle orphaned groups
            if not dry_run:
                orphaned = self._handle_orphaned_groups(processed_groups)
                changes.extend(orphaned)
                
        except Exception as e:
            logging.error(f"Error in sync_group_hierarchy: {str(e)}")
            raise
            
        return changes
        
    def _process_group_node(self, node: GroupNode, hierarchy: Dict[str, GroupNode], 
                          dry_run: bool) -> Optional[Dict[str, Any]]:
        """Process individual group node"""
        try:
            if node.id is None:
                # Create new group
                if not dry_run:
                    parent_id = None
                    if node.parent_path:
                        parent_node = hierarchy[node.parent_path]
                        parent_id = parent_node.id
                        
                    group_data = {
                        'name': node.name,
                        'description': f'NetBrain site: {node.path}',
                        'parentId': parent_id,
                        'domainId': self.firemon.domain_id
                    }
                    
                    new_group = self.firemon.create_device_group(group_data)
                    node.id = new_group['id']
                    self.path_cache[node.path] = node.id
                    
                    return {
                        'action': 'create',
                        'group': node.name,
                        'path': node.path,
                        'status': 'success'
                    }
                    
                return {
                    'action': 'create',
                    'group': node.name,
                    'path': node.path,
                    'status': 'dry_run'
                }
                
            else:
                # Update existing group if needed
                fm_group = self.group_cache.get(node.name)
                if fm_group:
                    updates_needed = []
                    parent_id = None
                    
                    if node.parent_path:
                        parent_node = hierarchy[node.parent_path]
                        if parent_node.id != fm_group.get('parentId'):
                            updates_needed.append('parent')
                            parent_id = parent_node.id
                            
                    if updates_needed and not dry_run:
                        fm_group['parentId'] = parent_id
                        self.firemon.update_device_group(fm_group['id'], fm_group)
                        return {
                            'action': 'update',
                            'group': node.name,
                            'updates': updates_needed,
                            'status': 'success'
                        }
                        
                    elif updates_needed:
                        return {
                            'action': 'update',
                            'group': node.name,
                            'updates': updates_needed,
                            'status': 'dry_run'
                        }
                        
        except Exception as e:
            logging.error(f"Error processing group {node.name}: {str(e)}")
            return {
                'action': 'error',
                'group': node.name,
                'error': str(e),
                'status': 'error'
            }

    def _handle_orphaned_groups(self, processed_groups: Set[str]) -> List[Dict[str, Any]]:
        """Handle groups that exist in FireMon but not in NetBrain"""
        changes = []
        try:
            fm_groups = self.firemon.get_device_groups()
            
            for group in fm_groups:
                if group['name'] not in processed_groups:
                    # Skip system groups and root groups
                    if group.get('system', False) or not group.get('parentId'):
                        continue
                        
                    try:
                        # Remove devices from group first
                        devices = self.firemon.get_devices_in_group(group['id'])
                        for device in devices:
                            self.firemon.remove_device_from_group(group['id'], device['id'])
                            
                        # Delete the group
                        self.firemon.delete_device_group(group['id'])
                        changes.append({
                            'action': 'delete',
                            'group': group['name'],
                            'status': 'success'
                        })
                        
                    except Exception as e:
                        changes.append({
                            'action': 'error',
                            'group': group['name'],
                            'error': f"Error deleting group: {str(e)}",
                            'status': 'error'
                        })
                        
        except Exception as e:
            logging.error(f"Error handling orphaned groups: {str(e)}")
            
        return changes
        
    def get_group_path(self, group_id: int) -> Optional[str]:
        """Get full path for a group ID"""
        for path, gid in self.path_cache.items():
            if gid == group_id:
                return path
        return None
        
    def ensure_path_exists(self, path: str, site_id: Optional[str] = None,
                          dry_run: bool = False) -> List[Dict[str, Any]]:
        """Ensure a complete path exists, creating missing groups if needed"""
        changes = []
        hierarchy = {}
        
        # Build path nodes
        self._create_path_nodes(path, site_id, hierarchy)
        
        # Sync the path
        for node in sorted(hierarchy.values(), key=lambda x: x.level):
            change = self._process_group_node(node, hierarchy, dry_run)
            if change:
                changes.append(change)
                
        return changes

    def get_group_membership_changes(self, device_id: int, site_path: str) -> Dict[str, Set[int]]:
        """Calculate group membership changes needed"""
        current_groups = set()
        target_groups = set()
        
        # Get current group memberships
        fm_device_groups = self.firemon.get_device_groups(device_id)
        current_groups = {g['id'] for g in fm_device_groups}
        
        # Calculate target groups based on site path
        path_parts = site_path.split('/')
        current_path = ''
        
        for part in path_parts:
            if current_path:
                current_path += '/'
            current_path += part
            
            group_id = self.path_cache.get(current_path)
            if group_id:
                target_groups.add(group_id)
                
        return {
            'add': target_groups - current_groups,
            'remove': current_groups - target_groups
        }

    def validate_hierarchy(self) -> List[Dict[str, Any]]:
        """Validate entire group hierarchy"""
        issues = []
        try:
            fm_groups = self.firemon.get_device_groups()
            group_map = {g['id']: g for g in fm_groups}
            
            for group in fm_groups:
                # Skip root groups
                if not group.get('parentId'):
                    continue
                    
                parent = group_map.get(group['parentId'])
                if not parent:
                    issues.append({
                        'type': 'missing_parent',
                        'group': group['name'],
                        'group_id': group['id'],
                        'parent_id': group['parentId'],
                        'severity': 'error'
                    })
                    continue
                    
                # Check for circular references
                visited = set()
                current = group
                while current.get('parentId'):
                    if current['id'] in visited:
                        issues.append({
                            'type': 'circular_reference',
                            'group': group['name'],
                            'path': [g['name'] for g in visited],
                            'severity': 'error'
                        })
                        break
                        
                    visited.add(current['id'])
                    current = group_map.get(current['parentId'])
                    if not current:
                        break
                        
        except Exception as e:
            logging.error(f"Error validating hierarchy: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'error': str(e),
                'severity': 'error'
            })
            
        return issues