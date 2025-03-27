# lib/group_hierarchy.py

"""
Group Hierarchy Manager
Handles the creation and management of device group hierarchies for syncing 
between NetBrain and FireMon systems.

Key features:
- Builds group hierarchy from NetBrain sites
- Handles parent-child relationships
- Skips root "My Network" group
- Validates hierarchy structure
- Manages group cache and path mappings
- Handles device group membership sync
- Manages orphaned groups
- Tracks group changes
"""

import logging
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime

@dataclass
class GroupNode:
    """Represents a node in the group hierarchy"""
    id: Optional[int]          # FireMon group ID
    name: str                  # Group name
    path: str                  # Full path including ancestors
    parent_path: Optional[str] # Path of parent group
    children: Set[str]         # Set of child path strings
    site_id: Optional[str]     # NetBrain site ID
    level: int                # Hierarchy level (1-based)

class GroupHierarchyManager:
    """Manages device group hierarchies between NetBrain and FireMon"""
    
    def __init__(self, firemon_client):
        """
        Initialize the group hierarchy manager
        
        Args:
            firemon_client: Initialized FireMon API client
        """
        self.firemon = firemon_client
        self.group_cache = {}  # Cache of FireMon groups by name
        self.path_cache = {}   # Cache of FireMon group IDs by path
        self.ROOT_GROUP = "My Network"
        self.last_sync = None
        self.changes = []  # Track group changes

    def build_group_hierarchy(self, sites: List[Dict[str, Any]]) -> Dict[str, GroupNode]:
        """
        Build complete group hierarchy with validation, excluding the root group
        
        Args:
            sites: List of site dictionaries from NetBrain
            
        Returns:
            Dictionary mapping paths to GroupNode objects
            
        Raises:
            Exception: If hierarchy building fails
        """
        try:
            hierarchy = {}
            
            # First pass: Create all nodes
            for site in sites:
                try:
                    self._create_path_nodes(site['sitePath'], site['siteId'], hierarchy)
                except Exception as e:
                    logging.error(f"Error creating path nodes for site {site.get('sitePath', 'UNKNOWN')}: {str(e)}")
            
            # Second pass: Validate and fix hierarchy
            self._validate_and_fix_hierarchy(hierarchy)
            
            self.last_sync = datetime.utcnow()
            return hierarchy
            
        except Exception as e:
            logging.error(f"Error building group hierarchy: {str(e)}")
            raise

    def _create_path_nodes(self, path: str, site_id: str, hierarchy: Dict[str, GroupNode]) -> None:
        """
        Create all nodes in a path, skipping the root group
        Ensures groups are unique by path, not by site_id
        
        Args:
            path: Full site path (e.g. "My Network/NA/DC1")
            site_id: NetBrain site ID
            hierarchy: Dictionary to store created nodes
            
        Raises:
            ValueError: If path format is invalid
        """
        parts = path.split('/')
        
        # Validate path
        if not parts or parts[0] != self.ROOT_GROUP:
            raise ValueError(f"Invalid path format, must start with '{self.ROOT_GROUP}': {path}")
            
        # Skip the root group
        parts = parts[1:]
        if not parts:  # Nothing left after skipping root
            return
            
        current_path = self.ROOT_GROUP  # Keep track of full path for reference
        parent_path = None
        level = 0
        
        for part in parts:
            # Update paths
            if current_path != self.ROOT_GROUP:
                parent_path = current_path
            current_path += '/' + part
            level += 1
            
            # Skip empty parts and root group
            if not part:
                continue
                
            node_path = current_path
            # For first level under root, parent will be None
            effective_parent_path = None if parent_path == self.ROOT_GROUP else parent_path
            
            # Create node if it doesn't exist
            if node_path not in hierarchy:
                # New node creation
                hierarchy[node_path] = GroupNode(
                    id=None,
                    name=part,
                    path=node_path,
                    parent_path=effective_parent_path,
                    children=set(),
                    site_id=site_id if node_path == path else None,
                    level=level
                )
                logging.debug(f"Created node: {part} (level {level})")
            elif node_path == path:
                # Node exists but this is the target path for this site_id
                # Update site_id only if this is the terminal node for this site
                # This is the key fix - we don't create a new node, but we do
                # update the site_id if this exact path corresponds to a site
                hierarchy[node_path].site_id = site_id
                logging.debug(f"Updated existing node {part} with site_id {site_id}")
                
            # Update parent's children set if parent exists
            if effective_parent_path and effective_parent_path in hierarchy:
                try:
                    parent = hierarchy[effective_parent_path]
                    parent.children.add(node_path)
                    logging.debug(f"Added {node_path} as child of {effective_parent_path}")
                except Exception as e:
                    logging.error(f"Error updating parent node for {node_path}: {str(e)}")
                    raise

    def _validate_and_fix_hierarchy(self, hierarchy: Dict[str, GroupNode]) -> None:
        """
        Validate hierarchy and fix any issues
        
        Args:
            hierarchy: Dictionary of path to GroupNode mappings
            
        Raises:
            Exception: If validation fails
        """
        try:
            # Get existing FireMon groups
            fm_groups = {g['name']: g for g in self.firemon.get_device_groups()}
            self.group_cache.update(fm_groups)
            
            # Map paths to FireMon group IDs
            for path, node in hierarchy.items():
                if node.name in fm_groups:
                    node.id = fm_groups[node.name]['id']
                    self.path_cache[path] = node.id
                    logging.debug(f"Mapped {node.name} to FireMon ID {node.id}")
                
            # Check for circular references
            self._check_circular_references(hierarchy)
            
            # Validate parent-child relationships
            issues = []
            for path, node in hierarchy.items():
                if node.parent_path:  # Only check if node has a parent
                    parent_node = hierarchy.get(node.parent_path)
                    if not parent_node:
                        # Don't report as issue if parent is root group
                        if node.parent_path != self.ROOT_GROUP:
                            issues.append(f"Missing parent node for {path}")
                        continue
                        
                    if parent_node.id is None:
                        # Don't report as issue if parent is root group
                        if node.parent_path != self.ROOT_GROUP:
                            issues.append(f"Parent group not found in FireMon for {path}")
                        continue
                        
                    # Check if current node exists in FireMon
                    if node.id is not None:
                        fm_group = fm_groups.get(node.name)
                        if fm_group and fm_group.get('parentId') != parent_node.id:
                            issues.append(f"Incorrect parent group for {path}")
                            
            if issues:
                logging.warning(f"Hierarchy validation issues found: {issues}")
                
        except Exception as e:
            logging.error(f"Error validating hierarchy: {str(e)}")
            raise

    def _check_circular_references(self, hierarchy: Dict[str, GroupNode]) -> None:
        """Check for circular references in the hierarchy"""
        visited = set()
        path = []
        
        def visit(node_path: str):
            if node_path in path:
                cycle = path[path.index(node_path):] + [node_path]
                raise ValueError(f"Circular reference detected: {' -> '.join(cycle)}")
                
            if node_path in visited:
                return
                
            visited.add(node_path)
            path.append(node_path)
            
            node = hierarchy.get(node_path)
            if node:
                for child in node.children:
                    visit(child)
                    
            path.pop()
            
        for node_path in hierarchy:
            visit(node_path)

    def sync_device_group_membership(self, device_id: int, site_path: str, dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Sync device group membership based on site path
        
        Args:
            device_id: FireMon device ID
            site_path: NetBrain site path
            dry_run: If True, only report changes without making them
            
        Returns:
            List of changes made or that would be made
        """
        changes = []
        try:
            # Get current device group memberships
            current_groups = self.firemon.get_device_groups(device_id)
            current_group_ids = {g['id'] for g in current_groups}
            
            # Get target groups based on site path
            target_groups = set()
            path_parts = site_path.split('/')
            current_path = ''
            
            for part in path_parts[1:]:  # Skip root group
                if current_path:
                    current_path += '/'
                current_path += part
                
                group = self.group_cache.get(current_path)
                if not group:
                    # Search for group and cache it
                    group = self.firemon.find_group_by_path(current_path)
                    if group:
                        self.group_cache[current_path] = group
                        target_groups.add(group['id'])

            # Calculate group changes
            groups_to_add = target_groups - current_group_ids
            groups_to_remove = current_group_ids - target_groups

            if not dry_run:
                # Add device to new groups
                for group_id in groups_to_add:
                    try:
                        self.firemon.add_device_to_group(group_id, device_id)
                        changes.append({
                            'action': 'add_to_group',
                            'group_id': group_id,
                            'device_id': device_id,
                            'status': 'success'
                        })
                    except Exception as e:
                        changes.append({
                            'action': 'error',
                            'group_id': group_id,
                            'device_id': device_id,
                            'error': str(e)
                        })

                # Remove device from old groups
                for group_id in groups_to_remove:
                    try:
                        self.firemon.remove_device_from_group(group_id, device_id)
                        changes.append({
                            'action': 'remove_from_group',
                            'group_id': group_id,
                            'device_id': device_id,
                            'status': 'success'
                        })
                    except Exception as e:
                        changes.append({
                            'action': 'error',
                            'group_id': group_id,
                            'device_id': device_id,
                            'error': str(e)
                        })
            else:
                # Record planned changes for dry run
                for group_id in groups_to_add:
                    changes.append({
                        'action': 'add_to_group',
                        'group_id': group_id,
                        'device_id': device_id,
                        'status': 'dry_run'
                    })
                
                for group_id in groups_to_remove:
                    changes.append({
                        'action': 'remove_from_group',
                        'group_id': group_id,
                        'device_id': device_id,
                        'status': 'dry_run'
                    })

            return changes
            
        except Exception as e:
            logging.error(f"Error syncing device {device_id} group membership: {str(e)}")
            raise

    def handle_orphaned_groups(self, processed_groups: Set[str], dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Handle groups that exist in FireMon but not in NetBrain
        
        Args:
            processed_groups: Set of group names that should be kept
            dry_run: If True, only report changes without making them
            
        Returns:
            List of changes made or that would be made
        """
        changes = []
        try:
            fm_groups = self.firemon.get_device_groups()
            
            for group in fm_groups:
                if group['name'] not in processed_groups:
                    # Skip system groups and root groups
                    if group.get('system', False) or not group.get('parentId'):
                        continue
                        
                    if not dry_run:
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
                    else:
                        changes.append({
                            'action': 'delete',
                            'group': group['name'],
                            'status': 'dry_run'
                        })
                        
        except Exception as e:
            logging.error(f"Error handling orphaned groups: {str(e)}")
            
        return changes

    def get_group_by_path(self, path: str) -> Optional[Dict[str, Any]]:
        """
        Get FireMon group by path
        
        Args:
            path: Full path to group
            
        Returns:
            FireMon group dictionary or None if not found
        """
        try:
            # Skip root group from path if present
            if path.startswith(f"{self.ROOT_GROUP}/"):
                path = path[len(self.ROOT_GROUP)+1:]
            
            # Get group by name (last part of path)
            group_name = path.split('/')[-1]
            return self.group_cache.get(group_name)
            
        except Exception as e:
            logging.error(f"Error getting group by path {path}: {str(e)}")
            return None

    def get_effective_parent_id(self, node: GroupNode, hierarchy: Dict[str, GroupNode]) -> Optional[int]:
        """
        Get effective parent ID for a node, handling root group special case
        
        Args:
            node: GroupNode to get parent for
            hierarchy: Current hierarchy dictionary
            
        Returns:
            FireMon parent group ID or None for top-level groups
        """
        if not node.parent_path or node.parent_path == self.ROOT_GROUP:
            return None
            
        parent_node = hierarchy.get(node.parent_path)
        return parent_node.id if parent_node else None

    def get_path_components(self, path: str) -> Tuple[List[str], bool]:
        """
        Split path into components and validate format
        
        Args:
            path: Path string to process
            
        Returns:
            Tuple of (path components, starts_with_root)
        """
        parts = path.split('/')
        starts_with_root = parts and parts[0] == self.ROOT_GROUP
        
        # Remove root group if present
        if starts_with_root:
            parts = parts[1:]
            
        return parts, starts_with_root

    def get_hierarchy_summary(self) -> Dict[str, Any]:
        """
        Get summary statistics about the current hierarchy
        
        Returns:
            Dictionary containing hierarchy statistics
        """
        return {
            'total_groups': len(self.group_cache),
            'mapped_paths': len(self.path_cache),
            'last_sync': self.last_sync.isoformat() if self.last_sync else None,
            'changes': len(self.changes)
        }

    def get_group_membership_changes(self, device_id: int, site_path: str) -> Dict[str, Set[int]]:
        """
        Calculate group membership changes needed
        
        Args:
            device_id: FireMon device ID
            site_path: NetBrain site path
            
        Returns:
            Dictionary with sets of group IDs to add and remove
        """
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
            
            if current_path == self.ROOT_GROUP:
                continue
                
            group_id = self.path_cache.get(current_path)
            if group_id:
                target_groups.add(group_id)
                
        return {
            'add': target_groups - current_groups,
            'remove': current_groups - target_groups
        }

    def validate_group_memberships(self) -> List[Dict[str, Any]]:
        """
        Validate all device group memberships
        
        Returns:
            List of validation issues found
        """
        issues = []
        try:
            # Get all FireMon devices
            devices = self.firemon.get_all_devices()
            
            for device in devices:
                device_groups = self.firemon.get_device_groups(device['id'])
                group_ids = {g['id'] for g in device_groups}
                
                # Check for orphaned group memberships
                for group in device_groups:
                    if group['id'] not in self.path_cache.values():
                        issues.append({
                            'type': 'orphaned_membership',
                            'device_id': device['id'],
                            'device_name': device['name'],
                            'group_id': group['id'],
                            'group_name': group['name'],
                            'severity': 'warning'
                        })
                        
                # Check for missing required groups
                if device.get('site'):
                    expected_changes = self.get_group_membership_changes(device['id'], device.get('site'))
                    if expected_changes['add']:
                        issues.append({
                            'type': 'missing_groups',
                            'device_id': device['id'],
                            'device_name': device['name'],
                            'missing_groups': list(expected_changes['add']),
                            'severity': 'error'
                        })
                        
        except Exception as e:
            logging.error(f"Error validating group memberships: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'error': str(e),
                'severity': 'error'
            })
            
        return issues

    def track_change(self, change: Dict[str, Any]) -> None:
        """
        Track a group-related change
        
        Args:
            change: Dictionary describing the change
        """
        change['timestamp'] = datetime.utcnow().isoformat()
        self.changes.append(change)

    def clear_caches(self) -> None:
        """Clear internal caches"""
        self.group_cache.clear()
        self.path_cache.clear()
        self.last_sync = None
        self.changes = []
        logging.debug("Cleared group hierarchy caches")

    def get_parent_chain(self, group_id: int) -> List[int]:
        """
        Get chain of parent group IDs
        
        Args:
            group_id: FireMon group ID
            
        Returns:
            List of parent group IDs from bottom to top
        """
        chain = []
        current_id = group_id
        
        while current_id:
            if current_id in chain:  # Prevent infinite loops
                logging.error(f"Circular reference detected in parent chain for group {group_id}")
                break
                
            chain.append(current_id)
            group = next((g for g in self.firemon.get_device_groups() if g['id'] == current_id), None)
            if not group:
                break
                
            current_id = group.get('parentId')
            
        return chain

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.clear_caches()