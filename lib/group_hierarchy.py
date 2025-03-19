# lib/group_hierarchy.py
"""
Consolidated Group Hierarchy Manager for NetBrain to FireMon synchronization

This module handles the creation and management of device group hierarchies for syncing 
between NetBrain and FireMon systems. It combines functionality from both previous
implementations and fixes various issues.

Key features:
- Builds and maintains group hierarchy from NetBrain sites
- Creates FireMon device groups based on NetBrain site structure
- Manages group memberships for devices
- Respects existing FireMon group structures
- Handles parent-child relationships
- Provides validation and reporting functions
"""

import logging
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
from datetime import datetime
import concurrent.futures
import os

@dataclass
class GroupNode:
    """Represents a node in the group hierarchy"""
    id: Optional[int]          # FireMon group ID
    name: str                  # Group name
    path: str                  # Full path including ancestors
    parent_path: Optional[str] # Path of parent group
    children: Set[str]         # Set of child path strings
    site_id: Optional[str]     # NetBrain site ID
    level: int                 # Hierarchy level (1-based)
    description: Optional[str] = None  # Group description

class GroupHierarchyManager:
    """
    Manages device group hierarchies between NetBrain and FireMon
    Consolidated implementation that merges functionality from both previous versions
    """
    
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
        
        # Configuration options
        self.preserve_existing_parents = os.getenv('PRESERVE_EXISTING_PARENTS', 'true').lower() == 'true'
        self.max_workers = int(os.getenv('GROUP_SYNC_MAX_WORKERS', '10'))
        
        # Create lock for threaded operations
        self._cache_lock = None
        self._changes_lock = None
        try:
            from threading import Lock
            self._cache_lock = Lock()
            self._changes_lock = Lock()
        except ImportError:
            logging.warning("Threading module not available - thread safety disabled")

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
                    site_path = site.get('sitePath')
                    site_id = site.get('siteId')
                    
                    if not site_path:
                        logging.warning(f"Skipping site with missing path: {site}")
                        continue
                        
                    self._create_path_nodes(site_path, site_id, hierarchy)
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
                hierarchy[node_path] = GroupNode(
                    id=None,
                    name=part,
                    path=node_path,
                    parent_path=effective_parent_path,
                    children=set(),
                    site_id=site_id if node_path == path else None,
                    level=level,
                    description=f"NetBrain site: {node_path}"
                )
                logging.debug(f"Created node: {part} (level {level})")
                
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
                            if not self.preserve_existing_parents:
                                issues.append(f"Incorrect parent group for {path}")
                            else:
                                logging.info(f"Preserving existing parent for group {node.name} (configured to respect existing structure)")
                            
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

    def sync_group_hierarchy(self, hierarchy: Dict[str, Any], dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Synchronize entire group hierarchy to FireMon based on hierarchy dictionary
        
        Args:
            hierarchy: Group hierarchy dictionary (output from build_group_hierarchy)
            dry_run: If True, only simulate changes
            
        Returns:
            List of changes made or that would be made
        """
        changes = []
        processed_groups = set()

        try:
            # Get existing FireMon groups
            fm_groups = {g['name']: g for g in self.firemon.get_device_groups()}
            
            # Process hierarchy level by level
            for level in range(1, max(node['level'] for path, node in hierarchy.items()) + 1):
                level_nodes = {path: node for path, node in hierarchy.items() 
                             if node['level'] == level}
                
                for path, node in level_nodes.items():
                    try:
                        change = self._process_group_node(node, fm_groups, hierarchy, dry_run)
                        if change:
                            changes.append(change)
                            processed_groups.add(node['name'])
                    
                    except Exception as e:
                        changes.append({
                            'action': 'error',
                            'group': node['name'],
                            'path': path,
                            'error': str(e),
                            'status': 'error'
                        })
                        logging.error(f"Error processing group {node['name']}: {str(e)}")

            # Find orphaned groups
            orphaned_changes = self.handle_orphaned_groups(processed_groups, dry_run)
            changes.extend(orphaned_changes)

        except Exception as e:
            logging.error(f"Error syncing group hierarchy: {str(e)}")
            raise

        return changes

    def sync_site_hierarchy(self, site: Dict[str, Any], dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Synchronize a single site's hierarchy to FireMon
        
        Args:
            site: NetBrain site dictionary
            dry_run: If True, only simulate changes
            
        Returns:
            List of changes made or that would be made
        """
        changes = []
        try:
            site_path = site.get('sitePath')
            if not site_path:
                logging.warning(f"Skipping site with missing path: {site}")
                return changes
                
            # Extract site components
            path_parts = site_path.split('/')
            if not path_parts or path_parts[0] != self.ROOT_GROUP:
                logging.warning(f"Invalid site path format: {site_path}")
                return changes
                
            # Process each level of the site path
            current_path = ""
            parent_id = None
            
            for i, part in enumerate(path_parts):
                if i == 0 and part == self.ROOT_GROUP:  # Skip root group
                    continue
                    
                if current_path:
                    current_path += '/'
                current_path += part
                
                # Check if group exists
                fm_group = self.firemon.find_group_by_path(current_path)
                
                if not fm_group and not dry_run:
                    # Create new group
                    group_data = {
                        'name': part,
                        'description': f'NetBrain site: {current_path}',
                        'parentId': parent_id,
                        'domainId': self.firemon.domain_id
                    }
                    
                    try:
                        new_group = self.firemon.create_device_group(group_data)
                        changes.append({
                            'action': 'create',
                            'group': part,
                            'path': current_path,
                            'parent_id': parent_id,
                            'status': 'success',
                            'group_id': new_group['id']
                        })
                        parent_id = new_group['id']
                        
                        # Update cache
                        if hasattr(self, '_cache_lock') and self._cache_lock:
                            with self._cache_lock:
                                self.group_cache[part] = new_group
                                self.path_cache[current_path] = new_group['id']
                        else:
                            self.group_cache[part] = new_group
                            self.path_cache[current_path] = new_group['id']
                            
                    except Exception as e:
                        changes.append({
                            'action': 'error',
                            'group': part,
                            'path': current_path,
                            'error': str(e),
                            'status': 'error'
                        })
                        break
                        
                elif not fm_group and dry_run:
                    changes.append({
                        'action': 'create',
                        'group': part,
                        'path': current_path,
                        'parent_id': parent_id,
                        'status': 'dry_run'
                    })
                    # Skip setting parent_id in dry run mode as we don't have the new ID
                    
                else:
                    # Group exists
                    parent_id = fm_group['id']
                    
                    # Check if we should update the group
                    updates_needed = []
                    
                    # Check description
                    expected_description = f'NetBrain site: {current_path}'
                    if fm_group.get('description') != expected_description:
                        updates_needed.append('description')
                        
                    # Check parent relationship if we should update it
                    expected_parent_id = parent_id if i == 1 else None  # First level should have no parent
                    if not self.preserve_existing_parents and fm_group.get('parentId') != expected_parent_id:
                        updates_needed.append('parent')
                        
                    # Update group if needed
                    if updates_needed and not dry_run:
                        try:
                            update_data = {
                                'id': fm_group['id'],
                                'name': fm_group['name'],
                                'domainId': self.firemon.domain_id,
                                'description': expected_description
                            }
                            
                            if not self.preserve_existing_parents:
                                update_data['parentId'] = expected_parent_id
                                
                            self.firemon.update_device_group(fm_group['id'], update_data)
                            changes.append({
                                'action': 'update',
                                'group': part,
                                'path': current_path,
                                'updates': updates_needed,
                                'status': 'success'
                            })
                            
                        except Exception as e:
                            changes.append({
                                'action': 'error',
                                'group': part,
                                'error': str(e),
                                'status': 'error'
                            })
                    elif updates_needed and dry_run:
                        changes.append({
                            'action': 'update',
                            'group': part,
                            'path': current_path,
                            'updates': updates_needed,
                            'status': 'dry_run'
                        })
            
            return changes
            
        except Exception as e:
            logging.error(f"Error syncing site hierarchy for {site.get('sitePath', 'UNKNOWN')}: {str(e)}")
            if hasattr(self, '_changes_lock') and self._changes_lock:
                with self._changes_lock:
                    self.changes.append({
                        'site': site.get('sitePath', 'UNKNOWN'),
                        'action': 'error',
                        'error': str(e)
                    })
            else:
                self.changes.append({
                    'site': site.get('sitePath', 'UNKNOWN'),
                    'action': 'error',
                    'error': str(e)
                })
            return changes

    def sync_device_group_membership(self, device_id: int, site_path: str, dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Sync device group membership based on site path
        Modified to only add devices to the most specific (leaf) group in the path
        
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
            
            # Extract only the leaf group (last part of the path)
            path_parts = site_path.split('/')
            if len(path_parts) <= 1:
                logging.warning(f"Invalid site path format for device {device_id}: {site_path}")
                return changes
            
            # Find the full path to the leaf group
            full_leaf_path = '/'.join(path_parts)
            leaf_group_name = path_parts[-1]
            
            logging.debug(f"Looking for leaf group '{leaf_group_name}' (path: {full_leaf_path}) for device {device_id}")
            
            # Try to find the group by path
            leaf_group = self.firemon.find_group_by_path(full_leaf_path) 
            
            # If not found, try direct lookup by name as fallback
            if not leaf_group:
                fm_groups = self.firemon.get_device_groups()
                leaf_group = next((g for g in fm_groups if g['name'] == leaf_group_name), None)
            
            if not leaf_group:
                logging.warning(f"Leaf group '{leaf_group_name}' not found for device {device_id}")
                return changes
            
            # Check if device is already in this group
            if leaf_group['id'] in current_group_ids:
                logging.debug(f"Device {device_id} is already in leaf group '{leaf_group_name}'")
                return changes
            
            if not dry_run:
                # Add device to the leaf group
                try:
                    self.firemon.add_device_to_group(leaf_group['id'], device_id)
                    changes.append({
                        'action': 'add_to_group',
                        'group_id': leaf_group['id'],
                        'group_name': leaf_group_name,
                        'device_id': device_id,
                        'status': 'success'
                    })
                    logging.info(f"Added device {device_id} to leaf group '{leaf_group_name}'")
                except Exception as e:
                    changes.append({
                        'action': 'error',
                        'group_id': leaf_group['id'],
                        'group_name': leaf_group_name,
                        'device_id': device_id,
                        'error': str(e),
                        'status': 'error'
                    })
                    logging.error(f"Error adding device {device_id} to group '{leaf_group_name}': {str(e)}")
            else:
                # Record planned changes for dry run
                changes.append({
                    'action': 'add_to_group',
                    'group_id': leaf_group['id'],
                    'group_name': leaf_group_name,
                    'device_id': device_id,
                    'status': 'dry_run'
                })
                logging.info(f"Would add device {device_id} to leaf group '{leaf_group_name}' (dry run)")

            return changes
            
        except Exception as e:
            logging.error(f"Error syncing device {device_id} group membership: {str(e)}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception("Detailed error trace:")
            changes.append({
                'action': 'error',
                'device_id': device_id,
                'error': str(e),
                'status': 'error'
            })
            return changes
    def handle_orphaned_groups(self, processed_groups: Set[str], dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Log groups that exist in FireMon but not in NetBrain
        Groups are no longer deleted per customer requirement to preserve manually created groups
        
        Args:
            processed_groups: Set of group names that should be kept
            dry_run: If True, only report changes without making them
            
        Returns:
            List of detected orphaned groups
        """
        changes = []
        try:
            fm_groups = self.firemon.get_device_groups()
            orphaned_count = 0
            
            for group in fm_groups:
                if group['name'] not in processed_groups:
                    # Skip system groups and root groups
                    if group.get('system', False) or not group.get('parentId'):
                        continue
                    
                    # Log orphaned group without deleting it
                    orphaned_count += 1
                    logging.info(f"Detected orphaned group in FireMon: {group['name']} (ID: {group['id']})")
                    changes.append({
                        'action': 'orphaned',
                        'group': group['name'],
                        'id': group['id'],
                        'status': 'kept'
                    })
            
            if orphaned_count > 0:
                logging.info(f"Found {orphaned_count} orphaned groups in FireMon that will be preserved")
                    
        except Exception as e:
            logging.error(f"Error handling orphaned groups: {str(e)}")
            
        return changes

    def sync_groups_parallel(self, sites: List[Dict[str, Any]], dry_run: bool = False) -> List[Dict[str, Any]]:
        """
        Process group hierarchy in parallel for multiple sites
        
        Args:
            sites: List of NetBrain site dictionaries
            dry_run: If True, only simulate changes
            
        Returns:
            List of changes made or that would be made
        """
        all_changes = []
        
        if dry_run:
            logging.info("Running group sync in dry run mode - no changes will be made")
        
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_site = {executor.submit(self.sync_site_hierarchy, site, dry_run): site 
                                for site in sites}
                
                for future in concurrent.futures.as_completed(future_to_site):
                    site = future_to_site[future]
                    try:
                        changes = future.result()
                        all_changes.extend(changes)
                    except Exception as e:
                        logging.error(f"Error processing site {site.get('sitePath', 'UNKNOWN')}: {str(e)}")
                        all_changes.append({
                            'site': site.get('sitePath', 'UNKNOWN'),
                            'action': 'error',
                            'error': str(e)
                        })
            
            # Handle orphaned groups after all sites are processed
            processed_groups = {change['group'] for change in all_changes 
                              if 'group' in change and change.get('action') in ['create', 'update']}
            
            orphaned_changes = self.handle_orphaned_groups(processed_groups, dry_run)
            all_changes.extend(orphaned_changes)
            
            return all_changes
            
        except Exception as e:
            logging.error(f"Error in parallel group sync: {str(e)}")
            raise

    def _process_group_node(self, node: Dict[str, Any], fm_groups: Dict[str, Any],
                          hierarchy: Dict[str, Any], dry_run: bool) -> Optional[Dict[str, Any]]:
        """Process individual group node during hierarchy sync"""
        group_name = node.get('name')
        if not group_name:
            logging.error(f"Missing group name in node: {node}")
            return None
            
        existing_group = fm_groups.get(group_name)
        parent_id = None

        # Get parent group ID if parent exists
        if node.get('parent_path'):
            parent_name = hierarchy[node['parent_path']]['name']
            parent_group = fm_groups.get(parent_name)
            if parent_group:
                parent_id = parent_group['id']

        try:
            if not existing_group:
                # Create new group
                if not dry_run:
                    group_data = {
                        'name': group_name,
                        'description': node.get('description', f'NetBrain site: {node["path"]}'),
                        'parentId': parent_id,
                        'domainId': self.firemon.domain_id
                    }
                    new_group = self.firemon.create_device_group(group_data)
                    return {
                        'action': 'create',
                        'group': group_name,
                        'path': node['path'],
                        'parent_id': parent_id,
                        'status': 'success',
                        'group_id': new_group['id']
                    }
                else:
                    return {
                        'action': 'create',
                        'group': group_name,
                        'path': node['path'],
                        'parent_id': parent_id,
                        'status': 'dry_run'
                    }
            else:
                # Update existing group if needed
                updates_needed = []
                
                # Check description
                expected_description = node.get('description', f'NetBrain site: {node["path"]}')
                if existing_group.get('description') != expected_description:
                    updates_needed.append('description')
                
                # Check parent relationship if we should update it
                if not self.preserve_existing_parents and existing_group.get('parentId') != parent_id:
                    updates_needed.append('parent')

                if updates_needed and not dry_run:
                    update_data = dict(existing_group)  # Copy to avoid modifying original
                    update_data['description'] = expected_description
                    
                    if not self.preserve_existing_parents:
                        update_data['parentId'] = parent_id
                        
                    self.firemon.update_device_group(existing_group['id'], update_data)
                    return {
                        'action': 'update',
                        'group': group_name,
                        'path': node['path'],
                        'updates': updates_needed,
                        'status': 'success',
                        'group_id': existing_group['id']
                    }
                elif updates_needed:
                    return {
                        'action': 'update',
                        'group': group_name,
                        'path': node['path'],
                        'updates': updates_needed,
                        'status': 'dry_run'
                    }

        except Exception as e:
            logging.error(f"Error processing group {group_name}: {str(e)}")
            raise

        return None

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
            
            # Check path cache first
            if path in self.path_cache:
                group_id = self.path_cache[path]
                group = next((g for g in self.firemon.get_device_groups() 
                           if g['id'] == group_id), None)
                return group
            
            # Get group by name (last part of path)
            group_name = path.split('/')[-1]
            if group_name in self.group_cache:
                return self.group_cache[group_name]
                
            # Search by path as a last resort
            return self.firemon.find_group_by_path(path)
            
        except Exception as e:
            logging.error(f"Error getting group by path {path}: {str(e)}")
            return None

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
            'changes': len(self.changes),
            'preserve_existing_parents': self.preserve_existing_parents
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
                        
        except Exception as e:
            logging.error(f"Error validating group memberships: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'error': str(e),
                'severity': 'error'
            })
            
        return issues

    def validate_hierarchy(self) -> List[Dict[str, Any]]:
        """
        Validate the group hierarchy structure
        
        Returns:
            List of issues found
        """
        logging.debug("Starting group hierarchy validation")
        issues = []
        
        try:
            # Get all FireMon device groups
            fm_groups = self.firemon.get_device_groups()
            logging.debug(f"Retrieved {len(fm_groups)} device groups from FireMon")
            
            # Build group ID to group mapping for efficient lookups
            group_map = {g['id']: g for g in fm_groups}
            
            # Check each group's parent-child relationships
            for group in fm_groups:
                group_id = group['id']
                parent_id = group.get('parentId')
                
                logging.debug(f"Validating group: {group['name']} (ID: {group_id})")
                
                if parent_id:
                    parent = group_map.get(parent_id)
                    if not parent:
                        logging.warning(f"Group {group['name']} has invalid parent ID: {parent_id}")
                        issues.append({
                            'type': 'missing_parent',
                            'group_name': group['name'],
                            'group_id': group_id,
                            'parent_id': parent_id,
                            'severity': 'error'
                        })
                        
                # Check for circular references
                if parent_id:
                    visited = set()
                    current_id = parent_id
                    while current_id:
                        if current_id in visited:
                            logging.error(f"Circular reference detected for group {group['name']}")
                            issues.append({
                                'type': 'circular_reference',
                                'group_name': group['name'],
                                'group_id': group_id,
                                'severity': 'error'
                            })
                            break
                            
                        visited.add(current_id)
                        current = group_map.get(current_id)
                        current_id = current.get('parentId') if current else None
                        
        except Exception as e:
            logging.error(f"Error validating group hierarchy: {str(e)}")
            issues.append({
                'type': 'validation_error',
                'message': str(e),
                'severity': 'error'
            })
            
        logging.debug(f"Validation complete. Found {len(issues)} issues")
        return issues

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

    def clear_caches(self) -> None:
        """Clear internal caches"""
        if hasattr(self, '_cache_lock') and self._cache_lock:
            with self._cache_lock:
                self.group_cache.clear()
                self.path_cache.clear()
        else:
            self.group_cache.clear()
            self.path_cache.clear()
            
        self.last_sync = None
        self.changes = []
        logging.debug("Cleared group hierarchy caches")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.clear_caches()