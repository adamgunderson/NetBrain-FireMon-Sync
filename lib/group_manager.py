# lib/group_manager.py

import logging
from typing import Dict, List, Any, Optional
from collections import defaultdict

class GroupHierarchyManager:
    def __init__(self, firemon_client):
        self.firemon = firemon_client
        self.group_cache = {}
        self.hierarchy_cache = defaultdict(list)

    def build_group_hierarchy(self, sites: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build complete group hierarchy from sites"""
        hierarchy = {}
        
        # First pass: Create all nodes
        for site in sites:
            path_parts = site['sitePath'].split('/')
            current_path = ''
            
            for part in path_parts:
                if current_path:
                    current_path += '/'
                current_path += part
                
                if current_path not in hierarchy:
                    hierarchy[current_path] = {
                        'name': part,
                        'full_path': current_path,
                        'children': [],
                        'parent': '/'.join(current_path.split('/')[:-1]),
                        'site_id': site['siteId'] if current_path == site['sitePath'] else None,
                        'level': len(current_path.split('/'))
                    }
        
        # Second pass: Build relationships
        for path, node in hierarchy.items():
            if node['parent'] in hierarchy:
                hierarchy[node['parent']]['children'].append(path)
        
        return hierarchy

    def sync_group_hierarchy(self, hierarchy: Dict[str, Any], dry_run: bool = False) -> List[Dict[str, Any]]:
        """Synchronize group hierarchy to FireMon"""
        changes = []
        processed_groups = set()

        try:
            # Get existing FireMon groups
            fm_groups = {g['name']: g for g in self.firemon.get_device_groups()}
            
            # Process hierarchy level by level
            for level in range(1, max(node['level'] for node in hierarchy.values()) + 1):
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

            # Remove orphaned groups if not in dry run
            if not dry_run:
                orphaned_groups = set(fm_groups.keys()) - processed_groups
                for group_name in orphaned_groups:
                    try:
                        group = fm_groups[group_name]
                        # Only remove if it's not a system group
                        if not group.get('system', False):
                            self.firemon.delete_device_group(group['id'])
                            changes.append({
                                'action': 'delete',
                                'group': group_name,
                                'status': 'success'
                            })
                    except Exception as e:
                        changes.append({
                            'action': 'error',
                            'group': group_name,
                            'error': str(e),
                            'status': 'error'
                        })

        except Exception as e:
            logging.error(f"Error syncing group hierarchy: {str(e)}")
            raise

        return changes

    def _process_group_node(self, node: Dict[str, Any], fm_groups: Dict[str, Any],
                          hierarchy: Dict[str, Any], dry_run: bool) -> Optional[Dict[str, Any]]:
        """Process individual group node"""
        group_name = node['name']
        existing_group = fm_groups.get(group_name)
        parent_id = None

        # Get parent group ID if parent exists
        if node['parent']:
            parent_name = hierarchy[node['parent']]['name']
            parent_group = fm_groups.get(parent_name)
            if parent_group:
                parent_id = parent_group['id']

        try:
            if not existing_group:
                # Create new group
                if not dry_run:
                    group_data = {
                        'name': group_name,
                        'description': f'NetBrain site: {node["full_path"]}',
                        'parentId': parent_id,
                        'domainId': self.firemon.domain_id
                    }
                    new_group = self.firemon.create_device_group(group_data)
                    return {
                        'action': 'create',
                        'group': group_name,
                        'path': node['full_path'],
                        'parent_id': parent_id,
                        'status': 'success',
                        'group_id': new_group['id']
                    }
                else:
                    return {
                        'action': 'create',
                        'group': group_name,
                        'path': node['full_path'],
                        'parent_id': parent_id,
                        'status': 'dry_run'
                    }
            else:
                # Update existing group if needed
                updates_needed = []
                
                if existing_group.get('parentId') != parent_id:
                    updates_needed.append('parent')
                
                if existing_group.get('description') != f'NetBrain site: {node["full_path"]}':
                    updates_needed.append('description')

                if updates_needed and not dry_run:
                    existing_group['parentId'] = parent_id
                    existing_group['description'] = f'NetBrain site: {node["full_path"]}'
                    self.firemon.update_device_group(existing_group['id'], existing_group)
                    return {
                        'action': 'update',
                        'group': group_name,
                        'path': node['full_path'],
                        'updates': updates_needed,
                        'status': 'success',
                        'group_id': existing_group['id']
                    }
                elif updates_needed:
                    return {
                        'action': 'update',
                        'group': group_name,
                        'path': node['full_path'],
                        'updates': updates_needed,
                        'status': 'dry_run'
                    }

        except Exception as e:
            logging.error(f"Error processing group {group_name}: {str(e)}")
            raise

        return None

    def sync_device_group_membership(self, device_id: int, site_path: str, 
                                   dry_run: bool = False) -> List[Dict[str, Any]]:
        """Sync device group membership based on site path"""
        changes = []
        try:
            # Get current device group memberships
            current_groups = self.firemon.get_device_groups(device_id)
            current_group_ids = {g['id'] for g in current_groups}
            
            # Get target groups based on site path
            target_groups = set()
            path_parts = site_path.split('/')
            current_path = ''
            
            for part in path_parts:
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
                            'error': str(e),
                            'status': 'error'
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
                            'error': str(e),
                            'status': 'error'
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

        except Exception as e:
            logging.error(f"Error syncing device group membership: {str(e)}")
            raise

        return changes

    def get_group_hierarchy_summary(self) -> Dict[str, Any]:
        """Get summary of current group hierarchy"""
        try:
            groups = self.firemon.get_device_groups()
            return {
                'total_groups': len(groups),
                'root_groups': len([g for g in groups if not g.get('parentId')]),
                'leaf_groups': len([g for g in groups 
                                  if not any(ch['parentId'] == g['id'] for ch in groups)]),
                'max_depth': self._calculate_max_depth(groups),
                'groups_by_level': self._count_groups_by_level(groups)
            }
        except Exception as e:
            logging.error(f"Error getting group hierarchy summary: {str(e)}")
            raise

    def _calculate_max_depth(self, groups: List[Dict[str, Any]]) -> int:
        """Calculate maximum depth of group hierarchy"""
        def get_depth(group_id: int, cache: Dict[int, int] = None) -> int:
            if cache is None:
                cache = {}
            
            if group_id in cache:
                return cache[group_id]
            
            group = next((g for g in groups if g['id'] == group_id), None)
            if not group or not group.get('parentId'):
                return 1
            
            parent_depth = get_depth(group['parentId'], cache)
            depth = parent_depth + 1
            cache[group_id] = depth
            return depth

        max_depth = 0
        depth_cache = {}
        for group in groups:
            depth = get_depth(group['id'], depth_cache)
            max_depth = max(max_depth, depth)
        
        return max_depth

    def _count_groups_by_level(self, groups: List[Dict[str, Any]]) -> Dict[int, int]:
        """Count number of groups at each level"""
        level_counts = defaultdict(int)
        depth_cache = {}

        for group in groups:
            depth = self._calculate_max_depth([group]) 
            level_counts[depth] += 1

        return dict(level_counts)