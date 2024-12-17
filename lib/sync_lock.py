# lib/sync_lock.py

import os
import fcntl
import time
import logging
import threading
from typing import Optional
from contextlib import contextmanager
from datetime import datetime, timedelta

class SyncLockError(Exception):
    pass

class SyncLock:
    """Thread and process safe locking mechanism for sync operations"""
    
    def __init__(self, lock_file: str = '/tmp/netbrain_firemon_sync.lock',
                 lock_timeout: int = 3600):
        self.lock_file = lock_file
        self.lock_timeout = lock_timeout
        self.thread_lock = threading.Lock()
        self._fd = None
        self.lock_start_time = None
        
    @contextmanager
    def acquire(self, timeout: int = 30):
        """
        Acquire lock with timeout
        Raises SyncLockError if lock cannot be acquired
        """
        acquired = False
        try:
            # First acquire thread lock
            if not self.thread_lock.acquire(timeout=timeout):
                raise SyncLockError("Could not acquire thread lock")
                
            # Then acquire file lock
            try:
                acquired = self._acquire_file_lock(timeout)
                if not acquired:
                    raise SyncLockError("Could not acquire file lock")
                    
                self.lock_start_time = datetime.now()
                yield
                
            finally:
                if acquired:
                    self._release_file_lock()
                    
        finally:
            if self.thread_lock.locked():
                self.thread_lock.release()
                
    def _acquire_file_lock(self, timeout: int) -> bool:
        """Acquire file lock with timeout"""
        start_time = time.time()
        
        while True:
            try:
                self._fd = open(self.lock_file, 'w')
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                
                # Check if existing lock is stale
                if os.path.exists(self.lock_file):
                    try:
                        lock_time = datetime.fromtimestamp(os.path.getmtime(self.lock_file))
                        if datetime.now() - lock_time > timedelta(seconds=self.lock_timeout):
                            logging.warning("Found stale lock file, removing")
                            self._release_file_lock()
                            continue
                    except Exception as e:
                        logging.error(f"Error checking lock file time: {str(e)}")
                
                # Write PID to lock file
                self._fd.write(f"{os.getpid()}\n")
                self._fd.flush()
                return True
                
            except (IOError, OSError) as e:
                if time.time() - start_time >= timeout:
                    return False
                    
                time.sleep(1)
                continue
                
    def _release_file_lock(self):
        """Release file lock"""
        try:
            if self._fd:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
                self._fd.close()
                self._fd = None
                
            if os.path.exists(self.lock_file):
                os.unlink(self.lock_file)
                
        except Exception as e:
            logging.error(f"Error releasing file lock: {str(e)}")
            
    def is_locked(self) -> bool:
        """Check if sync is currently locked"""
        if not os.path.exists(self.lock_file):
            return False
            
        try:
            with open(self.lock_file, 'r') as f:
                try:
                    fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return False
                except (IOError, OSError):
                    return True
                    
        except Exception:
            return False
            
    def get_lock_info(self) -> Optional[dict]:
        """Get information about current lock"""
        if not self.is_locked():
            return None
            
        try:
            with open(self.lock_file, 'r') as f:
                pid = int(f.readline().strip())
                
            lock_time = datetime.fromtimestamp(os.path.getmtime(self.lock_file))
            duration = datetime.now() - lock_time
            
            return {
                'pid': pid,
                'start_time': lock_time.isoformat(),
                'duration_seconds': duration.total_seconds()
            }
            
        except Exception as e:
            logging.error(f"Error getting lock info: {str(e)}")
            return None
            
    def break_lock(self) -> bool:
        """Force break a lock - use with caution"""
        try:
            if os.path.exists(self.lock_file):
                os.unlink(self.lock_file)
            return True
        except Exception as e:
            logging.error(f"Error breaking lock: {str(e)}")
            return False