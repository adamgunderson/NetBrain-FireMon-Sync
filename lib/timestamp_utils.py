# lib/timestamp_utils.py

from datetime import datetime, timezone
from typing import Optional

class TimestampUtil:
    @staticmethod
    def standardize_timestamp(timestamp_str: str) -> datetime:
        """
        Convert timestamp string to UTC datetime object regardless of input format
        Handles common formats from NetBrain and FireMon
        """
        try:
            # Handle 'Z' UTC format from NetBrain
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str.replace('Z', '+00:00')
            
            # Parse ISO format with timezone
            try:
                dt = datetime.fromisoformat(timestamp_str)
            except ValueError:
                # Try parsing other common formats
                for fmt in [
                    "%Y-%m-%dT%H:%M:%S.%f%z",
                    "%Y-%m-%d %H:%M:%S.%f%z",
                    "%Y-%m-%d %H:%M:%S%z"
                ]:
                    try:
                        dt = datetime.strptime(timestamp_str, fmt)
                        break
                    except ValueError:
                        continue
                else:
                    raise ValueError(f"Unsupported timestamp format: {timestamp_str}")
            
            # Convert to UTC if timezone is present
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc)
            else:
                # Assume UTC if no timezone specified
                dt = dt.replace(tzinfo=timezone.utc)
            
            return dt
            
        except Exception as e:
            raise ValueError(f"Error parsing timestamp {timestamp_str}: {str(e)}")

    @staticmethod
    def compare_timestamps(ts1: str, ts2: str) -> int:
        """
        Compare two timestamps and return:
        -1 if ts1 < ts2
         0 if ts1 = ts2
         1 if ts1 > ts2
        """
        dt1 = TimestampUtil.standardize_timestamp(ts1)
        dt2 = TimestampUtil.standardize_timestamp(ts2)
        
        if dt1 < dt2:
            return -1
        elif dt1 > dt2:
            return 1
        return 0

    @staticmethod
    def is_newer_than(ts1: str, ts2: str) -> bool:
        """Check if ts1 is newer than ts2"""
        return TimestampUtil.compare_timestamps(ts1, ts2) > 0