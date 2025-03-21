import time
from collections import defaultdict
from typing import Dict, Any

class RateLimiter:
    def __init__(self, rate_limit: int, window_seconds: int):
        """Initialize rate limiter with rate limit and time window"""
        self.rate_limit = rate_limit
        self.window_seconds = window_seconds
        self.packet_counts = defaultdict(lambda: {'count': 0, 'start_time': time.time()})

    def is_rate_limited(self, ip: str) -> bool:
        """Check if an IP has exceeded its rate limit"""
        current_time = time.time()
        if current_time - self.packet_counts[ip]['start_time'] > self.window_seconds:
            # Reset count and start time if the time window has passed
            self.packet_counts[ip] = {'count': 1, 'start_time': current_time}
        else:
            # Increment packet count within the current time window
            self.packet_counts[ip]['count'] += 1

        return self.packet_counts[ip]['count'] > self.rate_limit

    def get_packet_rate(self, ip: str) -> float:
        """Calculate the current packet rate for an IP"""
        current_time = time.time()
        time_diff = current_time - self.packet_counts[ip]['start_time']
        if time_diff > 0:
            return self.packet_counts[ip]['count'] / time_diff
        return 0.0

    def reset_counters(self):
        """Reset all packet counters"""
        self.packet_counts.clear() 