"""Filter engine for LogLens.

This module provides the FilterEngine class, which accepts a stream or list
of LogEntry objects (NginxAccessEntry or SyslogEntry) and filters them
according to a typed FilterCriteria configuration.
"""

from collections.abc import Iterable
from datetime import datetime, timezone
import re

from loglens.models import FilterCriteria, LogEntry, NginxAccessEntry, SyslogEntry


def _normalize_datetime(dt: datetime) -> datetime:
    """Normalize a datetime to timezone-naive UTC representation.

    This ensures safe comparisons between timezone-aware timestamps (Nginx)
    and timezone-naive timestamps (Syslog) without triggering Python's
    'can't compare offset-naive and offset-aware datetimes' TypeError.
    """
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


class FilterEngine:
    """Engine responsible for filtering LogEntry objects against FilterCriteria."""

    def matches(self, entry: LogEntry, criteria: FilterCriteria) -> bool:
        """Check whether a single LogEntry satisfies all specified criteria.

        Uses Boolean AND logic: if any specified criterion fails, returns False.
        Criteria set to None are ignored.

        Args:
            entry: A parsed NginxAccessEntry or SyslogEntry.
            criteria: The FilterCriteria configuration to check against.

        Returns:
            True if the entry satisfies all active criteria; False otherwise.
        """
        # 1. Minimum HTTP status code (Nginx only)
        if criteria.min_status is not None:
            if not isinstance(entry, NginxAccessEntry):
                return False
            if entry.status_code < criteria.min_status:
                return False

        # 2. Maximum HTTP status code (Nginx only)
        if criteria.max_status is not None:
            if not isinstance(entry, NginxAccessEntry):
                return False
            if entry.status_code > criteria.max_status:
                return False

        # 3. Start time (inclusive)
        if criteria.start_time is not None:
            if _normalize_datetime(entry.timestamp) < _normalize_datetime(criteria.start_time):
                return False

        # 4. End time (inclusive)
        if criteria.end_time is not None:
            if _normalize_datetime(entry.timestamp) > _normalize_datetime(criteria.end_time):
                return False

        # 5. IP Address match
        if criteria.ip is not None:
            if isinstance(entry, NginxAccessEntry):
                if entry.ip != criteria.ip:
                    return False
            elif isinstance(entry, SyslogEntry):
                # For syslog, match if IP appears anywhere in the message or raw line
                if criteria.ip not in entry.message and criteria.ip not in entry.raw_line:
                    return False

        # 6. Request Path Pattern (Nginx only)
        if criteria.path_pattern is not None:
            if not isinstance(entry, NginxAccessEntry):
                return False
            if not re.search(criteria.path_pattern, entry.path):
                return False

        # 7. Service Name (Syslog only)
        if criteria.service is not None:
            if not isinstance(entry, SyslogEntry):
                return False
            if entry.service != criteria.service:
                return False

        # 8. Message / Payload Pattern (Regex, case-insensitive)
        if criteria.message_pattern is not None:
            target = entry.message if isinstance(entry, SyslogEntry) else entry.raw_line
            if not re.search(criteria.message_pattern, target, re.IGNORECASE):
                return False

        return True

    def filter(self, entries: Iterable[LogEntry], criteria: FilterCriteria) -> list[LogEntry]:
        """Filter a collection of log entries, returning only matching entries.

        Args:
            entries: An iterable collection of NginxAccessEntry or SyslogEntry objects.
            criteria: FilterCriteria specifying active filter rules.

        Returns:
            A new list containing only entries that matched all active criteria.
        """
        return [entry for entry in entries if self.matches(entry, criteria)]

