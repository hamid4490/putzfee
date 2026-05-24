"""Timezone-aware time helpers.

The business is operated from one country (Europe/Berlin by default).
All work-hours, slot generation, and "today" calculations happen in the
business timezone, while values are *stored* in UTC.
"""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Iterable, List, Tuple

from .config import get_settings


def utc_now() -> datetime:
    """Current UTC timestamp (timezone-aware)."""
    return datetime.now(timezone.utc)


def to_utc(dt: datetime) -> datetime:
    """Convert any datetime to UTC. Naive datetimes are assumed UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_local(dt: datetime) -> datetime:
    """Convert any datetime to the configured business timezone."""
    tz = get_settings().tz
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(tz)


def local_today() -> date:
    """Today's date in the business timezone."""
    return to_local(utc_now()).date()


def local_now() -> datetime:
    """Current time in the business timezone."""
    return to_local(utc_now())


def combine_local(d: date, hour: int, minute: int = 0) -> datetime:
    """Build an aware datetime in the business timezone."""
    tz = get_settings().tz
    return datetime.combine(d, time(hour=hour, minute=minute, tzinfo=tz))


def work_window_for_date(d: date) -> Tuple[datetime, datetime]:
    """Return (start_utc, end_utc) of the work window on date *d* in local TZ."""
    s = get_settings()
    start_local = combine_local(d, s.WORK_START_HOUR)
    end_local = combine_local(d, s.WORK_END_HOUR)
    return to_utc(start_local), to_utc(end_local)


def generate_slots_for_date(d: date) -> List[Tuple[datetime, datetime]]:
    """Generate all hourly slot windows for date *d* in UTC.

    Each tuple is ``(start_utc, end_utc)`` of length SLOT_DURATION_HOURS.
    """
    s = get_settings()
    slots: List[Tuple[datetime, datetime]] = []
    cur = combine_local(d, s.WORK_START_HOUR)
    end = combine_local(d, s.WORK_END_HOUR)
    duration = timedelta(hours=s.SLOT_DURATION_HOURS)
    while cur + duration <= end:
        nxt = cur + duration
        slots.append((to_utc(cur), to_utc(nxt)))
        cur = nxt
    return slots


def slots_in_range(
    start_local_date: date, days: int
) -> Iterable[Tuple[datetime, datetime]]:
    """Yield all hourly slots over *days* consecutive days starting at *start*."""
    for i in range(days):
        d = start_local_date + timedelta(days=i)
        yield from generate_slots_for_date(d)


def parse_iso_utc(value: str) -> datetime:
    """Parse an ISO-8601 string and normalise to UTC."""
    dt = datetime.fromisoformat(value)
    return to_utc(dt)


def isoformat_utc(dt: datetime) -> str:
    """Format a datetime as an ISO-8601 string in UTC with 'Z' suffix."""
    return to_utc(dt).strftime("%Y-%m-%dT%H:%M:%SZ")
