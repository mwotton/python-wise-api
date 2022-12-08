from datetime import datetime, timezone


def zulu_time(dt: datetime):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
