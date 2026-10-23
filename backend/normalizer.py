import uuid
import json
import csv
import io
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple, Optional

# ─── Timestamp Normalization Engine ────────────────────────────────────────────
# Policy: 
#   - Automatically detect supported timestamp formats without user input.
#   - Normalize to ISO 8601 UTC (timezone-aware) as internal representation.
#   - Preserve original raw timestamp text in the event record.
#   - Never silently replace an unknown timestamp with the current time.
#   - Mark ambiguous or unparsable timestamps with a flag for analyst review.
#   - For timezone-naive timestamps, treat as UTC only when source is unknown,
#     and document this assumption in the event metadata.

# Regex patterns for common timestamp formats
_ISO8601_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?([+-]\d{2}:?\d{2}|Z)?$'
)
_EPOCH_RE = re.compile(r'^\d{10,13}(\.\d+)?$')
_SYSLOG_RE = re.compile(r'^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}')
_DATE_SLASH_RE = re.compile(r'^\d{1,2}/\d{1,2}/\d{4}')
_DATE_DASH_RE = re.compile(r'^\d{4}-\d{2}-\d{2}')

# Ordered list of unambiguous format patterns to try
_UNAMBIGUOUS_FORMATS = [
    # ISO 8601 variants
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y-%m-%d",
    # Syslog / Apache formats (no year)
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
    "%b %d %Y %H:%M:%S",
    # Apache CLF
    "%d/%b/%Y:%H:%M:%S",
    # YYYY/MM/DD variants
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S.%f",
    "%Y/%m/%d",
    # 12-hour time variants
    "%Y-%m-%d %I:%M:%S %p",
    "%Y-%m-%dT%I:%M:%S %p",
]

# DD/MM/YYYY and MM/DD/YYYY are ambiguous when day <= 12
# We handle these separately with explicit checks
_AMBIGUOUS_DMY_FORMATS = [
    ("%d/%m/%Y %H:%M:%S", "DD/MM/YYYY"),
    ("%d-%m-%Y %H:%M:%S", "DD-MM-YYYY"),
    ("%d/%m/%Y %H:%M", "DD/MM/YYYY"),
    ("%d/%m/%Y", "DD/MM/YYYY"),
    ("%d-%m-%Y", "DD-MM-YYYY"),
]

_AMBIGUOUS_MDY_FORMATS = [
    ("%m/%d/%Y %H:%M:%S", "MM/DD/YYYY"),
    ("%m-%d-%Y %H:%M:%S", "MM-DD-YYYY"),
    ("%m/%d/%Y %H:%M", "MM/DD/YYYY"),
    ("%m/%d/%Y", "MM/DD/YYYY"),
    ("%m-%d-%Y", "MM-DD-YYYY"),
]


class TimestampResult:
    """Result of timestamp normalization."""
    __slots__ = ('normalized', 'original', 'status', 'assumed_tz', 'format_used')
    
    def __init__(self, normalized: Optional[str], original: str, status: str,
                 assumed_tz: Optional[str] = None, format_used: Optional[str] = None):
        self.normalized = normalized       # ISO 8601 UTC string or None
        self.original = original           # Original timestamp text
        self.status = status               # 'ok', 'ambiguous', 'unparsed', 'missing'
        self.assumed_tz = assumed_tz       # e.g. 'UTC (assumed)' if naive
        self.format_used = format_used     # The format pattern that matched


def normalize_timestamp(ts_str: str) -> TimestampResult:
    """
    Attempt to automatically detect and normalize a timestamp string.
    Returns a TimestampResult with status indicating success or issues.
    """
    if not ts_str or not str(ts_str).strip():
        return TimestampResult(None, ts_str or '', 'missing')
    
    clean_str = str(ts_str).strip()
    original = clean_str
    
    # ── 1. Epoch timestamps (seconds or milliseconds) ──────────────────────
    if _EPOCH_RE.match(clean_str):
        try:
            val = float(clean_str)
            if val > 1e12:  # milliseconds
                val = val / 1000.0
            elif val > 1e11:  # could be milliseconds
                val = val / 1000.0
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return TimestampResult(
                dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                original, 'ok', 'UTC', 'epoch'
            )
        except (ValueError, OverflowError, OSError):
            pass
    
    # ── 2. ISO 8601 with timezone offset (fromisoformat) ──────────────────
    try:
        # Handle Z suffix
        iso_str = clean_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is not None:
            # Has explicit timezone — convert to UTC
            dt_utc = dt.astimezone(timezone.utc)
            return TimestampResult(
                dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
                original, 'ok', 'explicit', 'ISO8601'
            )
        else:
            # Timezone-naive ISO — assume UTC and note assumption
            return TimestampResult(
                dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                original, 'ok', 'UTC (assumed — no timezone in source)', 'ISO8601-naive'
            )
    except (ValueError, TypeError):
        pass
    
    # ── 3. Try unambiguous formats ─────────────────────────────────────────
    for fmt in _UNAMBIGUOUS_FORMATS:
        try:
            dt = datetime.strptime(clean_str, fmt)
            # Syslog formats without year
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now(timezone.utc).year)
            return TimestampResult(
                dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                original, 'ok', 'UTC (assumed — no timezone in source)', fmt
            )
        except ValueError:
            continue
    
    # ── 4. Handle potentially ambiguous DD/MM vs MM/DD formats ─────────────
    # Try to determine if the format is unambiguous (day > 12 → must be DD/MM)
    dmy_match = None
    mdy_match = None
    
    for fmt, label in _AMBIGUOUS_DMY_FORMATS:
        try:
            dt = datetime.strptime(clean_str, fmt)
            dmy_match = (dt, fmt, label)
            break
        except ValueError:
            continue
    
    for fmt, label in _AMBIGUOUS_MDY_FORMATS:
        try:
            dt = datetime.strptime(clean_str, fmt)
            mdy_match = (dt, fmt, label)
            break
        except ValueError:
            continue
    
    if dmy_match and mdy_match:
        dmy_dt, dmy_fmt, dmy_label = dmy_match
        mdy_dt, mdy_fmt, mdy_label = mdy_match
        
        # Extract first and second numeric components
        parts = re.split(r'[/\-]', clean_str.split()[0] if ' ' in clean_str else clean_str)
        if len(parts) >= 2:
            first_num = int(parts[0])
            second_num = int(parts[1])
            
            if first_num > 12:
                # First number > 12, must be DD/MM/YYYY
                return TimestampResult(
                    dmy_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    original, 'ok', 'UTC (assumed — no timezone in source)', dmy_fmt
                )
            elif second_num > 12:
                # Second number > 12, must be MM/DD/YYYY
                return TimestampResult(
                    mdy_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    original, 'ok', 'UTC (assumed — no timezone in source)', mdy_fmt
                )
            else:
                # Both <= 12 → truly ambiguous, mark as such
                # Use DD/MM/YYYY by default but flag as ambiguous
                return TimestampResult(
                    dmy_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    original, 'ambiguous',
                    'UTC (assumed — no timezone in source)',
                    f'{dmy_label} (ambiguous — could be {mdy_label})'
                )
    elif dmy_match:
        dt, fmt, label = dmy_match
        return TimestampResult(
            dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            original, 'ok', 'UTC (assumed — no timezone in source)', fmt
        )
    elif mdy_match:
        dt, fmt, label = mdy_match
        return TimestampResult(
            dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
            original, 'ok', 'UTC (assumed — no timezone in source)', fmt
        )
    
    # ── 5. Could not parse — mark as unparsed, do NOT use current time ─────
    return TimestampResult(None, original, 'unparsed')


def parse_timestamp_with_format(ts_str: str, date_format: str = "auto", time_format: str = "auto") -> str:
    """
    Legacy compatibility wrapper. Now delegates to normalize_timestamp for auto mode.
    Returns an ISO timestamp string. Falls back to marking unparsed.
    """
    result = normalize_timestamp(ts_str)
    if result.normalized:
        return result.normalized
    # For unparsed/missing, return a sentinel that can be detected downstream
    # Do NOT silently use current time
    return ""


def parse_iso_or_fallback(ts_str: str) -> str:
    return parse_timestamp_with_format(ts_str)


class IngestionStats:
    """Tracks statistics during log ingestion."""
    def __init__(self):
        self.total_records = 0
        self.parsed_ok = 0
        self.timestamps_ok = 0
        self.timestamps_ambiguous = 0
        self.timestamps_unparsed = 0
        self.timestamps_missing = 0
        self.parse_errors = 0
        self.warnings = []
    
    def to_dict(self):
        return {
            "total_records_processed": self.total_records,
            "successfully_parsed": self.parsed_ok,
            "timestamps_normalized": self.timestamps_ok,
            "timestamps_ambiguous": self.timestamps_ambiguous,
            "timestamps_invalid_or_unparsed": self.timestamps_unparsed,
            "timestamps_missing": self.timestamps_missing,
            "parse_errors": self.parse_errors,
            "warnings": self.warnings[:20]  # Cap warnings for response size
        }


def normalize_single_event(
    raw_dict: Dict[str, Any], 
    raw_text: str = "",
    date_format: str = "auto",
    time_format: str = "auto",
    ingestion_stats: Optional[IngestionStats] = None
) -> Dict[str, Any]:
    event_id = str(raw_dict.get("id") or raw_dict.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}")
    
    # Check for separate date and time fields (e.g., CSV with 'Date' and 'Time' columns)
    date_val = str(raw_dict.get("date") or raw_dict.get("Date") or raw_dict.get("log_date") or "").strip()
    time_val = str(raw_dict.get("time") or raw_dict.get("Time") or raw_dict.get("log_time") or "").strip()
    ts_raw = str(raw_dict.get("timestamp") or raw_dict.get("@timestamp") or "").strip()
    
    if not ts_raw and date_val and time_val:
        ts_raw = f"{date_val} {time_val}"
    elif not ts_raw and date_val:
        ts_raw = date_val
    elif not ts_raw and time_val:
        ts_raw = time_val

    # Normalize timestamp using the improved engine
    ts_result = normalize_timestamp(ts_raw)
    timestamp = ts_result.normalized or ""
    
    # Track ingestion stats
    if ingestion_stats:
        if ts_result.status == 'ok':
            ingestion_stats.timestamps_ok += 1
        elif ts_result.status == 'ambiguous':
            ingestion_stats.timestamps_ambiguous += 1
            ingestion_stats.warnings.append(
                f"Event {event_id}: Ambiguous timestamp '{ts_result.original}' — "
                f"interpreted as {ts_result.format_used}. Verify day/month order."
            )
        elif ts_result.status == 'unparsed':
            ingestion_stats.timestamps_unparsed += 1
            ingestion_stats.warnings.append(
                f"Event {event_id}: Could not parse timestamp '{ts_result.original}'. "
                f"Event retained with empty normalized timestamp."
            )
        elif ts_result.status == 'missing':
            ingestion_stats.timestamps_missing += 1
    
    # Identify category
    category_hint = str(raw_dict.get("category") or raw_dict.get("log_type") or raw_dict.get("event_category") or "").upper()
    event_type = str(raw_dict.get("event_type") or raw_dict.get("type") or raw_dict.get("action") or "").lower()
    raw_str = raw_text if raw_text else json.dumps(raw_dict)
    
    # Auto-detect category if missing
    if not category_hint or category_hint not in ("AUTHENTICATION", "SYSTEM", "NETWORK"):
        if any(k in event_type or k in raw_str.lower() for k in ("login", "auth", "logon", "failed password", "session_open", "4624", "4625")):
            category_hint = "AUTHENTICATION"
        elif any(k in event_type or k in raw_str.lower() for k in ("process", "exec", "sudo", "privilege", "service", "sysmon")):
            category_hint = "SYSTEM"
        elif any(k in event_type or k in raw_str.lower() for k in ("conn", "traffic", "flow", "bytes", "dns", "firewall", "egress", "network")):
            category_hint = "NETWORK"
        else:
            category_hint = "SYSTEM"
            
    # Normalize users, IPs, hosts
    user = (
        raw_dict.get("user") or raw_dict.get("username") or raw_dict.get("account") or 
        raw_dict.get("src_user") or raw_dict.get("TargetUserName") or None
    )
    source_ip = (
        raw_dict.get("source_ip") or raw_dict.get("src_ip") or raw_dict.get("client_ip") or 
        raw_dict.get("IpAddress") or raw_dict.get("orig_h") or None
    )
    dest_ip = (
        raw_dict.get("dest_ip") or raw_dict.get("dst_ip") or raw_dict.get("resp_h") or 
        raw_dict.get("DestinationIp") or None
    )
    host = (
        raw_dict.get("host") or raw_dict.get("hostname") or raw_dict.get("computer_name") or 
        raw_dict.get("Computer") or raw_dict.get("source_host") or "HOST-PRIMARY"
    )
    dest_host = raw_dict.get("dest_host") or raw_dict.get("dst_host") or raw_dict.get("target_host") or None
    port = raw_dict.get("port") or raw_dict.get("dest_port") or raw_dict.get("dst_port") or raw_dict.get("resp_p")
    try:
        port = int(port) if port is not None else None
    except (ValueError, TypeError):
        port = None
        
    protocol = str(raw_dict.get("protocol") or raw_dict.get("proto") or ("TCP" if port in (22, 445, 3389, 80, 443) else "UNKNOWN")).upper()
    
    bytes_out = raw_dict.get("bytes_out") or raw_dict.get("orig_bytes") or raw_dict.get("bytes_sent") or 0
    try:
        bytes_out = int(bytes_out)
    except (ValueError, TypeError):
        bytes_out = 0
        
    action = str(raw_dict.get("action") or raw_dict.get("status") or "allowed").lower()
    
    # Calculate severity score (1.0 to 10.0 scale for scatter plot)
    existing_score = raw_dict.get("severity_score")
    if existing_score is not None:
        try:
            severity_score = float(existing_score)
        except (ValueError, TypeError):
            severity_score = 3.0
    else:
        # Heuristic calculation
        score = 2.0
        if "fail" in action or "fail" in event_type:
            score += 3.5
        if "sudo" in event_type or "privilege" in event_type:
            score += 4.0
        if "lateral" in event_type or (port in (22, 445, 3389) and dest_host and dest_host != host):
            score += 4.5
        if bytes_out > 50_000_000: # >50MB
            score += 5.0
        elif bytes_out > 5_000_000: # >5MB
            score += 2.5
        if "brute" in raw_str.lower() or "exploit" in raw_str.lower() or "mimikatz" in raw_str.lower():
            score += 4.0
        severity_score = min(max(round(score, 1), 1.0), 10.0)
        
    status = raw_dict.get("status") or ("failure" if "fail" in action or "fail" in event_type else "success")
    
    metadata = {k: v for k, v in raw_dict.items() if k not in (
        "id", "timestamp", "category", "event_type", "user", "source_ip",
        "dest_ip", "host", "dest_host", "port", "protocol", "bytes_out",
        "action", "severity_score", "status", "raw_log"
    )}
    
    # Preserve original timestamp and normalization status in metadata
    metadata["_original_timestamp"] = ts_result.original
    metadata["_timestamp_status"] = ts_result.status
    if ts_result.assumed_tz:
        metadata["_timestamp_tz_note"] = ts_result.assumed_tz
    if ts_result.format_used:
        metadata["_timestamp_format"] = ts_result.format_used
    
    return {
        "id": event_id,
        "timestamp": timestamp,
        "category": category_hint,
        "event_type": event_type or ("auth_attempt" if category_hint == "AUTHENTICATION" else "network_session" if category_hint == "NETWORK" else "system_event"),
        "user": user,
        "source_ip": source_ip,
        "dest_ip": dest_ip,
        "host": host,
        "dest_host": dest_host,
        "port": port,
        "protocol": protocol,
        "bytes_out": bytes_out,
        "action": action,
        "severity_score": severity_score,
        "status": status,
        "raw_log": raw_str,
        "metadata": metadata
    }

def normalize_json_payload(content: str, date_format: str = "auto", time_format: str = "auto") -> Tuple[List[Dict[str, Any]], List[str]]:
    events = []
    errors = []
    stats = IngestionStats()
    
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            items = data.get("events") or data.get("logs") or [data]
        elif isinstance(data, list):
            items = data
        else:
            return [], ["Root JSON must be an array or an object containing an 'events'/'logs' list."]
            
        stats.total_records = len(items)
        
        for i, item in enumerate(items):
            try:
                norm = normalize_single_event(
                    item, 
                    json.dumps(item, indent=2),
                    date_format=date_format,
                    time_format=time_format,
                    ingestion_stats=stats
                )
                events.append(norm)
                stats.parsed_ok += 1
            except Exception as e:
                stats.parse_errors += 1
                errors.append(f"Row {i+1}: Failed to normalize item - {str(e)}")
    except Exception as e:
        errors.append(f"Invalid JSON format: {str(e)}")
    
    # Add ingestion stats as warnings/info
    if stats.timestamps_ambiguous > 0:
        errors.append(f"⚠ {stats.timestamps_ambiguous} timestamp(s) were ambiguous (DD/MM vs MM/DD). Review flagged events.")
    if stats.timestamps_unparsed > 0:
        errors.append(f"⚠ {stats.timestamps_unparsed} timestamp(s) could not be parsed. Events retained without normalized timestamps.")
    if stats.timestamps_missing > 0:
        errors.append(f"ℹ {stats.timestamps_missing} event(s) had no timestamp field.")
    
    return events, errors

def normalize_csv_payload(content: str, date_format: str = "auto", time_format: str = "auto") -> Tuple[List[Dict[str, Any]], List[str]]:
    events = []
    errors = []
    stats = IngestionStats()
    
    try:
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            return [], ["CSV file is empty or has missing column headers."]
        
        rows = list(reader)
        stats.total_records = len(rows)
            
        for i, row in enumerate(rows):
            try:
                raw_text = json.dumps(row)
                norm = normalize_single_event(
                    row, 
                    raw_text,
                    date_format=date_format,
                    time_format=time_format,
                    ingestion_stats=stats
                )
                events.append(norm)
                stats.parsed_ok += 1
            except Exception as e:
                stats.parse_errors += 1
                errors.append(f"Line {i+2}: Failed to normalize CSV row - {str(e)}")
    except Exception as e:
        errors.append(f"Invalid CSV structure: {str(e)}")
    
    # Add ingestion stats as warnings/info
    if stats.timestamps_ambiguous > 0:
        errors.append(f"⚠ {stats.timestamps_ambiguous} timestamp(s) were ambiguous (DD/MM vs MM/DD). Review flagged events.")
    if stats.timestamps_unparsed > 0:
        errors.append(f"⚠ {stats.timestamps_unparsed} timestamp(s) could not be parsed. Events retained without normalized timestamps.")
    if stats.timestamps_missing > 0:
        errors.append(f"ℹ {stats.timestamps_missing} event(s) had no timestamp field.")
    
    return events, errors
