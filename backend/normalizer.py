import uuid
import json
import csv
import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Tuple

def parse_timestamp_with_format(ts_str: str, date_format: str = "auto", time_format: str = "auto") -> str:
    if not ts_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    clean_str = str(ts_str).strip()
    if not clean_str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 1. Check for Epoch timestamps (seconds or milliseconds)
    clean_num = clean_str.replace(".", "", 1)
    if time_format == "epoch" or (clean_num.isdigit() and len(clean_str) >= 9):
        try:
            val = float(clean_str)
            if val > 1e11:  # milliseconds timestamp
                val = val / 1000.0
            dt = datetime.fromtimestamp(val, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            pass

    # 2. Build candidate patterns if user specified date_format or time_format
    date_patterns = []
    if date_format == "YYYY-MM-DD":
        date_patterns = ["%Y-%m-%d", "%Y.%m.%d"]
    elif date_format == "DD/MM/YYYY":
        date_patterns = ["%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y"]
    elif date_format == "MM/DD/YYYY":
        date_patterns = ["%m/%d/%Y", "%m-%d-%Y", "%m.%d.%Y"]
    elif date_format == "YYYY/MM/DD":
        date_patterns = ["%Y/%m/%d"]
    elif date_format == "syslog":
        date_patterns = ["%b %d", "%b  %d", "%b %d %Y", "%B %d %Y"]
    elif date_format and date_format != "auto":
        date_patterns = [date_format]

    time_patterns = []
    if time_format == "24h":
        time_patterns = ["%H:%M:%S.%f", "%H:%M:%S", "%H:%M"]
    elif time_format == "12h":
        time_patterns = ["%I:%M:%S %p", "%I:%M:%S%p", "%I:%M %p", "%I:%M%p"]
    elif time_format and time_format != "auto" and time_format != "epoch":
        time_patterns = [time_format]
    else:
        time_patterns = ["%H:%M:%S.%f", "%H:%M:%S", "%H:%M", "%I:%M:%S %p", "%I:%M %p"]

    # If specific date format was provided, test combined date + time patterns first
    if date_patterns:
        for dp in date_patterns:
            for tp in time_patterns:
                for sep in (" ", "T", ":"):
                    fmt = f"{dp}{sep}{tp}"
                    try:
                        dt = datetime.strptime(clean_str, fmt)
                        if dt.year == 1900:
                            dt = dt.replace(year=datetime.now(timezone.utc).year)
                        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                    except Exception:
                        continue
            # Try date format alone if time is not present in string
            try:
                dt = datetime.strptime(clean_str, dp)
                if dt.year == 1900:
                    dt = dt.replace(year=datetime.now(timezone.utc).year)
                return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            except Exception:
                continue

    # 3. Standard ISO parser
    try:
        clean_iso = clean_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        pass

    # 4. Common log format fallback
    common_formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%b %d %H:%M:%S",
        "%b  %d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
        "%Y-%m-%d",
        "%d/%m/%Y",
        "%m/%d/%Y"
    )
    for fmt in common_formats:
        try:
            dt = datetime.strptime(clean_str, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=datetime.now(timezone.utc).year)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except Exception:
            continue

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def parse_iso_or_fallback(ts_str: str) -> str:
    return parse_timestamp_with_format(ts_str)

def normalize_single_event(
    raw_dict: Dict[str, Any], 
    raw_text: str = "",
    date_format: str = "auto",
    time_format: str = "auto"
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

    timestamp = parse_timestamp_with_format(ts_raw, date_format=date_format, time_format=time_format)
    
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
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            items = data.get("events") or data.get("logs") or [data]
        elif isinstance(data, list):
            items = data
        else:
            return [], ["Root JSON must be an array or an object containing an 'events'/'logs' list."]
            
        for i, item in enumerate(items):
            try:
                norm = normalize_single_event(
                    item, 
                    json.dumps(item, indent=2),
                    date_format=date_format,
                    time_format=time_format
                )
                events.append(norm)
            except Exception as e:
                errors.append(f"Row {i+1}: Failed to normalize item - {str(e)}")
    except Exception as e:
        errors.append(f"Invalid JSON format: {str(e)}")
        
    return events, errors

def normalize_csv_payload(content: str, date_format: str = "auto", time_format: str = "auto") -> Tuple[List[Dict[str, Any]], List[str]]:
    events = []
    errors = []
    try:
        reader = csv.DictReader(io.StringIO(content))
        if not reader.fieldnames:
            return [], ["CSV file is empty or has missing column headers."]
            
        for i, row in enumerate(reader):
            try:
                raw_text = json.dumps(row)
                norm = normalize_single_event(
                    row, 
                    raw_text,
                    date_format=date_format,
                    time_format=time_format
                )
                events.append(norm)
            except Exception as e:
                errors.append(f"Line {i+2}: Failed to normalize CSV row - {str(e)}")
    except Exception as e:
        errors.append(f"Invalid CSV structure: {str(e)}")
        
    return events, errors
