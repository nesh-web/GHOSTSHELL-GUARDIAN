# src/main.py
"""
Ghost Shell Guardian - Main Orchestration Pipeline

PURPOSE:
  Links all four layers of Ghost Shell Guardian into a complete pipeline:
    Layer 1: Parser (extract structure from raw logs)
    Layer 2: Rules Engine (detect attack signatures)
    Layer 3: Gemini 3 API (enrich with AI analysis)
    Layer 4: Output (save enriched alerts to JSON)

WHAT IT DOES:
  Chains the security analysis pipeline:
  1. Read raw security alert log file
  2. Parse log into structured alert dict (source_ip, payload, user_agent)
  3. Detect attack type using signature rules
  4. Enrich alert with Gemini 3 AI analysis
  5. Save enriched alert to JSON output file

USAGE:
  # Process all 5 samples
  python src/main.py

  # Process specific sample
  python src/main.py shellshock.log

  # Show help
  python src/main.py --help

AVAILABLE SAMPLES:
  - shellshock.log          (Bash RCE, CVE-2014-6271)
  - sql_injection.log       (SQL escape attack)
  - path_traversal.log      (Directory traversal attempt)
  - rce_wget.log            (Command execution via wget)
  - xss_reflected.log       (Cross-site scripting injection)

DEPENDENCIES:
  - parser.py (extract structure from logs)
  - rules.py (detect attack signatures)
  - gemini_engine.py (enrich with Gemini 3 AI)

REQUIREMENTS:
  - GEMINI_API_KEY in .env file (MANDATORY)
  - Access to Gemini 3 models (no fallbacks, no degradation)

ERROR HANDLING:
  - Missing log file → Print error, skip to next sample
  - Parse failure → Print error with details
  - Attack detection → Always succeeds (worst case: "Unknown")
  - Gemini API failure → Print error, return False
  
OUTPUT:
  - Prints structured processing log to stdout
  - Saves enriched alerts to outputs/{sample_name}_enriched.json
  - Example output: outputs/shellshock_enriched.json
"""

import os
import json
import sys
import argparse
from parser import parse_log
from rules import detect_attack
from gemini_engine import enrich_alert


def process_sample(log_path):
    """
    Process a single security alert sample through the complete pipeline.

    PURPOSE:
      Takes a raw security alert log file and transforms it into an
      AI-enriched, actionable alert ready for SOC analyst review.

    PARAMETERS:
      log_path (str): Absolute or relative path to log file
        Example: "../samples/shellshock.log"
        or: "/full/path/to/samples/sql_injection.log"

    RETURNS:
      bool: True if processing succeeded, False if error occurred
        - True: Alert enriched and saved to outputs/
        - False: Error during parsing, detection, or enrichment

    PROCESSING PIPELINE:
      1. VALIDATE: Check log file exists
      2. LOAD: Read raw log file from disk
      3. PARSE: Extract source_ip, payload, user_agent
      4. DETECT: Match payload against attack signatures
      5. ENRICH: Send to Gemini 3 for intent/severity/recommendations
      6. SAVE: Write enriched alert to outputs/ as JSON
      7. REPORT: Print processing summary and output location

    SIDE EFFECTS:
      - Creates outputs/ directory if not exists
      - Creates outputs/{sample_name}_enriched.json file
      - Prints detailed processing logs to stdout
      - May make HTTP requests to Gemini API

    ERROR HANDLING:
      - Missing file: Print error, return False
      - Parse failure: Print error with details, return False
      - Enrichment failure: Print error from Gemini API, return False
      - Detection always succeeds (worst case: "Unknown" attack)

    EXAMPLE OUTPUT:
      ============================================================
      Processing: shellshock.log
      ============================================================
      [*] Loading log from: ../samples/shellshock.log
      [*] Parsing log...
      Parsed Alert: {
        "source_ip": "41.90.12.77",
        "payload": "() { :;}; /bin/bash ...",
        "user_agent": "ShellShock-Exploit/1.0"
      }
      
      [*] Detecting attack pattern...
      Attack Type: Shellshock
      
      [*] Enriching alert with Gemini API...
      Enriched Alert:
      ----------------------------------------
      {
        "intent": "Botnet recruitment",
        "mitre_technique": "T1059.004",
        "severity": "Critical",
        "reasoning": "Exploitation of bash vulnerability + malware download",
        "recommended_action": "Block IP, isolate systems, check firewall logs"
      }
      
      [SUCCESS] Enriched alert saved to: outputs/shellshock_enriched.json
    """
    print(f"\n{'='*60}")
    print(f"Processing: {os.path.basename(log_path)}")
    print(f"{'='*60}")
    
    # Step 1: Validate input file exists
    if not os.path.exists(log_path):
        print(f"[ERROR] Sample log not found at {log_path}")
        return False

    # Step 2: Load raw log file
    print(f"[*] Loading log from: {log_path}")
    with open(log_path, "r") as f:
        raw_log = f.read()

    # Step 3: Parse log into structured alert
    print("[*] Parsing log...")
    alert = parse_log(raw_log)
    print(f"Parsed Alert: {json.dumps(alert, indent=2)}")

    # Step 4: Detect attack pattern using rules
    print("\n[*] Detecting attack pattern...")
    attack_type = detect_attack(alert["payload"])
    alert["attack_type"] = attack_type
    print(f"Attack Type: {attack_type}")

    # Step 5: Enrich with Gemini 3 AI
    print("\n[*] Enriching alert with Gemini API...")
    try:
        enriched = enrich_alert(alert)
        print("\nEnriched Alert:")
        print("-" * 40)
        print(json.dumps(enriched, indent=2, ensure_ascii=True))

        # Step 6: Save enriched alert to JSON file
        output_dir = os.path.join(os.path.dirname(__file__), "..", "outputs")
        os.makedirs(output_dir, exist_ok=True)
        
        filename = os.path.splitext(os.path.basename(log_path))[0]
        output_path = os.path.join(output_dir, f"{filename}_enriched.json")
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2, ensure_ascii=True)
        
        # Step 7: Report success
        print(f"\n[SUCCESS] Enriched alert saved to: {output_path}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to enrich alert: {e}")
        return False


def main():
    """
    Main entry point for Ghost Shell Guardian.
    
    PURPOSE:
      Orchestrates complete SOC alert enrichment pipeline:
      - Parse command-line arguments (no args = all samples)
      - Process specified or all security alert samples
      - Display processing progress and results
      - Save enriched alerts to outputs/

    COMMAND-LINE INTERFACE:
      
      python src/main.py [SAMPLE]
      
      SAMPLE (optional):
        - If provided: Process only this sample file
        - If omitted: Process all 5 samples in sequence
        - Accepted values: shellshock.log, sql_injection.log, etc.

    ARGUMENTS:
      -h, --help    Show help message with examples and usage
      SAMPLE        Optional sample filename to process (no positional prefix)

    EXAMPLES:
      $ python src/main.py
        → Processes all 5 samples (shellshock, sql_injection, 
          path_traversal, rce_wget, xss_reflected)

      $ python src/main.py shellshock.log
        → Processes only shellshock.log sample

      $ python src/main.py --help
        → Displays detailed help with all options and examples

    PROCESSING FLOW:
      1. Parse command-line arguments
      2. Print header banner
      3. If SAMPLE argument provided:
         → Process single sample via process_sample()
      4. If no SAMPLE argument:
         → Loop through all 5 samples
         → Call process_sample() for each
         → Skip to next on error
      5. Print completion summary

    OUTPUT LOCATIONS:
      - Logs: Printed to stdout with detailed progress
      - Files: outputs/{sample_name}_enriched.json
      - Errors: Printed with [ERROR] or [WARN] prefix

    DEPENDENCIES:
      - process_sample(): Does the actual work for one file
      - argparse: Parses command-line arguments
      - os: File system operations

    REQUIREMENTS:
      - GEMINI_API_KEY in .env file (MANDATORY for enrichment)
      - samples/ directory with log files
      - outputs/ directory (created if missing)
    """
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Ghost Shell Guardian - SOC Alert Enrichment with Gemini 3 AI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python src/main.py                           # Process all 5 samples
  python src/main.py shellshock.log            # Process specific sample
  python src/main.py sql_injection.log         # Test SQL injection detection
  python src/main.py --help                    # Show this help message

Available samples:
  - shellshock.log          (Bash RCE vulnerability)
  - sql_injection.log       (SQL injection attack)
  - path_traversal.log      (Directory traversal attempt)
  - rce_wget.log            (Remote command execution via wget)
  - xss_reflected.log       (Cross-site scripting attack)

REQUIREMENTS:
  - GEMINI_API_KEY in .env file (MANDATORY)
  - Access to Gemini 3 models (no fallbacks)
        """
    )
    parser.add_argument(
        "sample",
        nargs="?",
        help="specific sample file to process (optional; defaults to all samples)",
        metavar="SAMPLE"
    )
    
    args = parser.parse_args()

    # Print header
    print("=" * 60)
    print("Ghost Shell Guardian - SOC Alert Enrichment")
    print("=" * 60)

    base_dir = os.path.dirname(__file__)
    samples_dir = os.path.join(base_dir, "..", "samples")

    # If sample filename provided as argument, process only that
    if args.sample:
        log_path = os.path.join(samples_dir, args.sample)
        process_sample(log_path)
    else:
        # Process all 5 samples in sequence
        samples = [
            'shellshock.log',
            'sql_injection.log',
            'path_traversal.log',
            'rce_wget.log',
            'xss_reflected.log'
        ]
        
        for sample in samples:
            log_path = os.path.join(samples_dir, sample)
            if not process_sample(log_path):
                print(f"[WARN] Skipping {sample} due to error")
                continue
            print()


if __name__ == "__main__":
    main()

