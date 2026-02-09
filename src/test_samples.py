import os
import json
from parser import parse_log
from rules import detect_attack

base_dir = os.path.dirname(__file__)
samples_dir = os.path.join(base_dir, '..', 'samples')

files = [
    'shellshock.log',
    'sql_injection.log',
    'path_traversal.log',
    'rce_wget.log',
    'xss_reflected.log'
]

for fname in files:
    path = os.path.join(samples_dir, fname)
    if not os.path.exists(path):
        print(f"[SKIP] {fname} not found at {path}")
        continue

    with open(path, 'r', encoding='utf-8') as f:
        raw = f.read()

    parsed = parse_log(raw)
    attack = detect_attack(parsed.get('payload', ''))

    print('=' * 60)
    print(f"Sample: {fname}")
    print('-' * 60)
    print(json.dumps(parsed, indent=2))
    print(f"Detected Attack: {attack}")

