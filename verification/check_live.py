"""Dated, read-only reference checks. Run from the repository root."""
import concurrent.futures
import datetime
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [
    ('ensakidag', 'https://ensakidag.se/api/mcp', 'server_info', '2025-11-25'),
    ('rise-ai-sweden', 'https://rise-ai-sweden.jardenberg.org/api/mcp', 'server_info', '2025-11-25'),
    ('sswcboken', 'https://sswcboken.se/api/mcp', 'server_info', '2025-06-18'),
    ('ppcp', 'https://joakim.jardenberg.net/mcp', 'ppcp_get_version', '2025-11-25'),
    ('hallbarhetsklivet', 'https://hkdemo.jardenberg.net/api/mcp', 'hallbarhetsklivet_get_status', '2025-11-25'),
]

def check(target):
    name, endpoint, tool, protocol = target
    record = {'name': name, 'endpoint': endpoint, 'tool': tool, 'protocol_version': protocol,
              'checked_at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'verifiers': {}}
    out = ROOT / 'verification' / record['checked_at'][:10]
    out.mkdir(exist_ok=True)
    for runtime, filename in [(sys.executable, 'verify.py'), ('node', 'verify.mjs')]:
        run = subprocess.run([runtime, str(ROOT/'verifiers'/filename), '--live', endpoint,
                              tool, '--protocol-version', protocol], capture_output=True, text=True, timeout=75)
        log = f'{name}-{filename}.log'
        (out/log).write_text(run.stdout+run.stderr)
        record['verifiers'][filename] = {'exit_code': run.returncode, 'log': log}
    return record

if __name__ == '__main__':
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        records = list(pool.map(check, TARGETS))
    out = ROOT / 'verification' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
    (out/'results.json').write_text(json.dumps({'scope': 'One successful tool call per endpoint with each verifier; not full conformance certification.', 'results': records}, indent=2)+'\n')
    for record in records:
        print(record['name'], {k:v['exit_code'] for k,v in record['verifiers'].items()})
    sys.exit(int(any(v['exit_code'] for r in records for v in r['verifiers'].values())))
