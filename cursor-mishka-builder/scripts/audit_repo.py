#!/usr/bin/env python3
import json
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

PORT_PATTERNS = [
    re.compile(r'(?i)\b(?:port|listen|targetPort|containerPort)\b\s*[:=]\s*["\']?(\d{2,5})'),
    re.compile(r'(?i)(?:-p\s*|ports?:\s*\[?\s*["\']?)(\d{2,5})'),
    re.compile(r'(?i)localhost:(\d{2,5})'),
]
INTERESTING = {
    '.env', '.yaml', '.yml', '.json', '.toml', '.ini', '.conf', '.xml', '.properties',
    '.sh', '.py', '.go', '.ts', '.tsx', '.js', '.jsx', '.rs', '.java', '.cs', '.md'
}
SKIP_DIRS = {'.git', 'node_modules', 'dist', 'build', 'target', '.next', '.venv', 'venv', '__pycache__', '.idea', '.cursor'}


def scan(root: Path):
    results = {
        'root': str(root),
        'exists': root.exists(),
        'top_level': [],
        'technology_hints': [],
        'files_checked': 0,
        'ports': defaultdict(list),
        'service_hints': defaultdict(list),
        'suspicious_duplicates': defaultdict(list),
    }
    if not root.exists():
        return results

    top = sorted(p.name for p in root.iterdir())
    results['top_level'] = top

    tech_markers = {
        'go': ['go.mod'],
        'node': ['package.json', 'pnpm-workspace.yaml'],
        'python': ['pyproject.toml', 'requirements.txt'],
        'rust': ['Cargo.toml'],
        'java': ['pom.xml', 'build.gradle'],
        'docker': ['docker-compose.yml', 'docker-compose.yaml', 'Dockerfile'],
        'kubernetes': ['kustomization.yaml'],
    }
    for tech, markers in tech_markers.items():
        if any((root / m).exists() for m in markers):
            results['technology_hints'].append(tech)

    for path in root.rglob('*'):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_dir():
            continue
        if path.suffix.lower() not in INTERESTING and path.name not in {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', 'Makefile', 'package.json', 'go.mod', 'pyproject.toml'}:
            continue
        results['files_checked'] += 1
        try:
            text = path.read_text(errors='ignore')[:200000]
        except Exception:
            continue

        lname = path.name.lower()
        for key in ['ingest', 'router', 'decision', 'policy', 'safety', 'enforcement', 'storage', 'replay', 'ui', 'agent', 'probe', 'shadow']:
            if key in lname or re.search(rf'\b{key}\b', text, re.IGNORECASE):
                results['service_hints'][key].append(str(path))

        stem = path.stem.lower()
        normalized = re.sub(r'[^a-z0-9]+', '-', stem).strip('-')
        results['suspicious_duplicates'][normalized].append(str(path))

        for patt in PORT_PATTERNS:
            for m in patt.findall(text):
                port = int(m)
                if 1 <= port <= 65535:
                    results['ports'][str(port)].append(str(path))

    results['ports'] = {k: v[:20] for k, v in sorted(results['ports'].items(), key=lambda kv: int(kv[0]))}
    results['service_hints'] = {k: v[:20] for k, v in sorted(results['service_hints'].items()) if v}
    results['suspicious_duplicates'] = {k: v for k, v in sorted(results['suspicious_duplicates'].items()) if len(v) > 1 and len(k) > 2}
    return results


def main():
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')
    report = scan(root)
    print(json.dumps(report, indent=2))

if __name__ == '__main__':
    main()
