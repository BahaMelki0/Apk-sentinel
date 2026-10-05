"""Bounded exact URL links between decompiled source and observed requests."""
from pathlib import Path
import re


def correlate_urls(source_dir: Path, captures: list[dict]) -> dict:
    observed = {}
    for capture in captures:
        for index, request in enumerate(capture.get('requests', [])):
            url = request.get('url', '')
            if url:
                observed.setdefault(url, []).append({'capture_id': capture.get('id'), 'request_index': index})
    links = []
    scanned = 0
    truncated = False
    if source_dir.exists():
        for path in source_dir.rglob('*'):
            if path.is_symlink() or path.suffix not in ('.java', '.kt') or not path.is_file():
                continue
            if scanned >= 2000:
                truncated = True
                break
            if path.stat().st_size > 1_000_000:
                truncated = True
                continue
            scanned += 1
            for line_number, line in enumerate(path.read_text(encoding='utf-8', errors='replace').splitlines(), 1):
                for url in set(re.findall(r'https?://[^\s"\'<>]+', line)):
                    if url in observed:
                        links.append({'source_file': path.relative_to(source_dir).as_posix(), 'line': line_number,
                                      'url': url, 'requests': observed[url][:20]})
                if len(links) >= 500:
                    truncated = True
                    break
            if len(links) >= 500:
                break
    return {'links': links, 'files_scanned': scanned, 'truncated': truncated,
            'limitation': 'Exact URL literals only. Matching traffic does not prove this source line executed or confirm a vulnerability. Dynamic URL construction is not covered.'}
