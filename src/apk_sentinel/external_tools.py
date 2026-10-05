"""Optional, explicit Android tooling with timeouts and observable failures."""
import os
from pathlib import Path
import shutil
import subprocess


def run_tool(tool, apk, destination=None):
    executable = os.environ.get('APK_SENTINEL_' + tool.upper()) or shutil.which(tool)
    if not executable:
        return {'tool': tool, 'status': 'unavailable', 'output': f'Configure APK_SENTINEL_{tool.upper()} or install {tool} on PATH.'}
    if tool == 'apksigner':
        args = [executable, 'verify', '--verbose', '--print-certs', str(Path(apk).resolve())]
    elif tool == 'jadx' and destination is not None:
        args = [executable, '-d', str(Path(destination).resolve()), str(Path(apk).resolve())]
    else:
        raise ValueError('Unsupported assessment tool')
    try:
        completed = subprocess.run(args, capture_output=True, text=True, timeout=120, shell=False, errors='replace')
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {'tool': tool, 'status': 'error', 'output': str(exc)[:1000]}
    return {'tool': tool, 'status': 'verified' if tool == 'apksigner' and completed.returncode == 0 else 'completed' if completed.returncode == 0 else 'failed',
            'exit_code': completed.returncode, 'output': (completed.stdout + '\n' + completed.stderr)[-20000:]}
