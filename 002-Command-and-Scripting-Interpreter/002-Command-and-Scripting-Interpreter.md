# 002: Command and Scripting Interpreter

**Rule Title:** Suspicious Command and Scripting Interpreter Activity

**Severity:** Critical / High

## Goal
Detect abuse of Windows command/scripting interpreters (PowerShell, Command Prompt, WScript/CScript, MSHTA) to execute disguised payloads, stage externally-downloaded tooling, or obfuscate interpreter invocation via environment-variable substring manipulation.

## Categorization
[Execution / Command and Scripting Interpreter (T1059)](https://attack.mitre.org/techniques/T1059/) — sub-techniques [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) and [T1059.003 – Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/)

## Strategy Abstract
Collect process-creation telemetry for core script/command interpreters. Flag command lines matching known-malicious artifact patterns observed during testing: masquerading-payload execution, external tool-staging downloads, environment-variable obfuscation of interpreter names, and a specific bundled local-account reconnaissance sequence.

## Technical Context
Interpreters are "living off the land" binaries — legitimate and expected on any Windows host — so command-line content is the primary detection surface. This rule specifically catches the environment-variable substring trick (`%LOCALAPPDATA:~-3,1%md` resolving to "cmd") used to spell out an interpreter name without it appearing literally in the command line, evading naive keyword-based detections.

```cql
// Scope to process-creation telemetry only
#event_simpleName=ProcessRollup2
// Restrict to the core script/command interpreters commonly abused for execution
FileName=/(?i)^(powershell|pwsh|cmd|wscript|cscript|mshta)\.exe$/
| case {
    // Exact masquerading-payload execution pattern used in the CHIPOM run - flags interpreters running the specific disguised "masquerading.*" files
    CommandLine=/(?i)masquerading\.(docx|pdf|xlsx|xls|png|rtf|doc)\.(exe|ps1|vbs)/ | _Risk := "Critical" ;

    // Exact tool-staging domains/files used in the CHIPOM run - flags the specific GhostTask/PsExec download artifacts
    CommandLine=/(?i)(download\.sysinternals\.com|githubusercontent\.com.*GhostTask|PSTools\.zip|GhostTask\.exe)/ | _Risk := "Critical" ;

    // Env-var substring obfuscation (spelling "cmd"/"powershell" via %VAR:~n,1%) - catches Atomic Test #3's evasion technique
    CommandLine=/%[A-Za-z0-9_]+:~-?\d+,\d+%(md|owershell|script)/ | _Risk := "Critical" ;

    // The exact bundled recon script observed in the CHIPOM run - requires all four specific commands together in one PowerShell invocation
    FileName="powershell.exe" AND CommandLine=/(?i)net\s+user/ AND CommandLine=/(?i)Get-LocalUser/ AND CommandLine=/(?i)Get-LocalGroupMember/ AND CommandLine=/(?i)cmdkey.*\/list/ | _Risk := "High" ;

    // Default: anything not matching the above patterns is treated as benign and dropped later
    * | _Risk := "Low" ;
}
// Keep only rows that matched a suspicious branch
| _Risk!="Low"
// Output the columns needed for triage; limit raised above the 200-row default
| table([timestamp, UserName, ParentBaseFileName, FileName, CommandLine, _Risk], limit=20000)
// Order results chronologically for timeline review
| sort(field=timestamp)
```

## Blind Spots and Assumptions
- Three of the four branches (masquerading filenames, tool-staging domains, exact recon bundle) are scoped to the **specific artifacts** observed during this test run rather than generalized behavioral patterns. A different tool name, staging domain, or a partial/reordered version of the recon command bundle will not be detected by those branches.
- Only the environment-variable obfuscation branch is fully behavioral and will generalize to any variant using that evasion technique.
- Assumes Falcon sensor captures full, untruncated command-line arguments.

## False Positives
Low, given the branches are artifact-specific rather than broad behavioral matches — but this also means the rule has narrow coverage (see Blind Spots). No significant false-positive sources identified during validation.

## Priority
- **Critical:** masquerading-payload execution, tool-staging download, or environment-variable obfuscation branches.
- **High:** bundled recon-script branch.

## Validation
Validated against Atomic Red Team T1059.003 (Atomic Test #1: Create and Execute Batch Script — not currently covered by this rule; Atomic Test #3: Suspicious Execution via Windows Command Shell — covered via the obfuscation branch) and the PowerShell tool-staging/recon activity observed in the source investigation.

## Response
- Retrieve and decode the full command line to determine actual intent.
- Identify the parent process chain to determine the initial access vector.
- Correlate with 001: Masquerading, 003: Scheduled Task, and 004: Account Discovery for the same host/user/time window before treating as an isolated alert.

## Known Limitation — Recommended Follow-Up
This rule is intentionally scoped to the exact artifacts from the source investigation and will not detect a differently-tooled repeat of the same technique (e.g., a different download domain or renamed payload). A generalized, behavior-based version of this rule (matching on double-extension execution broadly, any download-and-stage command, and a discovery-command flag count rather than an exact 4-command match) has been drafted separately and should be considered for defense-in-depth alongside this rule.