# 004: Account Discovery

**Rule Title:** Suspicious Local Account and Logged-On User Enumeration

**Severity:** Medium

## Goal
Detect command-line reconnaissance of local user accounts, group memberships, cached credentials, and currently logged-on users — activity that commonly precedes privilege escalation or lateral movement.

## Categorization
[Discovery / Account Discovery (T1087)](https://attack.mitre.org/techniques/T1087/) — sub-techniques [T1087.001 – Local Account](https://attack.mitre.org/techniques/T1087/001/) and [T1087.002 – Domain Account](https://attack.mitre.org/techniques/T1087/002/)

## Strategy Abstract
Collect process-creation telemetry and flag known account/group/logged-on-user enumeration commands issued via `net.exe`/`net1.exe`, PowerShell cmdlets, `wmic`, `dsquery`, `cmdkey`, and `query user`/`quser`.

## Technical Context
Account discovery causes no direct damage by itself and is common in legitimate IT/helpdesk work, so this rule is scored at Medium rather than High/Critical — it's intended as a contextual/correlation signal rather than a standalone high-urgency alert. Its value increases significantly when a hit here coincides with hits from the other three rules on the same host/user/time window.

```cql
// Scope to process-creation telemetry only
#event_simpleName=ProcessRollup2
| case {
    // "net user"/"net group"/"net localgroup"/"net accounts" via net.exe or its net1.exe delegate - Atomic Test #8
    CommandLine=/(?i)^\s*net1?\.exe\s+(user|group|localgroup|accounts)(\s|$)/ | _Risk := "Medium" ;
    // PowerShell native/AD account and group enumeration cmdlets - Atomic Test #9 (only catches cmdlets invoked in a freshly-launched process, not ones run inside an existing session)
    CommandLine=/(?i)(Get-LocalUser|Get-LocalGroup|Get-LocalGroupMember|Get-ADUser|Get-ADGroupMember|Get-DomainUser)/ | _Risk := "Medium" ;
    // WMI-based account enumeration
    CommandLine=/(?i)wmic\s+useraccount\s+get/ | _Risk := "Medium" ;
    // Active Directory command-line user query tool
    CommandLine=/(?i)dsquery\s+user/ | _Risk := "Medium" ;
    // Lists cached/stored credentials - often bundled with account enumeration
    CommandLine=/(?i)cmdkey(\.exe)?\s+\/list/ | _Risk := "Medium" ;
    // Shows currently logged-on users - Atomic Test #10
    CommandLine=/(?i)^\s*(query\s+user|quser)(\s|$)/ | _Risk := "Medium" ;
    // Default: no known discovery command pattern matched
    * | _Risk := "Low" ;
}
// Keep only rows that matched a suspicious branch
| _Risk!="Low"
// Output the columns needed for triage; limit raised above the 200-row default
| table([timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, _Risk], limit=20000)
```

## Blind Spots and Assumptions
- PowerShell cmdlets (`Get-LocalUser`, `Get-LocalGroupMember`, `Get-LocalGroup`) execute in-process and do not generate a new process-creation event when run inside an already-open PowerShell session. This rule only detects them when they appear in the command line of a freshly-launched `powershell.exe` process. Full coverage of cmdlet-based enumeration requires PowerShell Script Block Logging (Event ID 4104) or an equivalent script-content telemetry source, which is outside the scope of this rule.
- Enumeration performed via direct LDAP/`[ADSI]` bindings, or via a GUI tool (Active Directory Users and Computers), is not covered.

## False Positives
Helpdesk and IT support staff routinely run these same commands when troubleshooting account issues. This rule alone is not high-confidence and should not trigger standalone high-urgency response — it is intended primarily as a correlation input alongside the other three rules.

## Priority
**Medium** — every branch in this rule scores Medium; no Critical/High tier exists in this rule.

## Validation
Validated against Atomic Red Team T1087.001 Atomic Test #8 (Enumerate all accounts on Windows - Local), Atomic Test #9 (Enumerate all accounts via PowerShell - Local), and Atomic Test #10 (Enumerate logged on users via CMD - Local).

## Response
- Validate the account and host against any IT/helpdesk automation allow-list.
- If not allow-listed, review the parent process chain to determine whether this was interactive, scripted, or remotely triggered.
- Correlate with 001: Masquerading, 002: Command and Scripting Interpreter and 003: Scheduled Task for the same host/user/time window — account discovery observed alongside masquerading, scripted execution, or scheduled-task persistence should be treated as a high-confidence attack chain rather than an isolated discovery event.