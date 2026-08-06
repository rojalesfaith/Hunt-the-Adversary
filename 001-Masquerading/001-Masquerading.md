# 001: Masquerading

**Rule Title:** Suspicious Double File Extension Execution

**Severity:** High

## Goal
Detect execution of files whose name contains a document or media extension immediately followed by an executable extension (e.g., `invoice.docx.exe`, `report.pdf.ps1`), disguising a malicious executable as a harmless-looking document or script file.

## Categorization
[Defense Evasion / Masquerading (T1036)](https://attack.mitre.org/techniques/T1036/) — sub-technique [T1036.007 – Double File Extension](https://attack.mitre.org/techniques/T1036/007/)

## Strategy Abstract
Collect process-creation telemetry (`ProcessRollup2`) and flag any command line containing a document/media extension immediately followed by an executable extension. Group and count duplicate host/user/file/command combinations to reduce alert noise, then score every match as High risk.

## Technical Context
This naming pattern (`filename.docx.exe`) exploits Windows' default behavior of hiding known file extensions — a user sees `invoice.docx` and assumes it is a document, when the actual extension is `.exe` (or another executable/script type). This is a masquerading technique with virtually no legitimate use case, making it a high-confidence, low-noise detection.

```cql
// Scope to process-creation telemetry only
#event_simpleName=ProcessRollup2
// Filter for commands containing a document/media extension immediately followed by an executable extension (the double-extension masquerade pattern)
| CommandLine=/(?i)\.(doc|docx|xls|xlsx|ppt|pptx|pdf|txt|rtf|jpg|png|csv|zip)\.(exe|scr|com|pif|bat|cmd|ps1|vbs|js|jse|wsf|hta)(\s|$|")/
// Tag every matching row so it can be identified/filtered downstream if needed
| DoubleExt := "true"
// Group identical host/user/file/command combinations together and count occurrences, avoiding duplicate alert rows; limit raised above LogScale's 200-row default
| groupBy([ComputerName, UserName, FileName, CommandLine], function=count(as=Hits), limit=20000)
// Score every match as High risk - even a single occurrence of this pattern is rare in legitimate activity
| case {
    test(Hits >= 1) | _Risk := "High" ;
    * | _Risk := "Medium" ;
}
// Output only the columns needed for triage
| table([ComputerName, UserName, FileName, CommandLine, Hits, _Risk], limit=20000)
// Show the most-repeated pattern first
| sort(field=Hits, order=desc, limit=20000)
```

## Blind Spots and Assumptions
- Assumes Falcon sensor captures full command-line arguments for process creation events.
- Only covers the extension combinations explicitly listed in the regex; an extension pairing not included in the pattern will not be flagged.
- A single-extension disguise (e.g., renaming `malware.exe` to `invoice.exe` without a double extension) is not covered by this rule.

## False Positives
Very few known legitimate causes. The main known exception is QA/test tooling that intentionally creates files with compound extensions for functional testing — exclude by known QA host groups if this occurs in your environment.

## Priority
**High** — this rule has no tiered output; every match is scored High.

## Validation
Validated against Atomic Red Team T1036.007 (Double File Extension).

## Response
- Retrieve the file's full hash, signer, and parent process lineage.
- Check the hash against known-good (software inventory) and known-bad (threat intel) sources.
- Correlate with 002: Command and Scripting Interpreter for the same host/user/time window, since masquerading is frequently a delivery mechanism rather than the full attack.