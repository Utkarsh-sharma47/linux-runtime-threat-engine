#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run ONE reviewed Atomic Red Team test while the runtime engine monitors, then report.

.DESCRIPTION
    Guarded workflow around the official Invoke-AtomicTest:
      1. resolve the test by GUID (catalog + official YAML must agree)
      2. show its full description, commands, privileges, prerequisites and cleanup
      3. show the risk class; refuse class C, require -AllowReviewRequired for class B
      4. refuse tests that need root or prerequisites (never runs prerequisite commands)
      5. require a live engine monitor session writing to -EngineDb
      6. snapshot persistence locations, then ask for explicit approval (type the GUID prefix)
      7. record start time, run only this test, record end time
      8. show the cleanup command and run it only after a second approval, then verify
      9. correlate the window with the engine database and write a report

    Results go to testing/atomic-red-team/test-results/<run-id>/ (git-ignored).
    -DryRun performs every step except executing the test and its cleanup.

.EXAMPLE
    pwsh testing/atomic-red-team/scripts/run_atomic_test.ps1 `
        -TestGuid b04ed73c-7d43-4dc8-b563-a2fc595cba1a `
        -EngineDb testing/atomic-red-team/test-results/engine.db
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F-]{36}$')][string]$TestGuid,
    [Parameter(Mandatory)][string]$EngineDb,
    [string]$AtomicsPath = (Join-Path $HOME 'AtomicRedTeam/atomics'),
    [string]$ResultsDir = (Join-Path $PSScriptRoot '../test-results'),
    [ValidateRange(5, 600)][int]$TimeoutSeconds = 120,
    [switch]$AllowReviewRequired,
    [switch]$DryRun
)

# No Set-StrictMode: the official module's config.ps1 reads unset variables at import.
$ErrorActionPreference = 'Stop'

$Repo = (Resolve-Path (Join-Path $PSScriptRoot '../../..')).Path
$Python = Join-Path $Repo '.venv/bin/python'
$Catalog = Join-Path $PSScriptRoot 'catalog.py'
$Report = Join-Path $PSScriptRoot 'atomic_report.py'
$Verify = Join-Path $PSScriptRoot 'verify_cleanup.sh'
$Expectations = Join-Path $PSScriptRoot '../expectations.yaml'
$TestGuid = $TestGuid.ToLowerInvariant()
$EngineDb = [IO.Path]::GetFullPath($EngineDb, (Get-Location).Path)

function Section([string]$Title) {
    Write-Host ''
    Write-Host ('=' * 64)
    Write-Host $Title
    Write-Host ('=' * 64)
}

function Stop-Run([string]$Message, [int]$Code = 1) {
    Write-Host "REFUSED: $Message" -ForegroundColor Red
    exit $Code
}

function Get-EngineStatus {
    $json = & $Python $Report engine-status --db $EngineDb
    return ($json | ConvertFrom-Json)
}

function Approve([string]$Prompt, [string]$Expected) {
    if ([Console]::IsInputRedirected) {
        Stop-Run 'stdin is not interactive; explicit approval is required' 5
    }
    $answer = Read-Host $Prompt
    return ($answer.Trim() -eq $Expected)
}

if (-not $IsLinux) { Stop-Run 'this workflow is for Linux only' }
if ((id -u) -eq '0') { Stop-Run 'do not run the lab as root' }
foreach ($path in @($Python, $Catalog, $Report, $Verify, $AtomicsPath)) {
    if (-not (Test-Path $path)) { Stop-Run "missing $path (run preflight.sh)" }
}
Import-Module invoke-atomicredteam -ErrorAction Stop
$ModuleVersion = (Get-Module invoke-atomicredteam).Version.ToString()

# 1. Resolve the test from two sources that must agree.
$meta = & $Python $Catalog --atomics $AtomicsPath show --guid $TestGuid --json
if ($LASTEXITCODE -ne 0) { Stop-Run "no Linux Atomic test with GUID $TestGuid" 3 }
$meta = $meta | ConvertFrom-Json
$yaml = Join-Path $AtomicsPath "$($meta.technique)/$($meta.technique).yaml"
$technique = Get-AtomicTechnique -Path $yaml
$test = $technique.atomic_tests | Where-Object { $_.auto_generated_guid -eq $TestGuid }
if (-not $test) { Stop-Run "GUID $TestGuid not found in $yaml" 3 }
if ($test.supported_platforms -notcontains 'linux') { Stop-Run 'test does not support Linux' }

# 2-3. Full official details and risk triage.
Section "ATOMIC TEST: $($meta.technique) #$($meta.number) $($meta.name)"
Invoke-AtomicTest $meta.technique -TestGuids $TestGuid -PathToAtomicsFolder $AtomicsPath -ShowDetails
Section 'RISK, PRIVILEGES, PREREQUISITES AND ENGINE VIEW'
& $Python $Catalog --atomics $AtomicsPath show --guid $TestGuid
switch ($meta.risk) {
    'C' { Stop-Run 'class C (destructive or unsafe) tests are never run by this workflow' }
    'B' {
        if (-not $AllowReviewRequired) {
            Stop-Run 'class B test: review the commands above, then rerun with -AllowReviewRequired'
        }
    }
}

# 4. Privileges and prerequisites.
if ($meta.elevation_required) {
    Stop-Run 'the test requires root (elevation_required). This workflow does not elevate; run it manually only after a separate authorization and review.'
}
if (@($meta.dependencies).Count -gt 0) {
    Stop-Run "the test has prerequisites. This workflow never runs prerequisite commands. Review them, then check manually with: Invoke-AtomicTest $($meta.technique) -TestGuids $TestGuid -CheckPrereqs"
}

# 5. The engine must be monitoring.
$engineStart = Get-EngineStatus
if (-not $engineStart.running) {
    if (-not $DryRun) {
        Stop-Run "the engine is not monitoring $EngineDb ($($engineStart.reason)). Start it first: python -m runtime_engine.main --db $EngineDb monitor"
    }
    Write-Host "WARNING: engine not running ($($engineStart.reason)); continuing because of -DryRun" -ForegroundColor Yellow
}
else {
    Write-Host "Engine monitoring: session $($engineStart.session_id), PID $($engineStart.engine_pid), poll $($engineStart.poll_interval_seconds) s" -ForegroundColor Green
}

# 6. Snapshot, then explicit approval.
$runId = "{0}-{1}-{2}" -f (Get-Date -AsUTC -Format 'yyyyMMddTHHmmssZ'), $meta.technique, $TestGuid.Substring(0, 8)
$runDir = Join-Path ([IO.Path]::GetFullPath($ResultsDir)) $runId
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
chmod 700 $runDir
& $Verify snapshot $runDir | Out-Null
# Taken before approval so these helper processes start well before the test window.
$identity = (& $Python $Report identity --pid $PID) | ConvertFrom-Json

$execution = [ordered]@{ status = 'NOT_EXECUTED'; exit_code = $null; executor_pid = $null; log_path = $null }
$cleanup = [ordered]@{ status = 'NOT_RUN'; verification = $null; command = $meta.rendered_cleanup }
$prefix = $TestGuid.Substring(0, 8)
Section 'APPROVAL'
Write-Host "Exact command (executor: $($meta.executor), as user $(id -un)):"
Write-Host $meta.rendered_command
if ($DryRun) {
    Write-Host 'DRY RUN: the test will not be executed.' -ForegroundColor Yellow
}
elseif (-not (Approve "Type '$prefix' to execute exactly this test, anything else to abort" $prefix)) {
    Stop-Run 'not approved by the operator' 6
}

# 7. Execute only this test.
$start = [DateTime]::UtcNow
if (-not $DryRun) {
    $log = Join-Path $runDir 'execution-log.csv'
    $execution.log_path = $log
    Invoke-AtomicTest $meta.technique -TestGuids $TestGuid -PathToAtomicsFolder $AtomicsPath `
        -ExecutionLogPath $log -LoggingModule 'Default-ExecutionLogger' -TimeoutSeconds $TimeoutSeconds *>&1 |
        Tee-Object -FilePath (Join-Path $runDir 'test-output.txt')
    if (Test-Path $log) {
        $row = @(Import-Csv $log)[-1]
        $execution.exit_code = [int]$row.ExitCode
        $execution.executor_pid = [int]$row.ProcessId
        $execution.status = if ($execution.exit_code -eq 0) { 'COMPLETED' } else { 'FAILED' }
    }
    else {
        $execution.status = 'FAILED'
    }
}
$end = [DateTime]::UtcNow

# Let the engine finish at least one more poll before correlating.
$poll = if ($engineStart.running) { [double]$engineStart.poll_interval_seconds } else { 2.0 }
Start-Sleep -Milliseconds ([int](($poll + 1.5) * 1000))
$engineEnd = Get-EngineStatus

# 8. Cleanup after review and a second approval.
$absent = @()
$profiles = & $Python -c "import sys, yaml, json; print(json.dumps(yaml.safe_load(open(sys.argv[1])).get(sys.argv[2], {})))" $Expectations $TestGuid | ConvertFrom-Json
if ($profiles -and $profiles.PSObject.Properties.Name -contains 'cleanup_paths') { $absent = @($profiles.cleanup_paths) }
if ([string]::IsNullOrWhiteSpace($meta.rendered_cleanup)) {
    $cleanup.status = 'NOT REQUIRED'
}
elseif ($DryRun) {
    $cleanup.status = 'NOT_RUN (dry run)'
}
else {
    Section 'CLEANUP'
    Write-Host 'Cleanup command defined by the test:'
    Write-Host $meta.rendered_cleanup
    if (Approve "Type 'cleanup' to run exactly this cleanup command" 'cleanup') {
        Invoke-AtomicTest $meta.technique -TestGuids $TestGuid -PathToAtomicsFolder $AtomicsPath `
            -Cleanup -NoExecutionLog -TimeoutSeconds $TimeoutSeconds *>&1 |
            Tee-Object -FilePath (Join-Path $runDir 'cleanup-output.txt')
        $cleanup.status = 'COMPLETED'
    }
    else {
        $cleanup.status = 'SKIPPED BY OPERATOR'
        Write-Host 'Cleanup skipped: the test changes listed above remain on this system.' -ForegroundColor Yellow
    }
}
$verifyArgs = @('verify', $runDir) + ($absent | ForEach-Object { '--absent', $_ })
& $Verify @verifyArgs | Tee-Object -FilePath (Join-Path $runDir 'cleanup-verification.txt')
$verified = $LASTEXITCODE -eq 0
$cleanup.verification = if ($verified) { 'PASS' } else { 'FAIL' }
if (-not $verified -and $cleanup.status -eq 'COMPLETED') { $cleanup.status = 'FAILED' }

# 9. Record and report.
$sameSession = $engineStart.running -and $engineEnd.running -and ($engineStart.session_id -eq $engineEnd.session_id)
$record = [ordered]@{
    run_id            = $runId
    guid              = $TestGuid
    technique         = $meta.technique
    technique_name    = $meta.technique_name
    test_number       = $meta.number
    test_name         = $meta.name
    executor          = $meta.executor
    risk_class        = "$($meta.risk) $($meta.risk_label)"
    command           = $meta.rendered_command
    elevation_required = $meta.elevation_required
    start_utc         = $start.ToString('o')
    end_utc           = $end.ToString('o')
    runner            = [ordered]@{ pid = $PID; key = $identity.key; user = (id -un) }
    execution         = $execution
    cleanup           = $cleanup
    engine            = [ordered]@{
        db                    = $EngineDb
        session_id            = $engineStart.session_id
        poll_interval_seconds = $poll
        running_at_start      = [bool]$engineStart.running
        running_at_end        = [bool]$engineEnd.running
        active_for_window     = [bool]$sameSession
    }
    atomics_path      = $AtomicsPath
    atomics_commit    = (git -C (Split-Path $AtomicsPath) rev-parse HEAD)
    module_version    = $ModuleVersion
    dry_run           = [bool]$DryRun
}
$recordPath = Join-Path $runDir 'record.json'
$record | ConvertTo-Json -Depth 5 | Set-Content -Path $recordPath -Encoding utf8
chmod 600 $recordPath
Section 'REPORT'
& $Python $Report report --record $recordPath --db $EngineDb --expectations $Expectations --out $runDir
Write-Host "Run directory: $runDir"
