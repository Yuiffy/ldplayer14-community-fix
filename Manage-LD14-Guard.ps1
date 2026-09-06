param(
    [ValidateSet('Install', 'Start', 'Status', 'Stop', 'Uninstall')]
    [string]$Action = 'Status',
    [string]$Python,
    [string]$DependencyDir
)

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$guardScript = Join-Path $root 'experimental\ld14-guard.py'
$localConfig = Join-Path $root '.ld14-guard-local.json'
$startupDirectory = [Environment]::GetFolderPath('Startup')
$startupShortcut = Join-Path $startupDirectory 'LD14 Community Fix Guard.lnk'
$taskDescription = 'LD14 Community Fix Guard - repository: ' + $root
$hasher = [Security.Cryptography.SHA256]::Create()
try {
    $rootHash = [BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($root.ToLowerInvariant())))
}
finally { $hasher.Dispose() }
$taskName = 'LD14 Community Fix Guard-' + $rootHash.Replace('-', '').Substring(0, 12)
$saved = $null
if (Test-Path -LiteralPath $localConfig) {
    $saved = Get-Content -LiteralPath $localConfig -Raw -Encoding UTF8 | ConvertFrom-Json
}
if (-not $Python -and $saved) { $Python = $saved.python }
if (-not $DependencyDir -and $saved) { $DependencyDir = $saved.dependency_dir }
if (-not $Python) {
    $command = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($command) { $Python = $command.Source }
}
if (-not $Python) { throw 'Supply -Python with the path to 64-bit Python 3.10 or newer.' }
$Python = (Resolve-Path -LiteralPath $Python).Path
if ($DependencyDir) { $DependencyDir = (Resolve-Path -LiteralPath $DependencyDir).Path }

function Invoke-Guard {
    param([string[]]$GuardArguments)
    $arguments = @($guardScript) + $GuardArguments
    $output = & $Python @arguments
    if ($LASTEXITCODE -ne 0) { throw 'The LD14 guard command failed.' }
    return ($output | Out-String | ConvertFrom-Json)
}

function Stop-Guard {
    $result = Invoke-Guard @('--stop')
    for ($attempt = 0; $attempt -lt 20 -and $result.running; $attempt++) {
        Start-Sleep -Seconds 1
        $result = Invoke-Guard @('--status')
    }
    if ($result.running) { throw 'The guard is still stopping. Check logs\guard\status.json; the process was not killed.' }
    return $result
}

function Get-OwnedShortcut {
    if (-not (Test-Path -LiteralPath $startupShortcut)) { return $null }
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($startupShortcut)
    if ($shortcut.Description -ne 'LD14 Community Fix Guard - experimental dual process fixes') {
        throw "An unrelated shortcut already exists at $startupShortcut"
    }
    return $shortcut
}

function Get-OwnedTask {
    $task = Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object { $_.TaskName -eq $taskName }
    if (-not $task) { return $null }
    if ($task.Description -ne $taskDescription -or @($task.Actions).Count -ne 1 -or
        -not $task.Actions[0].Arguments.StartsWith('"' + $guardScript + '" --run ')) {
        throw "An unrelated scheduled task already exists: $taskName"
    }
    return $task
}

function Add-ManagementStatus {
    param($Result, $Task)
    $legacyStartup = Test-Path -LiteralPath $startupShortcut
    $taskDetails = $null
    $loginStartup = $legacyStartup
    if ($Task) {
        $info = Get-ScheduledTaskInfo -InputObject $Task
        $loginStartup = $legacyStartup -or ($Task.Settings.Enabled -and @($Task.Triggers).Count -gt 0)
        $taskDetails = [ordered]@{
            name = $Task.TaskName
            state = [string]$Task.State
            enabled = $Task.Settings.Enabled
            last_result = ('0x{0:X8}' -f $info.LastTaskResult)
            last_run_time = $info.LastRunTime.ToString('o')
            execution_time_limit = $Task.Settings.ExecutionTimeLimit
        }
    }
    $Result | Add-Member -NotePropertyName login_startup -NotePropertyValue $loginStartup -Force
    $Result | Add-Member -NotePropertyName legacy_startup_shortcut -NotePropertyValue $legacyStartup -Force
    $Result | Add-Member -NotePropertyName scheduled_task -NotePropertyValue $taskDetails -Force
    return $Result
}

$task = Get-OwnedTask
if ($Action -eq 'Status') {
    $result = Invoke-Guard @('--status')
    Add-ManagementStatus $result $task | ConvertTo-Json -Depth 8
    exit 0
}
if ($Action -eq 'Stop') {
    if ($task) { Disable-ScheduledTask -InputObject $task | Out-Null }
    $result = Stop-Guard
    Add-ManagementStatus $result (Get-OwnedTask) | ConvertTo-Json -Depth 8
    exit 0
}
if ($Action -eq 'Uninstall') {
    $shortcut = Get-OwnedShortcut
    if ($task) { Disable-ScheduledTask -InputObject $task | Out-Null }
    Stop-Guard | ConvertTo-Json -Depth 8
    if ($task) { Unregister-ScheduledTask -InputObject $task -Confirm:$false }
    if ($shortcut) { Remove-Item -LiteralPath $startupShortcut -ErrorAction Stop }
    Write-Output 'Login startup removed. Restart LD14 to also remove its process-local semaphore patch.'
    exit 0
}

$probe = "import sys,ctypes; sys.path.insert(0,sys.argv[1]) if sys.argv[1]!='-' else None; import frida; assert sys.version_info >= (3,10) and ctypes.sizeof(ctypes.c_void_p)==8; assert frida.__version__=='17.17.0'; print(sys.executable)"
$probeDirectory = if ($DependencyDir) { $DependencyDir } else { '-' }
& $Python -c $probe $probeDirectory
if ($LASTEXITCODE -ne 0) { throw 'Python or Frida validation failed. Install frida==17.17.0 or supply -DependencyDir.' }
$pythonw = Join-Path (Split-Path -Parent $Python) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonw -PathType Leaf)) { throw "Missing background interpreter: $pythonw" }
Invoke-Guard @('--status') | Out-Null
$backgroundArguments = '"' + $guardScript + '" --run --launcher task-scheduler'
if ($DependencyDir) { $backgroundArguments += ' --dependency-dir "' + $DependencyDir + '"' }

$shortcut = Get-OwnedShortcut
$enableLogon = $Action -eq 'Install' -or $null -ne $shortcut -or ($task -and @($task.Triggers).Count -gt 0)
$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$taskAction = New-ScheduledTaskAction -Execute $pythonw -Argument $backgroundArguments -WorkingDirectory $root
$principal = New-ScheduledTaskPrincipal -UserId $currentUser -LogonType Interactive -RunLevel Limited
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
$taskParameters = @{
    Action = $taskAction
    Principal = $principal
    Settings = $settings
    Description = $taskDescription
}
if ($enableLogon) { $taskParameters.Trigger = New-ScheduledTaskTrigger -AtLogOn -User $currentUser }
$definition = New-ScheduledTask @taskParameters
$task = Register-ScheduledTask -TaskName $taskName -InputObject $definition -Force
$configuration = @{ python = $Python; dependency_dir = $DependencyDir } | ConvertTo-Json
[IO.File]::WriteAllText($localConfig, $configuration, [Text.UTF8Encoding]::new($false))

$result = Invoke-Guard @('--status')
if ($result.running -and $result.launcher -ne 'task-scheduler') {
    # Migrate an existing direct launch through its normal hook cleanup path.
    $result = Stop-Guard
}
if (-not $result.running) {
    Start-ScheduledTask -InputObject $task
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        Start-Sleep -Seconds 1
        $result = Invoke-Guard @('--status')
        if ($result.running -and $result.state -notin @('starting', 'applying')) { break }
    }
}
if ($result.running -and $result.state -ne 'unresponsive' -and $shortcut) {
    Remove-Item -LiteralPath $startupShortcut -ErrorAction Stop
}
Add-ManagementStatus $result (Get-OwnedTask) | ConvertTo-Json -Depth 8
if (-not $result.running -or $result.state -in @('blocked', 'failed', 'unresponsive', 'starting', 'applying')) {
    throw 'Both fixes are not active. Check the guard state, controller.log and scheduled task result.'
}
