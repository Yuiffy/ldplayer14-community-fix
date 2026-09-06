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

if ($Action -eq 'Status') {
    $result = Invoke-Guard @('--status')
    $result | Add-Member -NotePropertyName login_startup -NotePropertyValue (Test-Path -LiteralPath $startupShortcut) -Force
    $result | ConvertTo-Json -Depth 8
    exit 0
}
if ($Action -eq 'Stop') {
    Stop-Guard | ConvertTo-Json -Depth 8
    exit 0
}
if ($Action -eq 'Uninstall') {
    $shortcut = Get-OwnedShortcut
    Stop-Guard | ConvertTo-Json -Depth 8
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
$configuration = @{ python = $Python; dependency_dir = $DependencyDir } | ConvertTo-Json
[IO.File]::WriteAllText($localConfig, $configuration, [Text.UTF8Encoding]::new($false))
$backgroundArguments = '"' + $guardScript + '" --run'
if ($DependencyDir) { $backgroundArguments += ' --dependency-dir "' + $DependencyDir + '"' }

if ($Action -eq 'Install') {
    $shortcut = Get-OwnedShortcut
    if (-not $shortcut) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($startupShortcut)
    }
    $shortcut.TargetPath = $pythonw
    $shortcut.Arguments = $backgroundArguments
    $shortcut.WorkingDirectory = $root
    $shortcut.Description = 'LD14 Community Fix Guard - experimental dual process fixes'
    $shortcut.WindowStyle = 7
    $shortcut.Save()
    Write-Output "Login startup: $startupShortcut"
}

$result = Invoke-Guard @('--status')
if (-not $result.running) {
    $process = Start-Process -FilePath $pythonw -ArgumentList $backgroundArguments -WorkingDirectory $root -WindowStyle Hidden -PassThru
    for ($attempt = 0; $attempt -lt 15; $attempt++) {
        Start-Sleep -Seconds 1
        $result = Invoke-Guard @('--status')
        if ($result.running -and $result.state -notin @('starting', 'applying')) { break }
        if ($process.HasExited) { throw 'The guard stopped during startup. Check logs\guard\status.json.' }
    }
}
$result | ConvertTo-Json -Depth 8
if (-not $result.running -or $result.state -in @('blocked', 'failed')) {
    throw 'Both fixes are not active. Review the reported guard state before testing.'
}
