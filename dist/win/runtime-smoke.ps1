<#
.SYNOPSIS
	Deterministic, time-bounded runtime smoke harness for the Windows ARM64 Cryptomator app-image.

.DESCRIPTION
	Drives the real, unmodified app-image through launch -> add vault -> unlock ->
	file round trip -> lock and quit, repeated -Repetitions times, and fails if any
	cycle does not reach a clean `Exit 0` or leaves a JVM fatal-error log behind.

	Runtime policy enforced by this harness:
	  * every wait is bounded by an explicit, operation-specific timeout;
	  * every cycle is additionally bounded by -RunTimeoutSec;
	  * on timeout or failure the app is first closed gracefully (WM_SYSCOMMAND/SC_CLOSE)
	    for -GracefulCloseSec, and only then terminated by exact process id;
	  * termination is limited to the launched process and descendants whose parent chain
	    and creation time prove they belong to this launch - never by process name;
	  * the timeout, process ids, command line, elapsed time and cleanup outcome are
	    recorded in runtime-smoke-result.json as failure evidence.

	The app is isolated through _JAVA_OPTIONS, so the packaged Cryptomator.cfg does not
	have to be modified and the developer profile is never touched.

	The launch/unlock smoke path drives the UI with Win32 SendInput. PostMessage remains
	available for focus-free experiments, but Auto deliberately fails fast on a locked
	session because PostMessage does not reliably drive the JavaFX unlock dialog. The
	harness never attaches a UI Automation client, because a single UIA tree query is a reproducible fatal-crash
	trigger for JavaFX 25.0.3 windows on Windows 11 ARM64 (build 26571): the Glass
	accessibility bridge answers WM_GETOBJECT with an outgoing COM call, Windows
	rejects it with RPC_E_CANTCALLOUT_ININPUTSYNCCALL (0x8001010d) as a non-continuable
	software exception, and HotSpot turns that into
	"Internal Error (0x8001010d) ... JavaFX Application Thread".
	Run -Mode AccessibilityProbe to check whether that platform defect is still present.

.EXAMPLE
	pwsh -File .\dist\win\runtime-smoke.ps1 -VaultPath D:\demo-vault -VaultPassword 'secret' -Repetitions 3

.EXAMPLE
	pwsh -File .\dist\win\runtime-smoke.ps1 -VaultPath D:\demo-vault -VaultPassword 'secret' -Mode AccessibilityProbe
#>
[CmdletBinding()]
Param(
	[string] $AppImage = (Join-Path (Split-Path -Parent $PSCommandPath) 'Cryptomator'),
	[Parameter(Mandatory = $true)][string] $VaultPath,
	[Parameter(Mandatory = $true)][string] $VaultPassword,
	[string] $WorkDir = (Join-Path (Split-Path -Parent $PSCommandPath) '.runtime-smoke'),
	[int] $Repetitions = 3,
	[ValidateSet('Launch', 'AccessibilityProbe')][string] $Mode = 'Launch',
	[switch] $DisableAccessibilityBridge,
	[string] $LoopbackAlias = 'cryptomator-vault',

	# explicit timeouts; no wait in this script is unbounded
	[int] $LaunchTimeoutSec = 60,
	[int] $UiActionTimeoutSec = 30,
	[int] $UnlockTimeoutSec = 60,
	[int] $ShutdownTimeoutSec = 60,
	[int] $GracefulCloseSec = 10,
	[int] $RunTimeoutSec = 300,

	# SendInput needs an unlocked interactive desktop. PostMessage can reach locked-session
	# windows but does not reliably drive the JavaFX unlock dialog, so Auto fails fast if locked.
	[ValidateSet('Auto', 'SendInput', 'PostMessage')][string] $InputTransport = 'Auto'
)

$ErrorActionPreference = 'Stop'

Add-Type -Namespace CryptomatorSmoke -Name Win32 -MemberDefinition @'
[DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
[DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
[DllImport("user32.dll", CharSet = CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, System.Text.StringBuilder text, int count);
[DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
[DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
[DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
[DllImport("user32.dll")] public static extern void SwitchToThisWindow(IntPtr hWnd, bool fAltTab);
[DllImport("user32.dll")] public static extern bool BringWindowToTop(IntPtr hWnd);
[DllImport("user32.dll")] public static extern bool AttachThreadInput(uint idAttach, uint idAttachTo, bool fAttach);
[DllImport("user32.dll", CharSet = CharSet.Auto)] public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);
[DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId();
[DllImport("user32.dll", SetLastError = true)] public static extern IntPtr OpenInputDesktop(uint dwFlags, bool fInherit, uint dwDesiredAccess);
[DllImport("user32.dll")] public static extern bool CloseDesktop(IntPtr hDesktop);

// Returns true when this session has a usable, unlocked interactive desktop. OpenInputDesktop
// alone is not sufficient on Windows 11: while the session is locked, LockApp owns the
// foreground window on the default desktop and no other window can be activated.
public static bool IsInputDesktopAvailable() {
	IntPtr d = OpenInputDesktop(0, false, 0x0100 /* DESKTOP_SWITCHDESKTOP */);
	if (d == IntPtr.Zero) return false;
	CloseDesktop(d);

	IntPtr fg = GetForegroundWindow();
	if (fg == IntPtr.Zero) return false;
	uint pid;
	GetWindowThreadProcessId(fg, out pid);
	try {
		var p = System.Diagnostics.Process.GetProcessById((int) pid);
		if (string.Equals(p.ProcessName, "LockApp", StringComparison.OrdinalIgnoreCase)) return false;
		if (string.Equals(p.ProcessName, "LogonUI", StringComparison.OrdinalIgnoreCase)) return false;
	} catch { }
	return true;
}

public static string ForegroundOwner() {
	IntPtr fg = GetForegroundWindow();
	if (fg == IntPtr.Zero) return "none";
	uint pid;
	GetWindowThreadProcessId(fg, out pid);
	try { return System.Diagnostics.Process.GetProcessById((int) pid).ProcessName; } catch { return "pid:" + pid; }
}

// Focus-free keyboard delivery: messages are posted straight to the target window, which works
// even when the interactive desktop is locked and SendInput cannot reach the app.
public static void PostText(IntPtr hWnd, string text) {
	foreach (char c in text) {
		PostMessage(hWnd, 0x0102 /* WM_CHAR */, (IntPtr) c, IntPtr.Zero);
	}
}

public static void PostKey(IntPtr hWnd, ushort vk, char ch) {
	PostMessage(hWnd, 0x0100 /* WM_KEYDOWN */, (IntPtr) vk, IntPtr.Zero);
	if (ch != '\0') PostMessage(hWnd, 0x0102 /* WM_CHAR */, (IntPtr) ch, IntPtr.Zero);
	PostMessage(hWnd, 0x0101 /* WM_KEYUP */, (IntPtr) vk, IntPtr.Zero);
}

[StructLayout(LayoutKind.Sequential)] public struct KEYBDINPUT { public ushort wVk; public ushort wScan; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
[StructLayout(LayoutKind.Sequential)] public struct MOUSEINPUT { public int dx; public int dy; public uint mouseData; public uint dwFlags; public uint time; public IntPtr dwExtraInfo; }
[StructLayout(LayoutKind.Explicit)] public struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
[StructLayout(LayoutKind.Sequential)] public struct INPUT { public uint type; public INPUTUNION u; }
[DllImport("user32.dll", SetLastError = true)] public static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

public static IntPtr FindWindow(uint pid, string titlePrefix) {
	IntPtr found = IntPtr.Zero;
	EnumWindows((h, l) => {
		uint p; GetWindowThreadProcessId(h, out p);
		if (p == pid && IsWindowVisible(h)) {
			var t = new System.Text.StringBuilder(512); GetWindowTextW(h, t, 512);
			if (t.ToString().StartsWith(titlePrefix, StringComparison.OrdinalIgnoreCase)) { found = h; return false; }
		}
		return true;
	}, IntPtr.Zero);
	return found;
}

public static System.Collections.Generic.List<string> ListWindows(uint pid) {
	var list = new System.Collections.Generic.List<string>();
	EnumWindows((h, l) => {
		uint p; GetWindowThreadProcessId(h, out p);
		if (p == pid && IsWindowVisible(h)) {
			var t = new System.Text.StringBuilder(512); GetWindowTextW(h, t, 512);
			list.Add(h.ToInt64() + "|" + t.ToString());
		}
		return true;
	}, IntPtr.Zero);
	return list;
}

public static System.Collections.Generic.List<long> ListWindowHandles(uint pid) {
	var list = new System.Collections.Generic.List<long>();
	EnumWindows((h, l) => {
		uint p; GetWindowThreadProcessId(h, out p);
		if (p == pid && IsWindowVisible(h)) list.Add(h.ToInt64());
		return true;
	}, IntPtr.Zero);
	return list;
}

public static void TypeText(string text) {
	var inputs = new System.Collections.Generic.List<INPUT>();
	foreach (char c in text) {
		var down = new INPUT { type = 1 }; down.u.ki = new KEYBDINPUT { wScan = c, dwFlags = 0x0004 };
		var up = new INPUT { type = 1 }; up.u.ki = new KEYBDINPUT { wScan = c, dwFlags = 0x0006 };
		inputs.Add(down); inputs.Add(up);
	}
	if (inputs.Count > 0) SendInput((uint) inputs.Count, inputs.ToArray(), Marshal.SizeOf(typeof(INPUT)));
}

public static void TapKey(ushort vk) {
	var inputs = new INPUT[2];
	inputs[0].type = 1; inputs[0].u.ki = new KEYBDINPUT { wVk = vk };
	inputs[1].type = 1; inputs[1].u.ki = new KEYBDINPUT { wVk = vk, dwFlags = 0x0002 };
	SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT)));
}

public static void AltF4() {
	var i = new INPUT[4];
	i[0].type = 1; i[0].u.ki = new KEYBDINPUT { wVk = 0x12 };
	i[1].type = 1; i[1].u.ki = new KEYBDINPUT { wVk = 0x73 };
	i[2].type = 1; i[2].u.ki = new KEYBDINPUT { wVk = 0x73, dwFlags = 0x0002 };
	i[3].type = 1; i[3].u.ki = new KEYBDINPUT { wVk = 0x12, dwFlags = 0x0002 };
	SendInput(4, i, Marshal.SizeOf(typeof(INPUT)));
}

// Windows only lets the foreground process change the foreground window. Synthesising an ALT
// keystroke marks this process as having recent input; if that is not enough, temporarily share
// the input queue with the current foreground thread.
public static bool ForceForeground(IntPtr hWnd) {
	ShowWindow(hWnd, 9);
	BringWindowToTop(hWnd);
	if (SetForegroundWindow(hWnd) && GetForegroundWindow() == hWnd) return true;

	TapKey(0x12);
	SetForegroundWindow(hWnd);
	if (GetForegroundWindow() == hWnd) return true;

	uint fgPid;
	uint fgThread = GetWindowThreadProcessId(GetForegroundWindow(), out fgPid);
	uint self = GetCurrentThreadId();
	if (fgThread != self) {
		AttachThreadInput(self, fgThread, true);
		BringWindowToTop(hWnd);
		SetForegroundWindow(hWnd);
		SwitchToThisWindow(hWnd, true);
		AttachThreadInput(self, fgThread, false);
	}
	return GetForegroundWindow() == hWnd;
}
'@

# ---------------------------------------------------------------------------
# process ownership: only processes whose parent chain and creation time prove
# they belong to this launch may ever be closed or terminated
# ---------------------------------------------------------------------------

function Update-OwnedProcesses {
	param([hashtable] $Owned, [int] $RootProcessId, [datetime] $NotBefore)

	if ($RootProcessId -le 0) { return $Owned }

	$all = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
			Select-Object ProcessId, ParentProcessId, Name, CreationDate, CommandLine)
	if ($all.Count -eq 0) { return $Owned }

	$byParent = @{}
	foreach ($p in $all) {
		$key = [int] $p.ParentProcessId
		if (-not $byParent.ContainsKey($key)) { $byParent[$key] = @() }
		$byParent[$key] += $p
	}

	$toRecord = {
		param($proc)
		[pscustomobject]@{
			ProcessId       = [int] $proc.ProcessId
			ParentProcessId = [int] $proc.ParentProcessId
			Name            = $proc.Name
			CreationDate    = $proc.CreationDate
			CommandLine     = $proc.CommandLine
		}
	}

	if (-not $Owned.ContainsKey($RootProcessId)) {
		$root = $all | Where-Object { [int] $_.ProcessId -eq $RootProcessId -and $_.CreationDate -ge $NotBefore } | Select-Object -First 1
		if ($root) { $Owned[$RootProcessId] = & $toRecord $root }
	}

	# breadth-first from every process already proven to belong to this launch, so ownership
	# survives the intermediate launcher exiting
	$queue = [System.Collections.Queue]::new()
	foreach ($o in @($Owned.Values)) { $queue.Enqueue($o) }
	while ($queue.Count -gt 0) {
		$current = $queue.Dequeue()
		foreach ($child in @($byParent[[int] $current.ProcessId])) {
			if ($null -eq $child) { continue }
			$childId = [int] $child.ProcessId
			if ($Owned.ContainsKey($childId)) { continue }
			# a child must have been created after its parent and after this launch started,
			# which rules out an unrelated process that merely reuses the parent's pid
			if ($child.CreationDate -ge $current.CreationDate -and $child.CreationDate -ge $NotBefore) {
				$record = & $toRecord $child
				$Owned[$childId] = $record
				$queue.Enqueue($record)
			}
		}
	}
	return $Owned
}

function Test-OwnedProcessAlive {
	param([pscustomobject] $Owned)

	$live = Get-CimInstance Win32_Process -Filter "ProcessId = $($Owned.ProcessId)" -ErrorAction SilentlyContinue |
		Select-Object -First 1
	if (-not $live) { return $false }
	# guard against pid reuse: the creation time must still match the one we recorded
	return ([math]::Abs(($live.CreationDate - $Owned.CreationDate).TotalSeconds) -lt 1)
}

function Stop-OwnedProcesses {
	param([hashtable] $Owned, [int] $GracefulSeconds, [string] $Reason)

	$report = [ordered]@{
		reason              = $Reason
		gracefulSeconds     = $GracefulSeconds
		requested           = @()
		gracefullyExited    = @()
		forceTerminated     = @()
		exitedWhileStopping = @()
		pidReuseSkipped     = @()
		stillRunning        = @()
	}

	$alive = @($Owned.Values | Where-Object { Test-OwnedProcessAlive -Owned $_ })
	$report.requested = @($alive | ForEach-Object { $_.ProcessId })
	if ($alive.Count -eq 0) { return $report }

	foreach ($p in $alive) {
		foreach ($h in [CryptomatorSmoke.Win32]::ListWindowHandles([uint32] $p.ProcessId)) {
			[CryptomatorSmoke.Win32]::PostMessage([IntPtr] $h, 0x0112, [IntPtr] 0xF060, [IntPtr]::Zero) | Out-Null
		}
	}

	$deadline = (Get-Date).AddSeconds($GracefulSeconds)
	while ((Get-Date) -lt $deadline) {
		$alive = @($alive | Where-Object { Test-OwnedProcessAlive -Owned $_ })
		if ($alive.Count -eq 0) { break }
		Start-Sleep -Milliseconds 500
	}
	$report.gracefullyExited = @($report.requested | Where-Object { $_ -notin @($alive | ForEach-Object { $_.ProcessId }) })

	# children first, so a parent cannot respawn a supervised child while we terminate
	foreach ($p in @($alive | Sort-Object CreationDate -Descending)) {
		if (-not (Test-OwnedProcessAlive -Owned $p)) { $report.exitedWhileStopping += $p.ProcessId; continue }
		$current = Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
		if (-not $current) { $report.exitedWhileStopping += $p.ProcessId; continue }
		if ([math]::Abs(($current.StartTime - $p.CreationDate).TotalSeconds) -ge 2) {
			$report.pidReuseSkipped += $p.ProcessId
			continue
		}
		Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
		$report.forceTerminated += $p.ProcessId
	}

	Start-Sleep -Milliseconds 500
	$report.stillRunning = @($Owned.Values | Where-Object { Test-OwnedProcessAlive -Owned $_ } | ForEach-Object { $_.ProcessId })
	return $report
}

# ---------------------------------------------------------------------------
# bounded waits
# ---------------------------------------------------------------------------

function Get-BoundedSeconds {
	param([int] $Requested, [datetime] $RunDeadline)
	$remaining = [int][math]::Floor(($RunDeadline - (Get-Date)).TotalSeconds)
	if ($remaining -le 0) { throw "run budget exhausted (RunTimeoutSec)" }
	return [math]::Min($Requested, $remaining)
}

function Get-RemainingSeconds {
	# never throws: used by cleanup paths that must still be bounded after a budget overrun
	param([int] $Requested, [datetime] $RunDeadline)
	$remaining = [int][math]::Floor(($RunDeadline - (Get-Date)).TotalSeconds)
	if ($remaining -lt 0) { $remaining = 0 }
	return [math]::Max(0, [math]::Min($Requested, $remaining))
}

function Get-DriveIdentity {
	param([string] $DriveLetter)

	$id = [ordered]@{
		driveLetter = $DriveLetter
		root        = "$DriveLetter`:\"
	}
	$info = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq "$DriveLetter`:\" } | Select-Object -First 1
	if ($info) {
		$id['driveInfoType'] = [string] $info.DriveType
		$id['driveInfoReady'] = $info.IsReady
		if ($info.IsReady) {
			$id['driveFormat'] = $info.DriveFormat
			$id['volumeLabel'] = $info.VolumeLabel
			$id['totalSizeBytes'] = $info.TotalSize
		}
	}
	$cim = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID = '$DriveLetter`:'" -ErrorAction SilentlyContinue | Select-Object -First 1
	if ($cim) {
		$id['cimDriveType'] = $cim.DriveType
		$id['cimProviderName'] = $cim.ProviderName
		$id['cimVolumeName'] = $cim.VolumeName
		$id['cimFileSystem'] = $cim.FileSystem
		$id['cimVolumeSerialNumber'] = $cim.VolumeSerialNumber
	}
	$psDrive = Get-PSDrive -Name $DriveLetter -ErrorAction SilentlyContinue
	if ($psDrive) { $id['psDriveDisplayRoot'] = $psDrive.DisplayRoot }
	return [pscustomobject] $id
}

function Resolve-VaultDrive {
	<#
		Binds the round trip to the drive that Cryptomator actually published for THIS vault.
		A drive qualifies only when its provider/UNC identity matches the configured loopback
		alias and the configured vault display name. A drive is never used just because it
		appeared after launch.
	#>
	param(
		[string[]] $DrivesBefore,
		[string] $Alias,
		[string] $VaultDisplayName,
		[int] $TimeoutSeconds
	)

	$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
	$candidates = @()
	while ((Get-Date) -lt $deadline) {
		$candidates = @()
		foreach ($letter in ((Get-PSDrive -PSProvider FileSystem).Name | Where-Object { $DrivesBefore -notcontains $_ })) {
			$identity = Get-DriveIdentity -DriveLetter $letter
			$unc = @($identity.cimProviderName, $identity.psDriveDisplayRoot) | Where-Object { $_ } | Select-Object -First 1
			$aliasMatch = ($null -ne $unc) -and ($unc -like "\\$Alias\*")
			$nameMatch = ($null -ne $unc) -and ($unc -like "*\$VaultDisplayName")
			$identity | Add-Member -NotePropertyName resolvedUnc -NotePropertyValue $unc -Force
			$identity | Add-Member -NotePropertyName aliasMatch -NotePropertyValue $aliasMatch -Force
			$identity | Add-Member -NotePropertyName vaultNameMatch -NotePropertyValue $nameMatch -Force
			$candidates += $identity
			if ($aliasMatch -and $nameMatch) {
				return [pscustomobject]@{ Matched = $identity; Candidates = $candidates }
			}
		}
		Start-Sleep -Milliseconds 500
	}
	return [pscustomobject]@{ Matched = $null; Candidates = $candidates }
}

function Wait-ForOwnedWindow {
	param([hashtable] $Owned, [int] $RootProcessId, [datetime] $NotBefore, [string] $TitlePrefix, [int] $TimeoutSeconds)

	$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
	$lastRefresh = [datetime]::MinValue
	while ((Get-Date) -lt $deadline) {
		if (((Get-Date) - $lastRefresh).TotalSeconds -ge 1) {
			Update-OwnedProcesses -Owned $Owned -RootProcessId $RootProcessId -NotBefore $NotBefore | Out-Null
			$lastRefresh = Get-Date
		}
		foreach ($p in @($Owned.Values)) {
			$hwnd = [CryptomatorSmoke.Win32]::FindWindow([uint32] $p.ProcessId, $TitlePrefix)
			if ($hwnd -ne [IntPtr]::Zero) { return [pscustomobject]@{ Hwnd = $hwnd; ProcessId = $p.ProcessId } }
		}
		Start-Sleep -Milliseconds 400
	}
	return $null
}

function Wait-ForLogLine {
	param([string] $LogFile, [string] $Pattern, [int] $TimeoutSeconds)

	$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
	while ((Get-Date) -lt $deadline) {
		if (Test-Path $LogFile) {
			$hit = Select-String -Path $LogFile -Pattern $Pattern -ErrorAction SilentlyContinue | Select-Object -Last 1
			if ($hit) { return $hit.Line }
		}
		Start-Sleep -Milliseconds 400
	}
	return $null
}

function Wait-ForProcessExit {
	param([pscustomobject] $Owned, [int] $TimeoutSeconds)

	$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
	while ((Get-Date) -lt $deadline) {
		if (-not (Test-OwnedProcessAlive -Owned $Owned)) { return $true }
		Start-Sleep -Milliseconds 400
	}
	return $false
}

function Invoke-Focused {
	param([IntPtr] $Hwnd, [string] $Text, [ushort[]] $Keys, [int] $FocusTimeoutSec = 10)

	if ($script:ActiveTransport -eq 'PostMessage') {
		# focus-free path: works on a locked desktop, no foreground steal required
		if ($Text) { [CryptomatorSmoke.Win32]::PostText($Hwnd, $Text) }
		foreach ($k in $Keys) {
			Start-Sleep -Milliseconds 300
			$ch = switch ($k) { 0x0D { "`r" } 0x09 { "`t" } 0x1B { [char] 27 } default { "`0" } }
			[CryptomatorSmoke.Win32]::PostKey($Hwnd, $k, $ch)
		}
		Start-Sleep -Milliseconds 300
		return
	}

	# bounded retry: the foreground lock can briefly reject the first attempt while a window
	# is still being created or while another process is finishing an activation
	$focused = $false
	$deadline = (Get-Date).AddSeconds($FocusTimeoutSec)
	while (-not $focused -and (Get-Date) -lt $deadline) {
		$focused = [CryptomatorSmoke.Win32]::ForceForeground($Hwnd)
		if (-not $focused) { Start-Sleep -Milliseconds 500 }
	}
	if (-not $focused) {
		throw "could not bring window 0x$($Hwnd.ToInt64().ToString('X')) to the foreground within $FocusTimeoutSec s (input desktop available: $([CryptomatorSmoke.Win32]::IsInputDesktopAvailable()))"
	}
	Start-Sleep -Milliseconds 400
	if ($Text) { [CryptomatorSmoke.Win32]::TypeText($Text) }
	foreach ($k in $Keys) {
		Start-Sleep -Milliseconds 400
		[CryptomatorSmoke.Win32]::TapKey($k)
	}
}

function Get-PeMachineType([string] $Path) {
	$stream = [System.IO.File]::OpenRead($Path)
	try {
		$reader = New-Object System.IO.BinaryReader($stream)
		$stream.Seek(0x3C, [System.IO.SeekOrigin]::Begin) > $null
		$peHeaderOffset = $reader.ReadInt32()
		$stream.Seek($peHeaderOffset + 4, [System.IO.SeekOrigin]::Begin) > $null
		return ('0x{0:X4}' -f $reader.ReadUInt16())
	} finally {
		$stream.Dispose()
	}
}

function Get-NonArm64Binaries([string] $Root) {
	$allowed = @('0xAA64', '0xA641', '0xA64E')
	return @(Get-ChildItem -Path $Root -Recurse -Include *.exe, *.dll -File | ForEach-Object {
			$machine = Get-PeMachineType $_.FullName
			if ($allowed -notcontains $machine) { [pscustomobject]@{ Path = $_.FullName; Machine = $machine } }
		})
}

# ---------------------------------------------------------------------------

$launcher = Join-Path $AppImage 'Cryptomator.exe'
if (-not (Test-Path $launcher)) { throw "app-image launcher not found: $launcher" }
if (-not (Test-Path (Join-Path $VaultPath 'vault.cryptomator'))) { throw "not a Cryptomator vault: $VaultPath" }

New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$crashDir = Join-Path $WorkDir 'crash'
New-Item -ItemType Directory -Force -Path $crashDir | Out-Null

$vaultName = Split-Path $VaultPath -Leaf
$inputDesktopAvailable = [CryptomatorSmoke.Win32]::IsInputDesktopAvailable()
$script:ActiveTransport = switch ($InputTransport) {
	'SendInput' { 'SendInput' }
	'PostMessage' { 'PostMessage' }
	default { 'SendInput' }
}
if ($Mode -eq 'Launch' -and $script:ActiveTransport -eq 'SendInput' -and -not $inputDesktopAvailable) {
	# Auto does not silently fall back: PostMessage reaches the window but was measured not to
	# drive the JavaFX unlock dialog while the session is locked, so a fallback would only
	# produce a misleading "unlock timed out" failure.
	throw "the interactive session is locked (foreground owner: $([CryptomatorSmoke.Win32]::ForegroundOwner())); SendInput cannot deliver input. Unlock the session and re-run. -InputTransport PostMessage is available for focus-free experiments but does not drive the JavaFX unlock dialog on a locked desktop."
}
Write-Host "input desktop available: $inputDesktopAvailable (foreground owner: $([CryptomatorSmoke.Win32]::ForegroundOwner())); transport: $($script:ActiveTransport)"
$nonArm64 = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { Get-NonArm64Binaries -Root $AppImage } else { @() }
$timeouts = [ordered]@{
	launchSec        = $LaunchTimeoutSec
	uiActionSec      = $UiActionTimeoutSec
	unlockSec        = $UnlockTimeoutSec
	shutdownSec      = $ShutdownTimeoutSec
	gracefulCloseSec = $GracefulCloseSec
	runSec           = $RunTimeoutSec
}

$results = @()
$repeats = if ($Mode -eq 'AccessibilityProbe') { 1 } else { $Repetitions }

for ($run = 1; $run -le $repeats; $run++) {
	$runDir = Join-Path $WorkDir "run$run"
	if (Test-Path $runDir) { Remove-Item $runDir -Recurse -Force }
	$userHome = Join-Path $runDir 'user'
	$logDir = Join-Path $userHome 'AppData\Local\Cryptomator'
	New-Item -ItemType Directory -Force -Path $userHome | Out-Null
	$appLog = Join-Path $logDir 'cryptomator0.log'
	$fwd = { param($p) $p.Replace('\', '/') }
	$ipcSocket = Join-Path $logDir 'ipc.socket'
	if ($ipcSocket.Length -gt 100) {
		throw "IPC socket path is $($ipcSocket.Length) characters; AF_UNIX paths are limited to ~108 bytes. Pass a shorter -WorkDir (for example D:\crypto-smoke)."
	}

	$jvmOptions = @(
		"-Duser.home=$(& $fwd $userHome)",
		"-Dcryptomator.settingsPath=$(& $fwd $userHome)/settings.json",
		"-Dcryptomator.logDir=$(& $fwd $logDir)",
		"-Dcryptomator.ipcSocketPath=$(& $fwd $logDir)/ipc.socket",
		"-Dcryptomator.p12Path=$(& $fwd $userHome)/key.p12",
		"-Dcryptomator.mountPointsDir=$(& $fwd $userHome)/Mounts",
		"-Dcryptomator.loopbackAlias=$LoopbackAlias",
		'-Dcryptomator.showTrayIcon=false',
		'-Dcryptomator.disableUpdateCheck=true',
		"-XX:ErrorFile=$(& $fwd $crashDir)/hs_err_run${run}_pid%p.log"
	)
	if ($DisableAccessibilityBridge) { $jvmOptions += '-Dglass.accessible.force=false' }
	# HotSpot splits _JAVA_OPTIONS on whitespace, so every option is quoted to survive paths with spaces
	$env:_JAVA_OPTIONS = (($jvmOptions | ForEach-Object { '"' + $_ + '"' }) -join ' ')

	$owned = @{}
	$runStart = Get-Date
	$runDeadline = $runStart.AddSeconds($RunTimeoutSec)
	$rootPid = 0
	$notBefore = $runStart.AddSeconds(-2)
	$stage = 'launch'
	$timedOutStage = $null
	$detail = [ordered]@{
		command  = "`"$launcher`" `"$VaultPath`""
		timeouts = $timeouts
	}

	try {
		$drivesBefore = (Get-PSDrive -PSProvider FileSystem).Name

		$rootProc = Start-Process -FilePath $launcher -ArgumentList $VaultPath -PassThru
		$rootPid = $rootProc.Id
		$detail['launcherPid'] = $rootPid

		$timedOutStage = 'launch'
		$mainWindow = Wait-ForOwnedWindow -Owned $owned -RootProcessId $rootPid -NotBefore $notBefore `
			-TitlePrefix 'Cryptomator' -TimeoutSeconds (Get-BoundedSeconds $LaunchTimeoutSec $runDeadline)
		if ($null -eq $mainWindow) { throw "main window did not appear within $LaunchTimeoutSec s" }
		$appProc = $owned[$mainWindow.ProcessId]
		$detail['appPid'] = $appProc.ProcessId
		$detail['ownedPids'] = @($owned.Keys | Sort-Object)

		$detail['launched'] = Wait-ForLogLine -LogFile $appLog -Pattern 'JavaFX runtime started' `
			-TimeoutSeconds (Get-BoundedSeconds $LaunchTimeoutSec $runDeadline)
		if (-not $detail['launched']) { throw "JavaFX runtime did not start within $LaunchTimeoutSec s" }
		$timedOutStage = $null

		if ($Mode -eq 'AccessibilityProbe') {
			$stage = 'accessibility-probe'
			$timedOutStage = 'accessibility-probe'
			$probeFile = Join-Path $runDir 'uia-probe.ps1'
			$probeOut = Join-Path $runDir 'uia-probe.result.json'
			$probeStdout = Join-Path $runDir 'uia-probe.stdout.txt'
			$probeStderr = Join-Path $runDir 'uia-probe.stderr.txt'
			Set-Content -Path $probeFile -Encoding utf8 -Value @'
param([long] $Hwnd, [string] $OutFile)
# Never fails the tooling contract: any UIA error is captured into the result document and
# the probe still exits 0, so the harness can tell "probe broke" from "target died".
$result = [ordered]@{
	stage = 'init'; rootName = $null; className = $null; controlType = $null
	nativeWindowHandle = $null; providerDescription = $null; frameworkId = $null; automationId = $null; isControlElement = $null; isContentElement = $null
	childCount = $null; descendantCount = $null; sampleNames = @(); error = $null
}
try {
	Add-Type -AssemblyName UIAutomationClient
	Add-Type -AssemblyName UIAutomationTypes

	$result.stage = 'from-handle'
	$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr] $Hwnd)
	$result.rootName = $root.Current.Name
	$result.className = $root.Current.ClassName
	$result.controlType = $root.Current.ControlType.ProgrammaticName
	$result.nativeWindowHandle = $root.Current.NativeWindowHandle
	# ProviderDescription is a UIA3 property and is not exposed by the UIA2 managed client,
	# so provider identity is characterised through FrameworkId and the element flags instead.
	$result.frameworkId = $root.Current.FrameworkId
	$result.automationId = $root.Current.AutomationId
	$result.isControlElement = $root.Current.IsControlElement
	$result.isContentElement = $root.Current.IsContentElement
	$result.providerDescription = 'not exposed by the UIA2 managed client (UIA3-only property)'

	$result.stage = 'children'
	$walker = [System.Windows.Automation.TreeWalker]::ControlViewWalker
	$child = $walker.GetFirstChild($root)
	$count = 0
	while ($null -ne $child -and $count -lt 500) {
		$count++
		if ($result.sampleNames.Count -lt 10) { $result.sampleNames += [string] $child.Current.Name }
		$child = $walker.GetNextSibling($child)
	}
	$result.childCount = $count

	$result.stage = 'descendants'
	$all = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants,
		[System.Windows.Automation.Condition]::TrueCondition)
	$result.descendantCount = $all.Count
	$result.stage = 'complete'
} catch {
	$result.error = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
}
$result | ConvertTo-Json -Depth 4 | Set-Content -Path $OutFile -Encoding utf8
Write-Output "probe stage=$($result.stage) children=$($result.childCount) descendants=$($result.descendantCount)"
exit 0
'@
			$probeStart = Get-Date
			$probeProc = Start-Process -FilePath 'powershell.exe' -PassThru -WindowStyle Hidden `
				-RedirectStandardOutput $probeStdout -RedirectStandardError $probeStderr `
				-ArgumentList @('-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $probeFile,
					'-Hwnd', $mainWindow.Hwnd.ToInt64(), '-OutFile', $probeOut)
			$probeTimeout = Get-BoundedSeconds $UiActionTimeoutSec $runDeadline
			$probeExited = $probeProc.WaitForExit($probeTimeout * 1000)
			if (-not $probeExited) {
				$probeOwned = @{}
				Update-OwnedProcesses -Owned $probeOwned -RootProcessId $probeProc.Id -NotBefore $probeStart.AddSeconds(-2) | Out-Null
				$detail['probeCleanup'] = Stop-OwnedProcesses -Owned $probeOwned `
					-GracefulSeconds (Get-RemainingSeconds 2 $runDeadline) -Reason "UIA probe exceeded $probeTimeout s"
			}
			$timedOutStage = $null

			$probeResult = $null
			if (Test-Path $probeOut) { $probeResult = Get-Content $probeOut -Raw | ConvertFrom-Json }
			$probeStdoutRaw = if (Test-Path $probeStdout) { Get-Content $probeStdout -Raw } else { $null }
			$probeStderrRaw = if (Test-Path $probeStderr) { Get-Content $probeStderr -Raw } else { $null }
			$detail['probe'] = [ordered]@{
				timeoutSeconds = $probeTimeout
				exited         = $probeExited
				exitCode       = if ($probeExited) { $probeProc.ExitCode } else { $null }
				elapsedSeconds = [math]::Round(((Get-Date) - $probeStart).TotalSeconds, 2)
				stdout         = if ($probeStdoutRaw) { $probeStdoutRaw.Trim() } else { '' }
				stderr         = if ($probeStderrRaw) { $probeStderrRaw.Trim() } else { '' }
				result         = $probeResult
			}

			Start-Sleep -Seconds 3
			$survived = Test-OwnedProcessAlive -Owned $appProc
			$probeToolingOk = $probeExited -and ($probeProc.ExitCode -eq 0) -and ($null -ne $probeResult)
			$detail['targetSurvived'] = $survived
			$detail['probeToolingOk'] = $probeToolingOk
			$detail['accessibilityExposure'] = if ($probeResult) {
				[ordered]@{
					reachedStage        = $probeResult.stage
					providerDescription = $probeResult.providerDescription
					childCount          = $probeResult.childCount
					descendantCount     = $probeResult.descendantCount
					uiaError            = $probeResult.error
				}
			} else { $null }
			$detail['elapsedSeconds'] = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 2)
			$results += [pscustomobject]@{
				Run = $run; Stage = $stage; Ok = ($probeToolingOk -and $survived)
				Detail = $detail
				Note = if (-not $probeToolingOk) {
					"probe tooling failed (exited=$probeExited exitCode=$(if ($probeExited) { $probeProc.ExitCode } else { 'n/a' }) result=$($null -ne $probeResult)) - result is inconclusive"
				} elseif ($survived) {
					"app survived a UI Automation tree query; exposure: children=$($probeResult.childCount) descendants=$($probeResult.descendantCount)"
				} else {
					"app was killed by a UI Automation tree query at probe stage '$($probeResult.stage)' (JavaFX Glass accessibility defect present)"
				}
			}
			continue
		}

		# a second launch with the same vault path is delivered to the running instance over IPC
		# and starts the unlock workflow
		$stage = 'unlock'
		$timedOutStage = 'ipc-handover'
		$ipcStart = Get-Date
		$ipcSender = Start-Process -FilePath $launcher -ArgumentList $VaultPath -PassThru
		$ipcTimeout = Get-BoundedSeconds $UiActionTimeoutSec $runDeadline
		if (-not $ipcSender.WaitForExit($ipcTimeout * 1000)) {
			$ipcOwned = @{}
			Update-OwnedProcesses -Owned $ipcOwned -RootProcessId $ipcSender.Id -NotBefore $ipcStart.AddSeconds(-2) | Out-Null
			$detail['ipcCleanup'] = Stop-OwnedProcesses -Owned $ipcOwned -GracefulSeconds 2 -Reason "IPC handover exceeded $ipcTimeout s"
			throw "second launch did not hand over to the running instance within $ipcTimeout s"
		}

		$timedOutStage = 'unlock-window'
		$unlockWindow = Wait-ForOwnedWindow -Owned $owned -RootProcessId $rootPid -NotBefore $notBefore `
			-TitlePrefix 'Unlock' -TimeoutSeconds (Get-BoundedSeconds $UiActionTimeoutSec $runDeadline)
		if ($null -eq $unlockWindow) { throw "unlock window did not appear within $UiActionTimeoutSec s" }

		$timedOutStage = 'unlock'
		Invoke-Focused -Hwnd $unlockWindow.Hwnd -Text $VaultPassword -Keys @([uint16] 0x0D)
		$detail['unlocked'] = Wait-ForLogLine -LogFile $appLog -Pattern "Unlock of '$([regex]::Escape($vaultName))' succeeded" `
			-TimeoutSeconds (Get-BoundedSeconds $UnlockTimeoutSec $runDeadline)
		if (-not $detail['unlocked']) { throw "unlock did not succeed within $UnlockTimeoutSec s" }
		$timedOutStage = $null

		$stage = 'roundtrip'
		$timedOutStage = 'mount'
		$settingsPath = Join-Path $userHome 'settings.json'
		$vaultDisplayName = $vaultName
		if (Test-Path $settingsPath) {
			$configured = (Get-Content $settingsPath -Raw | ConvertFrom-Json).directories |
				Where-Object { $_.path -eq (Resolve-Path $VaultPath).Path } | Select-Object -First 1
			if ($configured) {
				$vaultDisplayName = $configured.displayName
				$detail['configuredVault'] = [ordered]@{ id = $configured.id; path = $configured.path; displayName = $configured.displayName }
			}
		}
		$detail['expectedMount'] = "\\$LoopbackAlias\<vault-id>\$vaultDisplayName"

		$resolved = Resolve-VaultDrive -DrivesBefore $drivesBefore -Alias $LoopbackAlias `
			-VaultDisplayName $vaultDisplayName -TimeoutSeconds (Get-BoundedSeconds $UiActionTimeoutSec $runDeadline)
		$detail['mountCandidates'] = @($resolved.Candidates)
		if ($null -eq $resolved.Matched) {
			throw "no drive matching provider '\\$LoopbackAlias\*\$vaultDisplayName' appeared within $UiActionTimeoutSec s; $($resolved.Candidates.Count) unrelated new drive(s) were inspected and left untouched"
		}
		$timedOutStage = $null
		$mountIdentity = $resolved.Matched
		$mountDrive = $mountIdentity.driveLetter
		# identity is recorded before anything is written to the volume
		$detail['mountIdentity'] = $mountIdentity
		$detail['mountDrive'] = $mountIdentity.root

		$smokeDir = Join-Path $mountIdentity.root 'arm64-runtime-smoke'
		New-Item -ItemType Directory -Force -Path $smokeDir | Out-Null
		$smokeFile = Join-Path $smokeDir "run$run.txt"
		Set-Content -Path $smokeFile -Value "runtime smoke run $run"
		$detail['roundTrip'] = (Get-Content $smokeFile -Raw).Trim()
		Remove-Item $smokeDir -Recurse -Force

		$stage = 'dismiss-unlock-dialog'
		$successWindow = [CryptomatorSmoke.Win32]::FindWindow([uint32] $appProc.ProcessId, 'Unlock')
		if ($successWindow -ne [IntPtr]::Zero) {
			# the unlock workflow ends on an "unlock successful" page; close it with its default button
			Invoke-Focused -Hwnd $successWindow -Keys @([uint16] 0x0D)
			Start-Sleep -Seconds 2
			if ([CryptomatorSmoke.Win32]::FindWindow([uint32] $appProc.ProcessId, 'Unlock') -ne [IntPtr]::Zero) {
				Invoke-Focused -Hwnd $successWindow -Keys @([uint16] 0x1B)
				Start-Sleep -Seconds 2
			}
		}
		$detail['unlockDialogClosed'] = ([CryptomatorSmoke.Win32]::FindWindow([uint32] $appProc.ProcessId, 'Unlock') -eq [IntPtr]::Zero)

		$stage = 'quit'
		$detail['windows'] = @([CryptomatorSmoke.Win32]::ListWindows([uint32] $appProc.ProcessId))
		$mainHwnd = [CryptomatorSmoke.Win32]::FindWindow([uint32] $appProc.ProcessId, 'Cryptomator')
		if ($mainHwnd -eq [IntPtr]::Zero) { throw 'main window disappeared before quit' }
		# WM_SYSCOMMAND/SC_CLOSE is the focus-independent equivalent of clicking the window's close
		# button; Cryptomator maps that to FxApplicationTerminator.terminate().
		[CryptomatorSmoke.Win32]::PostMessage($mainHwnd, 0x0112, [IntPtr] 0xF060, [IntPtr]::Zero) | Out-Null
		$quitWindow = Wait-ForOwnedWindow -Owned $owned -RootProcessId $rootPid -NotBefore $notBefore `
			-TitlePrefix 'Quit' -TimeoutSeconds (Get-BoundedSeconds ([math]::Min(15, $UiActionTimeoutSec)) $runDeadline)
		if ($null -eq $quitWindow -and (Test-OwnedProcessAlive -Owned $appProc)) {
			# fall back to a real Alt+F4 on the focused main window
			Invoke-Focused -Hwnd $mainHwnd -Keys @()
			Start-Sleep -Milliseconds 800
			[CryptomatorSmoke.Win32]::AltF4()
			$quitWindow = Wait-ForOwnedWindow -Owned $owned -RootProcessId $rootPid -NotBefore $notBefore `
				-TitlePrefix 'Quit' -TimeoutSeconds (Get-BoundedSeconds ([math]::Min(15, $UiActionTimeoutSec)) $runDeadline)
		}
		$detail['quitDialog'] = ($null -ne $quitWindow)
		if ($null -ne $quitWindow) {
			# the dialog's default button is "cancel", the lock-and-quit button is next in tab order
			Invoke-Focused -Hwnd $quitWindow.Hwnd -Keys @([uint16] 0x09, [uint16] 0x0D)
		}

		$timedOutStage = 'shutdown'
		$detail['shutdown'] = Wait-ForLogLine -LogFile $appLog -Pattern 'UI shut down' `
			-TimeoutSeconds (Get-BoundedSeconds $ShutdownTimeoutSec $runDeadline)
		$exited = Wait-ForProcessExit -Owned $appProc -TimeoutSeconds (Get-BoundedSeconds $ShutdownTimeoutSec $runDeadline)
		if (-not $exited) { throw "process $($appProc.ProcessId) did not exit within $ShutdownTimeoutSec s after quit" }
		$timedOutStage = $null
		$detail['exitLine'] = Wait-ForLogLine -LogFile $appLog -Pattern 'Cryptomator - Exit 0' `
			-TimeoutSeconds (Get-RemainingSeconds 15 $runDeadline)
		if ((Get-PSDrive -PSProvider FileSystem).Name -contains $mountDrive) { throw "vault drive $mountDrive`: still mounted after quit" }

		$crashLogs = @(Get-ChildItem -Path $crashDir -Filter "hs_err_run${run}_*.log" -ErrorAction SilentlyContinue)
		$detail['crashLogs'] = $crashLogs.Count
		$detail['elapsedSeconds'] = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 2)
		$results += [pscustomobject]@{
			Run = $run; Stage = 'complete'; Ok = ($crashLogs.Count -eq 0) -and ($null -ne $detail['exitLine']); Detail = $detail
		}
	} catch {
		$detail['elapsedSeconds'] = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 2)
		$detail['timedOutStage'] = $timedOutStage
		$results += [pscustomobject]@{ Run = $run; Stage = $stage; Ok = $false; Detail = $detail; Error = $_.Exception.Message }
	} finally {
		Update-OwnedProcesses -Owned $owned -RootProcessId $rootPid -NotBefore $notBefore | Out-Null
		$detail['ownedPids'] = @($owned.Keys | Sort-Object)
		# final cleanup is itself bounded by whatever is left of the per-cycle budget
		$cleanupGrace = Get-RemainingSeconds $GracefulCloseSec $runDeadline
		$detail['cleanup'] = Stop-OwnedProcesses -Owned $owned -GracefulSeconds $cleanupGrace `
			-Reason "end of run $run (stage: $stage; graceful budget $cleanupGrace s of $GracefulCloseSec s)"
		$detail['elapsedSeconds'] = [math]::Round(((Get-Date) - $runStart).TotalSeconds, 2)

		# a run that leaks an owned process is a failed run, whatever else succeeded
		$leaked = @($detail['cleanup'].stillRunning)
		if ($leaked.Count -gt 0 -and $results.Count -gt 0) {
			$last = $results[$results.Count - 1]
			if ($last.Run -eq $run) {
				$last.Ok = $false
				$leakMessage = "cleanup left owned process(es) running: $($leaked -join ', ')"
				if ($last.PSObject.Properties.Name -contains 'Error' -and $last.Error) {
					$last.Error = "$($last.Error); $leakMessage"
				} else {
					$last | Add-Member -NotePropertyName Error -NotePropertyValue $leakMessage -Force
				}
			}
		}
		Remove-Item Env:\_JAVA_OPTIONS -ErrorAction SilentlyContinue
		Start-Sleep -Seconds 3
	}
}

$summary = [pscustomobject]@{
	AppImage            = $AppImage
	Mode                = $Mode
	Repetitions         = $repeats
	HostArchitecture    = $env:PROCESSOR_ARCHITECTURE
	InputDesktopAvailable = $inputDesktopAvailable
	InputTransport      = $script:ActiveTransport
	Timeouts            = $timeouts
	NonArm64BinaryCount = $nonArm64.Count
	NonArm64Binaries    = $nonArm64
	AccessibilityBridge = if ($DisableAccessibilityBridge) { 'disabled (glass.accessible.force=false)' } else { 'default' }
	Runs                = $results
}
$summary | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $WorkDir 'runtime-smoke-result.json')
$summary | ConvertTo-Json -Depth 8

$failed = @($results | Where-Object { -not $_.Ok })
if ($nonArm64.Count -gt 0) {
	Write-Error "app-image contains $($nonArm64.Count) non-ARM64 binaries"
	exit 1
}
if ($failed.Count -gt 0) {
	Write-Error "$($failed.Count) of $repeats runtime smoke runs failed"
	exit 1
}
exit 0

