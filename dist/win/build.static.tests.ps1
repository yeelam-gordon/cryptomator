$ErrorActionPreference = 'Stop'

# This static test suite parses/inspects build.ps1, which itself requires PowerShell 7+
# (pwsh) -- the same host build.bat already invokes. Fail with an explicit, accurate
# message rather than a confusing generic parser error when run under Windows PowerShell.
if ($PSVersionTable.PSEdition -ne 'Core' -or $PSVersionTable.PSVersion.Major -lt 7) {
	throw "dist\win\build.static.tests.ps1 requires PowerShell 7+ (pwsh), matching the pwsh contract build.bat uses to invoke build.ps1. Detected $($PSVersionTable.PSEdition) PowerShell $($PSVersionTable.PSVersion). Re-run with: pwsh -File .\dist\win\build.static.tests.ps1"
}

$buildScript = Join-Path $PSScriptRoot 'build.ps1'
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$errors)

if ($errors.Count -ne 0) {
	throw "PowerShell parse errors in build.ps1: $($errors.Count)"
}

$resolverAst = $ast.Find({
	param($node)
	$node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Resolve-AbsolutePathFromInvocationRoot'
}, $true)

if (-not $resolverAst) {
	throw 'Resolve-AbsolutePathFromInvocationRoot function not found in build.ps1.'
}

. ([scriptblock]::Create($resolverAst.Extent.Text))

$relativeJmodsPath = 'relative\jfx\jmods'
$expectedRelativeResolution = [System.IO.Path]::GetFullPath((Join-Path $repoRoot $relativeJmodsPath))
$actualRelativeResolution = Resolve-AbsolutePathFromInvocationRoot -Path $relativeJmodsPath -BasePath $repoRoot
if ($actualRelativeResolution -ne $expectedRelativeResolution) {
	throw "Relative JavafxJmodsPath resolved to '$actualRelativeResolution' instead of '$expectedRelativeResolution'."
}

$absoluteJmodsPath = Join-Path $repoRoot 'absolute-jfx\jmods'
$expectedAbsoluteResolution = [System.IO.Path]::GetFullPath($absoluteJmodsPath)
$actualAbsoluteResolution = Resolve-AbsolutePathFromInvocationRoot -Path $absoluteJmodsPath -BasePath 'C:\ignored'
if ($actualAbsoluteResolution -ne $expectedAbsoluteResolution) {
	throw "Absolute JavafxJmodsPath resolved to '$actualAbsoluteResolution' instead of '$expectedAbsoluteResolution'."
}

# Drive-relative forms (e.g. 'C:jmods', '\jfx\jmods') are rooted but not fully qualified:
# .NET would resolve them against the process's per-drive current directory, not -BasePath,
# which can silently pick a stale/unexpected directory. They must be rejected outright.
foreach ($ambiguousPath in @('C:jmods', '\jfx\jmods')) {
	$threw = $false
	try {
		Resolve-AbsolutePathFromInvocationRoot -Path $ambiguousPath -BasePath $repoRoot | Out-Null
	} catch {
		$threw = $true
	}
	if (-not $threw) {
		throw "Resolve-AbsolutePathFromInvocationRoot must reject the ambiguous drive-relative path '$ambiguousPath', not silently resolve it."
	}
}

Write-Host 'PASS: Resolve-AbsolutePathFromInvocationRoot rejects ambiguous drive-relative paths instead of resolving them against a stale current directory.'

$scriptText = Get-Content $buildScript -Raw
$normalizeIndex = $scriptText.IndexOf('$JavafxJmodsPath = Resolve-AbsolutePathFromInvocationRoot')
$pushIndex = $scriptText.IndexOf('Push-Location $BuildRoot')
$popIndex = $scriptText.IndexOf('Pop-Location')

if ($normalizeIndex -lt 0) {
	throw 'Expected JavafxJmodsPath normalization statement not found.'
}
if ($pushIndex -lt 0) {
	throw 'Expected Push-Location $BuildRoot statement not found.'
}
if ($popIndex -lt 0) {
	throw 'Expected Pop-Location statement not found.'
}
if ($normalizeIndex -gt $pushIndex) {
	throw 'JavafxJmodsPath normalization must occur before changing location to the build root.'
}

if ($scriptText -notmatch '(?s)try\s*\{.*Push-Location \$BuildRoot.*\}\s*finally\s*\{.*Pop-Location') {
	throw 'Expected Push-Location/Pop-Location try/finally structure not found.'
}

Write-Host 'PASS: build.ps1 normalizes relative JavafxJmodsPath before Push-Location and restores location with Pop-Location.'

# The file-association descriptor embeds an absolute icon path. It must be generated into a
# build-output directory so the tracked resource never picks up the builder's checkout path.
if ($scriptText -match '\|\s*Out-File -FilePath \.\\resources\\FAvaultFile\.properties') {
	throw 'build.ps1 must not overwrite the tracked dist\win\resources\FAvaultFile.properties.'
}
if ($scriptText -notmatch '\$faVaultFileProperties = Join-Path \$generatedDir "FAvaultFile\.properties"') {
	throw 'Expected generated FAvaultFile.properties path not found in build.ps1.'
}
if ($scriptText -notmatch '"--file-associations", \$faVaultFileProperties') {
	throw 'jpackage must consume the generated FAvaultFile.properties, not the tracked resource.'
}

$trackedDescriptor = Join-Path $PSScriptRoot 'resources\FAvaultFile.properties'
if (Test-Path $trackedDescriptor) {
	$descriptorText = Get-Content $trackedDescriptor -Raw
	$repoRootEscaped = [regex]::Escape($repoRoot.TrimEnd('\'))
	if ($descriptorText -match $repoRootEscaped -or $descriptorText -match [regex]::Escape($repoRoot.TrimEnd('\').Replace('\', '\\'))) {
		throw "Tracked FAvaultFile.properties contains this checkout's absolute path; it must stay build-independent."
	}
}

$gitignore = Join-Path $PSScriptRoot '.gitignore'
if (-not (Select-String -Path $gitignore -Pattern '^generated$' -Quiet)) {
	throw 'dist\win\.gitignore must ignore the generated build-output directory.'
}

Write-Host 'PASS: build.ps1 generates FAvaultFile.properties into an ignored build-output directory and leaves the tracked resource untouched.'

$runtimeSmokeScript = Join-Path $PSScriptRoot 'runtime-smoke.ps1'
$runtimeTokens = $null
$runtimeErrors = $null
[System.Management.Automation.Language.Parser]::ParseFile($runtimeSmokeScript, [ref]$runtimeTokens, [ref]$runtimeErrors) | Out-Null
if ($runtimeErrors.Count -ne 0) {
	throw "PowerShell parse errors in runtime-smoke.ps1: $($runtimeErrors.Count)"
}

$runtimeSmokeText = Get-Content $runtimeSmokeScript -Raw
if ($runtimeSmokeText -notmatch [regex]::Escape("if (`$Mode -eq 'Launch' -and `$script:ActiveTransport -eq 'SendInput' -and -not `$inputDesktopAvailable)")) {
	throw 'Locked-session SendInput validation must apply only to Launch mode, not AccessibilityProbe.'
}
if ($runtimeSmokeText -match 'Auto picks SendInput when the input desktop is reachable and PostMessage otherwise') {
	throw 'runtime-smoke.ps1 documentation must not promise an automatic PostMessage fallback.'
}

Write-Host 'PASS: runtime-smoke.ps1 keeps Auto fail-fast semantics and permits locked-session AccessibilityProbe runs.'

# The win-exe.yml workflow must follow the same generated-indirection invariant as build.ps1:
# it must never write the tracked dist/win/resources/FAvaultFile.properties, and must point
# jpackage at the generated copy instead.
$workflowPath = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\.github\workflows\win-exe.yml'))
if (-not (Test-Path $workflowPath)) {
	throw "Expected workflow not found: $workflowPath"
}
$workflowText = Get-Content $workflowPath -Raw
if ($workflowText -match [regex]::Escape('Out-File -FilePath .\resources\FAvaultFile.properties')) {
	throw 'win-exe.yml must not overwrite the tracked dist/win/resources/FAvaultFile.properties.'
}
if ($workflowText -match [regex]::Escape('--file-associations dist/win/resources/FAvaultFile.properties')) {
	throw 'win-exe.yml must not pass jpackage the tracked dist/win/resources/FAvaultFile.properties.'
}
$generatedWriteCount = ([regex]::Matches($workflowText, [regex]::Escape('Out-File -FilePath .\generated\FAvaultFile.properties'))).Count
if ($generatedWriteCount -lt 2) {
	throw "Expected win-exe.yml to generate FAvaultFile.properties into .\generated in both the x64 and ARM64 jobs (found $generatedWriteCount)."
}
$generatedUseCount = ([regex]::Matches($workflowText, [regex]::Escape('--file-associations dist/win/generated/FAvaultFile.properties'))).Count
if ($generatedUseCount -lt 2) {
	throw "Expected win-exe.yml jpackage steps to consume dist/win/generated/FAvaultFile.properties in both the x64 and ARM64 jobs (found $generatedUseCount)."
}

Write-Host 'PASS: win-exe.yml generates FAvaultFile.properties into dist/win/generated in both jobs and never overwrites the tracked resource.'

# The pwsh 7+ requirement must be explicit and accurate, not just an incidental side effect
# of a parse failure -- guard the guard itself so it can't silently regress.
if ($scriptText -notmatch [regex]::Escape("PSVersionTable.PSEdition -ne 'Core' -or")) {
	throw 'build.ps1 must explicitly guard against unsupported PowerShell hosts (require pwsh 7+).'
}
if ($scriptText -notmatch 'requires PowerShell 7\+ \(pwsh\)') {
	throw 'build.ps1 must fail with an explicit "requires PowerShell 7+ (pwsh)" message on unsupported hosts.'
}

$selfText = Get-Content $PSCommandPath -Raw
if ($selfText -notmatch [regex]::Escape("PSVersionTable.PSEdition -ne 'Core' -or")) {
	throw 'build.static.tests.ps1 must explicitly guard against unsupported PowerShell hosts (require pwsh 7+).'
}

Write-Host 'PASS: build.ps1 and build.static.tests.ps1 both explicitly require and report PowerShell 7+ (pwsh).'

# Demonstrate -- not just assert via text matching -- that Windows PowerShell 5.1 actually
# gets the explicit, accurate message rather than the confusing generic parser error this
# guard replaces. Bounded with a timeout so this suite can never hang; skipped only when
# Windows PowerShell truly is not installed on the host.
$windowsPowerShell = Get-Command 'powershell.exe' -ErrorAction SilentlyContinue
if ($windowsPowerShell) {
	$dummyArgs = @(
		'-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $buildScript,
		'-AppName', 'x', '-MainJarGlob', 'x', '-ModuleAndMainClass', 'x',
		'-UpgradeUUID', '00000000-0000-0000-0000-000000000000', '-Vendor', 'x',
		'-CopyrightStartYear', '2016', '-HelpUrl', 'x', '-UpdateUrl', 'x',
		'-AboutUrl', 'x', '-LoopbackAlias', 'x'
	)
	$job = Start-Job -ScriptBlock {
		param($exePath, $exeArgs)
		& $exePath @exeArgs 2>&1 | Out-String
	} -ArgumentList $windowsPowerShell.Source, $dummyArgs
	if (-not (Wait-Job $job -Timeout 60)) {
		Stop-Job $job | Out-Null
		Remove-Job $job -Force | Out-Null
		throw 'Windows PowerShell 5.1 host-guard demonstration timed out after 60s.'
	}
	$legacyOutput = Receive-Job $job
	Remove-Job $job -Force | Out-Null
	if ($legacyOutput -notmatch 'requires PowerShell 7\+ \(pwsh\)') {
		throw "Expected build.ps1 to fail under Windows PowerShell with an explicit 'requires PowerShell 7+ (pwsh)' message. Actual output: $legacyOutput"
	}
	Write-Host 'PASS: build.ps1 fails under Windows PowerShell 5.1 with the explicit, accurate host-requirement message.'
} else {
	Write-Host 'SKIP: Windows PowerShell (powershell.exe) is not installed on this host; cannot demonstrate the 5.1 host-guard message.'
}
