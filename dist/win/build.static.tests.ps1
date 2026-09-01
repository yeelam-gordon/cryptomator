$ErrorActionPreference = 'Stop'

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
