#requires -Version 7.0
# Build an unsigned NSIS installer without installing or starting the app.
# Requires npm dependencies, Rust/MSVC, and python3 on PATH.
$ErrorActionPreference = 'Stop'

if (-not $IsWindows) {
    throw 'Build the Windows installer on Windows.'
}

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$tauriRoot = Join-Path $repoRoot 'src-tauri'

function Assert-OutsideCheckout([string] $Path) {
    $relative = [IO.Path]::GetRelativePath($repoRoot, $Path)
    if (-not [IO.Path]::IsPathRooted($relative) -and
        $relative -ne '..' -and
        -not $relative.StartsWith('..' + [IO.Path]::DirectorySeparatorChar)) {
        throw 'Build output must be outside the checkout. Set TEMP and CARGO_TARGET_DIR to external directories.'
    }
}

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
Assert-OutsideCheckout $tempRoot
$buildRoot = Join-Path $tempRoot ('netorch-windows-' + [guid]::NewGuid().ToString('N'))
$frontendOutput = Join-Path $buildRoot 'frontend'
$frontendDist = [IO.Path]::GetRelativePath($tauriRoot, $frontendOutput)
# A Windows drive prefix is parsed as a URL by FrontendDist and disables embedding.
if ([IO.Path]::IsPathRooted($frontendDist) -or $frontendDist.Contains(':')) {
    throw 'TEMP must be on the same drive as the checkout so frontend assets can use a relative path.'
}

$previousTarget = $env:CARGO_TARGET_DIR
$previousPythonUtf8 = $env:PYTHONUTF8
$previousPythonBytecode = $env:PYTHONDONTWRITEBYTECODE
$previousSandbox = $env:VITE_NETORCH_SANDBOX
$targetDir = if ([string]::IsNullOrWhiteSpace($previousTarget)) {
    Join-Path $buildRoot 'target'
} else {
    [IO.Path]::GetFullPath($previousTarget)
}
Assert-OutsideCheckout $targetDir
$npm = (Get-Command npm.cmd -CommandType Application -ErrorAction Stop).Source

New-Item -ItemType Directory -Path $buildRoot | Out-Null
$overridePath = Join-Path $buildRoot 'tauri.unsigned.json'
@{
    build = @{
        beforeBuildCommand = $null
        frontendDist = $frontendDist
    }
    bundle = @{ createUpdaterArtifacts = $false }
} | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $overridePath -Encoding utf8

Push-Location $repoRoot
try {
    $env:CARGO_TARGET_DIR = $targetDir
    $env:PYTHONUTF8 = '1'
    $env:PYTHONDONTWRITEBYTECODE = '1'
    Remove-Item Env:VITE_NETORCH_SANDBOX -ErrorAction SilentlyContinue

    & $npm run build -- --outDir $frontendOutput --configLoader runner
    if ($LASTEXITCODE -ne 0) {
        throw "Frontend build failed with exit code $LASTEXITCODE."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $frontendOutput 'index.html') -PathType Leaf)) {
        throw 'Frontend build did not produce index.html.'
    }
    if ([IO.Path]::GetFullPath((Join-Path $tauriRoot $frontendDist)) -ne $frontendOutput) {
        throw 'The frontend asset path does not resolve to the build output.'
    }

    & $npm run tauri build -- --bundles nsis --no-sign --features tauri/custom-protocol --config $overridePath
    if ($LASTEXITCODE -ne 0) {
        throw "NSIS build failed with exit code $LASTEXITCODE."
    }

    $releaseDir = if ([string]::IsNullOrWhiteSpace($env:CARGO_BUILD_TARGET)) {
        Join-Path $targetDir 'release'
    } else {
        Join-Path $targetDir (Join-Path $env:CARGO_BUILD_TARGET 'release')
    }
    $installerDir = Join-Path $releaseDir 'bundle/nsis'
    $installers = @(Get-ChildItem -LiteralPath $installerDir -Filter '*.exe' -File)
    if ($installers.Count -eq 0) {
        throw 'The NSIS build did not produce an installer.'
    }
    $installers | ForEach-Object { Write-Host "Installer: $($_.FullName)" }
} finally {
    $env:CARGO_TARGET_DIR = $previousTarget
    $env:PYTHONUTF8 = $previousPythonUtf8
    $env:PYTHONDONTWRITEBYTECODE = $previousPythonBytecode
    $env:VITE_NETORCH_SANDBOX = $previousSandbox
    Pop-Location
}
