$ErrorActionPreference = 'Stop'
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue) -or
    $env:VSCMD_ARG_TGT_ARCH -notin @('x64', 'amd64')) {
    # Ordinary PowerShell does not inherit the VS compiler/SDK environment.
    # Discover Community/Professional/Enterprise/Build Tools, including custom install paths.
    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswherePath)) {
        throw 'Visual Studio Installer was not found. Install the Desktop development with C++ workload and a Windows SDK.'
    }
    $vsInstallPath = & $vswherePath -latest -products '*' `
        -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or -not $vsInstallPath) {
        throw 'No Visual Studio C++ toolchain found. In Visual Studio Installer, add Desktop development with C++ and a Windows SDK.'
    }
    $devShell = Join-Path $vsInstallPath 'Common7\Tools\Launch-VsDevShell.ps1'
    if (-not (Test-Path -LiteralPath $devShell)) {
        throw "Developer PowerShell is missing: $devShell. Repair the Visual Studio installation."
    }
    Write-Host "Initializing x64 compiler environment: $vsInstallPath"
    & $devShell -VsInstallationPath $vsInstallPath -Arch amd64 -HostArch amd64 -SkipAutomaticLocation -NoLogo
}
$compiler = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $compiler -or $env:VSCMD_ARG_TGT_ARCH -notin @('x64', 'amd64')) {
    throw 'Failed to initialize the x64 MSVC environment. Check the installed C++ tools and Windows SDK.'
}
Write-Host "Compiler: $($compiler.Source)"
$repo = Split-Path $PSScriptRoot -Parent
$output = Join-Path $PSScriptRoot 'out/runtime_lifetime'
New-Item -ItemType Directory -Force -Path $output | Out-Null
Push-Location $output
try {
    & $compiler.Source /nologo /std:c++20 /EHsc /utf-8 /W4 /MD /Fe:runtime_lifetime_selftest.exe `
        (Join-Path $PSScriptRoot 'runtime_lifetime_selftest.cpp') `
        (Join-Path $repo 'DllLoaderRuntime/Civ6MessageBus.cpp') `
        (Join-Path $repo 'DllLoaderRuntime/PluginInFlight.cpp')
    if ($LASTEXITCODE -ne 0) { throw 'Regression test build failed.' }
    # Own the process handle from launch; Start-Process -PassThru can lose ExitCode
    # when this short-lived test exits before Windows PowerShell observes the handle.
    $test = [System.Diagnostics.Process]::new()
    $test.StartInfo.FileName = Join-Path $output 'runtime_lifetime_selftest.exe'
    $test.StartInfo.UseShellExecute = $false
    $test.StartInfo.CreateNoWindow = $true
    $test.StartInfo.RedirectStandardOutput = $true
    $test.StartInfo.RedirectStandardError = $true
    try {
        if (-not $test.Start()) { throw 'Could not start regression tests.' }
        $stdout = $test.StandardOutput.ReadToEndAsync()
        $stderr = $test.StandardError.ReadToEndAsync()
        if (-not $test.WaitForExit(15000)) {
            $test.Kill()
            $test.WaitForExit()
            throw 'Regression test timed out (possible deadlock).'
        }
        $testOutput = $stdout.GetAwaiter().GetResult()
        $testError = $stderr.GetAwaiter().GetResult()
        if ($testOutput) { Write-Host $testOutput.TrimEnd() }
        if ($testError) { Write-Host $testError.TrimEnd() }
        if ($test.ExitCode -ne 0) { throw "Regression tests failed: exit $($test.ExitCode)." }
    } finally {
        $test.Dispose()
    }
} finally {
    Pop-Location
}
