# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Goal

Run `opencode.exe` (a Go-based TUI tool from https://github.com/anomalyco/opencode) inside a Windows AppContainer sandbox with working TUI display and user interaction. The launcher handles ConPTY setup, ACL permissions, environment configuration, and Bun VFS compatibility so the sandboxed child process can function normally.

## Build

VS 2022 安装在 `D:\app-install\CodingTools\VisualStudio\Installer`，使用其自带的 MSBuild（v143 toolset）：

```
"D:\app-install\CodingTools\VisualStudio\Installer\MSBuild\Current\Bin\amd64\MSBuild.exe" AppContainer\AppContainer.sln /p:Configuration=Release /p:Platform=x64
```

Debug build:
```
"D:\app-install\CodingTools\VisualStudio\Installer\MSBuild\Current\Bin\amd64\MSBuild.exe" AppContainer\AppContainer.sln /p:Configuration=Debug /p:Platform=x64
```

注意：PATH 中的 `msbuild` 是 VS 2019 BuildTools 版本，缺少 v143 toolset，不能用于本项目。

## Architecture

Single-file C++ console application: `AppContainer\AppContainer\AppContainer.cpp` (~2150 lines, work in progress).

### Key Subsystems (top to bottom in the file)

1. **Logging** — Timestamped file+console logging (`LogInfo`/`LogWarn`/`LogError`/`LogDebug`), enabled via `-g` flag. Log files written next to the exe.

2. **String/Path Utilities** — Wide-string helpers for trimming, case-insensitive comparison, path normalization, SUBST drive resolution (`ResolveSubstPath`), and parent/filename extraction.

3. **OpenCode TUI Detection** — `IsOpenCodeTuiInvocation()` inspects the command line to determine if the child is an interactive TUI session. When detected, `AutoEnableWaitForTuiIfNeeded()` force-enables wait mode so ConPTY can be used (fixes `setRawMode errno=1`).

4. **Default Environment Paths** — `ApplyDefaultOpenCodeEnvPaths()` creates an `opencode/` directory tree next to the exe (work, config, cache, data, temp) and sets `HOME`, `USERPROFILE`, `APPDATA`, `XDG_*`, etc. so the sandboxed process has writable locations. User config overrides take priority.

5. **Bun Runtime Compatibility** — `ApplyBunOpenTuiCompatibility()` auto-detects Bun invocations and adds `BUN_INSTALL/root` and `BUN_INSTALL/bin` to allowed paths and PATH.

6. **Bun VFS / Embedded DLL Extraction** — Scans the target exe binary for embedded `opentui-*.dll`, validates PE structure (`ValidatePEDllAndGetCompleteSize`), verifies exports (`PEDllExportsSymbol` checks for `setLogCallback`), and stages the DLL to a real directory mapped as `B:\~BUN` via `DefineDosDeviceW`. This works around AppContainer blocking the child's own `DefineDosDeviceW` call.

7. **Capability/SID Parsing** — Parses `-c` argument: accepts both string SIDs and capability names (via `DeriveCapabilitySidsFromName`).

8. **AppContainer Profile Management** — Creates/reuses/deletes AppContainer profiles via `CreateAppContainerProfile` / `DeriveAppContainerSidFromAppContainerName`.

9. **Security/ACL Management** — Grants `FILE_ALL_ACCESS` to the AppContainer SID on allowed paths, optionally sets Low Integrity labels. Saves and restores original DACLs/SACLs on exit.

10. **ConPTY Support** — Dynamically loads `CreatePseudoConsole` from kernel32. Input/output relay threads bridge the parent console to the pseudo-console attached to the sandboxed child.

### CLI Flags

| Flag | Purpose |
|------|---------|
| `-i` | Command line of exe to launch (required) |
| `-m` | Package moniker (required) |
| `-c` | Capabilities / SIDs (semicolon-separated) |
| `-d` | Display name for profile |
| `-a` | Directories to grant full access (semicolon-separated) |
| `-e` | Environment overrides `K=V` (semicolon-separated) |
| `-p` | PATH prepend entries (semicolon-separated) |
| `-s` | Skip Low Integrity on `-a` paths |
| `-w` | Wait for child exit |
| `-r` | Retain AppContainer profile after exit |
| `-l` | Launch as LPAC |
| `-k` | Enable win32k lockdown |
| `-x` | Cleanup: delete subdirs under `-a` paths after exit |
| `-g` | Enable logging |

A `config.ini` `[App]` section is auto-loaded when no CLI args are provided.

## Conventions

- All code is in a single `.cpp` file using Win32 wide-string APIs (`wchar_t`, `std::wstring`).
- Libraries are linked via `#pragma comment(lib, ...)`: Userenv, Advapi32, OneCoreUAP.
- Security descriptors are saved before modification and restored on exit (even on crash via `InterlockedCompareExchange` guards).
- Path comparisons are always case-insensitive and normalized (backslashes, trailing slash handling).
- Language: code comments and logs are in English; project documentation may be in Chinese.
