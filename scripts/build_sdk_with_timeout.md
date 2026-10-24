# SDK build with timeout

`build_sdk_with_timeout.ps1` runs msbuild with two timeouts so a hanging `cl.exe`/`msbuild` cannot block forever, and prints periodic heartbeat lines so long compile stretches are visible.

- **Total timeout** (`TimeoutMinutes`): wall-clock limit for the whole build.
- **No-activity timeout** (`NoOutputTimeoutMinutes`): tracks output and compiler CPU progress, and stops a build that makes none.

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_sdk_with_timeout.ps1
```

With a custom timeout and log:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_sdk_with_timeout.ps1 `
  -TimeoutMinutes 120 `
  -NoOutputTimeoutMinutes 10 `
  -HeartbeatSeconds 30 `
  -LogPath .\msbuild_sdk_debug_x86_timeout.log
```

## Parameters

| Parameter | Default |
|---|---|
| `Solution` | `faf.sln` |
| `Target` | `sdk` |
| `Configuration` | `Debug` |
| `Platform` | `x86` |
| `TimeoutMinutes` | `120` |
| `NoOutputTimeoutMinutes` | `10` (`0` disables this check) |
| `HeartbeatSeconds` | `30` (`0` disables heartbeat lines) |
| `PollSeconds` | `2` |
| `MaxCpuCount` | `1` |
| `LogPath` | `msbuild_sdk_timeout.log` |

## Exit codes

- `0`: build succeeded.
- msbuild's non-zero exit code: build failed.
- `124`: timed out (total or no-activity) and the process tree was terminated.
