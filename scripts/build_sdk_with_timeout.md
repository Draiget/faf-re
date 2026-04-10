# SDK build with timeout

Use the timeout wrapper to avoid hanging `cl.exe`/`msbuild` runs.

It enforces both:
- a total wall-clock timeout (`TimeoutMinutes`)
- a no-activity timeout (`NoOutputTimeoutMinutes`) that tracks output and compiler CPU progress

It also prints periodic heartbeat lines so long compile stretches are visible.

## Default

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_sdk_with_timeout.ps1
```

Defaults:

- `Target`: `sdk`
- `Configuration`: `Debug`
- `Platform`: `x86`
- `TimeoutMinutes`: `120`
- `NoOutputTimeoutMinutes`: `10` (`0` disables this check)
- `HeartbeatSeconds`: `30` (`0` disables heartbeat lines)
- `PollSeconds`: `2`
- `MaxCpuCount`: `1`
- `LogPath`: `msbuild_sdk_timeout.log`

## Custom timeout and log

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_sdk_with_timeout.ps1 `
  -TimeoutMinutes 120 `
  -NoOutputTimeoutMinutes 10 `
  -HeartbeatSeconds 30 `
  -LogPath .\msbuild_sdk_debug_x86_timeout.log
```

## Exit codes

- `0`: build succeeded
- non-zero msbuild exit code: build failed
- `124`: timed out (total or no-activity) and process tree was terminated
