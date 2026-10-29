import subprocess
import sys
import time
import os
import re
import csv
import json

def kill_games():
    subprocess.run(
        ['powershell', '-Command', 'Get-Process main_x64, main_x64_profile, main, headless_x64 -ErrorAction SilentlyContinue | Stop-Process -Force'],
        check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(2)

def run_configuration(cfg, replay_path, bin_dir, capture_tool, csvexport_tool, speedkeys_script, capture_duration=60):
    kill_games()

    log_path = r"C:\ProgramData\FAForever\logs\ui_gc_benchmark.log"
    trace_path = os.path.abspath(f"ui_gc_{cfg['id']}.tracy")
    csv_stats_path = os.path.abspath(f"ui_gc_{cfg['id']}_stats.csv")
    csv_zones_path = os.path.abspath(f"ui_gc_{cfg['id']}_zones.csv")

    for p in [log_path, trace_path, csv_stats_path, csv_zones_path]:
        if os.path.exists(p):
            try:
                os.remove(p)
            except OSError:
                pass

    exe = os.path.join(bin_dir, "main_x64_profile.exe")
    con_str = f"sim_Workers=8;ui_PeriodicGC={cfg.get('periodic', 1)};ui_ParallelMark={cfg.get('parallel_mark', 1)};ui_ParallelSweep={cfg.get('parallel_sweep', 1)};ui_IdleGC={cfg.get('idle_gc', 1)}"
    args = [
        exe,
        "/prefs", "dev.prefs",
        "/replay", replay_path,
        "/nosound",
        "/nobugreport",
        "/windowed", "1280", "720",
        "/simworkers", "8",
        "/con", con_str,
        "/log", log_path
    ]

    print(f"\n=======================================================", flush=True)
    print(f"[*] Starting Config: {cfg['name']}", flush=True)
    print(f"    Command line /con: {con_str}", flush=True)
    print(f"=======================================================", flush=True)

    proc = subprocess.Popen(args, cwd=bin_dir)
    print(f"[*] Launched {exe} (PID: {proc.pid})", flush=True)

    t_launch = time.time()
    sim_started = False
    speedkeys_sent = False
    t_sim_start = None

    # Wait for simulation to start
    while proc.poll() is None:
        time.sleep(1.5)
        if not os.path.exists(log_path):
            continue

        try:
            with open(log_path, 'r', encoding='latin1') as f:
                text = f.read()
        except Exception:
            continue

        if not sim_started and "Game time: 00:00:" in text and "Session time" in text:
            sim_started = True
            t_sim_start = time.time()
            print(f"[*] Simulation active at {time.time() - t_launch:.1f}s after launch.", flush=True)
            time.sleep(2)
            subprocess.run([sys.executable, speedkeys_script, str(proc.pid), "12"], stdout=subprocess.DEVNULL)
            speedkeys_sent = True
            print("[*] Speedkeys sent (+10 speed). Letting game ramp up for 15s...", flush=True)
            time.sleep(15)
            break

    if proc.poll() is not None:
        print(f"[!] Game process exited prematurely!", flush=True)
        return None

    # Start Tracy capture
    print(f"[*] Starting Tracy capture ({capture_duration}s) to {trace_path}...", flush=True)
    cap_cmd = [capture_tool, "-a", "127.0.0.1", "-p", "8086", "-s", str(capture_duration), "-f", "-o", trace_path]
    cap_res = subprocess.run(cap_cmd, capture_output=True, text=True)
    print(f"[*] Tracy capture finished. Output:\n{cap_res.stdout.strip()}", flush=True)

    # Stop game
    kill_games()

    if not os.path.exists(trace_path):
        print(f"[!] Tracy trace file not created: {trace_path}", flush=True)
        return None

    print(f"[*] Trace size: {os.path.getsize(trace_path) / (1024*1024):.2f} MB", flush=True)

    # Export zone statistics
    print(f"[*] Exporting stats with tracy-csvexport...", flush=True)
    exp_res = subprocess.run([csvexport_tool, trace_path], capture_output=True, text=True)
    with open(csv_stats_path, 'w', encoding='utf-8') as f:
        f.write(exp_res.stdout)

    # Export unwrapped zone events for detailed percentiles
    exp_unwrap_res = subprocess.run([csvexport_tool, "-u", "-f", "UI::LuaGC", trace_path], capture_output=True, text=True)
    with open(csv_zones_path, 'w', encoding='utf-8') as f:
        f.write(exp_unwrap_res.stdout)

    # Parse UI::LuaGC stats
    gc_stats = {
        "name": cfg["name"],
        "count": 0,
        "total_ms": 0.0,
        "mean_ms": 0.0,
        "min_ms": 0.0,
        "max_ms": 0.0,
        "app_frame_max_ms": 0.0,
        "ui_update_max_ms": 0.0,
        "durations_ms": []
    }

    # Parse individual events
    lines = exp_unwrap_res.stdout.strip().splitlines()
    if len(lines) > 1:
        reader = csv.reader(lines)
        header = next(reader)
        dur_idx = -1
        for idx, col in enumerate(header):
            if "duration" in col.lower() or "exec_time" in col.lower() or "time" in col.lower():
                dur_idx = idx
                break

        durations = []
        for row in reader:
            if len(row) > dur_idx and dur_idx >= 0:
                try:
                    val_ns = float(row[dur_idx])
                    durations.append(val_ns / 1_000_000.0) # convert to ms
                except ValueError:
                    pass

        if durations:
            gc_stats["count"] = len(durations)
            gc_stats["total_ms"] = sum(durations)
            gc_stats["mean_ms"] = sum(durations) / len(durations)
            gc_stats["min_ms"] = min(durations)
            gc_stats["max_ms"] = max(durations)
            gc_stats["durations_ms"] = durations

    # Also parse from aggregate stats
    if os.path.exists(csv_stats_path):
        with open(csv_stats_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 9:
                    name = parts[0]
                    file_src = parts[1]
                    try:
                        max_ns = float(parts[8])
                        if name == "AppFrame":
                            gc_stats["app_frame_max_ms"] = max(gc_stats["app_frame_max_ms"], max_ns / 1_000_000.0)
                        elif name == "UI" and "CUIManager.cpp" in file_src:
                            gc_stats["ui_update_max_ms"] = max(gc_stats["ui_update_max_ms"], max_ns / 1_000_000.0)
                    except ValueError:
                        pass

    print(f"[*] Result: Count={gc_stats['count']} | Min={gc_stats['min_ms']:.2f}ms | Mean={gc_stats['mean_ms']:.2f}ms | Max={gc_stats['max_ms']:.2f}ms | UI Update Max={gc_stats['ui_update_max_ms']:.2f}ms | AppFrame Max={gc_stats['app_frame_max_ms']:.2f}ms", flush=True)
    return gc_stats

def main():
    bin_dir = r"C:\ProgramData\FAForever\bin_x64"
    replay_path = r"C:\ProgramData\FAForever\replays\28007941.scfareplay"
    capture_tool = r"I:\ProjectsFaf\faf-re\tools\tracy\tracy-capture.exe"
    csvexport_tool = r"I:\ProjectsFaf\faf-re\tools\tracy\tracy-csvexport.exe"
    speedkeys_script = r"I:\ProjectsFaf\faf-re\scripts\perf\speedkeys.py"

    configurations = [
        {
            "id": "retail_baseline",
            "name": "Retail Baseline (Mark 0, Sweep 0, Idle 0)",
            "periodic": 1,
            "parallel_mark": 0,
            "parallel_sweep": 0,
            "idle_gc": 0
        },
        {
            "id": "parallel_mark_only",
            "name": "Parallel Mark Only (Mark 1, Sweep 0, Idle 0)",
            "periodic": 1,
            "parallel_mark": 1,
            "parallel_sweep": 0,
            "idle_gc": 0
        },
        {
            "id": "parallel_mark_sweep",
            "name": "Parallel Mark + Sweep (Mark 1, Sweep 1, Idle 0)",
            "periodic": 1,
            "parallel_mark": 1,
            "parallel_sweep": 1,
            "idle_gc": 0
        },
        {
            "id": "full_opt_with_idle",
            "name": "Full Opt + Idle GC (Mark 1, Sweep 1, Idle 1)",
            "periodic": 1,
            "parallel_mark": 1,
            "parallel_sweep": 1,
            "idle_gc": 1
        },
    ]

    results = []
    for cfg in configurations:
        res = run_configuration(cfg, replay_path, bin_dir, capture_tool, csvexport_tool, speedkeys_script, capture_duration=60)
        if res:
            results.append(res)
        time.sleep(3)

    print("\n\n" + "="*115)
    print("FINAL BENCHMARK COMPARISON TABLE (UI Lua GC & Frame Times - 60s Windowed Capture)")
    print("="*115)
    print(f"{'Configuration':<45} | {'GC Count':<8} | {'Mean Pause':<10} | {'Max Pause':<10} | {'Max UI Loop':<11} | {'Max AppFrame'}")
    print("-" * 115)
    for r in results:
        print(f"{r['name']:<45} | {r['count']:<8} | {r['mean_ms']:<7.2f} ms | {r['max_ms']:<7.2f} ms | {r['ui_update_max_ms']:<8.2f} ms | {r['app_frame_max_ms']:.2f} ms")
    print("="*115)

if __name__ == "__main__":
    main()
