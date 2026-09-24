"""Launch the original FA on a replay (or /map skirmish), start the sampler, push sim speed up.

usage: run_game.py <outdir> <seconds> -- <game args...>
  e.g. run_game.py out/rep 1500 -- /replay C:\path\game.scfareplay /replayid 123 /nomovie
From Git Bash, set MSYS_NO_PATHCONV=1 so /replay etc. are not rewritten into paths.
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
outdir = os.path.abspath(sys.argv[1])
os.makedirs(outdir, exist_ok=True)
seconds = int(sys.argv[2])
game_args = sys.argv[sys.argv.index("--") + 1:]
exe = os.environ.get("FA_EXE", r"C:\ProgramData\FAForever\bin\ForgedAlliance.exe")
log = os.path.join(outdir, "game.log")
game = subprocess.Popen([exe, "/init", "init.lua", "/nobugreport", *game_args, "/log", log],
                        cwd=os.path.dirname(exe))
print("game pid", game.pid, flush=True)
sampler = subprocess.Popen([sys.executable, os.path.join(HERE, "sampler.py"), str(game.pid),
                            outdir, str(seconds), "60"],
                           stdout=open(os.path.join(outdir, "sampler.out"), "w"), stderr=subprocess.STDOUT)
t0 = time.time()
sped = False
while game.poll() is None and time.time() - t0 < seconds:
    time.sleep(2)
    if not sped:
        try:
            text = open(log, encoding="latin1").read()
        except OSError:
            continue
        if "Game time: 00:00:" in text and "Session time" in text:
            time.sleep(3)
            subprocess.run([sys.executable, os.path.join(HERE, "speedkeys.py"), str(game.pid), "12"],
                           stdout=subprocess.DEVNULL)
            sped = True
            print("speed keys posted at %.0fs" % (time.time() - t0), flush=True)
print("game exit", game.poll(), "after %.0fs" % (time.time() - t0), flush=True)
if game.poll() is None:
    game.terminate()
time.sleep(3)
sampler.terminate()
