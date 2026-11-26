"""gen_soak.py <api> <cfg> <out.lua> [steps] -> a long battle soak: one setup step, then N steps of 15 s, each logging ren_Info (process + GPU memory).
cfg: off | default | user | ultra (ours; everything on, rays on d3d12/vulkan) | base (shipped baseline, nothing but the limiter)"""
import sys
sys.argv_saved = sys.argv
api, cfg, out = sys.argv[1], sys.argv[2], sys.argv[3]
n = int(sys.argv[4]) if len(sys.argv) > 4 else 16
sys.argv = ['gen_steps.py', 'battle', api, 'NUL']
src = open(__file__.replace('gen_soak.py', 'gen_steps.py')).read()
ns = {}
exec(compile(src, 'gen_steps.py', 'exec'), ns)
OFF, DEFAULT_ON, ULTRA, ULTRA_RT = ns['OFF'], ns['DEFAULT_ON'], ns['ULTRA'], ns['ULTRA_RT']
cmds = {'off': OFF, 'default': ['sc_FrameTimeClamp 0'], 'user': ['sc_FrameTimeClamp 0'], 'base': ['sc_FrameTimeClamp 0'],
        'ultra': ['sc_FrameTimeClamp 0'] + DEFAULT_ON + ULTRA + (ULTRA_RT if api != 'd3d11' else [])}[cfg]
q = lambda s: "'" + s + "'"
with open(out, 'w') as o:
    o.write("AB_PRESETS = { wide = { 70, 0.95, 0, 0, 20 }, close = { 22, 0.6, 0, 0, 5 } }\nAB_STEPS = {\n")
    o.write("  { 'setup', { %s }, 'wide', 6, 'info' },\n" % ', '.join(q(c) for c in cmds))
    for k in range(1, n + 1):
        o.write("  { 'soak.%d', {}, '%s', 15, 'info' },\n" % (k, 'wide' if k % 4 else 'close'))
    o.write('}\n')
print('soak', api, cfg, n, 'steps ->', out)
