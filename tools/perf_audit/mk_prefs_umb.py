"""mk_prefs_umb.py: prefs copies of the user's profile with one group of its options put back to the default (for jobs.py umb): Game_perf_u_<name>.prefs"""
import os, re
P = os.environ.get('FAF_PREFS_DIR', os.path.expandvars('%LOCALAPPDATA%/Gas Powered Games/Supreme Commander Forged Alliance')).replace(chr(92), '/') + '/'
src = open(P + 'Game_perf_user.prefs', errors='replace').read()


def patch(text, changes):
    i = text.find("graphics_api = 'd3d12'")
    s = text.rfind('options = {', 0, i)
    e = text.find('\n            },', i)
    blk = text[s:e]
    for k, v in changes.items():
        pat = re.compile(r'^(\s+)' + re.escape(k) + r' = .*?(,?)$', re.M)
        blk = pat.sub(lambda m: m.group(1) + k + ' = ' + v + m.group(2), blk, count=1)
    return text[:s] + blk + text[e:]


V = {'nolights': {'dynlights_quality': "'off'"}, 'noshadow': {'shadow_filter': "'off'"}, 'noao': {'ambient_occlusion': "'-1'"}, 'nosoft': {'soft_particles': "'low'"},
     'nosharp': {'sharpen_quality': "'medium'"}, 'less3': {'dynlights_quality': "'off'", 'shadow_filter': "'off'", 'ambient_occlusion': "'-1'"}}
for name, ch in V.items():
    open(P + 'Game_perf_u_%s.prefs' % name, 'w', errors='replace').write(patch(src, ch))
print('ok', list(V))
