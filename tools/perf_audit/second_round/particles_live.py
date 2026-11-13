"""particles_live.py <apis> [tag]: live switching of the particle patch in one session (battle scene, every option off at start)."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import jobs, parity
apis = sys.argv[1].split(','); tag = sys.argv[2] if len(sys.argv) > 2 else 'p2live'
pres = "wide = { 70, 0.95, 0, 0, 0 }"
steps = [
    ('off', parity.OFF_OURS, 5),
    ('soft_on', ['ren_SoftParticles 1'], 5),
    ('soft_off', ['ren_SoftParticles 0'], 5),
    ('lowres_half_small_view', ['ren_ParticleLowRes 1'], 8),
    ('minvp0', ['ren_ParticleLowResMinViewport 0'], 8),
    ('minvp5', ['ren_ParticleLowResMinViewport 5'], 25),
    ('lowres_off', ['ren_ParticleLowRes 0'], 5),
    ('soft_high', ['ren_SoftParticles 2'], 5),
]
for api in apis:
    name = 'steps_%s.lua' % tag
    with open(jobs.HERE + '/' + name, 'w') as o:
        o.write('AB_PRESETS = { %s }\nAB_STEPS = {\n' % pres)
        for lab, cmds, hold in steps:
            o.write("  { %r, { %s }, 'wide', %d },\n" % (lab, ', '.join(repr(c) for c in cmds), hold))
        o.write('}\n')
    jobs.run('perf', api, '%s_%s' % (tag, api), 'battle', name, prefs='off', con=';'.join(c.replace(' ', '=') for c in parity.OFF_OURS))
