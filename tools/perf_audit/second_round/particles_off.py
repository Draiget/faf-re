"""every particle option off, battle scene: perfbase, perf (new), perf /noparticlelowres; usage: particles_off.py <apis> <reps> <tagprefix>"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # tools/perf_audit
import jobs, parity
apis = sys.argv[1].split(','); reps = int(sys.argv[2]); pre = sys.argv[3]
pres = "wide = { 70, 0.95, 0, 0, 0 }, strat = { 420, 1.25, 0, 0, 0 }"
for rep in range(reps):
    for api in apis:
        for lab, exe, xa in (('base', 'perfbase', None), ('new', 'perf', None), ('newnp', 'perf', ['/noparticlelowres'])):
            cmds = parity.OFF_BASE if exe == 'perfbase' else parity.OFF_OURS
            steps = 'steps_%s_%s.lua' % (pre, lab)
            parity.write_steps(jobs.HERE + '/' + steps, pres, 'wide', 'strat', cmds, 10)
            jobs.run(exe, api, '%s_%s_r%d' % (pre, lab, rep), 'battle', steps, prefs='off_base' if exe == 'perfbase' else 'off', con=';'.join(c.replace(' ', '=') for c in cmds), xargs=xa)
