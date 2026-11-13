import os
LOGS = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs')
import sys, statistics as st
import perf_parse as pp
D = LOGS + '/pf_partest_%s_r%d_d3d12_%s.log'
for view in ('meas1', 'meas2'):
    print('==', view)
    for lab, exe in (('base', 'perfbase'), ('patched', 'perf'), ('unpatched', 'perf')):
        vals = {'gpu': [], 'cpu': [], 'wall': [], 'EffParticles': [], 'EffParticlesCpu': []}
        for r in range(3):
            try:
                d = pp.by_label(pp.parse(D % (lab, r, exe))[0])[view][0]
            except Exception as e:
                continue
            vals['gpu'].append(d['gpu']); vals['cpu'].append(d['cpu']); vals['wall'].append(d['wall'])
            p = d['passes'].get('EffParticles', (0, 0)); vals['EffParticles'].append(p[1]); vals['EffParticlesCpu'].append(p[0])
        print('%-10s n=%d GPU %s | EffParticles GPU %s cpu %s | CPU %s | wall %s' % (lab, len(vals['gpu']), ' '.join('%.3f' % x for x in vals['gpu']), ' '.join('%.3f' % x for x in vals['EffParticles']), ' '.join('%.3f' % x for x in vals['EffParticlesCpu']), ' '.join('%.3f' % x for x in vals['cpu']), ' '.join('%.3f' % x for x in vals['wall'])))
