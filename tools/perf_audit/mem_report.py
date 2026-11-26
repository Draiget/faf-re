import os
"""mem_report.py [dir_logs] -> table of the memory diff runs (mem_<cfg>): the backend's own memory log lines and the process / GPU counters."""
import glob, json, os, re, sys

LOGS = os.environ.get('FAF_LOGS', 'C:/ProgramData/FAForever/logs')
OUT = (os.environ.get('PERF_AUDIT_OUT', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'out')).replace(chr(92), '/')) + '/perf_out'
rx = re.compile(r'D3D12 memory: buffer copies ([\d.]+) MB, texture copies ([\d.]+) MB, upload pages ([\d.]+) MB \((\d+)\), placed textures ([\d.]+) of ([\d.]+) MB, placed buffers ([\d.]+) of ([\d.]+) MB, (\d+) pipelines.*process private ([\d.]+) MB')
print('| cfg | build | buffer copies | texture copies | upload pages | placed textures (used / heap) | placed buffers (used / heap) | pipelines | process private MB | GPU dedicated MB (counter) |')
print('|---|---|---|---|---|---|---|---|---|---|')
for cfg in ('off', 'default', 'user'):
    for exe in ('perfbase', 'perf'):
        log = '%s/pf_mem_%s_d3d12_%s.log' % (LOGS, cfg, exe)
        if not os.path.exists(log):
            continue
        last = None
        for l in open(log, errors='replace'):
            m = rx.search(l)
            if m:
                last = m.groups()
        gpu = None
        jf = '%s/mem_%s_d3d12_%s.json' % (OUT, cfg, exe)
        if os.path.exists(jf):
            samples = [s for s in json.load(open(jf)).get('mem', []) if s.get('gpu', -1) >= 0]
            if samples:
                gpu = samples[-1]['gpu']
        if last:
            print('| %s | %s | %s | %s | %s (%s) | %s / %s | %s / %s | %s | %s | %s |' % (cfg, 'baseline' if exe == 'perfbase' else 'ours', last[0], last[1], last[2], last[3], last[4], last[5], last[6], last[7], last[8], last[9], gpu))
