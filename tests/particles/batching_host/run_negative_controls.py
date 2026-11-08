#!/usr/bin/env python3
"""Compile four deliberate defects in isolated generated-source copies.

A negative control passes only when it compiles and GoogleTest reports an
assertion failure. The selected engine source tree and positive binding are
never modified. This does not exercise a graphics backend.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

p=argparse.ArgumentParser()
p.add_argument('--source-root', type=Path, required=True)
p.add_argument('--binding', type=Path, required=True)
p.add_argument('--gtest-root', type=Path, required=True)
p.add_argument('--gtest-build', type=Path, required=True)
p.add_argument('--output-dir', type=Path, required=True)
p.add_argument('--source-head', required=True)
p.add_argument('--compiler', default='g++')
a=p.parse_args()
for name in ['source_root','binding','gtest_root','gtest_build','output_dir']:
    setattr(a,name,getattr(a,name).resolve())
a.output_dir.mkdir(parents=True,exist_ok=True)
positive=a.binding.read_text()

# Each replacement is confined to a production definition and is asserted to
# occur once. No test expectations or graphics recorder behavior are changed.
mutations={
 'omit_early_forget': (
  '  void PruneExpiredParticleBucketWorkItems(',
  '        ForgetMirroredParticles(*static_cast<const ParticleBuffer*>(workItem->mParticleBuffer)); // engine addition',
  '        // NEGATIVE CONTROL: omitted mirror release on expiry'),
 'keep_released_slot_mapping': (
  '    struct ParticleMirrorStore',
  '          mSlotOf.erase(found);',
  '          // NEGATIVE CONTROL: stale ownership survives release'),
 'ignore_failed_mirror_copy': (
  '  void MirrorUploadedParticles(',
  '    mirrored = gpg::gal::Device::GetInstance()->CopyVertexBufferRegion(',
  '    (void)gpg::gal::Device::GetInstance()->CopyVertexBufferRegion('),
 'omit_gather_fallback': (
  '    bool RenderParticleBucketBatched(',
  '          // Nothing drawn yet: the caller draws the buffers one by one.\n          return false;',
  '          // NEGATIVE CONTROL: falsely report success after failed gathering.\n          return true;'),
}
results=[]
for name,(definition,old,new) in mutations.items():
    start=positive.index(definition)
    end=positive.find('#line ',start)
    if end<0: end=len(positive)
    section=positive[start:end]
    assert section.count(old)==1,(name,section.count(old))
    changed=positive[:start]+section.replace(old,new)+positive[end:]
    directory=a.output_dir/name;directory.mkdir(exist_ok=True)
    (directory/'ParticleBatchProduction.inc').write_text(changed)
    binary=directory/'test'
    command=[a.compiler,'-std=c++20','-g','-O0','-Wall','-Wextra','-Werror','-pedantic',
      '-Wno-error=changes-meaning','-Wno-error=use-after-free','-DFAF_RETAIL_LAYOUT=0','-pthread',
      '-I'+str(a.source_root/'src'),'-I'+str(directory),'-I'+str(a.gtest_root/'googletest/include'),
      str(Path(__file__).with_name('ParticleBatchReclaimTests.cpp')),
      str(a.gtest_build/'lib/libgtest_main.a'),str(a.gtest_build/'lib/libgtest.a'),'-o',str(binary)]
    with (directory/'compile.log').open('w') as log:
        log.write('source_head='+a.source_head+'\n');log.flush()
        compiled=subprocess.run(command,stdout=log,stderr=subprocess.STDOUT)
    if compiled.returncode:
        raise RuntimeError(f'{name}: did not compile; see {directory}/compile.log')
    xml=directory/'tests.xml'
    env=dict(os.environ);env.pop('FAF_PARTICLE_BATCH_DIAG',None)
    with (directory/'run.log').open('w') as log:
        log.write('source_head='+a.source_head+'\n');log.flush()
        run=subprocess.run([str(binary),'--gtest_output=xml:'+str(xml)],stdout=log,stderr=subprocess.STDOUT,env=env)
    if not xml.exists():
        raise RuntimeError(f'{name}: no test result (crash is not an assertion control)')
    failures=[t.attrib['name'] for t in ET.parse(xml).getroot().iter('testcase') if t.find('failure') is not None]
    assert run.returncode==1 and failures,(name,run.returncode,failures)
    row={'name':name,'source_head':a.source_head,'positive_binding_sha256':hashlib.sha256(positive.encode()).hexdigest(),
         'mutated_binding_sha256':hashlib.sha256(changed.encode()).hexdigest(),'replaced':old,'replacement':new,
         'compile_command':command,'compile_exit':compiled.returncode,'test_exit':run.returncode,'failing_tests':failures}
    results.append(row)
    print(name+': caught by '+str(len(failures))+' tests',flush=True)
(a.output_dir/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
