#!/usr/bin/env python3
"""Compile verbatim named production definitions; hash every source and slice.

No functional rewriting in the normal target. Explicit negative controls mutate
only generated test copies and record both original and generated slice hashes.
"""
import argparse, hashlib, json, re
from pathlib import Path
p=argparse.ArgumentParser(); p.add_argument('--source-root',type=Path,required=True); p.add_argument('--output-dir',type=Path,required=True); p.add_argument('--negative-control',default=''); a=p.parse_args()
root=a.source_root.resolve(); out=a.output_dir; out.mkdir(parents=True,exist_ok=True)
records=[]; outputs={}; definitions={}
def sha(v): return hashlib.sha256(v).hexdigest()
def extract(path,pattern,semi=False):
    data=(root/path).read_bytes(); source=data.decode(); hits=list(re.finditer(pattern,source,re.M))
    if len(hits)!=1: raise ValueError(f'{path}: expected 1 match for {pattern}, found {len(hits)}')
    start=hits[0].start(); opening=source.index('{',hits[0].end()); depth=0
    if ';' in source[hits[0].end():opening]: raise ValueError(f'not a complete definition: {pattern}')
    for t in re.finditer(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]',source[opening:]):
        if t.group()=='{': depth+=1
        elif t.group()=='}':
            depth-=1
            if not depth: end=opening+t.end(); break
    else: raise ValueError(pattern)
    if semi:
        assert source[end]==';'; end+=1
    text=source[start:end]; line=source[:start].count('\n')+1
    records.append(dict(path=path,line=line,source_sha256=sha(data),definition_sha256=sha(text.encode()),pattern=pattern))
    return text,line
world='src/moho/particles/CWorldParticles.cpp'; buckets='src/moho/particles/ParticleRenderBuckets.cpp'; work='src/moho/particles/ParticleRenderWorkItem.cpp'; lifecycle='src/moho/sim/WldSessionControl.cpp'
def binding(path,pattern,semi=False):
    text,line=extract(path,pattern,semi); original=text
    if a.negative_control=='segments_as_vertices' and 'EnsureAndFillTrailBucketWorkItems' in pattern:
        text=text.replace('DropTrailSegments(bucket.pendingTrails.size())','DropTrailSegments(4 * bucket.pendingTrails.size())')
    if a.negative_control=='omit_partial_capacity' and 'CWorldParticles::Init' in pattern:
        text=text.replace('particlePoolStats.AddTrailBuffer();','/* negative control: omit successful insert metadata */')
    if a.negative_control=='clear_ends_session' and 'CWorldParticles::ClearRenderBuckets' in pattern:
        text=text.replace('{','{\n    EndParticlePoolStatsSession();',1)
    if a.negative_control=='clear_resets_session' and 'CWorldParticles::ClearRenderBuckets' in pattern:
        text=text.replace('{','{\n    (void)particlePoolStats.EndSession();\n    particlePoolStats.BeginSession();',1)
    if a.negative_control=='end_after_clear' and 'WLD_Teardown' in pattern:
        text=text.replace('    EndParticlePoolStatsSession();\n    sWorldParticles.ClearRenderBuckets();','    sWorldParticles.ClearRenderBuckets();\n    EndParticlePoolStatsSession();')
    if a.negative_control=='end_before_drain' and 'WLD_Teardown' in pattern:
        text=text.replace('    EndParticlePoolStatsSession();\n',''); text=text.replace('{','{\n    EndParticlePoolStatsSession();',1)
    if a.negative_control=='omit_inherited_occupancy' and 'BeginPoolStatsSession' in pattern:
        text=re.sub(r'^    particlePoolStats.Observe[^\n]+\n','',text,flags=re.M)
    if a.negative_control=='omit_summary_log' and 'EndParticlePoolStatsSession' in pattern:
        text=text.replace('    try {','    return;\n    try {',1)
    records[-1]['bound_sha256']=sha(text.encode()); records[-1]['mutated']=text!=original
    definitions[pattern]=original
    return f'#line {line} "{path}"\n{text}\n'
def literal(path, pattern):
    data=(root/path).read_bytes(); hits=list(re.finditer(pattern,data.decode(),re.M))
    if len(hits)!=1: raise ValueError(f'{path}: expected one literal {pattern}, found {len(hits)}')
    text=hits[0].group(); records.append(dict(path=path,source_sha256=sha(data),definition_sha256=sha(text.encode()),bound_sha256=sha(text.encode()),pattern=pattern))
    return text+'\n'
parts=['namespace moho {\n']
for path,name in [('src/moho/particles/SWorldTrail.h','SWorldTrail'),('src/moho/particles/ParticleRenderWorkItem.h','SParticleRenderInterval'),('src/moho/particles/ParticleRenderWorkItem.h','SParticleRenderWorkItem'),('src/moho/particles/ParticleRenderBuckets.h','STrailSegmentBuffer'),('src/moho/particles/ParticleRenderBuckets.h','STrailRenderBucket')]:
    parts.append(binding(path,rf'^  struct {name}\s*',True))
parts.append(literal('src/moho/particles/ParticleRenderBuckets.h',r'^  using TrailSegmentPool = [^;]+;'))
parts.append(literal(world,r'^  bool ren_LargeParticlePools = [^;]+;'))
parts.append('}\n')
outputs['Payload.inc']=''.join(parts)
parts=['namespace {\n']
for name in ['kPooledParticleBufferCount','kParticleBufferCapacity','kPooledTrailSegmentBufferCount','kTrailSegmentCapacity','kLargePooledParticleBufferCount','kLargePooledTrailSegmentBufferCount','kTrailVertexFormatToken','kTrailVertexSheetUsageToken','kTrailVertexSheetFrequencyToken']:
    data=(root/world).read_bytes(); match=re.search(r'^  constexpr [^\n]*\b'+name+r' = [^;]+;',data.decode(),re.M); assert match,name
    parts.append(match.group()+'\n'); records.append(dict(path=world,source_sha256=sha(data),definition_sha256=sha(match.group().encode()),pattern=name))
parts.append(binding(buckets,r'^  struct STrailVertex\s*',True)); parts.append(literal(buckets,r'^  inline constexpr std::size_t kTrailSegmentVertexCount = [^;]+;'))
for name in ['AppendInterval','GetTrailSegmentBufferMaxSegments','LockTrailSegmentVertexRangeFromStart','LockTrailSegmentVertexRangeSubspan','PackTrailSegmentQuadVertices']:
    parts.append(binding(buckets,rf'^  (?:\[\[nodiscard\]\] )?[A-Za-z_][^\n]*\b{name}\('))
parts.append(binding(world,r'^  void ReleaseTrailSegmentPoolBuffers\(')); parts.append('}\nnamespace moho {\n')
for name in ['Shutdown','Reset']:
    parts.append(binding('src/moho/render/SParticleBuffer.cpp',rf'^  void ParticleBuffer::{name}\('))
for name in ['ResetParticleRenderWorkItemIntervals','DestroyParticleRenderWorkItem','InitializeParticleRenderWorkItem','AdvanceParticleRenderWorkItemCursorToFrame']:
    parts.append(binding(work,rf'^  [A-Za-z_][^\n]*\b{name}\('))
for name in ['BeginPoolStatsSession','AcquireParticleBuffer','ReleaseParticleBuffer','AcquireTrailSegmentBuffer','ReleaseTrailSegmentBuffer','Init']:
    parts.append(binding(world,rf'^  [A-Za-z_][^\n]*\bCWorldParticles::{name}\('))
parts.append(binding(world,r'^  void EndParticlePoolStatsSession\('))
for name in ['UploadPendingTrailsIntoWorkItem','RecycleAndDestroyTrailBucketWorkItems','DestroyTrailRenderBucket','PruneExpiredTrailBucketWorkItems','EnsureAndFillTrailBucketWorkItems']:
    parts.append(binding(buckets,rf'^  (?:void|bool) {name}\('))
for name in ['ClearRenderBuckets']:
    parts.append(binding(world,rf'^  [A-Za-z_][^\n]*\bCWorldParticles::{name}\('))
parts.append(binding(world,r'^  void DestroyWorldParticlesSingleton\(')); parts.append('}\n'); parts.append('namespace {\n'); parts.append(binding('src/moho/render/d3d/CD3DDevice.cpp',r'^  void ResetWorldParticleBuffers\(')); parts.append('}\n'); outputs['Production.inc']=''.join(parts)
parts=['namespace moho {\n']
for name in ['WLD_CreateSession','DeleteWldSessionAndReturn','WLD_DestroySession','WLD_Teardown']:
    parts.append(binding(lifecycle,rf'^  [A-Za-z_][^\n]*\b{name}\('))
parts.append('}\n'); outputs['Lifecycle.inc']=''.join(parts)
# Full replay-reset body is a source contract only, never represented as runtime execution.
reset,_=extract('src/moho/sim/CWldSessionCore.cpp',r'^  void CWldSession::ResetForNewReplaySim\(')
outputs['SourceContracts.inc']='namespace source_contracts {\nconstexpr char replay_reset[] = R"SCS('+reset+')SCS";\nconstexpr char stats_header[] = R"SCS('+(root/'src/moho/particles/ParticlePoolStats.h').read_text()+')SCS";\n}\n'
for name,data in outputs.items(): (out/name).write_text(data)
paths=['src/moho/particles/ParticlePoolStats.h','src/moho/particles/CWorldParticles.h','src/legacy/containers/Vector.h','src/legacy/containers/Set.h','src/legacy/containers/RbTree.h','src/legacy/containers/Map.h','src/legacy/containers/String.h','src/legacy/containers/String.cpp','src/legacy/containers/AutoPtr.h','src/moho/misc/CountedObject.h','src/platform/LayoutAsserts.h']
# Record the actual transitive WildMagic include closure used by the payload.
wm=root/'dependencies/WildMagic3p8/Foundation'; by_name={p.name:p for p in wm.rglob('*') if p.is_file()}; seen=set(); pending=['Wm3Vector3.h']
while pending:
    name=pending.pop()
    if name in seen: continue
    seen.add(name); path=by_name[name]; paths.append(path.relative_to(root).as_posix())
    for inc in re.findall(r'^\s*#\s*include\s*"([^"]+)"',path.read_text(),re.M):
        if inc in by_name: pending.append(inc)
paths.append('src/legacy/containers/Layout.h')
manifest=dict(kind='source-bound host adapters; not native engine or GPU',negative_control=a.negative_control,definitions=records,included_headers={x:sha((root/x).read_bytes()) for x in paths},generated_sha256={x:sha((out/x).read_bytes()) for x in outputs})
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n'); print(f'Bound {len(records)} production definitions/constants to {out}')
if a.negative_control and not any(r.get('mutated') for r in records): raise ValueError('negative control did not change any source')
