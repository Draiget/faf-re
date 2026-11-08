#!/usr/bin/env python3
"""Bind unchanged production bodies to the host recorder, never a numerical model.

The generated file and manifest belong in the build directory. Fail closed if a
named definition is ambiguous or absent. The source root is always explicit.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('--source-root', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--inject-append',action='store_true')
args = parser.parse_args()
root = args.source_root.resolve()
records = []
chunks = []

def sha(data):
    return hashlib.sha256(data).hexdigest()

def bind(path, pattern, trailing_semicolon=False):
    input_path = root / path
    data = input_path.read_bytes()
    text = data.decode('utf-8')
    hits = list(re.finditer(pattern, text, re.MULTILINE))
    if len(hits) != 1:
        raise ValueError(f'{path}: expected one definition for {pattern}, got {len(hits)}')
    start = hits[0].start()
    opening = text.index('{', hits[0].end())
    # Ignore braces in comments and quoted literals without rewriting any bytes.
    tokens = re.compile(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|[{}]')
    depth = 0
    for token in tokens.finditer(text, opening):
        if token.group() == '{':
            depth += 1
        elif token.group() == '}':
            depth -= 1
            if depth == 0:
                end = token.end()
                break
    else:
        raise ValueError(f'unclosed definition: {pattern}')
    if trailing_semicolon:
        if text[end] != ';':
            raise ValueError(f'missing struct semicolon: {pattern}')
        end += 1
    body = text[start:end]
    if args.inject_append and 'AppendInterval' in pattern:
        original = '    workItem.mIntervals.push_back(intervalValue);'
        if body.count(original) != 1:
            raise ValueError('AppendInterval pre-push hook no longer matches exactly')
        body = body.replace(original, '    if (moho::beforeAppend) moho::beforeAppend();\n' + original)
    line = text[:start].count('\n') + 1
    records.append({'path': path, 'line': line, 'source_sha256': sha(data),
                    'definition_sha256': sha(body.encode()), 'pattern': pattern})
    chunks.extend([f'#line {line} "{path}"\n', body, '\n'])

buckets = 'src/moho/particles/ParticleRenderBuckets.cpp'
work = 'src/moho/particles/ParticleRenderWorkItem.cpp'
world = 'src/moho/particles/CWorldParticles.cpp'
chunks.append('namespace {\n')
bind(buckets, r'^  struct SParticleInstance\s*', True)
bind(buckets, r'^  \[\[nodiscard\]\] bool AppendInterval\(')
chunks.append('}\nnamespace moho {\n')
for name in ['ResetParticleRenderWorkItemIntervals', 'DestroyParticleRenderWorkItem',
             'InitializeParticleRenderWorkItem', 'AdvanceParticleRenderWorkItemCursorToFrame']:
    bind(work, r'^  (?:void|bool|SParticleRenderWorkItem\*) ' + name + r'\(')
for name in ['AcquireParticleBuffer', 'ReleaseParticleBuffer']:
    bind(world, r'^  [^\n]*\bCWorldParticles::' + name + r'\(')
# The switch default comes from production, not a test-side constant.
data = (root / buckets).read_bytes()
match = re.search(r'^  int ren_ParticleLinearUpload = 0;', data.decode(), re.MULTILINE)
if match is None:
    raise ValueError('Expected opt-in production switch default')
chunks.append(match.group() + '\n')
records.append({'path': buckets, 'source_sha256': sha(data),
                'definition_sha256': sha(match.group().encode()), 'pattern': 'ren_ParticleLinearUpload default'})
chunks.append('namespace {\n')
bind(buckets, r'^    struct ParticlePendingCursor\s*', True)
bind(buckets, r'^    void UploadPendingParticleRangeIntoWorkItem\(')
chunks.append('}\n')
for name in ['UploadPendingParticlesIntoWorkItem', 'RecycleAndDestroyParticleBucketWorkItems',
             'PruneExpiredParticleBucketWorkItems', 'EnsureAndFillParticleBucketWorkItems']:
    bind(buckets, r'^  (?:void|bool) ' + name + r'\(')
bind('src/moho/render/GpuPathSettings.cpp', r'^  bool GpuPathEnabled\(')
bind(buckets, r'^  bool ParticleBatchActive\(')
chunks.append('namespace {\n')
for name in ['ParticleGatherBuffer', 'ParticleMirrorStore']:
    bind(buckets, r'^    struct ' + name + r'\s*', True)
    chunks.append(f'{name} sParticle{"Gather" if name == "ParticleGatherBuffer" else "Mirror"};\n')
for name in ['ParticleBatchDiagnosticMode', 'DrawnParticleCount', 'RenderParticleBucketBatched']:
    bind(buckets, r'^    (?:\[\[nodiscard\]\] )?(?:int|bool) ' + name + r'\(')
chunks.append('}\n')
for name in ['ForgetMirroredParticles', 'MirrorUploadedParticles', 'RenderParticleBucket']:
    bind(buckets, r'^  (?:void|bool) ' + name + r'\([^;]*?\)\s*(?=\{)')
for name in ['RenderEffects', 'RenderRefractingEffects']:
    bind(world, r'^  (?:char|void) CWorldParticles::' + name + r'\(')
chunks.append('}\n')
args.output.parent.mkdir(parents=True, exist_ok=True)
args.output.write_text(''.join(chunks), encoding='utf-8')
header_paths = ['src/moho/misc/CountedObject.h', 'src/legacy/containers/String.h',
                'src/legacy/containers/String.cpp',
                'src/legacy/containers/Vector.h', 'src/legacy/containers/Layout.h',
                'src/gpg/gal/GpuDriven.h', 'src/platform/LayoutAsserts.h']
# Hash the real WildMagic header closure, with repository-relative identities.
wm = root / 'dependencies/WildMagic3p8/Foundation'
wm_paths = {path.name: path for path in wm.rglob('*') if path.is_file()}
wm_seen = set()
wm_pending = ['Wm3Vector3.h']
while wm_pending:
    name = wm_pending.pop()
    if name in wm_seen:
        continue
    path = wm_paths[name]
    wm_seen.add(name)
    header_paths.append('dependencies/WildMagic3p8/Foundation/' + path.relative_to(wm).as_posix())
    for include in re.findall(r'^\s*#\s*include\s*"([^"]+)"', path.read_text(), re.MULTILINE):
        if include in wm_paths:
            wm_pending.append(include)
manifest = {'kind': 'source-bound host tests; fake graphics, not engine or GPU execution', 'append_hook':args.inject_append,
            'definitions': records,
            'included_headers': {p: sha((root / p).read_bytes()) for p in header_paths},
            'generated_sha256': sha(args.output.read_bytes())}
args.output.with_suffix('.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(f'Bound {len(records)} source definitions; append injection hook={args.inject_append}; manifest: {args.output.with_suffix(".json")}')
