"""Fail-closed extraction and explicit host adapters for the splat regression.

This is not a C++ parser. Unsupported syntax/shape must fail, not silently test
another function. Every consumed production byte is SHA-256 recorded.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import shutil
import subprocess

LANES = ('High', 'Medium', 'Low')
TERRAIN = 'src/moho/terrain/'
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def code_mask(source):
    # Keep positions and line breaks while hiding comments and string literals.
    require('R"' not in source, 'Raw C++ strings need an explicit extractor update')
    token = r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(token, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), source, flags=re.S)


def unique(pattern, source, label):
    matches = list(re.finditer(pattern, code_mask(source), re.S))
    require(len(matches) == 1, f'{label}: expected exactly 1 match, found {len(matches)}')
    return matches[0]


def block_end(source, opening):
    masked = code_mask(source)
    require(masked[opening] == '{', 'Expected opening brace')
    depth = 0
    for i in range(opening, len(masked)):
        depth += (masked[i] == '{') - (masked[i] == '}')
        if depth == 0:
            return i + 1
    raise RuntimeError('Unbalanced source block')


def function_body(source, signature):
    match = unique(signature + r'\s*\{', source, signature)
    opening = code_mask(source).index('{', match.start())
    return source[opening:block_end(source, opening)]


class Sources:
    def __init__(self):
        self.files = {}
        self.adaptations = []

    def read(self, root, relative, role='production'):
        path = Path(root) / relative
        data = path.read_bytes()
        key = (role, str(relative))
        digest = hashlib.sha256(data).hexdigest()
        require(key not in self.files or self.files[key]['sha256'] == digest,
                f'Source changed during test: {path}')
        self.files[key] = {'role': role, 'path': str(relative), 'sha256': digest}
        return data.decode('utf-8')

    def fixture(self, name):
        return self.read(FIXTURES, name, 'fixture')

    def adapt(self, label, count):
        self.adaptations.append({'adapter': label, 'count': count})

    def generated(self, root):
        self.generated_files = [
            {'path': str(path.relative_to(root)), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(root.rglob('*')) if path.is_file()
        ]

    def manifest(self):
        return {'sources': list(self.files.values()), 'host_adaptations': self.adaptations, 'generated': getattr(self, 'generated_files', [])}


def write(root, relative, data):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data)


def replace_exact(source, old, new, count, label):
    require(source.count(old) == count, f'{label}: expected {count} occurrences, found {source.count(old)}')
    return source.replace(old, new)


def collection_method(source, lane, baseline=False):
    body = function_body(source, r'void\s+' + lane + r'FidelityTerrain::UpdateRenderContext\s*\([^)]*\)')
    visible = unique(r'gpg::fastvector<CWldTerrainDecal\*>\s+visibleSplats\s*;', body, lane + ' visible list')
    loop = unique(r'for\s*\(CWldTerrainDecal\* const decalEntry : visibleSplats\)\s*\{', body, lane + ' collector')
    declaration = unique(r'(?:std::size_t|std::int32_t)\s+splatBudget\s*=\s*0\s*;', body, lane + ' counter')
    opening = code_mask(body).index('{', loop.start())
    require(visible.end() < declaration.start() < loop.start(), lane + ' collector ordering drift')
    require(not code_mask(body[declaration.end():loop.start()]).strip(), lane + ' unexpected collector prelude')
    if baseline:
        prep = 'mSplatVertices.ResetStorageToInline();'
        require(body.count(prep) == 1 and body.index(prep) < visible.start(), lane + ' baseline clearing drift')
        limit = unique(r'constexpr\s+std::int32_t\s+kMaxSplatsPerFrame\s*=\s*\d+\s*;', source, lane + ' original constant')
        prep += source[limit.start():limit.end()]
    else:
        match = unique(r'auto splatOutputBudget = PrepareSplatOutput\(mSplatVertices, ren_SplatBudgetTier\);', body, lane + ' preparation')
        require(match.end() < visible.start(), lane + ' preparation moved after visibility filtering')
        prep = body[match.start():match.end()]
    if lane == 'High':
        alias = unique(r'auto& splatVertices = mSplatVertices;', body, lane + ' output alias')
        require(visible.end() < alias.start() < declaration.start(), lane + ' alias order drift')
        prep += body[alias.start():alias.end()]
    # Only explicit surrounding infrastructure is mocked. Collector is unedited.
    return prep + body[declaration.start():block_end(body, opening)]


def prepare_types(source, out, sources, wildmagic=None):
    header = sources.read(source, TERRAIN + 'splat/CWldSplat.h')
    vertex_match = unique(r'struct\s+SplatVertex\s*\{', header, 'SplatVertex')
    opening = code_mask(header).index('{', vertex_match.start())
    end = block_end(header, opening)
    require(header[end] == ';', 'SplatVertex terminator changed')
    vertex = header[vertex_match.start():end + 1]
    array = unique(r'SplatVertex\s+mSplatVertices\[4\]\s*;', header, 'splat vertex array')
    array = header[array.start():array.end()]
    # Inherited member declarations come from the real base header when present.
    # A complete checkout must supply this header; no checkpoint fallback exists.
    base = sources.read(source, 'src/moho/render/CWldTerrainDecal.h')
    fields = []
    for typ, name in (('float', 'mCutoffLOD'), ('float', 'mNearCutoff'),
                      ('float', 'mCurrentAlpha'), (r'(?:int|std::int32_t)', 'mFidelity')):
        m = unique(r'\b' + typ + r'\s+' + name + r'\s*;', base, name)
        fields.append(base[m.start():m.end()])
    vectors = []
    for dim in (2, 3):
        axes = ';'.join('float ' + axis for axis in 'xyz'[:dim]) + ';'
        if wildmagic:
            h = sources.read(wildmagic, f'Foundation/Math/Wm3Vector{dim}.h', 'wildmagic')
            unique(r'Real\s+m_afTuple\[' + str(dim) + r'\]\s*;', h, f'Vector{dim} storage')
            inline = sources.read(wildmagic, f'Foundation/Math/Wm3Vector{dim}.inl', 'wildmagic')
            copy = function_body(inline, rf'Vector{dim}<Real>::Vector{dim}\s*\(const Vector{dim}& rkV\)')
            assign = function_body(inline, rf'Vector{dim}<Real>&\s+Vector{dim}<Real>::operator=\s*\(const Vector{dim}& rkV\)')
        else:
            copy = '{for(unsigned i=0;i<' + str(dim) + ';++i)m_afTuple[i]=rkV.m_afTuple[i];}'
            assign = copy[:-1] + 'return *this;}'
        vectors.append(f'''struct Vec{dim} {{
 union {{float m_afTuple[{dim}];struct {{{axes}}};}};
 Vec{dim}():m_afTuple{{}} {{}}
 Vec{dim}(const Vec{dim}&rkV){copy}
 Vec{dim}&operator=(const Vec{dim}&rkV){assign}
}};''')
    mock = '''#pragma once
#include <cstddef>
#include <cstdint>
inline std::size_t textureCalls=0,vertexCalls=0;
namespace Wm3 {
''' + '\n'.join(vectors) + '''
using Vec3f=Vec3;using Vec2f=Vec2;
}
namespace moho {
struct CWldTerrainDecal {virtual ~CWldTerrainDecal()=default;
''' + '\n'.join(fields) + '''
};
struct CWldSplat:CWldTerrainDecal {
''' + vertex + '\n' + array + '''
 void UpdateBatchTexture(void*){++textureCalls;}
 void UpdateVertices(){++vertexCalls;}
};
}
static_assert(sizeof(moho::CWldSplat::SplatVertex)==28);
static_assert(offsetof(moho::CWldSplat::SplatVertex,mTexCoord)==12);
static_assert(offsetof(moho::CWldSplat::SplatVertex,mAlpha)==20);
'''
    write(out, 'moho/terrain/splat/CWldSplat.h', mock)
    sources.adapt('CWldSplat: exact vertex+array, 4 inherited fields; virtual base and 2 methods mocked', 1)
    sources.adapt('Wm3 storage shells with ' + ('actual copy/assignment bodies' if wildmagic else 'explicit nontrivial mock copies'), 2)


def prepare_fastvector(source, out, sources):
    fast = sources.read(source, 'src/gpg/core/containers/FastVector.h')
    pattern = r'static_assert\(\s*sizeof\(FastVector.*?\);'
    matches = list(re.finditer(pattern, fast, re.S))
    expected = ('FastVectorInline<int>', 'FastVector<int>', 'FastVectorN<int, 4>',
                'FastVectorN<std::uint32_t, 4>', 'FastVectorN<char, 64>')
    require(len(matches) == 5, 'FastVector: expected exactly five retail-x86 size assertions')
    for match, typ in zip(matches, expected):
        require('sizeof(' + typ + ')' in match[0], 'FastVector size assertion set changed')
    fast = re.sub(pattern, '// Host adapter: retail x86 sizeof assertion omitted.', fast, flags=re.S)
    write(out, 'gpg/core/containers/FastVector.h', fast)
    sources.adapt('FastVector retail-x86 sizeof assertions removed; all other assertions retained', 5)


def compile_run(out, cxx, sanitize=False, negative=False, gtest=None):
    compiler = shutil.which(cxx) or str(Path(cxx).resolve())
    command = [compiler, '-std=c++20', '-O1', '-g', '-pthread', '-Wall', '-Wextra', '-Werror',
               '-Wno-error=mismatched-new-delete', '-I', str(out), str(out / 'main.cpp'), '-o', str(out / 'test')]
    require(gtest is not None, 'GoogleTest source root is required')
    gtest = Path(gtest).resolve()
    for relative in ('include/gtest/gtest.h', 'src/gtest-all.cc', 'src/gtest_main.cc'):
        require((gtest / relative).is_file(), f'Missing GoogleTest input: {gtest / relative}')
    command.extend(['-I', str(gtest / 'include'), '-I', str(gtest),
                    str(gtest / 'src/gtest-all.cc'), str(gtest / 'src/gtest_main.cc')])
    if sanitize:
        command[1:1] = ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    result = subprocess.run(command, capture_output=True, text=True, cwd=out, timeout=180)
    require(result.returncode == 0, 'Host compile FAILED (not a valid negative control):\n' + result.stdout + result.stderr)
    env = os.environ.copy()
    env['LC_ALL'] = 'C'
    if sanitize:
        # Explicitly not a leak acceptance test (custom deterministic allocator).
        env['ASAN_OPTIONS'] = 'detect_leaks=0'
    result = subprocess.run([str(out / 'test')], capture_output=True, text=True, env=env, cwd=out, timeout=120)
    if negative:
        require(result.returncode == 1 and '[  FAILED  ]' in result.stdout and 'Failure' in result.stdout
                and 'C++ exception' not in result.stdout and 'unknown file: Failure' not in result.stdout,
                'Negative control must compile and fail a GoogleTest assertion:\n' + result.stdout + result.stderr)
        print('PASS mutation: compiled successfully and GoogleTest assertion rejected it')
        print(next(line for line in result.stdout.splitlines() if '[  FAILED  ]' in line))
    else:
        print(result.stdout, end='')
        require(result.returncode == 0, 'Host test FAILED:\n' + result.stdout + result.stderr)
    return {'compiler': compiler, 'sanitize': sanitize, 'compiled': True,
            'runtime_assertion_rejection': negative, 'returncode': result.returncode}
