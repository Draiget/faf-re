"""Compile live draw bodies and helper against recording GAL interface fixtures."""
import json
from source_extract import (LANES, TERRAIN, Sources, compile_run, function_body,
                            prepare_types, replace_exact, require, unique, block_end, code_mask, write)

# Exact header list: any added dependency requires adapter review.
MOCK_HEADERS = (
    'gpg/core/utils/Global.h', 'gpg/gal/Device.hpp', 'gpg/gal/DrawIndexedContext.hpp',
    'gpg/gal/EffectTechnique.hpp', 'gpg/gal/Error.hpp', 'moho/render/ID3DVertexStream.h',
    'moho/render/d3d/CD3DDevice.h', 'moho/render/d3d/CD3DEffectTechnique.h',
    'moho/render/d3d/CD3DIndexSheet.h', 'moho/render/d3d/CD3DVertexSheet.h',
    'moho/render/font/MsdfTextGpuRenderer.h',
    'moho/terrain/splat/CWldSplat.h',
)


def run(source, temp, cxx='g++', sanitize=False, wildmagic=None, baseline=None, negative=False):
    sources = Sources()
    prepare_types(source, temp, sources, wildmagic)
    header = sources.read(source, TERRAIN + 'SplatChunkRenderer.h')
    dependencies = tuple(line.split('"')[1] for line in header.splitlines() if line.startswith('#include "'))
    require(dependencies == MOCK_HEADERS, 'Chunk helper quoted includes changed; review GAL adapter')
    if negative:
        header = replace_exact(header, 'if (pass == 0 || count > quadCap * 4) {',
                               'if (pass == 0) {', 1, 'multipass reupload mutation')
        sources.adapt('Intentional mutation: omit multipass retransmission', 1)
    write(temp, 'SplatChunkRenderer.h', header)
    for path in MOCK_HEADERS[:-1]:
        write(temp, path, '#include "draw_mocks.h"\n')
    device = sources.read(source, 'src/moho/render/d3d/CD3DDevice.cpp')
    methods = []
    for name in ('DrawTriangleList', 'SelectTechnique'):
        match = unique(r'bool CD3DDevice::' + name + r'\s*\([^)]*\)\s*\{', device, name)
        opening = code_mask(device).index('{', match.start())
        methods.append('inline ' + device[match.start():block_end(device, opening)])
    mocks = replace_exact(sources.fixture('draw_mocks.h'), '@DEVICE_METHODS@', '\n'.join(methods), 1, 'actual device draw/selection bodies')
    write(temp, 'draw_mocks.h', mocks)
    sources.adapt('Quoted GAL/render include redirects to recording interfaces', 11)
    sources.adapt('MSDF flush recorded; actual DrawTriangleList and SelectTechnique bodies compiled', 2)
    methods = []
    for root, tag in [(source, 'New')] + ([(baseline, 'Base')] if baseline else []):
        for lane in LANES:
            code = sources.read(root, TERRAIN + lane + 'FidelityTerrain.cpp',
                                'baseline' if tag == 'Base' else 'production')
            body = function_body(code, r'void\s+' + lane + r'FidelityTerrain::DrawSplatComposite\(\)')
            methods.append(f'void DrawLane::{tag}{lane}()' + body)
    fixture = sources.fixture('draw_fixture.cpp.in')
    fixture = replace_exact(fixture, '@METHODS@', '\n'.join(methods), 1, 'draw fixture insertion')
    write(temp, 'main.cpp', ('#define HAS_BASELINE 1\n' if baseline else '') + fixture)
    sources.generated(temp)
    print('DRAW_SOURCE_MANIFEST ' + json.dumps(sources.manifest(), sort_keys=True), flush=True)
    result = compile_run(temp, cxx, sanitize, negative=negative)
    return sources.manifest() | result
