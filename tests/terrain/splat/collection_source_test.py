"""Compile all three live collection bodies against production budget/container code."""
import json
from source_extract import (LANES, TERRAIN, Sources, collection_method, compile_run,
                            prepare_fastvector, prepare_types, replace_exact, unique, write)


def run(source, temp, cxx='g++', sanitize=False, wildmagic=None, baseline=None, gtest=None, mutation=None):
    sources = Sources()
    prepare_fastvector(source, temp, sources)
    prepare_types(source, temp, sources, wildmagic)
    common = sources.read(source, TERRAIN + 'TerrainCommon.cpp')
    unique(r'int ren_SplatBudgetTier = 0;', common, 'default console tier')
    unique(r'TConVar<int> gTConVar_ren_SplatBudgetTier\s*\(', common, 'console command registration')
    budget = sources.read(source, TERRAIN + 'SplatBudget.h')
    if mutation and mutation[0] == TERRAIN + 'SplatBudget.h':
        budget = replace_exact(budget, mutation[1], mutation[2], 1, 'budget mutation')
    write(temp, 'SplatBudget.h', budget)
    methods = []
    for root, tag in [(source, 'New')] + ([(baseline, 'Base')] if baseline else []):
        for lane in LANES:
            path = TERRAIN + lane + 'FidelityTerrain.cpp'
            code = sources.read(root, path, 'baseline' if tag == 'Base' else 'production')
            if tag == 'New' and mutation and mutation[0] == path:
                code = replace_exact(code, mutation[1], mutation[2], 1, 'collector mutation')
            body = collection_method(code, lane, baseline=tag == 'Base')
            methods.append(f'template<std::size_t N>void Lane<N>::{tag}{lane}(std::vector<CWldTerrainDecal*>& visibleSplats){{{body}}}')
    fixture = sources.fixture('collection_fixture.cpp.in')
    fixture = replace_exact(fixture, '@METHODS@', '\n'.join(methods), 1, 'collection fixture insertion')
    write(temp, 'main.cpp', ('#define HAS_BASELINE 1\n' if baseline else '') + fixture)
    sources.adapt('Camera four-component row, prebuilt visible list, texture/update counting mocks', 3)
    if mutation:
        sources.adapt('Intentional behavior mutation: ' + mutation[3], 1)
    sources.generated(temp)
    print('COLLECTION_SOURCE_MANIFEST ' + json.dumps(sources.manifest(), sort_keys=True), flush=True)
    result = compile_run(temp, cxx, sanitize, negative=mutation is not None, gtest=gtest)
    return sources.manifest() | result
