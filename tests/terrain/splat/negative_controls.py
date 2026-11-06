"""Mutations must compile, then fail independently expected runtime behavior."""
from source_extract import LANES, TERRAIN
import collection_source_test
import draw_source_test


def run(source, temp, cxx='g++', wildmagic=None):
    mutations = []
    for lane in LANES:
        old = 'if (splatBudget++ >= splatOutputBudget.available\n' + ('          ' if lane == 'Low' else '            ') + '&& !TryGrowSplatOutput(mSplatVertices, splatOutputBudget)) {'
        cap = 249 if lane == 'Low' else 2499
        new = old.replace('if (splatBudget++ >= splatOutputBudget.available',
                          f'if ((splatBudget >= {cap}) || (splatBudget++ >= splatOutputBudget.available').replace(')) {', '))) {')
        mutations.append((TERRAIN + lane + 'FidelityTerrain.cpp', old, new, lane + ' restored old cap'))
    mutations.extend([
        (TERRAIN + 'SplatBudget.h', 'return {inlineQuads - 1, inlineQuads - 1};',
         'return {inlineQuads, inlineQuads};', 'default off by one'),
        (TERRAIN + 'SplatBudget.h', 'skippedCalls = 32;', 'skippedCalls = 0;', 'disable OOM backoff'),
        (TERRAIN + 'SplatBudget.h', 'if (requestedBytes >= failedBytes) {',
         'if (requestedBytes > 0) {', 'small success erases larger failure'),
    ])
    for index, mutation in enumerate(mutations):
        print('NEGATIVE CONTROL:', mutation[3], flush=True)
        collection_source_test.run(source, temp/str(index), cxx=cxx, wildmagic=wildmagic, mutation=mutation)
    print('NEGATIVE CONTROL: omit multipass retransmission', flush=True)
    draw_source_test.run(source, temp/'draw', cxx=cxx, wildmagic=wildmagic, negative=True)
    print('PASS 7 negative controls: every mutation compiled, every runtime rejected')
