#!/usr/bin/env python3
"""Source-derived UI host regression. No game widgets, VFS, GPU or performance claims.

FAF mode executes source bytes unchanged. Stock mode has a finite, count-checked
compatibility map: upstream drift fails rather than silently broadening rewriting.
Only the dialog's event-handler region is executed, against explicit widget mocks;
the five other inputs are parsed whole, and the engine hooks/options logic execute.
"""
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import tempfile

INPUTS = (
    ('source', 'data/fafengine/lua/options/options.lua'),
    ('source', 'data/fafengine/lua/ui/help/tooltips.lua'),
    ('faf', 'lua/options/optionsLogic.lua'),
    ('faf', 'lua/options/options.lua'),
    ('faf', 'lua/ui/help/tooltips.lua'),
    ('faf', 'lua/ui/dialogs/options.lua'),
)
# Exact fragments and expected occurrence counts, not arbitrary generic-for rewrites.
STOCK = {
    0: [('for index, item in video.items do', 'for index, item in pairs(video.items) do', 1)],
    2: [
        ('for section, secInfo in options do', 'for section, secInfo in pairs(options) do', 2),
        ('for index, item in secInfo.items do', 'for index, item in pairs(secInfo.items) do', 8),
        ('for section, secInfo in GetOptionsData() do', 'for section, secInfo in pairs(GetOptionsData()) do', 6),
        ('for index, item in itemsToSet do', 'for index, item in pairs(itemsToSet) do', 1),
        ('for key, val in curOptions do', 'for key, val in pairs(curOptions) do', 1),
        ('for index, item in needsVerify do', 'for index, item in pairs(needsVerify) do', 1),
        ('newOptions[item.key] != curOptions[item.key]', 'newOptions[item.key] ~= curOptions[item.key]', 3),
        ('table.getn(needsRestart) != 0', 'table.getn(needsRestart) ~= 0', 1),
        ('table.getn(needsVerify) != 0', 'table.getn(needsVerify) ~= 0', 1),
        ('nil != customDataChangedCallback', 'nil ~= customDataChangedCallback', 1),
    ],
    3: [('for k, worldview in worldViewManager.MapControls do', 'for k, worldview in pairs(worldViewManager.MapControls) do', 1)],
    5: [('for index,option in currentTabButton.tabData.items do', 'for index,option in pairs(currentTabButton.tabData.items) do', 1)],
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(source: Path, faf_root: Path, lua: str, dialect: str, temp: Path):
    if dialect not in ('faf', 'stock'):
        raise ValueError('lua dialect must be faf or stock')
    source, faf_root, temp = Path(source).resolve(), Path(faf_root).resolve(), Path(temp).resolve()
    runtime = shutil.which(str(lua))
    if not runtime:
        raise FileNotFoundError('Lua runtime not found: ' + str(lua))
    runtime = Path(runtime).resolve()
    temp.mkdir(parents=True, exist_ok=True)
    manifest = {'test': 'splat-ui-source', 'dialect': dialect,
                'runtime': {'path': str(runtime), 'sha256': sha(runtime.read_bytes())},
                'production_source_adaptation': 'none' if dialect == 'faf' else 'explicit count-checked stock compatibility map',
                'sources': [], 'adaptations': [],
                'scope': 'source-derived host mocks, not game widgets/VFS/GPU/performance acceptance'}
    for index, (owner, relative) in enumerate(INPUTS):
        path = (source if owner == 'source' else faf_root) / relative
        data = path.read_bytes()
        entry = {'root': owner, 'path': relative, 'sha256': sha(data)}
        manifest['sources'].append(entry)
        if index == 5:
            # Unique, ordered source anchors isolate the real Cancel, Apply and
            # Reset callbacks. Include nested DoReset and confirmation call.
            text = data.decode('utf-8')
            start = '    dialog.cancelBtn.OnClick = function(self, modifiers)'
            end = '    UIUtil.MakeInputModal(dialog,'
            if text.count(start) != 1 or text.count(end) != 1:
                raise AssertionError('Dialog event handler anchors changed; review extraction')
            left, right = text.index(start), text.index(end)
            if left >= right:
                raise AssertionError('Dialog handler order changed')
            data = text[left:right].encode('utf-8')
            entry['executed_fragment_sha256'] = sha(data)
        if dialect == 'stock':
            text = data.decode('utf-8')
            for old, new, count in STOCK.get(index, []):
                actual = text.count(old)
                if actual != count:
                    raise AssertionError(f'{relative}: stock adaptation {old!r}: expected {count}, found {actual}')
                text = text.replace(old, new)
                manifest['adaptations'].append({'path': relative, 'from': old, 'to': new, 'count': count})
            data = text.encode('utf-8')
        output = temp / ('dialog_handlers.lua' if index == 5 else f'source_{index}.lua')
        output.write_bytes(data)
        entry['executed_sha256'] = sha(data)
    fixture = Path(__file__).parent / 'fixtures/ui_fixture.lua'
    fixture_bytes = fixture.read_bytes()
    manifest['fixture_sha256'] = sha(fixture_bytes)
    (temp / 'ui_fixture.lua').write_bytes(fixture_bytes)
    # Emit provenance before execution so failed tests retain exact inputs too.
    print('UI_SOURCE_MANIFEST ' + json.dumps(manifest, sort_keys=True), flush=True)
    result = subprocess.run([str(runtime), str(temp / 'ui_fixture.lua'), str(temp)],
                            text=True, capture_output=True, timeout=60)
    print(result.stdout, end='')
    if result.stderr:
        print(result.stderr, end='')
    result.check_returncode()
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True, help='faf-re checkout root')
    parser.add_argument('--faf-root', type=Path, required=True, help='FAF source checkout root')
    parser.add_argument('--lua', required=True, help='existing Lua executable or command')
    parser.add_argument('--lua-dialect', choices=('faf', 'stock'), default='faf')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='splat-ui-host-') as directory:
        run(args.source, args.faf_root, args.lua, args.lua_dialect, Path(directory))


if __name__ == '__main__':
    main()
