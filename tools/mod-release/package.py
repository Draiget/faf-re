"""Build one installable FAF mod ZIP from a version tag, without executing Lua."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

# tag prefix: installation folder, release title, requirements
MODS = {
    'chat-mention': ('Microchip-Chat-Mention', 'Microchip Chat Mention', 'Current FAF and UI Mod Tools for the options screen.'),
    'client-test': ('Microchip-Client-Test', 'Microchip Client Test Recorder', 'Diagnostic recorder; updated Microchip x64 engine for additional network metrics.'),
    'eco-sharing': ('Microchip-Eco-Sharing', 'Microchip Eco Sharing', 'FAF; allied economy data must be available for automatic sharing.'),
    'logo-stamps': ('Microchip-Evil-Stamp', 'Microchip Logo Stamps', 'FAF with painting enabled in Interface options. Ctrl+Shift+L opens the picker.'),
    'connectivity': ('Microchip-F11-Lag-Connectivity-Screen', 'Microchip F11 Connectivity', 'Updated Microchip x64 engine for wait metrics; classic engines show unavailable timing.'),
    'icon-mod': ('Microchip-Icon-Mod', 'Microchip Icon Mod', 'Updated Microchip x64 engine for live icon scaling; UI Mod Tools for options. Original icon credits remain in mod_info.lua.'),
    'offline-chat': ('Microchip-Offline-Chat', 'Microchip Offline Chat Translation', 'Compatible Microchip x64 engine, separately installed offline translator and language packs. This ZIP contains the UI mod only.'),
    'team-colours': ('Microchip-Team-Colour-Bands', 'Microchip Team Colour Bands', 'FAF. Display-only colour changes.'),
}
EXTENSIONS = {'.lua', '.dds', '.png', '.ico', '.jpg', '.jpeg', '.wav', '.ogg', '.mp3', '.md', '.txt', '.json', '.bmp', '.tga', '.bp', '.ttf', '.otf'}


def version(root, folder):
    text = (root / 'mods' / folder / 'mod_info.lua').read_text(encoding='utf-8-sig')
    match = re.search(r'^\s*version\s*=\s*([0-9]+(?:\.[0-9]+){0,2})\s*(?:--[^\n]*)?$', text, re.M)
    if not match:
        raise ValueError('Missing or unsupported mod_info.lua version: ' + folder)
    return match.group(1)


def build(root, tag, output):
    match = re.fullmatch(r'([a-z][a-z-]*)-v([0-9]+(?:\.[0-9]+){0,2})', tag)
    if not match or match.group(1) not in MODS:
        raise ValueError('Unknown mod tag: ' + tag)
    slug, requested = match.groups()
    folder, title, requirements = MODS[slug]
    actual = version(root, folder)
    if requested != actual:
        raise ValueError(f'{tag} does not match {folder}/mod_info.lua version {actual}')
    source = root / 'mods' / folder
    if source.is_symlink():
        raise ValueError('Mod root must not be a symbolic link')
    files = []
    for path in sorted(source.rglob('*')):
        if path.is_symlink():
            raise ValueError('Symbolic links are not packaged: ' + str(path))
        relative = path.relative_to(source)
        if any(part in {'preview', '__pycache__', '.git', '.DS_Store'} for part in relative.parts):
            continue
        if path.is_file() and path.suffix.lower() in EXTENSIONS:
            files.append((path, folder + '/' + relative.as_posix()))
    if not any(name == folder + '/mod_info.lua' for _, name in files):
        raise ValueError('Package has no mod_info.lua')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'{folder}-v{actual}.zip'
    # A published version must not be silently rebuilt over an existing package.
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for path, name in files:
            entry = zipfile.ZipInfo(name, (2026, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o100644 << 16
            bundle.writestr(entry, path.read_bytes())
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = output / (archive.name + '.sha256')
    checksum.write_text(digest + '  ' + archive.name + '\n', encoding='utf-8')
    with zipfile.ZipFile(archive) as bundle:
        if bundle.testzip() is not None:
            raise ValueError('ZIP integrity check failed')
        assert all(name.startswith(folder + '/') for name in bundle.namelist())
    notes = f"""## {title} v{actual}

Requirements: {requirements}

### Install / update
1. Close the game and download **{archive.name}** below.
2. Extract it into your FAF Mods directory, usually:
   `Documents/My Games/Gas Powered Games/Supreme Commander Forged Alliance/mods`
3. Keep the folder name exactly **{folder}**. Do not add the version to the folder name or leave an extra ZIP wrapper folder.
4. When updating, replace the old copy of this mod to avoid duplicate mod UIDs. Enable the mod in FAF's UI Mod Manager.

The ZIP contains only this mod. Game executables, personal settings and translator language packs are not included.
SHA-256: `{digest}`

Source tag: `{tag}`. Engine-specific features require the Microchip engine branch.
"""
    result = {'tag': tag, 'title': f'{title} v{actual}', 'folder': folder, 'version': actual,
              'archive': archive.name, 'sha256': digest, 'files': len(files)}
    return result, notes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tag')
    parser.add_argument('--all', action='store_true', help='Package all current versions without publishing')
    parser.add_argument('--output', type=Path, default=Path('dist/mods'))
    args = parser.parse_args()
    if bool(args.tag) == args.all:
        parser.error('Choose exactly one of --tag or --all')
    root = Path(__file__).resolve().parents[2]
    tags = [args.tag] if args.tag else [slug + '-v' + version(root, values[0]) for slug, values in MODS.items()]
    for tag in tags:
        result, notes = build(root, tag, args.output)
        if args.tag:
            (args.output / 'release.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
            (args.output / 'release-notes.md').write_text(notes, encoding='utf-8')
        print(json.dumps(result))


if __name__ == '__main__':
    main()
