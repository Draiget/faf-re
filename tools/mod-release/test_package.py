import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

spec = importlib.util.spec_from_file_location('mod_package', Path(__file__).with_name('package.py'))
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)

class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.mod = self.root / 'mods/Microchip-Eco-Sharing'
        self.mod.mkdir(parents=True)
        (self.mod / 'mod_info.lua').write_text("name='Test'\nversion = 4\n")
        (self.mod / 'modules').mkdir()
        (self.mod / 'modules/panel.lua').write_text('-- runtime code')
        (self.mod / 'textures').mkdir()
        (self.mod / 'textures/check.dds').write_bytes(b'DDS test')
        (self.mod / 'preview').mkdir()
        (self.mod / 'preview/private.png').write_bytes(b'not runtime')
        for name in ['desktop.ini', 'private.log', 'generate.py']:
            (self.mod / name).write_text('not runtime')
        (self.root / 'mods/OtherMod').mkdir()
        (self.root / 'mods/OtherMod/mod_info.lua').write_text('version=99')

    def test_only_selected_mod_and_correct_root(self):
        result, notes = package.build(self.root, 'eco-sharing-v4', self.root / 'dist')
        with zipfile.ZipFile(self.root / 'dist' / result['archive']) as z:
            self.assertEqual(set(z.namelist()), {
                'Microchip-Eco-Sharing/mod_info.lua', 'Microchip-Eco-Sharing/modules/panel.lua',
                'Microchip-Eco-Sharing/textures/check.dds'})
        self.assertIn('Microchip-Eco-Sharing', notes)
        self.assertTrue((self.root / 'dist' / (result['archive'] + '.sha256')).exists())

    def test_rejects_wrong_version_unknown_mod_and_tag_injection(self):
        for tag in ['eco-sharing-v5', 'unknown-v4', '../eco-sharing-v4', 'eco-sharing-v4;echo bad']:
            with self.assertRaises(ValueError):
                package.build(self.root, tag, self.root / 'dist')
        self.assertFalse((self.root / 'dist').exists())

    def test_reproducible_and_never_overwrites(self):
        a, _ = package.build(self.root, 'eco-sharing-v4', self.root / 'one')
        b, _ = package.build(self.root, 'eco-sharing-v4', self.root / 'two')
        self.assertEqual(a['sha256'], b['sha256'])
        with self.assertRaises(FileExistsError):
            package.build(self.root, 'eco-sharing-v4', self.root / 'one')

if __name__ == '__main__':
    unittest.main()
