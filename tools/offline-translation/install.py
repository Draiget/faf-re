"""Install private runtime and official Argos model data, without touching game files."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import venv
import zipfile
from pathlib import Path, PurePosixPath

INDEX = 'https://raw.githubusercontent.com/argosopentech/argospm-index/main/index.json'


def install(home):
    home.mkdir(parents=True, exist_ok=True)
    runtime = home / 'python'
    if not (runtime / 'Scripts/python.exe').is_file():
        venv.create(runtime, with_pip=True)
    subprocess.run([str(runtime / 'Scripts/python.exe'), '-m', 'pip', 'install',
                    '--disable-pip-version-check', 'setuptools==80.9.0', 'ctranslate2==4.6.0',
                    'sentencepiece==0.2.1', 'lingua-language-detector==2.1.1',
                    'sacremoses==0.1.1', 'subword-nmt==0.3.8'], check=True)
    with urllib.request.urlopen(INDEX, timeout=60) as response:
        index = json.load(response)
    for language in ('ru', 'de', 'fr', 'es'):
        destination = home / 'models' / language
        if (destination / 'model/model.bin').is_file() and (destination / 'README.md').is_file() and any((destination / t).is_file() for t in ('sentencepiece.model', 'bpe.model')):
            continue
        package = max((p for p in index if p['from_code'] == language and p['to_code'] == 'en'),
                      key=lambda p: tuple(int(n) for n in p['package_version'].split('.')))
        url = next(u for u in package['links'] if u.startswith('https://argos-net.com/'))
        print('Downloading offline language:', language, flush=True)
        with tempfile.TemporaryDirectory(dir=home) as temporary:
            temporary = Path(temporary)
            archive = temporary / 'model.zip'
            request = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(request, timeout=120) as response, archive.open('wb') as output:
                size = 0
                while block := response.read(1024 * 1024):
                    size += len(block)
                    if size > 500 * 1024 * 1024:
                        raise ValueError('Language package too large')
                    output.write(block)
            extracted = temporary / 'extracted'
            extracted.mkdir()
            with zipfile.ZipFile(archive) as zipped:
                total = 0
                for item in zipped.infolist():
                    parts = PurePosixPath(item.filename).parts[1:]
                    if not parts or '..' in parts or '\\' in item.filename or ':' in item.filename:
                        continue
                    if parts[0] != 'model' and parts not in (('sentencepiece.model',), ('bpe.model',), ('metadata.json',), ('README.md',)) and 'LICENSE' not in parts[-1].upper():
                        continue
                    total += item.file_size
                    if total > 1024 * 1024 * 1024:
                        raise ValueError('Expanded language package too large')
                    target = extracted.joinpath(*parts)
                    if item.is_dir():
                        target.mkdir(parents=True, exist_ok=True)
                    else:
                        target.parent.mkdir(parents=True, exist_ok=True)
                        with zipped.open(item) as source, target.open('wb') as output:
                            shutil.copyfileobj(source, output)
            if not (extracted / 'model/model.bin').is_file() or not any((extracted / t).is_file() for t in ('sentencepiece.model', 'bpe.model')):
                raise ValueError('Incomplete language package')
            (extracted / 'source.json').write_text(json.dumps({'url': url, 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest()}), encoding='utf-8')
            destination.parent.mkdir(exist_ok=True)
            if destination.exists():
                shutil.rmtree(destination)
            shutil.move(str(extracted), destination)
    shutil.copyfile(Path(__file__).with_name('worker.py'), home / 'worker.py')
    print('Offline translator installed.', flush=True)


if __name__ == '__main__':
    install(Path(sys.argv[1]))
