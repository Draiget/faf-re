"""Offline-only chat translator. ASCII pipe protocol; never records chat."""
import os
import sys
from pathlib import Path

os.environ['OMP_NUM_THREADS'] = '1'
os.environ['OPENBLAS_NUM_THREADS'] = '1'
os.environ['RAYON_NUM_THREADS'] = '1'
try:
    import ctranslate2
    import sentencepiece
    from lingua import Language, LanguageDetectorBuilder
except Exception:
    # Startup exceptions happen before any chat is read. Keep that diagnostic only.
    import traceback
    try:
        (Path(__file__).resolve().parent / 'startup-error.txt').write_text(
            traceback.format_exc(), encoding='utf-8')
    except OSError:
        pass
    raise

HOME = Path(__file__).resolve().parent
LANGUAGES = {'ru': Language.RUSSIAN, 'de': Language.GERMAN,
             'fr': Language.FRENCH, 'es': Language.SPANISH}
AVAILABLE = {code: lang for code, lang in LANGUAGES.items()
             if any((HOME / 'models' / code / t).is_file() for t in ('sentencepiece.model', 'bpe.model'))}
DETECTOR = LanguageDetectorBuilder.from_languages(
    Language.ENGLISH, *AVAILABLE.values()).with_low_accuracy_mode().build()
CACHE = {}


class BPETokenizer:
    def __init__(self, root, code):
        from sacremoses import MosesTokenizer, MosesDetokenizer, MosesPunctNormalizer
        from subword_nmt.apply_bpe import BPE
        self.tokenizer = MosesTokenizer(code)
        self.detokenizer = MosesDetokenizer('en')
        self.normalizer = MosesPunctNormalizer(code)
        with (root / 'bpe.model').open(encoding='utf-8') as source:
            self.bpe = BPE(source)

    def encode(self, text, out_type=str):
        return self.bpe.segment_tokens(self.tokenizer.tokenize(self.normalizer.normalize(text)))

    def decode(self, tokens):
        return self.detokenizer.detokenize(' '.join(tokens).replace('@@ ', '').split())


def translate(text):
    if len(text.encode('utf-8')) > 2048 or sum(c.isalpha() for c in text) < 4:
        return '', ''
    scores = DETECTOR.compute_language_confidence_values(text)
    if not scores or scores[0].language == Language.ENGLISH or scores[0].value < .6:
        return '', ''
    code = next((c for c, lang in AVAILABLE.items() if lang == scores[0].language), None)
    if not code:
        return '', ''
    if code not in CACHE:
        root = HOME / 'models' / code
        CACHE[code] = (ctranslate2.Translator(str(root / 'model'), device='cpu',
                       # This older Spanish model produces invalid output when quantized.
                       compute_type='float32' if code == 'es' else 'int8', intra_threads=1, inter_threads=1),
                       sentencepiece.SentencePieceProcessor(model_file=str(root / 'sentencepiece.model'))
                       if (root / 'sentencepiece.model').is_file() else BPETokenizer(root, code))
    model, tokenizer = CACHE[code]
    tokens = tokenizer.encode(text, out_type=str)[:256]
    result = model.translate_batch([tokens], beam_size=1, max_input_length=256,
                                   max_decoding_length=256)[0]
    if len(result.hypotheses[0]) >= 256:
        return '', ''
    output = tokenizer.decode(result.hypotheses[0]).replace('\u2581', ' ').replace('_', ' ')
    return code, output.replace('\n', ' ').replace('\r', ' ').strip()


def main():
    for line in sys.stdin.buffer:
        request = '0'
        try:
            if len(line) > 4200:
                continue
            request, encoded = line.decode('ascii').strip().split('\t', 1)
            if not request.isdecimal() or len(request) > 10:
                continue
            language, result = translate(bytes.fromhex(encoded).decode('utf-8'))
        except Exception:
            language, result = '', ''
        sys.stdout.buffer.write(f'{request}\t{language}\t{result.encode("utf-8").hex()}\n'.encode('ascii'))
        sys.stdout.buffer.flush()


if __name__ == '__main__':
    main()
