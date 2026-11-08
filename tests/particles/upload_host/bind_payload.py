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
args = parser.parse_args()
root = args.source_root.resolve()
records = []
chunks = []

def sha(data):
    return hashlib.sha256(data).hexdigest()

def bind(path, pattern, trailing_semicolon=False):
    data = (root / path).read_bytes()
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
    line = text[:start].count('\n') + 1
    records.append({'path': path, 'line': line, 'source_sha256': sha(data),
                    'definition_sha256': sha(body.encode()), 'pattern': pattern})
    chunks.extend([f'#line {line} "{path}"\n', body, '\n'])

bind('src/moho/particles/SWorldParticle.h', r'^  struct SWorldParticle\s*', True)
path='src/moho/particles/SWorldParticle.cpp'
data=(root/path).read_bytes(); text=data.decode('utf-8')
hits=list(re.finditer(r'^  SWorldParticle::SWorldParticle\(\)[\s\S]*?^  \{\}',text,re.MULTILINE))
if len(hits) != 1:
    raise ValueError(f'{path}: expected exactly one default constructor, got {len(hits)}')
body=hits[0].group(); records.append({'path':path,'source_sha256':sha(data),'definition_sha256':sha(body.encode())})
chunks.extend([body,'\n'])
args.output.parent.mkdir(parents=True,exist_ok=True)
args.output.write_text(''.join(chunks),encoding='utf-8')
args.output.with_suffix('.json').write_text(json.dumps(records,indent=2)+'\n')
