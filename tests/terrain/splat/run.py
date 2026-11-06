#!/usr/bin/env python3
"""Run source-bound splat host tests. Uses Python standard library and a C++20 compiler.

All generated headers/executables live in TemporaryDirectory and are removed.
Actual source checkouts are read only; there are no network/download steps.
"""
import argparse
from pathlib import Path
import sys
import tempfile

# Do not leave Python bytecode in the source checkout.
sys.dont_write_bytecode = True
import collection_source_test
import draw_source_test


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', '--source-root', type=Path, required=True, help='actual faf-re checkout root')
    parser.add_argument('--baseline', '--baseline-root', type=Path, help='optional old checkout for default/small-path equivalence')
    parser.add_argument('--wildmagic', '--wildmagic-root', type=Path, help='existing WildMagic source root with Foundation/Math')
    parser.add_argument('--cxx', default='g++', help='existing GCC/Clang-compatible C++20 compiler')
    parser.add_argument('--gtest-root', type=Path, help='existing GoogleTest root containing include/ and src/')
    parser.add_argument('--sanitize', action='store_true', help='ASan+UBSan; leak checking explicitly disabled')
    parser.add_argument('--only', choices=('all', 'collection', 'draw', 'ui'), default='all')
    parser.add_argument('--negative', action='store_true', help='also compile and behavior-reject seven mutations')
    parser.add_argument('--faf-root', type=Path, help='optional actual FAF source checkout for UI test')
    parser.add_argument('--lua', help='existing Lua runtime, required with --faf-root')
    parser.add_argument('--lua-dialect', choices=('faf', 'stock'), default='faf')
    args = parser.parse_args()
    if bool(args.faf_root) != bool(args.lua):
        parser.error('--faf-root and --lua must be supplied together')
    if args.only == 'ui' and not args.faf_root:
        parser.error('--only ui requires --faf-root and --lua')
    source = args.source.resolve()
    if (args.only != 'ui' or args.negative) and not args.gtest_root:
        parser.error('--gtest-root is required for C++ host gates (no downloads)')
    with tempfile.TemporaryDirectory(prefix='splat-source-host-') as directory:
        temp = Path(directory)
        common = dict(source=source, cxx=args.cxx, sanitize=args.sanitize,
                      wildmagic=args.wildmagic, baseline=args.baseline, gtest=args.gtest_root)
        if args.only in ('all', 'collection'):
            collection_source_test.run(temp=temp/'collection', **common)
        if args.only in ('all', 'draw'):
            draw_source_test.run(temp=temp/'draw', **common)
        if args.only in ('all', 'ui') and args.faf_root:
            import ui_source_test
            ui_source_test.run(source, args.faf_root, args.lua, args.lua_dialect, temp/'ui')
        elif args.only == 'all':
            print('UI NOT RUN: supply both --faf-root and --lua to enable compatibility checks')
        if args.negative:
            from negative_controls import run
            run(source, temp/'negative', args.cxx, args.wildmagic, args.gtest_root)
    print('PASS requested host gates; native renderer/ABI/GPU/performance acceptance remains separate')


if __name__ == '__main__':
    main()
