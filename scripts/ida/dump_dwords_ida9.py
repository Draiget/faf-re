# dump_dwords_ida9.py
# Headless helper: dump N dwords from EA and optional pointed names.

import argparse
import os

import ida_auto
import ida_bytes
import ida_name
import idaapi
import idc


def parse_ea(token: str):
    s = token.strip()
    if s.lower().startswith('0x'):
        return int(s, 16)
    if all(c in '0123456789abcdefABCDEF' for c in s):
        return int(s, 16)
    ea = ida_name.get_name_ea(idaapi.BADADDR, s)
    if ea != idaapi.BADADDR:
        return ea
    raise ValueError(f'cannot parse ea: {token}')


def get_script_args():
    argv = list(getattr(idc, 'ARGV', []) or [])
    return argv[1:] if argv else []


def fmt_ea(ea):
    return f'0x{ea:08X}'


def main():
    ida_auto.auto_wait()

    parser = argparse.ArgumentParser(description='Dump dwords from EA')
    parser.add_argument('--ea', required=True)
    parser.add_argument('--count', type=int, default=8)
    parser.add_argument('--out', required=True)
    args = parser.parse_args(get_script_args())

    ea = parse_ea(args.ea)
    lines = []
    lines.append(f'input_file: {idaapi.get_input_file_path()}')
    lines.append(f'idb_file: {idaapi.get_path(idaapi.PATH_TYPE_IDB)}')
    lines.append(f'base_ea: {fmt_ea(ea)}')
    lines.append(f'count: {args.count}')
    lines.append('')
    lines.append('[dwords]')

    for i in range(max(args.count, 0)):
        cur = ea + i * 4
        val = ida_bytes.get_dword(cur)
        name = ida_name.get_name(val) or ''
        lines.append(f'{i:02d} ea={fmt_ea(cur)} val={fmt_ea(val)} name={name}')

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')


if __name__ == '__main__':
    rc = 0
    try:
        main()
    except Exception as exc:
        print(f'[dump-dwords] ERROR: {exc}')
        rc = 1
    idc.qexit(rc)
