"""Turns a probe run's P lines into faf_math_dump --values lines.

faf_math_dump checks our functions against retail on "name iteration inputs ->
outputs" lines, but only for rows whose inputs are all plain values (a row on
engine objects builds its objects from generated inputs, which a recorded
pointer cannot replace). kRows names those rows and says how a P line's words
become the row's. Faulting variants are dropped, identical inputs are written
once, and NaN outputs are canonical, as --values expects.

usage: probe_values.py <probe_out.txt> <values.txt>
       faf_math_dump --values values.txt
"""
import struct
import sys


def word(value):
    return f"{value:08X}"


def canon_float(bits):
    return 0x7FC00000 if (bits & 0x7F800000) == 0x7F800000 and bits & 0x007FFFFF else bits


def double_to_float(low, high):
    """st0 read as a double, as the float a row's output holds."""
    value = struct.unpack("<d", struct.pack("<II", low, high))[0]
    try:
        return canon_float(struct.unpack("<I", struct.pack("<f", value))[0])
    except OverflowError:
        return 0x7F800000 if value > 0 else 0xFF800000


def same(words):
    return list(words)


def trig_inputs(words):
    return [words[0], 0]  # the row's "x _": the second word is unused


def float_output(words):
    return [double_to_float(words[0], words[1])]


# va: (row, inputs from the P line's argument words, outputs from its result words)
kRows = {
    0x004E9DF0: ("atan2f", same, float_output),
    0x005734D0: ("cosf", trig_inputs, float_output),
    0x005734E0: ("sinf", trig_inputs, float_output),
    0x0055AE10: ("RATE_GameRateToSpeed", same, same),
    0x005A9D60: ("ComputeOctileDistanceCore", same, float_output),
    0x0091A4E0: ("luaO_int2fb", same, same),
    0x0091A510: ("luaO_log2", same, same),
}


def main():
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    seen = set()
    counts = {}
    with open(sys.argv[2], "w", newline="\n") as out:
        out.write("# retail values from a recorder probe run: real objects, edge arguments\n")
        for line in open(sys.argv[1]):
            parts = line.split()
            if len(parts) < 5 or parts[0] != "P":
                continue
            row = kRows.get(int(parts[1], 16))
            if row is None:
                continue
            arrow = parts.index("->")
            results = parts[arrow + 1 :]
            # A fault is F plus the 8-digit code; a result word is 8 digits.
            if not results or any(len(r) != 8 for r in results):
                continue
            name, to_inputs, to_outputs = row
            inputs = to_inputs([int(w, 16) for w in parts[4:arrow]])
            outputs = to_outputs([int(w, 16) for w in results])
            key = (name, tuple(inputs))
            if key in seen:
                continue
            seen.add(key)
            index = counts.get(name, 0)
            counts[name] = index + 1
            out.write(f"{name} {index} {' '.join(map(word, inputs))} -> {' '.join(map(word, outputs))}\n")
    for name, count in sorted(counts.items()):
        print(f"{name}: {count} distinct inputs")


if __name__ == "__main__":
    main()
