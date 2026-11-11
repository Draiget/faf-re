"""Plane predictors, exactly as CONTAINER.md section 3 defines them.

A plane has `rows`, `cols` and `channels` (interleaved components); a row holds `cols * channels` elements of
`elem_bytes` little-endian unsigned bytes. Arithmetic is modulo 2^(8*elem_bytes). Per element `i` of a row:

  left        = element i - channels of the same row   (0 when i < channels)
  upper       = element i of the previous row           (0 on row 0)
  upper-left  = element i - channels of the previous row (0 when either is absent)

PREDICT 0 none, 1 left, 2 upper, 3 Paeth. encoded = value - prediction, decoded = encoded + prediction (the
decoder uses already decoded neighbours, the encoder the original ones, so both see the same numbers).

Paeth: p = a + b - c in signed 64 bit (a left, b upper, c upper-left), pa = |p-a|, pb = |p-b|, pc = |p-c|;
choose a if pa <= pb and pa <= pc, else b if pb <= pc, else c. Python ints are unbounded, which is the same
as signed 64 bit for 1, 2 and 4 byte elements.

Plain loops on purpose: the goldens are small and the loops are easy to compare with the C++.
"""
import struct

from .errors import ChunkError

_FMT = {1: "B", 2: "H", 4: "I", 8: "Q"}


def _unpack(data, elem_bytes):
    n = len(data) // elem_bytes
    return list(struct.unpack("<%d%s" % (n, _FMT[elem_bytes]), data))


def _pack(vals, elem_bytes):
    return struct.pack("<%d%s" % (len(vals), _FMT[elem_bytes]), *vals)


def paeth(a, b, c):
    p = a + b - c
    pa = abs(p - a)
    pb = abs(p - b)
    pc = abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    if pb <= pc:
        return b
    return c


def _check(data, rows, cols, channels, elem_bytes, predictor):
    if predictor not in (0, 1, 2, 3):
        raise ChunkError("unknown predictor %d" % predictor)
    if elem_bytes not in _FMT:
        raise ChunkError("unsupported element width %d" % elem_bytes)
    if len(data) != rows * cols * channels * elem_bytes:
        raise ChunkError("plane data is %d bytes, expected %d x %d x %d x %d" %
                         (len(data), rows, cols, channels, elem_bytes))


def _prediction(vals, base, rowlen, i, r, channels, predictor):
    """Prediction for element i of row r (base = index of the row start). `vals` holds neighbours that are final."""
    a = vals[base + i - channels] if i >= channels else 0
    if predictor == 1:
        return a
    b = vals[base - rowlen + i] if r > 0 else 0
    if predictor == 2:
        return b
    c = vals[base - rowlen + i - channels] if (r > 0 and i >= channels) else 0
    return paeth(a, b, c)


def encode_plane(samples, rows, cols, channels, elem_bytes, predictor):
    """samples: little-endian bytes of the raw plane -> residual bytes."""
    _check(samples, rows, cols, channels, elem_bytes, predictor)
    if predictor == 0:
        return bytes(samples)
    vals = _unpack(samples, elem_bytes)
    mask = (1 << (8 * elem_bytes)) - 1
    rowlen = cols * channels
    out = [0] * len(vals)
    for r in range(rows):
        base = r * rowlen
        for i in range(rowlen):
            out[base + i] = (vals[base + i] - _prediction(vals, base, rowlen, i, r, channels, predictor)) & mask
    return _pack(out, elem_bytes)


def decode_plane(residuals, rows, cols, channels, elem_bytes, predictor):
    """residual bytes -> little-endian bytes of the raw plane."""
    _check(residuals, rows, cols, channels, elem_bytes, predictor)
    if predictor == 0:
        return bytes(residuals)
    res = _unpack(residuals, elem_bytes)
    mask = (1 << (8 * elem_bytes)) - 1
    rowlen = cols * channels
    vals = [0] * len(res)
    for r in range(rows):
        base = r * rowlen
        for i in range(rowlen):
            vals[base + i] = (res[base + i] + _prediction(vals, base, rowlen, i, r, channels, predictor)) & mask
    return _pack(vals, elem_bytes)
