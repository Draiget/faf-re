"""Reference of the normative scatter placement (EXTENDED.md, SCAT).

Everything here must give the same bits on every machine, so every step names its arithmetic.

PCG32 (PCG-XSH-RR 64/32, M.E. O'Neill's reference `pcg32_srandom_r(rng, initstate, initseq)`):
    state = 0; inc = (initseq << 1) | 1; next(); state += initstate; next()
    next(): old = state; state = old * 6364136223846793005 + inc            (mod 2^64)
            xorshifted = (((old >> 18) ^ old) >> 27) (as u32); rot = old >> 59
            return (xorshifted >> rot) | (xorshifted << ((-rot) & 31))       (u32)
  The layer RNG is `PCG32(initstate = hash64(seed, L, bx, bz), initseq = 54)`. Known answer: PCG32(42, 54) yields
  0xa15c02b7, 0x7b47f409, 0xba1d3330, 0x83d2f293, 0xbfa4784b, 0xcbed606e.

hash64(seed, L, bx, bz) = SplitMix64( seed ^ (L << 48) ^ (bx << 24) ^ bz ), all in u64 arithmetic mod 2^64 with the
  block coordinates taken as two's complement (a negative block index sign-extends); L is the 0-based layer index in the
  SCAT array. SplitMix64(x): z = x + 0x9E3779B97F4A7C15; z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EB; return z ^ (z >> 31)          (all mod 2^64).

Blocks: 32 x 32 world units, block (bx, bz) has its origin at (bx*32, bz*32). Blocks are visited z-major (bz outer,
  bx inner) over the world rectangle of the grid; the output order is that visiting order, then candidate order.

Per block, random numbers are consumed in this order (always, whether or not anything is accepted):
  1. one number for the candidate count: n = floor(d) + (r < frac(d) * 2^32 ? 1 : 0), with
     d = binary32(density * mapValue), mapValue = the layer's density map at the block centre
     (bx*32+16, bz*32+16), bilinear, 0..1 (1.0 without a map); frac(d) = d - floor(d) (exact in binary32);
     the comparison is exact (an integer against a binary32 value scaled by 2^32).
  2. for each of the n candidates exactly six numbers r0..r5, in the order x, z, variant, scale, yaw, tint.

Uniform float from a number: u(r) = (r >> 8) * (1.0 / 16777216.0)  -- an integer below 2^24 times 2^-24, exact in
binary32, so u is in [0, 1) with no rounding at all. Every following operation is rounded to binary32 *after each
single operation* (Python: struct pack/unpack 'f'), never fused, and evaluated in the order written:
  x = r32(bx*32 + r32(u(r0) * 32));            z likewise with u(r1), bz
  variant: total = running sum of the weights (each partial sum rounded); target = r32(u(r2) * total);
           the first variant i whose running sum cum_i = r32(cum_{i-1} + w_i) satisfies target < cum_i; if rounding
           leaves none (target == total) the last variant with a positive weight. Zero-weight variants are never chosen.
  scale = r32(scaleMin + r32(u(r3) * r32(scaleMax - scaleMin)))   (the picked variant's range)
  yawDeg = RANDOM_YAW ? r32(u(r4) * 360) : 0                        (r4 is consumed either way)
  tint  = r32(1 + r32(r32(r32(u(r5) * 2) - 1) * tintVariation))     (a multiplier in [1 - v, 1 + v))
  y = sampler.height(x, z)

Rejection tests, in this order, after all six numbers are drawn (a rejected candidate still consumed them):
  outside the grid rectangle [origin, origin + cells * cellSize);  slope_deg outside [minSlopeDeg, maxSlopeDeg];
  y outside [minAltitude, maxAltitude];  allowedMaterials non-empty and the dominant SPLT material not in it;
  surface id in forbiddenSurfaces;  the layer's density map at the point is <= 0 (the map thins candidates only through
  the block-centre count and by this hard zero test: a fractional per-point test would need a seventh number);  HOLE.
  Flags ALIGN_TO_NORMAL, CAST_SHADOW, WIND, AVOID_STRUCTURES and `jitter` are renderer matters and not part of the record.

Record (what the golden hashes): `<I6f` little endian = variant u32, then f32 x, z, y, scale, yawDeg, tint.
"""
import hashlib
import math
import struct

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1
BLOCK = 32
RECORD = struct.Struct("<I6f")
SCAT_RANDOM_YAW = 2


def r32(x):
    """Round a Python float (binary64) to binary32."""
    return struct.unpack("<f", struct.pack("<f", x))[0]


class PCG32(object):
    MULT = 6364136223846793005

    def __init__(self, initstate, initseq=54):
        self.state = 0
        self.inc = ((initseq << 1) | 1) & M64
        self.next()
        self.state = (self.state + initstate) & M64
        self.next()

    def next(self):
        old = self.state
        self.state = (old * self.MULT + self.inc) & M64
        xs = (((old >> 18) ^ old) >> 27) & M32
        rot = old >> 59
        return ((xs >> rot) | (xs << ((-rot) & 31))) & M32


def splitmix64(x):
    z = (x + 0x9E3779B97F4A7C15) & M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
    return z ^ (z >> 31)


def hash64(seed, layer, bx, bz):
    return splitmix64((seed ^ ((layer & M64) << 48) ^ ((bx & M64) << 24) ^ (bz & M64)) & M64)


def unit(r):
    return (r >> 8) * (1.0 / 16777216.0)


class Sampler(object):
    """What the placement asks the world. Positions are world units; heights / slopes are binary32 values."""

    def height(self, x, z):
        raise NotImplementedError

    def slope_deg(self, x, z):
        raise NotImplementedError

    def material(self, x, z):
        """Dominant SPLT material id at the point."""
        raise NotImplementedError

    def surface(self, x, z):
        raise NotImplementedError

    def hole(self, x, z):
        raise NotImplementedError

    def density_map(self, index, x, z):
        """SCDM instance `index` sampled bilinearly at the point, 0..1."""
        raise NotImplementedError


class FlatSampler(Sampler):
    """The sampler of the golden: flat terrain, slope 0, material 0, surface 0, no holes, constant density map."""

    def __init__(self, height=10.0, density=1.0):
        self._h = r32(height)
        self._d = r32(density)

    def height(self, x, z):
        return self._h

    def slope_deg(self, x, z):
        return 0.0

    def material(self, x, z):
        return 0

    def surface(self, x, z):
        return 0

    def hole(self, x, z):
        return False

    def density_map(self, index, x, z):
        return self._d


def bilinear_u8(data, w, h, u, v):
    """Bilinear sample of a u8 plane at texel coordinates (u, v) (texel centres at +0.5 are the caller's business),
    clamped at the edges; result 0..1 in binary32. Provided for samplers backed by SCDM."""
    u = min(max(u, 0.0), w - 1.0)
    v = min(max(v, 0.0), h - 1.0)
    x0, y0 = int(math.floor(u)), int(math.floor(v))
    x1, y1 = min(x0 + 1, w - 1), min(y0 + 1, h - 1)
    fx, fy = r32(u - x0), r32(v - y0)
    a = r32(r32(data[y0 * w + x0]) * r32(1.0 - fx) + r32(data[y0 * w + x1]) * fx)
    b = r32(r32(data[y1 * w + x0]) * r32(1.0 - fx) + r32(data[y1 * w + x1]) * fx)
    return r32(r32(a * r32(1.0 - fy) + b * fy) / 255.0)


def pick_variant(variants, u):
    total = 0.0
    for v in variants:
        total = r32(total + v["weight"])
    target = r32(u * total)
    cum = 0.0
    for i, v in enumerate(variants):
        cum = r32(cum + v["weight"])
        if target < cum:
            return i
    return max(i for i, v in enumerate(variants) if v["weight"] > 0)


def generate_layer(layer, index, cells_x, cells_z, sampler, cell_size=1.0, origin=(0.0, 0.0)):
    """All accepted instances of SCAT layer `index` over a grid, as dicts with keys variant, x, z, y, scale, yawDeg, tint."""
    x0, z0 = origin
    x1, z1 = x0 + cells_x * cell_size, z0 + cells_z * cell_size
    out = []
    for bz in range(int(math.floor(z0 / BLOCK)), int(math.ceil(z1 / BLOCK))):
        for bx in range(int(math.floor(x0 / BLOCK)), int(math.ceil(x1 / BLOCK))):
            rng = PCG32(hash64(layer["seed"], index, bx, bz), 54)
            map_value = 1.0
            if layer["densityMap"] >= 0:
                map_value = sampler.density_map(layer["densityMap"], bx * BLOCK + BLOCK // 2, bz * BLOCK + BLOCK // 2)
            d = r32(layer["density"] * map_value)
            fl = math.floor(d)
            frac = r32(d - fl)
            n = int(fl) + (1 if rng.next() < frac * 4294967296.0 else 0)
            for _ in range(n):
                r = [rng.next() for _ in range(6)]
                x = r32(bx * BLOCK + r32(unit(r[0]) * BLOCK))
                z = r32(bz * BLOCK + r32(unit(r[1]) * BLOCK))
                vi = pick_variant(layer["variants"], unit(r[2]))
                var = layer["variants"][vi]
                scale = r32(var["scaleMin"] + r32(unit(r[3]) * r32(var["scaleMax"] - var["scaleMin"])))
                yaw = r32(unit(r[4]) * 360.0) if layer["flags"] & SCAT_RANDOM_YAW else 0.0
                tint = r32(1.0 + r32(r32(r32(unit(r[5]) * 2.0) - 1.0) * layer["tintVariation"]))
                if not (x0 <= x < x1 and z0 <= z < z1):
                    continue
                y = sampler.height(x, z)
                if not layer["minSlopeDeg"] <= sampler.slope_deg(x, z) <= layer["maxSlopeDeg"]:
                    continue
                if not layer["minAltitude"] <= y <= layer["maxAltitude"]:
                    continue
                if layer["allowedMaterials"] and sampler.material(x, z) not in layer["allowedMaterials"]:
                    continue
                if sampler.surface(x, z) in layer["forbiddenSurfaces"]:
                    continue
                if layer["densityMap"] >= 0 and sampler.density_map(layer["densityMap"], x, z) <= 0.0:
                    continue
                if sampler.hole(x, z):
                    continue
                out.append({"variant": vi, "x": x, "z": z, "y": y, "scale": scale, "yawDeg": yaw, "tint": tint})
    return out


def pack_records(instances):
    return b"".join(RECORD.pack(i["variant"], i["x"], i["z"], i["y"], i["scale"], i["yawDeg"], i["tint"])
                    for i in instances)


def summary(instances):
    """(count, sha256 hex of the packed records)."""
    return len(instances), hashlib.sha256(pack_records(instances)).hexdigest()
