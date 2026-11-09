"""Reads and patches the parts of a Supreme Commander .scmap a test map needs: the heightmap and
the sea level. Layout as src/moho/terrain/CWldTerrainRes.cpp and src/moho/sim/WldTerrainResHeadless.cpp
read it: header and preview image, then version, width, height, height scale, (w+1)*(h+1) uint16
heights, the stratum byte (version >= 0x36), shader / background / skycube strings, environment
lookups, the lighting and fog block, then the water: enabled byte and three floats."""
import struct

LIGHTING_FLOATS = 23  # multiplier, sun direction 3, ambience 3, sun colour 3, shadow fill 3, specular 4, bloom, fog 5 (CWldTerrainRes::LoadLightingAndFog)


class ScMap:
    def __init__(self, data: bytes):
        self.data = bytearray(data)
        if self.data[:4] != b"Map\x1a":
            raise ValueError("not an scmap")
        at = 4 + 4 * 3 + 4 * 2 + 4 + 2  # magic, version 2, 0xEDFEEFBE, 2, width, height (floats), 0, 0 (short)
        (preview_len,) = struct.unpack_from("<i", self.data, at)
        at += 4 + preview_len
        self.version, self.width, self.height = struct.unpack_from("<iii", self.data, at)
        at += 12
        (self.height_scale,) = struct.unpack_from("<f", self.data, at)
        at += 4
        self.heights_at = at
        self.count = (self.width + 1) * (self.height + 1)
        at += 2 * self.count
        if self.version >= 0x36:
            at += 1
        for _ in range(3):
            at = self._skip_string(at)
        if self.version < 0x37:
            at = self._skip_string(at)
        else:
            (env_count,) = struct.unpack_from("<i", self.data, at)
            at += 4
            for _ in range(2 * env_count):
                at = self._skip_string(at)
        at += 4 * LIGHTING_FLOATS
        self.water_at = at

    def _skip_string(self, at: int) -> int:
        end = self.data.index(b"\0", at)
        return end + 1

    def heights(self) -> list:
        return list(struct.unpack_from("<%dH" % self.count, self.data, self.heights_at))

    def set_heights(self, words: list) -> None:
        if len(words) != self.count:
            raise ValueError("expected %d heights" % self.count)
        struct.pack_into("<%dH" % self.count, self.data, self.heights_at, *words)

    def water(self) -> tuple:
        enabled = self.data[self.water_at]
        levels = struct.unpack_from("<fff", self.data, self.water_at + 1)
        return enabled, levels

    def set_water(self, enabled: bool, elevation: float, deep: float, abyss: float) -> None:
        self.data[self.water_at] = 1 if enabled else 0
        struct.pack_into("<fff", self.data, self.water_at + 1, elevation, deep, abyss)


if __name__ == "__main__":
    import sys
    m = ScMap(open(sys.argv[1], "rb").read())
    h = m.heights()
    print("version", m.version, "size", m.width, m.height, "scale", m.height_scale)
    print("heights min/max (world)", min(h) * m.height_scale, max(h) * m.height_scale)
    print("water", m.water())
