"""High level writer: dicts in, file out.

`MapBuilder` collects decoded chunks, encodes them with the right context, derives requiredFeatures from their
content (features.py) and lays the container out. `add_raw` writes an arbitrary payload (negative tests, unknown
chunks).
"""
from . import chunks as C
from .chunkdef import CHUNKS
from .container import ChunkSpec, F_REQUIRED, write_container
from .features import derive_features


class MapBuilder(object):
    def __init__(self, container=3, guid=b"\0" * 16):
        self.container = container
        self.guid = guid
        self.items = []          # (id, instance, dict, compress, required, version)
        self.raw_items = []

    def add(self, id, d, instance=0, compress=False, required=None, version=1):
        self.items.append((id, instance, d, compress, required, version))
        return self

    def add_raw(self, id, payload, instance=0, flags=0, compress=False, version=1):
        self.raw_items.append(ChunkSpec(id, payload, instance, version, flags, compress))
        return self

    def decoded(self):
        return dict(((i, n), d) for i, n, d, _, _, _ in self.items)

    def build(self, render_required=0, extra_required=0, extra_optional=0):
        dec = self.decoded()
        ctx = C.context_from(dict((k[0], v) for k, v in dec.items() if k[1] == 0))
        specs = list(self.raw_items)
        for id, inst, d, compress, required, version in self.items:
            cd = CHUNKS[id]
            specs.append(ChunkSpec(id, C.encode_chunk(id, d, ctx), inst, version, cd.default_flags(required), compress))
        req, opt = derive_features(dec, render_required)
        self.required, self.optional = req | extra_required, opt | extra_optional
        return write_container(specs, self.container, required=self.required, optional=self.optional, guid=self.guid)
