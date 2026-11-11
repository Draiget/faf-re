"""Error types of the reference implementation.

Every refusal carries a stable `code` so tests (and the C++ side) can check *why* a file was refused, not only that
it was. The codes are part of the test contract:

  BAD_MAGIC, UNSUPPORTED_CONTAINER, TRUNCATED, BAD_HEADER, BAD_HEADER_CRC, FILE_SIZE_MISMATCH, BAD_DIRECTORY,
  BAD_DIR_CRC, BAD_ENTRY, CHUNK_RANGE, CHUNK_OVERLAP, LIMIT, INFLATE_RATIO, BAD_CHUNK_CRC, INFLATE_FAILED,
  BAD_SIM_HASH                          (container level)
  UNSUPPORTED_FEATURE, UNKNOWN_REQUIRED_CHUNK, MISSING_CHUNK, BAD_CHUNK, CROSS_CHUNK   (file level)
"""


class MapFormatError(Exception):
    """A file (or chunk) is refused. `code` is one of the stable codes above."""

    def __init__(self, code, message):
        super().__init__("%s: %s" % (code, message))
        self.code = code
        self.message = message


class ChunkError(MapFormatError):
    """A chunk payload is malformed. `chunk` is filled in by the chunk codec wrapper."""

    def __init__(self, message, chunk=None, code="BAD_CHUNK"):
        self.chunk = chunk
        MapFormatError.__init__(self, code, ("%s: " % chunk if chunk else "") + message)
        self.detail = message
