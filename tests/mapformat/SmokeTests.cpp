#include <gtest/gtest.h>
#include "moho/sim/mapformat/MapFormatCommon.h"

using namespace moho::mapformat;

TEST(MapFormatSmoke, Checks)
{
  const char* s = "hello map";
  EXPECT_EQ(Crc32(reinterpret_cast<const std::uint8_t*>(s), 9), 0x7d254c76U);
  EXPECT_EQ(Sha256Hex(reinterpret_cast<const std::uint8_t*>(s), 9),
              std::string("1ab7921baed4921ab4738dd1a253f12d128391fdc9fc28a5f0da637d214855c8"));
  ByteWriter w;
  w.u32(7);
  w.str("ab");
  ByteReader r(w.buf.data(), w.buf.size());
  EXPECT_EQ(r.u32(), 7U);
  EXPECT_EQ(r.str(), std::string("ab"));
  EXPECT_TRUE(r.finish());
  ByteReader bad(w.buf.data(), 3);
  (void)bad.u32();
  EXPECT_TRUE(!bad.ok());
}
