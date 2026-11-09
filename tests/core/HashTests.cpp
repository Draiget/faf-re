// MD5 (RFC 1321) and SHA-256 (FIPS 180-2) against their published test vectors, inputs fed in pieces across
// the 64-byte block boundary, and gpg's salted 32-bit hash. Expected values:
//  - MD5: RFC 1321 appendix A.5; the million-'a' digest and the boundary-length digests were computed with
//    Python's hashlib (an independent implementation), not with the code under test.
//  - SHA-256: FIPS 180-2 appendix B (one block, two blocks, one million 'a'), plus hashlib for the rest.
//  - HashDword/HashBytes: computed in Python from the retail instructions at 0x008E3EA0 and 0x008E3EC0
//    (xor, imul 0x106D643D, then x ^= x >> 13; whole little-endian dwords first, then the tail bytes).

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <gtest/gtest.h>

#include "CoreTestSupport.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/algorithms/SHA256.h"

namespace
{
  using faf_core_tests::ToHex;

  std::string Md5Hex(const std::string& input)
  {
    gpg::MD5Context context{};
    context.Reset();
    context.Update(input.data(), input.size());
    return std::string(context.Digest().ToString().view());
  }

  /** The same input fed in pieces of `piece` bytes. */
  std::string Md5HexInPieces(const std::string& input, const std::size_t piece)
  {
    gpg::MD5Context context{};
    context.Reset();
    for (std::size_t offset = 0; offset < input.size(); offset += piece) {
      context.Update(input.data() + offset, (std::min)(piece, input.size() - offset));
    }
    return std::string(context.Digest().ToString().view());
  }

  std::string Sha256Hex(const std::string& input, const std::size_t piece = 0)
  {
    gpg::SHA256 hasher;
    if (piece == 0) {
      hasher.Update(input.data(), input.size());
    } else {
      for (std::size_t offset = 0; offset < input.size(); offset += piece) {
        hasher.Update(input.data() + offset, (std::min)(piece, input.size() - offset));
      }
    }
    const gpg::SHA256::Digest digest = hasher.Snapshot();
    return ToHex(digest.data(), digest.size());
  }

  /** The bytes `(i * 7 + 3) & 0xFF`, as in the Python that produced the boundary digests below. */
  std::string BoundaryInput(const std::size_t size)
  {
    std::string bytes(size, '\0');
    for (std::size_t index = 0; index < size; ++index) {
      bytes[index] = static_cast<char>((index * 7u + 3u) & 0xFFu);
    }
    return bytes;
  }

  struct BoundaryVector
  {
    std::size_t size;
    const char* md5;
    const char* sha256;
  };

  // hashlib.md5 / hashlib.sha256 of BoundaryInput(size): the sizes that land just before, on and after the
  // point where the length no longer fits (55/56) and where a block fills (63/64/65), once and twice.
  constexpr BoundaryVector kBoundaryVectors[] = {
    {55u, "52c0e574e1198de5fe3f8f11440dcb1b", "e7313d333c272e639f790978283f9eb392e843d0f29b7016828bb1daa4aac70b"},
    {56u, "46c9907fc908ee68b1e7b8e71286a518", "4324d65f3c103567f5589c710bc08f8523f929a9272e3af36fc968e52abc6c27"},
    {57u, "1c805dd236c35cab25fcb1bc73802c51", "35df609437dcfea3279283ab79fd554e2bf78f8f7ae2de532d8ee300b09e8f73"},
    {63u, "a62f6d59e837867693f042f5b8f5a236", "81c80242132f230c3bd41b3e63bbcff16107339549214a99614ff26664625055"},
    {64u, "7160b8fb5e9e4023d549c3971fbaeead", "39e3d7b6b5d075d37d053ad89b24b41bef4f3c29760c84447cab3f3be1882241"},
    {65u, "70bd662e7aefbda85a0f7244167b7897", "aacca6ff74fdbb296d165a45cecfa04e5127bc008770fbbdd48006f2d2fae95e"},
    {119u, "e84905d4214f4d1ca56c2cdcc152b143", "9ce7368e4daf32341631b492e80359dc9f594b48453cd0dd5bf0b19279cc177e"},
    {120u, "e3eb5a6c8669ea01a8c185b8abc8a5dc", "7836b787757e95e58b3ca5aec90b1b004e8deba1e50e9675af9cabf1a13a04b5"},
    {128u, "10b2da1a82f16d99a81a7203fe9f02cb", "d2742f1f4ac6bb7ca2b239ee18402ba8b3f9f8e652d2a72973c2b9ba11c08cf6"},
    {1000u, "10046f077f2082ac19676b8079f1cb1a", "1e9bc38cbf860b9ec31918b065f9b52476c549a782e0e7990bed8ce3868d2371"},
  };

  constexpr std::size_t kPieceSizes[] = {1u, 3u, 55u, 63u, 64u, 65u, 100u};

  // ---------------------------------------------------------------------------------------------
  // MD5, both ProcessBlock forms (md5_UnrolledBlocks true and false)
  // ---------------------------------------------------------------------------------------------

  /** Runs each test body once per ProcessBlock form and puts the switch back afterwards. */
  class GpgMd5 : public ::testing::Test
  {
  protected:
    void SetUp() override { mSaved = gpg::md5_UnrolledBlocks; }
    void TearDown() override { gpg::md5_UnrolledBlocks = mSaved; }

    template <class Body>
    static void ForBothBlockForms(const Body& body)
    {
      for (const bool unrolled : {true, false}) {
        gpg::md5_UnrolledBlocks = unrolled;
        SCOPED_TRACE(unrolled ? "unrolled ProcessBlock" : "table-driven ProcessBlock");
        body();
      }
    }

  private:
    bool mSaved = true;
  };

  TEST_F(GpgMd5, Rfc1321TestSuite)
  {
    ForBothBlockForms([] {
      EXPECT_EQ(Md5Hex(""), "d41d8cd98f00b204e9800998ecf8427e");
      EXPECT_EQ(Md5Hex("a"), "0cc175b9c0f1b6a831c399e269772661");
      EXPECT_EQ(Md5Hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
      EXPECT_EQ(Md5Hex("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
      EXPECT_EQ(Md5Hex("abcdefghijklmnopqrstuvwxyz"), "c3fcd3d76192e4007dfb496cca67e13b");
      EXPECT_EQ(
        Md5Hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"), "d174ab98d277d9f5a5611c2c9f419d9f"
      );
      EXPECT_EQ(
        Md5Hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
        "57edf4a22be3c955ac49da2e2107b67a"
      );
    });
  }

  TEST_F(GpgMd5, OneMillionA)
  {
    ForBothBlockForms([] {
      const std::string input(1000000u, 'a');
      EXPECT_EQ(Md5Hex(input), "7707d6ae4e027c70eea2a935c2296f21");
      EXPECT_EQ(Md5HexInPieces(input, 4093u), "7707d6ae4e027c70eea2a935c2296f21");
    });
  }

  TEST_F(GpgMd5, BlockBoundariesInPieces)
  {
    ForBothBlockForms([] {
      for (const BoundaryVector& vector : kBoundaryVectors) {
        const std::string input = BoundaryInput(vector.size);
        EXPECT_EQ(Md5Hex(input), vector.md5) << "size " << vector.size;
        for (const std::size_t piece : kPieceSizes) {
          EXPECT_EQ(Md5HexInPieces(input, piece), vector.md5) << "size " << vector.size << " in pieces of " << piece;
        }
      }
    });
  }

  TEST_F(GpgMd5, DigestLeavesTheContextRunning)
  {
    ForBothBlockForms([] {
      gpg::MD5Context context{};
      context.Reset();
      context.Update("ab", 2u);
      const gpg::MD5Digest early = context.Digest();
      EXPECT_EQ(std::string(early.ToString().view()), Md5Hex("ab"));
      context.Update("c", 1u);
      EXPECT_EQ(std::string(context.Digest().ToString().view()), "900150983cd24fb0d6963f7d28e17f72");
      EXPECT_EQ(context.size, 3);

      context.Reset();
      EXPECT_EQ(std::string(context.Digest().ToString().view()), "d41d8cd98f00b204e9800998ecf8427e");
    });
  }

  TEST(GpgMd5Digest, ToStringIsTheBytesInMemoryOrder)
  {
    // The RFC's digest of "" read back as the four little-endian words the context holds.
    gpg::MD5Digest digest{{0xd98c1dd4u, 0x04b2008fu, 0x980980e9u, 0x7e42f8ecu}};
    EXPECT_EQ(std::string(digest.ToString().view()), "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(digest.ToString().size(), 32u);
  }

  TEST(GpgMd5Digest, InequalityComparesAllFourWords)
  {
    gpg::MD5Digest a{{1u, 2u, 3u, 4u}};
    gpg::MD5Digest same{{1u, 2u, 3u, 4u}};
    gpg::MD5Digest last{{1u, 2u, 3u, 5u}};
    gpg::MD5Digest first{{0u, 2u, 3u, 4u}};
    EXPECT_FALSE(a != &same);
    EXPECT_TRUE(a != &last);
    EXPECT_TRUE(a != &first);
  }

  TEST(GpgMd5Digest, StdStringUpdateIncludesTheTerminator)
  {
    gpg::MD5Context context{};
    context.Reset();
    context.Update(std::string("abc"));
    // hashlib.md5(b"abc\0")
    EXPECT_EQ(std::string(context.Digest().ToString().view()), "147a664a2ca9410911e61986d3f0d52a");
    EXPECT_EQ(context.size, 4);
  }

  // ---------------------------------------------------------------------------------------------
  // SHA-256
  // ---------------------------------------------------------------------------------------------

  TEST(GpgSha256, Fips180Examples)
  {
    EXPECT_EQ(Sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    EXPECT_EQ(
      Sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    EXPECT_EQ(Sha256Hex(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  }

  TEST(GpgSha256, OneMillionA)
  {
    const std::string input(1000000u, 'a');
    EXPECT_EQ(Sha256Hex(input), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    EXPECT_EQ(Sha256Hex(input, 1000u), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  }

  TEST(GpgSha256, BlockBoundariesInPieces)
  {
    for (const BoundaryVector& vector : kBoundaryVectors) {
      const std::string input = BoundaryInput(vector.size);
      EXPECT_EQ(Sha256Hex(input), vector.sha256) << "size " << vector.size;
      for (const std::size_t piece : kPieceSizes) {
        EXPECT_EQ(Sha256Hex(input, piece), vector.sha256) << "size " << vector.size << " in pieces of " << piece;
      }
    }
  }

  TEST(GpgSha256, SnapshotLeavesTheHasherRunning)
  {
    gpg::SHA256 hasher;
    hasher.Update("ab", 2u);
    const gpg::SHA256::Digest early = hasher.Snapshot();
    EXPECT_EQ(ToHex(early.data(), early.size()), Sha256Hex("ab"));
    hasher.Update("c", 1u);
    const gpg::SHA256::Digest full = hasher.Snapshot();
    EXPECT_EQ(ToHex(full.data(), full.size()), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    hasher.Update("", 0u);
    EXPECT_EQ(hasher.Snapshot(), full);
  }

  // ---------------------------------------------------------------------------------------------
  // HashDword / HashBytes / Hash
  // ---------------------------------------------------------------------------------------------

  TEST(GpgHash, HashDwordMatchesTheRetailMix)
  {
    EXPECT_EQ(gpg::HashDword(0x12345678u, 0u), 0x1957b023u);
    EXPECT_EQ(gpg::HashDword(0u, 0x12345678u), 0x1957b023u); // xor first: the two arguments commute
    EXPECT_EQ(gpg::HashDword(0x00000001u, 0xdeadbeefu), 0x1951bc3du);
  }

  TEST(GpgHash, HashBytesMatchesTheRetailLoop)
  {
    EXPECT_EQ(gpg::HashBytes("", 0u, 7u), 7u); // nothing mixed in: the salt comes back
    EXPECT_EQ(gpg::HashBytes("abc", 3u, 0u), 0x5baa1efbu); // tail bytes only
    EXPECT_EQ(gpg::HashBytes("abcd", 4u, 0u), 0xb16cde57u); // one little-endian dword
    EXPECT_EQ(gpg::HashBytes("Forged Alliance", 15u, 0x9e3779b9u), 0x12d671e1u); // three dwords and a tail
    EXPECT_EQ(gpg::HashBytes("abcd", 4u, 0u), gpg::HashDword(0x64636261u, 0u));
  }

  TEST(GpgHash, StringHashIsHashBytesWithoutTheTerminator)
  {
    EXPECT_EQ(gpg::Hash(std::string("Forged Alliance"), 0x9e3779b9u), 0x12d671e1u);
    EXPECT_EQ(gpg::Hash(std::string(), 99u), 99u);
  }
} // namespace
