// WriteArchive / ReadArchive (binary and text), the object and pointer framing in ArchiveSerialization.cpp,
// and the ArchiveToken enum type. The expected bytes are built here from the format the recovered bodies
// document: each scalar at its width, little-endian (BinaryWriteArchive 0x009057C0-0x00905A80); a string as a
// 32-bit length and its bytes without a terminator (0x00905AC0); a token as one of `} N 0 * {` (0x00905B60);
// an object as `{`, its type handle (-1, name, version the first time, the handle's index after), its payload
// and `}` (WriteArchive::Write 0x00953CA0, WriteRefCounts 0x00953200); a pointer as `0`, `* index` or
// `N handle payload }` (WriteRawPointer 0x00953320).

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <typeinfo>
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "CoreTestSupport.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ArchiveTokenTypeInfo.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"

namespace faf_core_tests
{
  /** A reflected value type with a member payload: an int, a float and a string. */
  struct ArchivePoint
  {
    int x = 0;
    float y = 0.0f;
    fa::string name;
  };

  /** A reflected type built by its construct hook from a key, like CSndParams: no member payload. */
  struct ArchiveKeyed
  {
    int key = 0;
  };
} // namespace faf_core_tests

namespace
{
  using namespace std::string_view_literals;
  using faf_core_tests::ArchiveKeyed;
  using faf_core_tests::ArchivePoint;

  constexpr const char* kPointTypeName = "faf_core_tests::ArchivePoint";
  constexpr const char* kKeyedTypeName = "faf_core_tests::ArchiveKeyed";
  constexpr int kPointVersion = 3;
  constexpr int kKeyedVersion = 1;

  int gLoadedVersion = -1;
  int gPointsDeleted = 0;
  ArchiveKeyed gKeyedInstances[3] = {{0}, {1}, {2}};

  class ArchivePointTypeInfo final : public gpg::RType
  {
  public:
    ArchivePointTypeInfo() { gpg::PreRegisterRType(typeid(ArchivePoint), this); }

    [[nodiscard]] const char* GetName() const override { return kPointTypeName; }

    void Init() override
    {
      size_ = static_cast<int>(sizeof(ArchivePoint));
      version_ = kPointVersion;
      serSaveFunc_ = &Save;
      serLoadFunc_ = &Load;
      newRefFunc_ = &New;
      deleteFunc_ = &Delete;
      gpg::RType::Init();
      Finish();
    }

  private:
    static void Save(gpg::WriteArchive* const archive, const std::intptr_t object, int, gpg::RRef*)
    {
      auto& point = *reinterpret_cast<ArchivePoint*>(object);
      archive->WriteInt(point.x);
      archive->WriteFloat(point.y);
      archive->WriteString(&point.name);
    }

    static void Load(gpg::ReadArchive* const archive, const std::intptr_t object, const int version, gpg::RRef*)
    {
      gLoadedVersion = version;
      auto& point = *reinterpret_cast<ArchivePoint*>(object);
      archive->ReadInt(&point.x);
      archive->ReadFloat(&point.y);
      archive->ReadString(&point.name);
    }

    static gpg::RRef New() { return gpg::RRef{new ArchivePoint, gpg::LookupRType(typeid(ArchivePoint))}; }

    static void Delete(void* const object)
    {
      ++gPointsDeleted;
      delete static_cast<ArchivePoint*>(object);
    }
  };

  class ArchiveKeyedTypeInfo final : public gpg::RType
  {
  public:
    ArchiveKeyedTypeInfo() { gpg::PreRegisterRType(typeid(ArchiveKeyed), this); }

    [[nodiscard]] const char* GetName() const override { return kKeyedTypeName; }

    void Init() override
    {
      size_ = static_cast<int>(sizeof(ArchiveKeyed));
      version_ = kKeyedVersion;
      serSaveConstructArgsFunc_ = &SaveConstructArgs;
      serConstructFunc_ = &Construct;
      gpg::RType::Init();
      Finish();
    }

  private:
    static void SaveConstructArgs(
      gpg::WriteArchive* const archive, void* const object, int, gpg::RRef*, gpg::SerSaveConstructArgsResult* const result
    )
    {
      archive->WriteInt(static_cast<ArchiveKeyed*>(object)->key);
      result->SetOwned(1u); // the members are not written: the key rebuilds the object
    }

    static void Construct(gpg::ReadArchive* const archive, int, gpg::RRef*, gpg::SerConstructResult* const result)
    {
      int key = -1;
      archive->ReadInt(&key);
      ArchiveKeyed* const instance = (key >= 0 && key < 3) ? &gKeyedInstances[key] : nullptr;
      result->SetOwned(gpg::RRef{instance, gpg::LookupRType(typeid(ArchiveKeyed))}, 1u);
    }
  };

  ArchivePointTypeInfo gArchivePointTypeInfo;
  ArchiveKeyedTypeInfo gArchiveKeyedTypeInfo;

  /** Expected archive bytes, built by hand from the documented format. */
  class Bytes
  {
  public:
    Bytes& I32(const std::int32_t value) { return Raw(&value, 4u); }
    Bytes& U64(const std::uint64_t value) { return Raw(&value, 8u); }
    Bytes& I16(const std::int16_t value) { return Raw(&value, 2u); }
    Bytes& U8(const std::uint8_t value) { return Raw(&value, 1u); }
    Bytes& F32(const float value) { return Raw(&value, 4u); }
    Bytes& Str(const std::string_view text)
    {
      I32(static_cast<std::int32_t>(text.size()));
      mBytes.append(text);
      return *this;
    }
    Bytes& Token(const char token)
    {
      mBytes.push_back(token);
      return *this;
    }
    Bytes& Raw(const void* const data, const std::size_t size)
    {
      mBytes.append(static_cast<const char*>(data), size);
      return *this;
    }
    Bytes& Point(const int x, const float y, const std::string_view name) { return I32(x).F32(y).Str(name); }

    [[nodiscard]] const std::string& str() const noexcept { return mBytes; }

  private:
    std::string mBytes;
  };

  void CloseFile(std::FILE* const file)
  {
    if (file != nullptr) {
      std::fclose(file);
    }
  }

  boost::shared_ptr<std::FILE> OpenFile(const std::string& path, const char* const mode)
  {
    std::FILE* file = nullptr;
    EXPECT_EQ(fopen_s(&file, path.c_str(), mode), 0) << path;
    return boost::shared_ptr<std::FILE>(file, &CloseFile);
  }

  class StringSink final : public gpg::WriteArchiveSink
  {
  public:
    [[nodiscard]] bool Write(const void* const bytes, const std::size_t byteCount) override
    {
      mBytes.append(static_cast<const char*>(bytes), byteCount);
      return true;
    }
    std::string mBytes;
  };

  enum class WriterKind
  {
    Binary,
    FastFile,
    FastSink,
  };

  class ArchiveFixture : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      gLoadedVersion = -1;
      gPointsDeleted = 0;
    }

    /** Runs `body` on a fresh write archive, closes it and returns the bytes it produced. */
    std::string Write(const std::function<void(gpg::WriteArchive&)>& body, const WriterKind kind = WriterKind::Binary)
    {
      const std::string path = mFolder.File(("written" + std::to_string(mCount++) + ".bin").c_str());
      StringSink sink;
      {
        boost::shared_ptr<std::FILE> file = OpenFile(path, "wb");
        std::unique_ptr<gpg::WriteArchive> archive(
          kind == WriterKind::Binary     ? gpg::CreateBinaryWriteArchive(file)
          : kind == WriterKind::FastFile ? gpg::CreateFastBinaryWriteArchive(file)
                                         : gpg::CreateFastBinaryWriteArchive(sink)
        );
        body(*archive);
        archive->Close();
      }
      return kind == WriterKind::FastSink ? sink.mBytes : faf_core_tests::ReadWholeFile(path);
    }

    /** Runs `body` on a read archive over `bytes`. */
    void Read(const std::string& bytes, const std::function<void(gpg::ReadArchive&)>& body)
    {
      const std::string path = mFolder.File(("read" + std::to_string(mCount++) + ".bin").c_str());
      faf_core_tests::WriteWholeFile(path, bytes);
      boost::shared_ptr<std::FILE> file = OpenFile(path, "rb");
      std::unique_ptr<gpg::ReadArchive> archive(gpg::CreateBinaryReadArchive(file));
      body(*archive);
    }

    static gpg::RType* PointType() { return gpg::RTypeOf<ArchivePoint>(); }

    faf_core_tests::TempDir mFolder;
    int mCount = 0;
  };

  void WritePrimitives(gpg::WriteArchive& archive)
  {
    archive.WriteInt(0x01020304);
    archive.WriteUInt(0xFFFFFFFEu);
    archive.WriteLong(-5L);
    archive.WriteULong(7UL);
    archive.WriteInt64(-2LL);
    archive.WriteUInt64(0x1122334455667788ULL);
    archive.WriteShort(-300);
    archive.WriteUShort(0xBEEF);
    archive.WriteByte(-1);
    archive.WriteUByte(0xAB);
    archive.WriteBool(true);
    archive.WriteBool(false);
    archive.WriteFloat(1.5f);
    fa::string text("hey");
    archive.WriteString(&text);
    fa::string empty;
    archive.WriteString(&empty);
    char raw[] = {'r', '\0', 'w'};
    archive.WriteBytes(raw, sizeof(raw));
    for (int token = 0; token <= 4; ++token) {
      archive.WriteMarker(token);
    }
  }

  std::string ExpectedPrimitives()
  {
    Bytes bytes;
    bytes.I32(0x01020304).I32(-2).I32(-5).I32(7);
    bytes.U64(static_cast<std::uint64_t>(-2LL)).U64(0x1122334455667788ULL);
    bytes.I16(-300).I16(static_cast<std::int16_t>(0xBEEF));
    bytes.U8(0xFF).U8(0xAB).U8(1).U8(0);
    bytes.F32(1.5f);
    bytes.Str("hey").Str("");
    bytes.Raw("r\0w", 3u);
    bytes.Token('}').Token('N').Token('0').Token('*').Token('{');
    return bytes.str();
  }

  // ---------------------------------------------------------------------------------------------
  // Binary archive
  // ---------------------------------------------------------------------------------------------

  class GpgBinaryArchive : public ArchiveFixture
  {
  };

  TEST_F(GpgBinaryArchive, PrimitivesHaveTheirDocumentedBytes)
  {
    EXPECT_EQ(Write(&WritePrimitives), ExpectedPrimitives());
  }

  TEST_F(GpgBinaryArchive, FastArchiveWritesTheSameBytes)
  {
    EXPECT_EQ(Write(&WritePrimitives, WriterKind::FastFile), ExpectedPrimitives());
    EXPECT_EQ(Write(&WritePrimitives, WriterKind::FastSink), ExpectedPrimitives());
  }

  TEST_F(GpgBinaryArchive, PrimitivesReadBack)
  {
    Read(ExpectedPrimitives(), [](gpg::ReadArchive& archive) {
      int i = 0;
      unsigned int u = 0;
      long l = 0;
      unsigned long ul = 0;
      __int64 i64 = 0;
      std::uint64_t u64 = 0;
      short s = 0;
      unsigned short us = 0;
      __int8 b = 0;
      unsigned __int8 ub = 0;
      bool yes = false;
      bool no = true;
      float f = 0.0f;
      fa::string text("will be replaced");
      fa::string empty("not empty");
      char raw[3] = {};
      archive.ReadInt(&i);
      archive.ReadUInt(&u);
      archive.ReadLong(&l);
      archive.ReadULong(&ul);
      archive.ReadInt64(&i64);
      archive.ReadUInt64(&u64);
      archive.ReadShort(&s);
      archive.ReadUShort(&us);
      archive.ReadByte(&b);
      archive.ReadUByte(&ub);
      archive.ReadBool(&yes);
      archive.ReadBool(&no);
      archive.ReadFloat(&f);
      archive.ReadString(&text);
      archive.ReadString(&empty);
      archive.ReadBytes(raw, sizeof(raw));
      EXPECT_EQ(i, 0x01020304);
      EXPECT_EQ(u, 0xFFFFFFFEu);
      EXPECT_EQ(l, -5L);
      EXPECT_EQ(ul, 7UL);
      EXPECT_EQ(i64, -2LL);
      EXPECT_EQ(u64, 0x1122334455667788ULL);
      EXPECT_EQ(s, -300);
      EXPECT_EQ(us, 0xBEEF);
      EXPECT_EQ(b, -1);
      EXPECT_EQ(ub, 0xAB);
      EXPECT_TRUE(yes);
      EXPECT_FALSE(no);
      EXPECT_EQ(f, 1.5f);
      EXPECT_EQ(text.view(), "hey"sv);
      EXPECT_EQ(empty.view(), ""sv);
      EXPECT_EQ(std::string_view(raw, 3u), std::string_view("r\0w", 3u));
      for (int token = 0; token <= 4; ++token) {
        EXPECT_EQ(archive.NextMarker(), token);
      }
    });
  }

  TEST_F(GpgBinaryArchive, ReadingPastTheEndThrows)
  {
    Read(Bytes().I32(1).U8(2).str(), [](gpg::ReadArchive& archive) {
      int value = 0;
      archive.ReadInt(&value);
      EXPECT_EQ(value, 1);
      EXPECT_THROW(archive.ReadInt(&value), gpg::SerializationError); // one byte left
    });
    Read(Bytes().Str("abcdef").str().substr(0, 7u), [](gpg::ReadArchive& archive) {
      fa::string text;
      EXPECT_THROW(archive.ReadString(&text), gpg::SerializationError); // length 6, three bytes there
    });
    Read(std::string(), [](gpg::ReadArchive& archive) {
      EXPECT_THROW((void)archive.NextMarker(), gpg::SerializationError);
    });
  }

  TEST_F(GpgBinaryArchive, UnknownMarkerByteThrows)
  {
    Read("X", [](gpg::ReadArchive& archive) {
      try {
        (void)archive.NextMarker();
        FAIL() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_NE(std::string(error.what()).find("invalid marker token 0x58"), std::string::npos) << error.what();
      }
    });
  }

  TEST_F(GpgBinaryArchive, ReflectedObjectsAreFramedWithTheirTypeHandle)
  {
    ArchivePoint first{5, 2.5f, fa::string("alpha")};
    ArchivePoint second{-1, -0.25f, fa::string()};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.Write(PointType(), &first, gpg::RRef{});
      archive.Write(PointType(), &second, gpg::RRef{});
    });

    const std::string expected = Bytes()
                                   .Token('{').I32(-1).Str(kPointTypeName).I32(kPointVersion).Point(5, 2.5f, "alpha").Token('}')
                                   .Token('{').I32(0).Point(-1, -0.25f, "").Token('}')
                                   .str();
    EXPECT_EQ(faf_core_tests::ToHex(bytes.data(), bytes.size()), faf_core_tests::ToHex(expected.data(), expected.size()));

    Read(bytes, [&](gpg::ReadArchive& archive) {
      ArchivePoint a;
      ArchivePoint b{9, 9.0f, fa::string("old")};
      archive.Read(PointType(), &a, gpg::RRef{});
      EXPECT_EQ(gLoadedVersion, kPointVersion);
      archive.Read(PointType(), &b, gpg::RRef{});
      EXPECT_EQ(a.x, 5);
      EXPECT_EQ(a.y, 2.5f);
      EXPECT_EQ(a.name.view(), "alpha"sv);
      EXPECT_EQ(b.x, -1);
      EXPECT_EQ(b.y, -0.25f);
      EXPECT_EQ(b.name.view(), ""sv);
    });
  }

  TEST_F(GpgBinaryArchive, TheVersionComesFromTheArchive)
  {
    const std::string bytes = Bytes().Token('{').I32(-1).Str(kPointTypeName).I32(1).Point(1, 1.0f, "v1").Token('}').str();
    Read(bytes, [](gpg::ReadArchive& archive) {
      ArchivePoint point;
      archive.Read(gpg::RTypeOf<ArchivePoint>(), &point, gpg::RRef{});
      EXPECT_EQ(gLoadedVersion, 1);
      EXPECT_EQ(point.name.view(), "v1"sv);
    });
  }

  TEST_F(GpgBinaryArchive, EndSectionForgetsTypeHandles)
  {
    ArchivePoint point{1, 2.0f, fa::string("p")};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.Write(PointType(), &point, gpg::RRef{});
      archive.EndSection(false);
      archive.Write(PointType(), &point, gpg::RRef{});
    });
    const std::string once = Bytes().Token('{').I32(-1).Str(kPointTypeName).I32(kPointVersion).Point(1, 2.0f, "p").Token('}').str();
    EXPECT_EQ(bytes, once + once);
  }

  TEST_F(GpgBinaryArchive, MalformedObjectsThrow)
  {
    ArchivePoint point;
    // A type name nobody registered.
    Read(Bytes().Token('{').I32(-1).Str("faf_core_tests::NoSuchType").I32(1).str(), [&](gpg::ReadArchive& archive) {
      try {
        archive.Read(PointType(), &point, gpg::RRef{});
        FAIL() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_NE(std::string(error.what()).find("No type named \"faf_core_tests::NoSuchType\""), std::string::npos) << error.what();
      }
    });
    // A handle index before any type was named.
    Read(Bytes().Token('{').I32(0).str(), [&](gpg::ReadArchive& archive) {
      EXPECT_THROW(archive.Read(PointType(), &point, gpg::RRef{}), gpg::SerializationError);
    });
    // Something else where the object should start: the message names the token through ArchiveTokenTypeInfo.
    Read(Bytes().Token('}').str(), [&](gpg::ReadArchive& archive) {
      try {
        archive.Read(PointType(), &point, gpg::RRef{});
        FAIL() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_NE(std::string(error.what()).find("but got a OBJECT_TERMINATOR instead"), std::string::npos) << error.what();
      }
    });
    // A payload that does not end with `}`.
    Read(Bytes().Token('{').I32(-1).Str(kPointTypeName).I32(kPointVersion).Point(1, 1.0f, "x").Token('{').str(), [&](gpg::ReadArchive& archive) {
      EXPECT_THROW(archive.Read(PointType(), &point, gpg::RRef{}), gpg::SerializationError);
    });
  }

  TEST_F(GpgBinaryArchive, EveryTruncationOfAnObjectThrows)
  {
    ArchivePoint source{77, 0.5f, fa::string("truncate me")};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(PointType(), &source, gpg::RRef{}); });
    ASSERT_GT(bytes.size(), 20u);
    for (std::size_t length = 0; length < bytes.size(); ++length) {
      Read(bytes.substr(0, length), [&](gpg::ReadArchive& archive) {
        ArchivePoint point;
        EXPECT_THROW(archive.Read(PointType(), &point, gpg::RRef{}), gpg::SerializationError) << "cut at " << length;
      });
    }
  }

  TEST_F(GpgBinaryArchive, TypesWithoutASerializerAreRefused)
  {
    int value = 3;
    EXPECT_THROW(
      (void)Write([&](gpg::WriteArchive& archive) { archive.Write(gpg::RTypeOf<int>(), &value, gpg::RRef{}); }),
      gpg::SerializationError
    );
    Read(Bytes().Token('{').str(), [&](gpg::ReadArchive& archive) {
      EXPECT_THROW(archive.Read(gpg::RTypeOf<int>(), &value, gpg::RRef{}), gpg::SerializationError);
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Tracked pointers
  // ---------------------------------------------------------------------------------------------

  class GpgArchivePointers : public ArchiveFixture
  {
  };

  TEST_F(GpgArchivePointers, NewExistingAndNullPointers)
  {
    auto* const point = new ArchivePoint{7, 1.25f, fa::string("ptr")};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(point, gpg::TrackedPointerState::Owned, gpg::RRef{});
      archive.WritePointer(point, gpg::TrackedPointerState::Unowned, gpg::RRef{});
      archive.WritePointer<ArchivePoint>(nullptr, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    });
    delete point;

    const std::string expected = Bytes()
                                   .Token('N').I32(-1).Str(kPointTypeName).I32(kPointVersion).Point(7, 1.25f, "ptr").Token('}')
                                   .Token('*').I32(0)
                                   .Token('0')
                                   .str();
    EXPECT_EQ(faf_core_tests::ToHex(bytes.data(), bytes.size()), faf_core_tests::ToHex(expected.data(), expected.size()));

    ArchivePoint* owned = nullptr;
    Read(bytes, [&](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ArchivePoint* again = nullptr;
      auto* none = reinterpret_cast<ArchivePoint*>(&again); // anything non-null: a null pointer must overwrite it
      archive.ReadPointerOwned(&owned, &owner);
      archive.ReadPointer(&again, &owner);
      archive.ReadPointer(&none, &owner);
      ASSERT_NE(owned, nullptr);
      EXPECT_EQ(again, owned);
      EXPECT_EQ(none, nullptr);
      EXPECT_EQ(owned->x, 7);
      EXPECT_EQ(owned->y, 1.25f);
      EXPECT_EQ(owned->name.view(), "ptr"sv);
      archive.EndSection(false);
    });
    EXPECT_EQ(gPointsDeleted, 0); // owned by the reader: EndSection leaves it
    delete owned;
  }

  TEST_F(GpgArchivePointers, EndSectionDeletesWhatNobodyOwned)
  {
    ArchivePoint point{1, 0.0f, fa::string("orphan")};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(&point, gpg::TrackedPointerState::Owned, gpg::RRef{});
    });
    Read(bytes, [&](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ArchivePoint* borrowed = nullptr;
      archive.ReadPointer(&borrowed, &owner);
      ASSERT_NE(borrowed, nullptr);
      EXPECT_EQ(borrowed->name.view(), "orphan"sv);
      archive.EndSection(false);
    });
    EXPECT_EQ(gPointsDeleted, 1);
  }

  TEST_F(GpgArchivePointers, OwnershipIsCheckedOnWrite)
  {
    ArchivePoint point;
    // Two owners.
    EXPECT_THROW(
      (void)Write([&](gpg::WriteArchive& archive) {
        archive.WritePointer(&point, gpg::TrackedPointerState::Owned, gpg::RRef{});
        archive.WritePointer(&point, gpg::TrackedPointerState::Owned, gpg::RRef{});
      }),
      gpg::SerializationError
    );
    // No owner by the end of the section.
    try {
      (void)Write([&](gpg::WriteArchive& archive) {
        archive.WritePointer(&point, gpg::TrackedPointerState::Unowned, gpg::RRef{});
      });
      FAIL() << "no throw";
    } catch (const gpg::SerializationError& error) {
      EXPECT_NE(std::string(error.what()).find("nobody claimed ownership of faf_core_tests::ArchivePoint"), std::string::npos)
        << error.what();
    }
    // Shared after owned.
    EXPECT_THROW(
      (void)Write([&](gpg::WriteArchive& archive) {
        archive.WritePointer(&point, gpg::TrackedPointerState::Owned, gpg::RRef{});
        archive.WritePointer(&point, gpg::TrackedPointerState::Shared, gpg::RRef{});
      }),
      gpg::SerializationError
    );
  }

  TEST_F(GpgArchivePointers, PreCreatedPointersAreWrittenAsExisting)
  {
    ArchivePoint point;
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.PreCreatedPtr(gpg::MakeRRef(&point));
      archive.WritePointer(&point, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    });
    EXPECT_EQ(bytes, Bytes().Token('*').I32(0).str());

    Read(bytes, [&](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      archive.TrackPointer(gpg::MakeRRef(&point));
      ArchivePoint* read = nullptr;
      archive.ReadPointer(&read, &owner);
      EXPECT_EQ(read, &point);
      archive.EndSection(false);
    });
    EXPECT_EQ(gPointsDeleted, 0);

    EXPECT_THROW(
      (void)Write([&](gpg::WriteArchive& archive) { archive.PreCreatedPtr(gpg::RRef{nullptr, PointType()}); }),
      gpg::SerializationError
    );
    EXPECT_THROW(
      (void)Write([&](gpg::WriteArchive& archive) {
        archive.PreCreatedPtr(gpg::MakeRRef(&point));
        archive.PreCreatedPtr(gpg::MakeRRef(&point));
      }),
      gpg::SerializationError
    );
  }

  TEST_F(GpgArchivePointers, ConstructHooksRebuildFromTheirArguments)
  {
    ArchiveKeyed local{2};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(&local, gpg::TrackedPointerState::Unowned, gpg::RRef{});
      archive.WritePointer(&local, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    });
    // No member payload: only the hook's key between the handle and `}`.
    EXPECT_EQ(bytes, Bytes().Token('N').I32(-1).Str(kKeyedTypeName).I32(kKeyedVersion).I32(2).Token('}').Token('*').I32(0).str());

    Read(bytes, [&](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ArchiveKeyed* first = nullptr;
      ArchiveKeyed* second = nullptr;
      archive.ReadPointer(&first, &owner);
      archive.ReadPointer(&second, &owner);
      EXPECT_EQ(first, &gKeyedInstances[2]); // the cached instance, not a new object
      EXPECT_EQ(second, first);
      archive.EndSection(false); // Owned by the hook: not deleted
    });
  }

  TEST_F(GpgArchivePointers, BadPointerTokensThrow)
  {
    Read(Bytes().Token('*').I32(0).str(), [](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ArchivePoint* point = nullptr;
      EXPECT_THROW(archive.ReadPointer(&point, &owner), gpg::SerializationError); // no pointer 0 yet
    });
    Read(Bytes().Token('{').str(), [](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ArchivePoint* point = nullptr;
      EXPECT_THROW(archive.ReadPointer(&point, &owner), gpg::SerializationError);
    });
    // A keyed object where an ArchivePoint is expected.
    ArchiveKeyed local{0};
    const std::string keyed = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(&local, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    });
    Read(keyed, [](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ArchivePoint* point = nullptr;
      EXPECT_THROW(archive.ReadPointer(&point, &owner), gpg::SerializationError);
    });
  }

  // ---------------------------------------------------------------------------------------------
  // Text archive
  // ---------------------------------------------------------------------------------------------

  std::string WriteText(const std::function<void(gpg::WriteArchive&)>& body)
  {
    auto* const text = new std::ostringstream;
    const boost::shared_ptr<std::ostream> stream(text);
    {
      std::unique_ptr<gpg::WriteArchive> archive(gpg::CreateTextWriteArchive(stream));
      body(*archive);
      archive->Close();
    }
    return text->str();
  }

  void ReadText(const std::string& text, const std::function<void(gpg::ReadArchive&)>& body)
  {
    const boost::shared_ptr<std::istream> stream(new std::istringstream(text));
    std::unique_ptr<gpg::ReadArchive> archive(gpg::CreateTextReadArchive(stream));
    body(*archive);
  }

  TEST(GpgTextArchive, ScalarsAreSpaceSeparatedTokens)
  {
    const std::string text = WriteText([](gpg::WriteArchive& archive) {
      archive.WriteInt(-7);
      archive.WriteBool(true);
      archive.WriteMarker(static_cast<int>(gpg::ArchiveToken::ObjectStart));
      archive.WriteUByte(200);
      archive.WriteByte(-5);
      archive.WriteFloat(1.5f);
      archive.WriteUInt64((std::numeric_limits<std::uint64_t>::max)());
      archive.WriteShort(-300);
      archive.WriteMarker(static_cast<int>(gpg::ArchiveToken::ObjectTerminator));
    });
    EXPECT_EQ(text, "-7 1 { 200 -5 1.5 18446744073709551615 -300 } ");

    ReadText(text, [](gpg::ReadArchive& archive) {
      int i = 0;
      bool b = false;
      unsigned __int8 ub = 0;
      __int8 sb = 0;
      float f = 0.0f;
      std::uint64_t u64 = 0;
      short s = 0;
      archive.ReadInt(&i);
      archive.ReadBool(&b);
      EXPECT_EQ(archive.NextMarker(), static_cast<int>(gpg::ArchiveToken::ObjectStart));
      archive.ReadUByte(&ub);
      archive.ReadByte(&sb);
      archive.ReadFloat(&f);
      archive.ReadUInt64(&u64);
      archive.ReadShort(&s);
      EXPECT_EQ(archive.NextMarker(), static_cast<int>(gpg::ArchiveToken::ObjectTerminator));
      EXPECT_EQ(i, -7);
      EXPECT_TRUE(b);
      EXPECT_EQ(ub, 200);
      EXPECT_EQ(sb, -5);
      EXPECT_EQ(f, 1.5f);
      EXPECT_EQ(u64, (std::numeric_limits<std::uint64_t>::max)());
      EXPECT_EQ(s, -300);
    });
  }

  TEST(GpgTextArchive, StringsAreQuotedAndEscaped)
  {
    fa::string tricky(std::string_view("a\"b\\c\n\t\x01\x7f\xe9z", 11u));
    const std::string text = WriteText([&](gpg::WriteArchive& archive) { archive.WriteString(&tricky); });
    EXPECT_EQ(text, "\"a\\\"b\\\\c\\n\\t\\001\\177\\351z\"\n");

    ReadText(text + "\"\"\n", [&](gpg::ReadArchive& archive) {
      fa::string back;
      archive.ReadString(&back);
      EXPECT_EQ(back.view(), tricky.view());
      archive.ReadString(&back);
      EXPECT_EQ(back.view(), ""sv);
    });
  }

  TEST(GpgTextArchive, MalformedStringsThrow)
  {
    for (const char* const bad : {"no quote", "\"never closed", "\"bad escape \\q\"", ""}) {
      ReadText(bad, [&](gpg::ReadArchive& archive) {
        fa::string out;
        EXPECT_THROW(archive.ReadString(&out), gpg::SerializationError) << bad;
      });
    }
  }

  TEST(GpgTextArchive, BytesAreHexPairsInGroupsOfFour)
  {
    const std::string text = WriteText([](gpg::WriteArchive& archive) {
      char five[] = {0x00, 0x01, 0x02, 0x03, static_cast<char>(0xAB)};
      archive.WriteBytes(five, sizeof(five));
      char none[1] = {};
      archive.WriteBytes(none, 0u);
    });
    EXPECT_EQ(text, "00 01 02 03  ab \n");

    std::string row(32u, '\0');
    for (std::size_t index = 0; index < row.size(); ++index) {
      row[index] = static_cast<char>(index);
    }
    const std::string full = WriteText([&](gpg::WriteArchive& archive) { archive.WriteBytes(row.data(), row.size()); });
    // 32 to a line, which ends at the 32nd byte without a trailing separator.
    EXPECT_EQ(
      full,
      "00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f  10 11 12 13  14 15 16 17  18 19 1a 1b  1c 1d 1e 1f\n"
    );

    ReadText(full, [&](gpg::ReadArchive& archive) {
      std::string back(32u, 'x');
      archive.ReadBytes(back.data(), back.size());
      EXPECT_EQ(back, row);
    });
  }

  TEST(GpgTextArchive, ReflectedObjectRoundTrip)
  {
    ArchivePoint point{12, 0.75f, fa::string("text point")};
    const std::string text = WriteText([&](gpg::WriteArchive& archive) {
      archive.Write(gpg::RTypeOf<ArchivePoint>(), &point, gpg::RRef{});
    });
    EXPECT_EQ(text, std::string("{ -1 \"") + kPointTypeName + "\"\n3 12 0.75 \"text point\"\n} ");

    ReadText(text, [](gpg::ReadArchive& archive) {
      ArchivePoint back;
      archive.Read(gpg::RTypeOf<ArchivePoint>(), &back, gpg::RRef{});
      EXPECT_EQ(back.x, 12);
      EXPECT_EQ(back.y, 0.75f);
      EXPECT_EQ(back.name.view(), "text point"sv);
    });
  }

  TEST(GpgTextArchive, UnknownMarkerThrows)
  {
    ReadText("?", [](gpg::ReadArchive& archive) { EXPECT_THROW((void)archive.NextMarker(), gpg::SerializationError); });
  }

  // ---------------------------------------------------------------------------------------------
  // ArchiveToken reflection and the construct/save result helpers
  // ---------------------------------------------------------------------------------------------

  TEST(GpgArchiveToken, EnumTypeNamesEveryToken)
  {
    const gpg::RType* const type = gpg::RTypeOf<gpg::ArchiveToken>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "ArchiveToken");
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(gpg::ArchiveToken)));
    EXPECT_EQ(gpg::REF_FindTypeNamed("ArchiveToken"), type);

    const gpg::REnumType* const enumType = type->IsEnumType();
    ASSERT_NE(enumType, nullptr);
    const auto& options = enumType->GetEnumOptions();
    ASSERT_EQ(options.size(), 5u);
    const char* const names[] = {"OBJECT_TERMINATOR", "NEW_OBJECT_TOKEN", "NULL_POINTER_TOKEN", "EXISTING_POINTER_TOKEN", "OBJECT_START"};
    for (std::size_t index = 0; index < 5u; ++index) {
      EXPECT_EQ(options[index].mValue, static_cast<int>(index));
      EXPECT_STREQ(options[index].mName, names[index]);
    }
  }

  TEST(GpgArchiveToken, LexicalFormBothWays)
  {
    gpg::ArchiveToken token = gpg::ArchiveToken::ExistingPointerToken;
    const gpg::RRef ref = gpg::RRef_ArchiveToken(&token);
    ASSERT_NE(ref.mType, nullptr);
    EXPECT_EQ(ref.GetLexical().view(), "EXISTING_POINTER_TOKEN"sv);

    EXPECT_TRUE(ref.SetLexical("null_pointer_token")); // names match without case
    EXPECT_EQ(token, gpg::ArchiveToken::NullPointerToken);
    EXPECT_TRUE(ref.SetLexical("4"));
    EXPECT_EQ(token, gpg::ArchiveToken::ObjectStart);
    EXPECT_FALSE(ref.SetLexical("NOT_A_TOKEN"));
    EXPECT_EQ(token, gpg::ArchiveToken::ObjectStart);

    token = static_cast<gpg::ArchiveToken>(9);
    EXPECT_EQ(ref.GetLexical().view(), "9"sv); // no name: the number
  }

  TEST(GpgSerResults, ConstructResultStates)
  {
    int object = 0;
    const gpg::RRef ref{&object, gpg::RTypeOf<int>()};

    gpg::SerConstructResult owned{};
    owned.SetOwned(ref, 0u);
    EXPECT_EQ(owned.mInfo.state, gpg::TrackedPointerState::Owned);
    EXPECT_EQ(owned.mInfo.object, &object);
    EXPECT_EQ(owned.mInfo.type, ref.mType);
    EXPECT_TRUE(owned.mLoadMembers);

    gpg::SerConstructResult unowned{};
    unowned.SetUnowned(ref, 1u);
    EXPECT_EQ(unowned.mInfo.state, gpg::TrackedPointerState::Unowned);
    EXPECT_FALSE(unowned.mLoadMembers);

    gpg::SerConstructResult shared{};
    const boost::shared_ptr<void> holder(new int(5));
    shared.SetShared(holder, ref.mType, 1u);
    EXPECT_EQ(shared.mInfo.state, gpg::TrackedPointerState::Shared);
    EXPECT_EQ(shared.mInfo.object, holder.get());
    EXPECT_EQ(shared.mInfo.sharedPtr.get(), holder.get());
    EXPECT_FALSE(shared.mLoadMembers);

    // A second state change trips the binary's assertion (serialization.cpp line 196).
    EXPECT_NONFATAL_FAILURE(owned.SetOwned(ref, 0u), "mInfo.mState == RESERVED");
  }

  TEST(GpgSerResults, SaveConstructArgsResultStates)
  {
    gpg::SerSaveConstructArgsResult owned{};
    owned.SetOwned(0u);
    EXPECT_EQ(owned.mOwnership, gpg::TrackedPointerState::Owned);
    EXPECT_TRUE(owned.mWriteMembers);

    gpg::SerSaveConstructArgsResult unowned{};
    unowned.SetUnowned(1u);
    EXPECT_EQ(unowned.mOwnership, gpg::TrackedPointerState::Unowned);
    EXPECT_FALSE(unowned.mWriteMembers);

    gpg::SerSaveConstructArgsResult shared{};
    shared.SetShared(0u);
    EXPECT_EQ(shared.mOwnership, gpg::TrackedPointerState::Shared);

    EXPECT_NONFATAL_FAILURE(shared.SetShared(0u), "mOwnership == RESERVED");
  }

  TEST(GpgSerResults, RRefCompareOrdersByTypeThenObject)
  {
    int a = 0;
    int b = 0;
    gpg::RType* const intType = gpg::RTypeOf<int>();
    gpg::RType* const floatType = gpg::RTypeOf<float>();
    const gpg::RRefCompare less{};
    int* const low = (&a < &b) ? &a : &b;
    int* const high = (&a < &b) ? &b : &a;
    EXPECT_TRUE(less(gpg::RRef{low, intType}, gpg::RRef{high, intType}));
    EXPECT_FALSE(less(gpg::RRef{high, intType}, gpg::RRef{low, intType}));
    EXPECT_FALSE(less(gpg::RRef{low, intType}, gpg::RRef{low, intType}));
    // Different types: the type decides, whatever the objects.
    const bool intFirst = intType < floatType;
    EXPECT_EQ(less(gpg::RRef{high, intType}, gpg::RRef{low, floatType}), intFirst);
    EXPECT_EQ(less(gpg::RRef{low, floatType}, gpg::RRef{high, intType}), !intFirst);
  }
} // namespace
