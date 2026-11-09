// The reflected types of src/moho/serialization through WriteArchive/ReadArchive, as a save game and a replay
// keyframe write them: the saved-game header and its army rows (SSavedGameHeader 0x00883280/0x008831C0, the army
// vector 0x008827F0/0x008826C0), SBlackListInfo (0x006DD300/0x006DD2B0) and its vector, SBuildReserveInfo, an empty
// CPrefetchSet, and the file header layout. Each archive is checked against bytes built by hand from the format
// ReflectionTestSupport.h describes, read back, and cut or corrupted to check that a bad archive throws.
//
// No resource, entity or unit is built: weak pointers are empty, the launch info is null, the prefetch set is empty.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <string>
#include <string_view>
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "ReflectionTestSupport.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/Entity.h"
#include "moho/serialization/CPrefetchSet.h"
#include "moho/serialization/PrefetchHandleBaseVectorReflection.h"
#include "moho/serialization/SBlackListInfo.h"
#include "moho/serialization/SBlackListInfoVectorReflection.h"
#include "moho/serialization/SBuildReserveInfo.h"
#include "moho/serialization/SSavedGameArmyInfo.h"
#include "moho/serialization/SSavedGameArmyInfoVectorReflection.h"
#include "moho/serialization/SSavedGameHeader.h"
#include "moho/serialization/SaveGameFileHeader.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/Unit.h"

namespace
{
  using faf_reflection_tests::ArchiveFixture;
  using faf_reflection_tests::Bytes;
  using faf_reflection_tests::ToHex;
  using faf_reflection_tests::WriterKind;
  using namespace std::string_view_literals;

  constexpr const char* kHeaderName = "SSavedGameHeader";
  constexpr const char* kArmyVectorName = "vector<SSavedGameArmyInfo>";
  constexpr const char* kArmyName = "SSavedGameArmyInfo";

  moho::SSavedGameHeader MakeHeader()
  {
    moho::SSavedGameHeader header;
    header.mMapName = fa::string("/maps/SCMP_009/SCMP_009_scenario.lua");
    header.mFocusArmy = 2;
    moho::SSavedGameArmyInfo alice;
    alice.mPlayerName = fa::string("Alice");
    moho::SSavedGameArmyInfo bob;
    bob.mPlayerName = fa::string("a player name longer than sixteen bytes");
    header.mArmyInfo.push_back(alice);
    header.mArmyInfo.push_back(bob);
    header.mScenarioInfoText = fa::string("ScenarioInfo = { name = 'Seton' }");
    return header;
  }

  /** The bytes of MakeHeader(), from the member order of 0x00883280 and the vector body 0x008827F0. */
  std::string ExpectedHeaderBytes(const std::int32_t headerVersion = 3)
  {
    return Bytes()
      .NewObject(kHeaderName, headerVersion)
      .I32(0x14)
      .Str("/maps/SCMP_009/SCMP_009_scenario.lua")
      .I32(2)
      .NewObject(kArmyVectorName, 1)
      .U32(2)
      .NewObject(kArmyName, 0).Str("Alice").End()
      .KnownObject(2).Str("a player name longer than sixteen bytes").End()
      .End()
      .Str("ScenarioInfo = { name = 'Seton' }")
      .Token('0') // the launch info: a null shared pointer
      .End()
      .str();
  }

  void ExpectSameHeader(const moho::SSavedGameHeader& actual, const moho::SSavedGameHeader& expected)
  {
    EXPECT_EQ(actual.mVersion, expected.mVersion);
    EXPECT_EQ(actual.mMapName.view(), expected.mMapName.view());
    EXPECT_EQ(actual.mFocusArmy, expected.mFocusArmy);
    ASSERT_EQ(actual.mArmyInfo.size(), expected.mArmyInfo.size());
    for (std::size_t index = 0; index < expected.mArmyInfo.size(); ++index) {
      EXPECT_EQ(actual.mArmyInfo[index].mPlayerName.view(), expected.mArmyInfo[index].mPlayerName.view()) << index;
    }
    EXPECT_EQ(actual.mScenarioInfoText.view(), expected.mScenarioInfoText.view());
    EXPECT_EQ(actual.mLaunchInfo.px, nullptr);
  }

  class SavedGameSerialization : public ArchiveFixture
  {
  protected:
    static gpg::RType* HeaderType() { return gpg::RTypeOf<moho::SSavedGameHeader>(); }
  };

  TEST_F(SavedGameSerialization, TypesAreRegisteredAsTheBinaryNamesThem)
  {
    // SSavedGameHeaderTypeInfo 0x008801A0/0x00880170 (version 3), SSavedGameArmyInfoTypeInfo 0x0087FF80,
    // RVectorType_SSavedGameArmyInfo 0x00882100/0x008821A0 (version 1).
    gpg::RType* const header = HeaderType();
    ASSERT_NE(header, nullptr);
    EXPECT_STREQ(header->GetName(), kHeaderName);
    EXPECT_EQ(header->version_, 3);
    EXPECT_EQ(header->size_, static_cast<int>(sizeof(moho::SSavedGameHeader)));
    EXPECT_NE(header->serSaveFunc_, nullptr);
    EXPECT_NE(header->serLoadFunc_, nullptr);
    EXPECT_EQ(moho::SSavedGameHeader::StaticGetClass(), header);

    gpg::RType* const army = moho::SSavedGameArmyInfo::StaticGetClass();
    EXPECT_STREQ(army->GetName(), kArmyName);
    EXPECT_EQ(army->version_, 0);
    EXPECT_EQ(army->size_, static_cast<int>(sizeof(moho::SSavedGameArmyInfo)));

    gpg::RType* const vector = gpg::ResolveSavedGameArmyInfoVectorType();
    EXPECT_STREQ(vector->GetName(), kArmyVectorName);
    EXPECT_EQ(vector->version_, 1);
    EXPECT_EQ(vector, gpg::RTypeOf<fa::vector<moho::SSavedGameArmyInfo>>());
    EXPECT_NE(vector->IsIndexed(), nullptr);
    EXPECT_EQ(vector->IsPointer(), nullptr);
  }

  TEST_F(SavedGameSerialization, AHeaderStartsAtVersion0x14)
  {
    // 0x00880580.
    const moho::SSavedGameHeader header;
    EXPECT_EQ(header.mVersion, 0x14);
    EXPECT_EQ(header.mFocusArmy, 0);
    EXPECT_TRUE(header.mMapName.view().empty());
    EXPECT_TRUE(header.mArmyInfo.empty());
    EXPECT_TRUE(header.mScenarioInfoText.view().empty());
    EXPECT_EQ(header.mLaunchInfo.px, nullptr);

    const moho::SSavedGameHeader source = MakeHeader();
    const moho::SSavedGameHeader copy(source);
    ExpectSameHeader(copy, source);
    moho::SSavedGameHeader assigned;
    assigned = source;
    ExpectSameHeader(assigned, source);
  }

  TEST_F(SavedGameSerialization, HeaderHasItsDocumentedBytes)
  {
    const moho::SSavedGameHeader header = MakeHeader();
    const std::string bytes =
      Write([&](gpg::WriteArchive& archive) { archive.Write(HeaderType(), &header, gpg::RRef{}); });
    EXPECT_EQ(ToHex(bytes), ToHex(ExpectedHeaderBytes()));

    // A replay keyframe writes the same bytes through the fast archive.
    const std::string fast = Write(
      [&](gpg::WriteArchive& archive) { archive.Write(HeaderType(), &header, gpg::RRef{}); }, WriterKind::FastSink
    );
    EXPECT_EQ(ToHex(fast), ToHex(bytes));
  }

  TEST_F(SavedGameSerialization, HeaderReadsBackOverAnotherOne)
  {
    const moho::SSavedGameHeader source = MakeHeader();
    moho::SSavedGameHeader back;
    back.mVersion = 1;
    back.mMapName = fa::string("stale");
    back.mArmyInfo.resize(5);
    Read(ExpectedHeaderBytes(), [&](gpg::ReadArchive& archive) { archive.Read(HeaderType(), &back, gpg::RRef{}); });
    ExpectSameHeader(back, source);
  }

  TEST_F(SavedGameSerialization, HeaderRoundTripsThroughTheTextArchive)
  {
    const moho::SSavedGameHeader source = MakeHeader();
    const std::string text = WriteText([&](gpg::WriteArchive& archive) { archive.Write(HeaderType(), &source, gpg::RRef{}); });
    EXPECT_NE(text.find("\"SSavedGameHeader\""), std::string::npos) << text;
    EXPECT_NE(text.find("\"Alice\""), std::string::npos) << text;

    moho::SSavedGameHeader back;
    ReadText(text, [&](gpg::ReadArchive& archive) { archive.Read(HeaderType(), &back, gpg::RRef{}); });
    ExpectSameHeader(back, source);
  }

  TEST_F(SavedGameSerialization, AnOlderHeaderVersionIsRefused)
  {
    // 0x008831C9: `cmp version, 3; jge`, else throw "WrongVersion" (0x00E49A94).
    moho::SSavedGameHeader back;
    Read(ExpectedHeaderBytes(2), [&](gpg::ReadArchive& archive) {
      try {
        archive.Read(HeaderType(), &back, gpg::RRef{});
        ADD_FAILURE() << "no throw";
      } catch (const std::exception& error) {
        EXPECT_STREQ(error.what(), "WrongVersion");
      }
    });
  }

  TEST_F(SavedGameSerialization, ArmyVectorIsIndexedThroughReflection)
  {
    gpg::RType* const type = gpg::ResolveSavedGameArmyInfoVectorType();
    const gpg::RIndexed* const indexed = type->IsIndexed();
    ASSERT_NE(indexed, nullptr);

    fa::vector<moho::SSavedGameArmyInfo> armies;
    const gpg::RRef ref{&armies, type};
    EXPECT_EQ(ref.GetCount(), 0u);
    indexed->SetCount(&armies, 3);
    ASSERT_EQ(armies.size(), 3u);
    EXPECT_EQ(ref.GetCount(), 3u);
    armies[2].mPlayerName = fa::string("third");

    const gpg::RRef third = ref[2];
    EXPECT_EQ(third.mObj, &armies[2]);
    EXPECT_STREQ(third.GetName(), kArmyName);

    const std::string lexical(ref.GetLexical().view());
    EXPECT_EQ(lexical.substr(0, std::strlen(kArmyVectorName) + 4), std::string(kArmyVectorName) + " at ");
    EXPECT_EQ(lexical.substr(lexical.size() - 8), ", size=3");

    // Out of range: the element type with no object, after the binary's assertion.
    gpg::RRef outside{};
    EXPECT_NONFATAL_FAILURE(outside = indexed->SubscriptIndex(&armies, 3), "storage->size()");
    EXPECT_EQ(outside.mObj, nullptr);
    EXPECT_STREQ(outside.GetName(), kArmyName);

    gpg::RRef packed{};
    EXPECT_EQ(gpg::RRef_SSavedGameArmyInfo(&packed, &armies[0]), &packed);
    EXPECT_EQ(packed.mObj, &armies[0]);
    EXPECT_EQ(gpg::RRef_SSavedGameArmyInfo(nullptr, &armies[0]), nullptr);

    indexed->SetCount(&armies, 1);
    EXPECT_EQ(armies.size(), 1u);
  }

  // ---------------------------------------------------------------------------------------------
  // Blacklist rows, build reservations, prefetch sets
  // ---------------------------------------------------------------------------------------------

  TEST_F(SavedGameSerialization, BlackListRowsWriteTheirWeakEntityThenTheValue)
  {
    // SBlackListInfo::MemberSerialize 0x006DD300: the WeakPtr<Entity> (version 1, the entity as an unowned
    // tracked pointer), then the int at +0x08. The vector (0x006DB670, version 1): the count, then each row.
    gpg::RType* const type = gpg::RTypeOf<fa::vector<moho::SBlackListInfo>>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "vector<SBlackListInfo>");
    EXPECT_STREQ(moho::SBlackListInfo::StaticGetClass()->GetName(), "SBlackListInfo");

    fa::vector<moho::SBlackListInfo> rows;
    type->IsIndexed()->SetCount(&rows, 2);
    ASSERT_EQ(rows.size(), 2u);
    rows[0].mValue = 17;
    rows[1].mValue = -4;

    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(type, &rows, gpg::RRef{}); });
    const std::string expected = Bytes()
                                   .NewObject("vector<SBlackListInfo>", 1)
                                   .U32(2)
                                   .NewObject("SBlackListInfo", 0).NewObject("WeakPtr<Entity>", 1).Token('0').End().I32(17).End()
                                   .KnownObject(1).KnownObject(2).Token('0').End().I32(-4).End()
                                   .End()
                                   .str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));

    fa::vector<moho::SBlackListInfo> back;
    Read(bytes, [&](gpg::ReadArchive& archive) { archive.Read(type, &back, gpg::RRef{}); });
    ASSERT_EQ(back.size(), 2u);
    EXPECT_EQ(back[0].mValue, 17);
    EXPECT_EQ(back[1].mValue, -4);
    EXPECT_EQ(back[0].mEntity.GetObjectPtr(), nullptr);

    const gpg::RRef second = gpg::RRef{&rows, type}[1];
    EXPECT_EQ(second.mObj, &rows[1]);
    EXPECT_STREQ(second.GetName(), "SBlackListInfo");
  }

  TEST_F(SavedGameSerialization, BuildReservationsWriteTwoWeakPointers)
  {
    // SBuildReserveInfo: WeakPtr<Unit> then WeakPtr<CUnitCommand>, each version 1 (UnitWeakPtrReflection.cpp,
    // CUnitCommandWeakPtrReflection.cpp), each an unowned tracked pointer.
    gpg::RType* const type = gpg::RTypeOf<moho::SBuildReserveInfo>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "SBuildReserveInfo");
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(moho::SBuildReserveInfo)));

    const moho::SBuildReserveInfo info{};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.Write(type, &info, gpg::RRef{});
      archive.Write(type, &info, gpg::RRef{});
    });
    const std::string expected = Bytes()
                                   .NewObject("SBuildReserveInfo", 0)
                                   .NewObject("WeakPtr<Unit>", 1).Token('0').End()
                                   .NewObject("WeakPtr<CUnitCommand>", 1).Token('0').End()
                                   .End()
                                   .KnownObject(0).KnownObject(1).Token('0').End().KnownObject(2).Token('0').End().End()
                                   .str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));

    moho::SBuildReserveInfo back{};
    Read(bytes, [&](gpg::ReadArchive& archive) {
      archive.Read(type, &back, gpg::RRef{});
      archive.Read(type, &back, gpg::RRef{});
    });
    EXPECT_EQ(back.mUnit.GetObjectPtr(), nullptr);
    EXPECT_EQ(back.mCom.GetObjectPtr(), nullptr);
  }

  TEST_F(SavedGameSerialization, AnEmptyPrefetchSetIsAnEmptyHandleVector)
  {
    // CPrefetchSet::MemberSerialize writes the set as its handle vector (vector<PrefetchHandleBase>, version 1).
    gpg::RType* const type = gpg::RTypeOf<moho::CPrefetchSet>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "CPrefetchSet");
    gpg::RType* const vector = gpg::ResolvePrefetchHandleBaseVectorType();
    EXPECT_STREQ(vector->GetName(), "vector<PrefetchHandleBase>");
    EXPECT_EQ(vector->version_, 1);

    moho::CPrefetchSet set;
    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(type, &set, gpg::RRef{}); });
    const std::string expected =
      Bytes().NewObject("CPrefetchSet", 0).NewObject("vector<PrefetchHandleBase>", 1).U32(0).End().End().str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));

    // Indexed access over default (empty) handles.
    vector->IsIndexed()->SetCount(&set.mHandles, 2);
    EXPECT_EQ(gpg::RRef(&set.mHandles, vector).GetCount(), 2u);
    const gpg::RRef first = gpg::RRef(&set.mHandles, vector)[0];
    EXPECT_EQ(first.mObj, &set.mHandles[0]);
    EXPECT_STREQ(first.GetName(), "PrefetchHandleBase");
  }

  TEST_F(SavedGameSerialization, ReadingAPrefetchSetReplacesItsHandles)
  {
    // The binary hands the loaded storage to the destination and frees the old one (0x004A657F..0x004A659C);
    // LoadPrefetchHandleBaseVector moves the loaded vector into the set. A set holding two empty handles, read
    // from an archive of an empty set, ends with none.
    moho::CPrefetchSet empty;
    const std::string bytes =
      Write([&](gpg::WriteArchive& archive) { archive.Write(gpg::RTypeOf<moho::CPrefetchSet>(), &empty, gpg::RRef{}); });

    moho::CPrefetchSet set;
    gpg::ResolvePrefetchHandleBaseVectorType()->IsIndexed()->SetCount(&set.mHandles, 2);
    ASSERT_EQ(set.mHandles.size(), 2u);
    Read(bytes, [&](gpg::ReadArchive& archive) {
      archive.Read(gpg::RTypeOf<moho::CPrefetchSet>(), &set, gpg::RRef{});
    });
    EXPECT_EQ(set.mHandles.size(), 0u);
  }

  TEST(SavedGameFileHeader, LayoutAndDefaultsMatchTheBinary)
  {
    // The 0x2028-byte file header: "RGMH" magic, version 1, its own size, then the preview and game id words and
    // two 1024-unit UTF-16 strings.
    const moho::SSaveGameFileHeader header{};
    unsigned char raw[4];
    std::memcpy(raw, &header.mMagic, 4u);
    EXPECT_EQ(std::string(reinterpret_cast<const char*>(raw), 4u), "RGMH");
    EXPECT_EQ(header.mVersion, 1u);
    EXPECT_EQ(header.mByteSize, 0x2028u);
    EXPECT_EQ(sizeof(moho::SSaveGameFileHeader), 0x2028u);
    EXPECT_EQ(offsetof(moho::SSaveGameFileHeader, mPreviewOffsetLow), 0x0Cu);
    EXPECT_EQ(offsetof(moho::SSaveGameFileHeader, mGameIdPart1), 0x18u);
    EXPECT_EQ(offsetof(moho::SSaveGameFileHeader, mGameIdPart2), 0x24u);
    EXPECT_EQ(offsetof(moho::SSaveGameFileHeader, mAppNameUtf16), 0x28u);
    EXPECT_EQ(offsetof(moho::SSaveGameFileHeader, mSessionNameUtf16), 0x828u);
    EXPECT_EQ(offsetof(moho::SSaveGameFileHeader, mReservedTail), 0x1028u);
    EXPECT_EQ(header.mAppNameUtf16[0], u'\0');
    EXPECT_EQ(header.mPreviewByteSize, 0u);
  }

  // ---------------------------------------------------------------------------------------------
  // Broken archives
  // ---------------------------------------------------------------------------------------------

  class SerializationRobustness : public SavedGameSerialization
  {};

  TEST_F(SerializationRobustness, EveryTruncationOfAHeaderThrows)
  {
    const std::string bytes = ExpectedHeaderBytes();
    for (std::size_t length = 0; length < bytes.size(); ++length) {
      Read(bytes.substr(0, length), [&](gpg::ReadArchive& archive) {
        moho::SSavedGameHeader back;
        EXPECT_THROW(archive.Read(HeaderType(), &back, gpg::RRef{}), gpg::SerializationError) << "cut at " << length;
      });
    }
  }

  TEST_F(SerializationRobustness, AnArmyCountPastTheDataThrows)
  {
    // The count says three rows, two follow.
    std::string bytes = ExpectedHeaderBytes();
    const std::string count2 = Bytes().U32(2).str();
    const std::size_t at = bytes.find(count2, bytes.find(kArmyVectorName));
    ASSERT_NE(at, std::string::npos);
    bytes.replace(at, 4u, Bytes().U32(3).str());
    Read(bytes, [&](gpg::ReadArchive& archive) {
      moho::SSavedGameHeader back;
      EXPECT_THROW(archive.Read(HeaderType(), &back, gpg::RRef{}), gpg::SerializationError);
    });
  }

  TEST_F(SerializationRobustness, AHugeArmyCountThrowsInsteadOfCrashing)
  {
    // 0x008826C0 reserves the count it read before reading any row (0x0088270D), so a corrupted count asks for
    // that much memory at once; it must end in an exception, not a crash.
    for (const std::uint32_t count : {0x7FFFFFFFu, 0xFFFFFFFFu}) {
      std::string bytes = ExpectedHeaderBytes();
      const std::size_t at = bytes.find(Bytes().U32(2).str(), bytes.find(kArmyVectorName));
      ASSERT_NE(at, std::string::npos);
      bytes.replace(at, 4u, Bytes().U32(count).str());
      Read(bytes, [&](gpg::ReadArchive& archive) {
        moho::SSavedGameHeader back;
        EXPECT_THROW(archive.Read(HeaderType(), &back, gpg::RRef{}), std::exception) << count;
      });
    }
  }

  TEST_F(SerializationRobustness, AnotherTypeWhereTheHeaderIsExpectedThrows)
  {
    Read(Bytes().NewObject(kArmyName, 0).Str("x").End().str(), [&](gpg::ReadArchive& archive) {
      moho::SSavedGameHeader back;
      try {
        archive.Read(HeaderType(), &back, gpg::RRef{});
        ADD_FAILURE() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_NE(
          std::string(error.what()).find("found an object of type \"SSavedGameArmyInfo\", but expected one of \"SSavedGameHeader\""),
          std::string::npos
        ) << error.what();
      }
    });
  }

  TEST_F(SerializationRobustness, AStringLengthPastTheDataThrows)
  {
    // The map name's length rewritten to 0x7FFFFFF0.
    std::string bytes = ExpectedHeaderBytes();
    const std::string nameLength = Bytes().I32(static_cast<std::int32_t>(std::strlen("/maps/SCMP_009/SCMP_009_scenario.lua"))).str();
    const std::size_t at = bytes.find(nameLength, 1u + 4u + 4u + std::strlen(kHeaderName));
    ASSERT_NE(at, std::string::npos);
    bytes.replace(at, 4u, Bytes().I32(0x7FFFFFF0).str());
    Read(bytes, [&](gpg::ReadArchive& archive) {
      moho::SSavedGameHeader back;
      EXPECT_THROW(archive.Read(HeaderType(), &back, gpg::RRef{}), std::exception);
    });
  }

  TEST_F(SerializationRobustness, AMissingTerminatorThrows)
  {
    std::string bytes = ExpectedHeaderBytes();
    bytes.back() = '{';
    Read(bytes, [&](gpg::ReadArchive& archive) {
      moho::SSavedGameHeader back;
      try {
        archive.Read(HeaderType(), &back, gpg::RRef{});
        ADD_FAILURE() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_NE(std::string(error.what()).find("did not terminate properly"), std::string::npos) << error.what();
      }
    });
  }
} // namespace
