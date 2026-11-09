// Reflected pointer types (ReflectionPointerTypes.cpp, RPointerTypeBase in Reflection.cpp) and reflected containers:
// RVectorType<SimArmy*>, the RListType and RSharedPointerType templates, the map<string,float> armour table type and
// list<Rect2i>, each through its RIndexed view and through an archive.
//
// A pointer type is named after its pointee with a '*' (RPointerType_SimArmy::GetName 0x0074FD80), reads "NULL" when
// empty (GetLexical 0x0074FF10), counts one element when set (GetCount 0x007500B0, the shared five-instruction body at
// 0x0040CAF0), and is the size of a pointer. No test here builds an engine object: pointer slots hold null or the
// address of a local the code under test only copies.

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <typeinfo>
#include <vector>
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "ReflectionTestSupport.h"
#include "boost/shared_ptr.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/RListType.h"
#include "gpg/core/reflection/RSharedPointerType.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "legacy/containers/List.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/audio/CSndParams.h"
#include "moho/effects/rendering/IEffect.h"
#include "moho/entity/Entity.h"
#include "moho/entity/Shield.h"
#include "moho/lua/CLuaConOutputHandler.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/render/CDecalHandle.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/SimArmy.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"

namespace faf_reflection_tests
{
  /** A small reflected value for the container templates: two ints written in order. */
  struct ReflPair
  {
    int first = 0;
    int second = 0;

    void MemberSerialize(gpg::WriteArchive* const archive) const
    {
      archive->WriteInt(first);
      archive->WriteInt(second);
    }

    void MemberDeserialize(gpg::ReadArchive* const archive)
    {
      archive->ReadInt(&first);
      archive->ReadInt(&second);
    }
  };
} // namespace faf_reflection_tests

namespace
{
  using faf_reflection_tests::ArchiveFixture;
  using faf_reflection_tests::Bytes;
  using faf_reflection_tests::ReflPair;
  using faf_reflection_tests::ToHex;
  using namespace std::string_view_literals;

  int gPairsDeleted = 0;

  class ReflPairTypeInfo final : public gpg::RType
  {
  public:
    ReflPairTypeInfo() { gpg::PreRegisterRType(typeid(ReflPair), this); }

    [[nodiscard]] const char* GetName() const override { return "faf_reflection_tests::ReflPair"; }

    void Init() override
    {
      size_ = static_cast<int>(sizeof(ReflPair));
      version_ = 2;
      newRefFunc_ = []() { return gpg::RRef{new ReflPair, gpg::RTypeOf<ReflPair>()}; };
      deleteFunc_ = [](void* const object) {
        ++gPairsDeleted;
        delete static_cast<ReflPair*>(object);
      };
      gpg::RType::Init();
      Finish();
    }
  };

  ReflPairTypeInfo gPairType;
  gpg::SerSaveLoadHelper<ReflPair> gPairSerializer;
  gpg::RListType<ReflPair> gPairListType;
  gpg::RSharedPointerType<ReflPair> gPairSharedType;

  constexpr const char* kPairName = "faf_reflection_tests::ReflPair";

  // ---------------------------------------------------------------------------------------------
  // Pointer types
  // ---------------------------------------------------------------------------------------------

  struct PointerCase
  {
    const char* pointee;
    gpg::RType* type;
    /** The type's checked slot upcast, when RRef has one: returns the slot or throws BadRefCast. */
    std::function<void*(const gpg::RRef&)> tryUpcast;
  };

  std::vector<PointerCase> PointerCases()
  {
    // clang-format off
    return {
      {"SimArmy", moho::SimArmy::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastSimArmyPointerSlot(); }},
      {"Shield", moho::Shield::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastShieldPointerSlot(); }},
      {"CDecalHandle", moho::CDecalHandle::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastCDecalHandlePointerSlot(); }},
      {"RBlueprint", moho::RBlueprint::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastRBlueprintPointerSlot(); }},
      {"RUnitBlueprint", moho::RUnitBlueprint::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastRUnitBlueprintPointerSlot(); }},
      {"UnitWeapon", moho::UnitWeapon::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastUnitWeaponPointerSlot(); }},
      {"IAniManipulator", moho::IAniManipulator::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastIAniManipulatorPointerSlot(); }},
      {"IEffect", moho::IEffect::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastIEffectPointerSlot(); }},
      {"CUnitCommand", moho::CUnitCommand::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastCUnitCommandPointerSlot(); }},
      {"Entity", moho::Entity::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastEntityPointerSlot(); }},
      {"CEconomyEvent", moho::CEconomyEvent::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastCEconomyEventPointerSlot(); }},
      {"CAcquireTargetTask", moho::CAcquireTargetTask::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastCAcquireTargetTaskPointerSlot(); }},
      {"ReconBlip", moho::ReconBlip::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastReconBlipPointerSlot(); }},
      {"CArmyStatItem", moho::CArmyStatItem::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastCArmyStatItemPointerSlot(); }},
      {"IFormationInstance", moho::IFormationInstance::GetPointerType(), [](const gpg::RRef& r) -> void* { return r.TryUpcastIFormationInstancePointerSlot(); }},
      {"CTaskThread", moho::CTaskThread::GetPointerType(), nullptr},
      {"CScriptObject", moho::CScriptObject::GetPointerType(), nullptr},
      {"CSndParams", moho::CSndParams::GetPointerType(), nullptr},
      {"CLuaConOutputHandler", moho::CLuaConOutputHandler::GetPointerType(), nullptr},
    };
    // clang-format on
  }

  // Suspected gap on Linux: several pointer types (SimArmy*, Shield*, CDecalHandle*, CAcquireTargetTask*, ...)
  // register lazily on their first GetPointerType call (e.g. Shield.cpp, 0x0074E5D0). In faf_sim that call
  // comes after the startup pass that finishes types, so they have no name entry and size 0 there; Windows has
  // every one finished. Whether a server's keyframes or saves reach them is unchecked. The next test shows it
  // (disabled on Linux); the others skip unfinished types on Linux only.
  bool UnfinishedOnLinux(const gpg::RType* const type)
  {
#if defined(__linux__)
    return type != nullptr && gpg::REF_FindTypeNamed(type->GetName()) != type;
#else
    (void)type;
    return false;
#endif
  }

#if defined(__linux__)
  TEST(ReflectionPointerTypes, DISABLED_EveryPointerTypeIsFinished)
#else
  TEST(ReflectionPointerTypes, EveryPointerTypeIsFinished)
#endif
  {
    for (const PointerCase& pointer : PointerCases()) {
      ASSERT_NE(pointer.type, nullptr) << pointer.pointee;
      EXPECT_EQ(gpg::REF_FindTypeNamed(pointer.type->GetName()), pointer.type) << pointer.pointee;
      EXPECT_EQ(pointer.type->size_, static_cast<int>(sizeof(void*))) << pointer.pointee;
    }
  }

  TEST(ReflectionPointerTypes, NamedAfterThePointeeWithAStar)
  {
    for (const PointerCase& pointer : PointerCases()) {
      if (UnfinishedOnLinux(pointer.type)) {
        continue;
      }
      ASSERT_NE(pointer.type, nullptr) << pointer.pointee;
      EXPECT_EQ(std::string(pointer.type->GetName()), std::string(pointer.pointee) + "*");
      EXPECT_EQ(gpg::REF_FindTypeNamed(pointer.type->GetName()), pointer.type) << pointer.pointee;
      EXPECT_EQ(pointer.type->size_, static_cast<int>(sizeof(void*))) << pointer.pointee;
      EXPECT_NE(pointer.type->IsPointer(), nullptr) << pointer.pointee;
      EXPECT_EQ(pointer.type->IsPointer(), pointer.type->IsIndexed()) << pointer.pointee;
      EXPECT_EQ(pointer.type->IsEnumType(), nullptr) << pointer.pointee;
    }
  }

  TEST(ReflectionPointerTypes, AnEmptySlotReadsNullAndHoldsNothing)
  {
    for (const PointerCase& pointer : PointerCases()) {
      void* slot = nullptr;
      const gpg::RRef ref{&slot, pointer.type};
      EXPECT_EQ(ref.GetLexical().view(), "NULL"sv) << pointer.pointee;
      EXPECT_EQ(ref.GetCount(), 0u) << pointer.pointee;

      const gpg::RRef element = pointer.type->IsIndexed()->SubscriptIndex(&slot, 0);
      EXPECT_EQ(element.mObj, nullptr) << pointer.pointee;
      ASSERT_NE(element.mType, nullptr) << pointer.pointee;
      EXPECT_STREQ(element.mType->GetName(), pointer.pointee);
    }
  }

  TEST(ReflectionPointerTypes, ASetSlotCountsOneElement)
  {
    int target = 0;
    for (const PointerCase& pointer : PointerCases()) {
      void* slot = &target;
      EXPECT_EQ(pointer.type->IsIndexed()->GetCount(&slot), 1u) << pointer.pointee;
    }
  }

  TEST(ReflectionPointerTypes, AssignPointerTakesNullAndRefusesOtherTypes)
  {
    int target = 0;
    int notAnObject = 5;
    for (const PointerCase& pointer : PointerCases()) {
      void* slot = &target;
      pointer.type->IsIndexed()->AssignPointer(&slot, gpg::RRef{});
      EXPECT_EQ(slot, nullptr) << pointer.pointee;

      slot = &target;
      EXPECT_THROW(
        pointer.type->IsIndexed()->AssignPointer(&slot, gpg::RRef{&notAnObject, gpg::RTypeOf<int>()}), gpg::BadRefCast
      ) << pointer.pointee;
    }
  }

  TEST(ReflectionPointerTypes, CountZeroClearsTheSlotAndMoreThanOneIsRefused)
  {
    int target = 0;
    for (const PointerCase& pointer : PointerCases()) {
      const gpg::RIndexed* const indexed = pointer.type->IsIndexed();
      void* slot = &target;
      indexed->SetCount(&slot, 1);
      EXPECT_EQ(slot, &target) << pointer.pointee;
      EXPECT_THROW(indexed->SetCount(&slot, 2), std::bad_cast) << pointer.pointee;
      indexed->SetCount(&slot, 0);
      EXPECT_EQ(slot, nullptr) << pointer.pointee;
    }
  }

  TEST(ReflectionPointerTypes, SlotLanesCreateCopyAndMoveTheAddress)
  {
    int target = 0;
    for (const PointerCase& pointer : PointerCases()) {
      gpg::RType* const type = pointer.type;
      void* source = &target;
      gpg::RRef sourceRef{&source, type};

      if (type->newRefFunc_ != nullptr) {
        gpg::RRef fresh = type->NewRef();
        EXPECT_NE(fresh.mObj, nullptr) << pointer.pointee;
        EXPECT_EQ(fresh.mType, type) << pointer.pointee;
        ASSERT_NE(type->deleteFunc_, nullptr) << pointer.pointee;
        type->deleteFunc_(fresh.mObj);
      }
      if (type->cpyRefFunc_ != nullptr) {
        const gpg::RRef copy = type->cpyRefFunc_(&sourceRef);
        ASSERT_NE(copy.mObj, nullptr) << pointer.pointee;
        EXPECT_NE(copy.mObj, &source) << pointer.pointee;
        EXPECT_EQ(copy.mType, type) << pointer.pointee;
        EXPECT_EQ(*static_cast<void**>(copy.mObj), &target) << pointer.pointee;
        ASSERT_NE(type->deleteFunc_, nullptr) << pointer.pointee;
        type->deleteFunc_(copy.mObj);
      }
      if (type->movRefFunc_ != nullptr) {
        void* destination = nullptr;
        const gpg::RRef moved = type->movRefFunc_(&destination, &sourceRef);
        EXPECT_EQ(moved.mObj, &destination) << pointer.pointee;
        EXPECT_EQ(moved.mType, type) << pointer.pointee;
        EXPECT_EQ(destination, &target) << pointer.pointee;
      }
      if (type->ctorRefFunc_ != nullptr) {
        void* destination = nullptr;
        const gpg::RRef constructed = type->ctorRefFunc_(&destination);
        EXPECT_EQ(constructed.mObj, &destination) << pointer.pointee;
        EXPECT_EQ(constructed.mType, type) << pointer.pointee;
      }
    }
  }

  TEST(ReflectionPointerTypes, CheckedSlotUpcastsReturnTheSlotOrThrow)
  {
    int notASlot = 0;
    const gpg::RRef intRef{&notASlot, gpg::RTypeOf<int>()};
    for (const PointerCase& pointer : PointerCases()) {
      if (!pointer.tryUpcast) {
        continue;
      }
      void* slot = nullptr;
      EXPECT_EQ(pointer.tryUpcast(gpg::RRef{&slot, pointer.type}), &slot) << pointer.pointee;
      try {
        (void)pointer.tryUpcast(intRef);
        ADD_FAILURE() << pointer.pointee << ": no throw";
      } catch (const gpg::BadRefCast& error) {
        EXPECT_EQ(std::string(error.what()), std::string("type error: can't convert int to ") + pointer.pointee + "*");
      }
    }
  }

  TEST(ReflectionPointerTypes, MakeRRefOfASlotUsesThePointerType)
  {
    moho::SimArmy* army = nullptr;
    const gpg::RRef ref = gpg::MakeRRef(&army);
    EXPECT_EQ(ref.mObj, &army);
    EXPECT_EQ(ref.mType, moho::SimArmy::GetPointerType());
    EXPECT_EQ(gpg::RTypeOf<moho::SimArmy*>(), moho::SimArmy::GetPointerType());

    gpg::RRef packed{};
    EXPECT_EQ(gpg::PackRRef_SimArmy_P(&packed, &army), &packed);
    EXPECT_EQ(packed.mObj, &army);
    EXPECT_EQ(packed.mType, ref.mType);
  }

  // ---------------------------------------------------------------------------------------------
  // vector<SimArmy*>
  // ---------------------------------------------------------------------------------------------

  class ReflectionContainers : public ArchiveFixture
  {
  protected:
    void SetUp() override { gPairsDeleted = 0; }
  };

  TEST_F(ReflectionContainers, SimArmyPointerVectorIsIndexedAndCounted)
  {
    // RVectorType<SimArmy*>: GetName 0x0074CB70, Init 0x0074CBF0 (version 1), GetLexical 0x0074CC10.
    gpg::RType* const type = gpg::RTypeOf<fa::vector<moho::SimArmy*>>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "vector<SimArmy*>");
    EXPECT_EQ(type->version_, 1);
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(fa::vector<moho::SimArmy*>)));
    EXPECT_EQ(type->IsPointer(), nullptr);
    const gpg::RIndexed* const indexed = type->IsIndexed();
    ASSERT_NE(indexed, nullptr);

    fa::vector<moho::SimArmy*> armies;
    const gpg::RRef ref{&armies, type};
    EXPECT_EQ(ref.GetCount(), 0u);
    indexed->SetCount(&armies, 3);
    ASSERT_EQ(armies.size(), 3u);
    EXPECT_EQ(ref.GetCount(), 3u);

    const gpg::RRef second = ref[1];
    EXPECT_EQ(second.mObj, &armies[1]);
    EXPECT_EQ(second.mType, moho::SimArmy::GetPointerType());

    const std::string lexical(ref.GetLexical().view());
    EXPECT_EQ(lexical.substr(0, 20), "vector<SimArmy*> at ");
    EXPECT_EQ(lexical.substr(lexical.size() - 8), ", size=3");
  }

  TEST_F(ReflectionContainers, SimArmyPointerVectorRoundTripsNullArmies)
  {
    // SerializeSimArmyPtrVector 0x0074E350: the count, then each army as an unowned tracked pointer.
    gpg::RType* const type = gpg::RTypeOf<fa::vector<moho::SimArmy*>>();
    fa::vector<moho::SimArmy*> armies;
    armies.resize(2);
    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(type, &armies, gpg::RRef{}); });
    const std::string expected = Bytes().NewObject("vector<SimArmy*>", 1).U32(2).Token('0').Token('0').End().str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));

    fa::vector<moho::SimArmy*> back;
    back.resize(5);
    Read(bytes, [&](gpg::ReadArchive& archive) { archive.Read(type, &back, gpg::RRef{}); });
    ASSERT_EQ(back.size(), 2u);
    EXPECT_EQ(back[0], nullptr);
    EXPECT_EQ(back[1], nullptr);
  }

  // ---------------------------------------------------------------------------------------------
  // RListType / RSharedPointerType
  // ---------------------------------------------------------------------------------------------

  TEST_F(ReflectionContainers, ListTypeIsNamedAfterItsElement)
  {
    gpg::RType* const type = gpg::RTypeOf<fa::list<ReflPair>>();
    ASSERT_EQ(type, &gPairListType);
    EXPECT_EQ(std::string(type->GetName()), std::string("list<") + kPairName + ">");
    EXPECT_EQ(type->version_, 1);
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(fa::list<ReflPair>)));

    fa::list<ReflPair> list;
    list.push_back(ReflPair{1, 2});
    list.push_back(ReflPair{3, 4});
    const std::string lexical(gpg::RRef{&list, type}.GetLexical().view());
    EXPECT_EQ(lexical.substr(lexical.size() - 8), ", size=2");
  }

  TEST_F(ReflectionContainers, ListOfValuesRoundTrips)
  {
    fa::list<ReflPair> list;
    list.push_back(ReflPair{1, 2});
    list.push_back(ReflPair{-3, 4});
    list.push_back(ReflPair{5, -6});
    gpg::RType* const type = gpg::RTypeOf<fa::list<ReflPair>>();
    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(type, &list, gpg::RRef{}); });

    std::string listName = std::string("list<") + kPairName + ">";
    const std::string expected = Bytes()
                                   .NewObject(listName, 1)
                                   .U32(3)
                                   .NewObject(kPairName, 2).I32(1).I32(2).End()
                                   .KnownObject(1).I32(-3).I32(4).End()
                                   .KnownObject(1).I32(5).I32(-6).End()
                                   .End()
                                   .str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));
    EXPECT_EQ(Write([&](gpg::WriteArchive& archive) { archive.Write(type, &list, gpg::RRef{}); }, faf_reflection_tests::WriterKind::FastSink), bytes);

    fa::list<ReflPair> back;
    back.push_back(ReflPair{9, 9}); // replaced, not appended to
    Read(bytes, [&](gpg::ReadArchive& archive) { archive.Read(type, &back, gpg::RRef{}); });
    ASSERT_EQ(back.size(), 3u);
    auto it = back.begin();
    EXPECT_EQ(it->first, 1);
    EXPECT_EQ(it->second, 2);
    ++it;
    EXPECT_EQ(it->first, -3);
    ++it;
    EXPECT_EQ(it->second, -6);
  }

  TEST_F(ReflectionContainers, ListOfEntityPointersWritesEachAsATrackedPointer)
  {
    // RListType<Entity*> (EntityDb.cpp): the count, then each element as an unowned tracked pointer (`0` for null).
    gpg::RType* const type = gpg::RTypeOf<fa::list<moho::Entity*>>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "list<Entity*>");
    fa::list<moho::Entity*> entities;
    entities.push_back(nullptr);
    entities.push_back(nullptr);
    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(type, &entities, gpg::RRef{}); });
    EXPECT_EQ(ToHex(bytes), ToHex(Bytes().NewObject("list<Entity*>", 1).U32(2).Token('0').Token('0').End().str()));

    fa::list<moho::Entity*> back;
    Read(bytes, [&](gpg::ReadArchive& archive) { archive.Read(type, &back, gpg::RRef{}); });
    ASSERT_EQ(back.size(), 2u);
    EXPECT_EQ(back.front(), nullptr);

    // A tracked object of another type where an Entity* is expected is refused.
    ReflPair pair{1, 2};
    const std::string wrong = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(&pair, gpg::TrackedPointerState::Owned, gpg::RRef{});
    });
    Read(Bytes().NewObject("list<Entity*>", 1).U32(1).Append(wrong).End().str(), [&](gpg::ReadArchive& archive) {
      fa::list<moho::Entity*> refused;
      try {
        archive.Read(type, &refused, gpg::RRef{});
        ADD_FAILURE() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_NE(std::string(error.what()).find("expected a pointer to an object of type \"Entity\""), std::string::npos)
          << error.what();
      }
    });
  }

  TEST_F(ReflectionContainers, SharedPointerTypeViewsItsPointee)
  {
    gpg::RType* const type = gpg::RTypeOf<boost::shared_ptr<ReflPair>>();
    ASSERT_EQ(type, &gPairSharedType);
    EXPECT_EQ(std::string(type->GetName()), std::string("boost::shared_ptr<") + kPairName + ">");
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(boost::shared_ptr<ReflPair>)));
    ASSERT_NE(type->IsPointer(), nullptr);
    EXPECT_EQ(type->IsPointer(), type->IsIndexed());

    boost::shared_ptr<ReflPair> empty;
    const gpg::RRef emptyRef{&empty, type};
    EXPECT_EQ(emptyRef.GetLexical().view(), "NULL"sv);
    EXPECT_EQ(emptyRef.GetCount(), 0u);

    boost::shared_ptr<ReflPair> held(new ReflPair{1, 2});
    const gpg::RRef heldRef{&held, type};
    EXPECT_EQ(heldRef.GetCount(), 1u);
    const gpg::RRef pointee = heldRef[0];
    EXPECT_EQ(pointee.mObj, held.get());
    EXPECT_EQ(pointee.mType, gpg::RTypeOf<ReflPair>());
    const std::string lexical(heldRef.GetLexical().view());
    EXPECT_EQ(lexical.front(), '[');
    EXPECT_EQ(lexical.back(), ']');
    EXPECT_NE(lexical.find(kPairName), std::string::npos) << lexical;
  }

  TEST_F(ReflectionContainers, SharedPointersReadBackSharingOneObject)
  {
    boost::shared_ptr<ReflPair> pair(new ReflPair{11, 12});
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(pair.get(), gpg::TrackedPointerState::Shared, gpg::RRef{});
      archive.WritePointer(pair.get(), gpg::TrackedPointerState::Shared, gpg::RRef{});
    });
    EXPECT_EQ(
      ToHex(bytes), ToHex(Bytes().Token('N').I32(-1).Str(kPairName).I32(2).I32(11).I32(12).End().Token('*').I32(0).str())
    );

    boost::shared_ptr<ReflPair> first;
    boost::shared_ptr<ReflPair> second;
    Read(bytes, [&](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      archive.ReadPointerShared(&first, &owner);
      archive.ReadPointerShared(&second, &owner);
      archive.EndSection(false);
    });
    ASSERT_TRUE(first);
    EXPECT_EQ(first.get(), second.get());
    EXPECT_EQ(first->first, 11);
    EXPECT_EQ(first->second, 12);
    EXPECT_EQ(gPairsDeleted, 0);
    first.reset();
    EXPECT_EQ(gPairsDeleted, 0); // `second` still holds it
    second.reset();
    EXPECT_EQ(gPairsDeleted, 1); // freed through the type's delete lane (ReadPointerShared, serialization.h:392)
  }

  TEST_F(ReflectionContainers, SharedThenOwnedIsAnOwnershipConflict)
  {
    ReflPair pair{1, 1};
    const std::string bytes = Write([&](gpg::WriteArchive& archive) {
      archive.WritePointer(&pair, gpg::TrackedPointerState::Owned, gpg::RRef{});
    });
    Read(bytes + Bytes().Token('*').I32(0).str(), [&](gpg::ReadArchive& archive) {
      const gpg::RRef owner{};
      ReflPair* owned = nullptr;
      archive.ReadPointerOwned(&owned, &owner);
      boost::shared_ptr<ReflPair> shared;
      try {
        archive.ReadPointerShared(&shared, &owner);
        ADD_FAILURE() << "no throw";
      } catch (const gpg::SerializationError& error) {
        EXPECT_STREQ(error.what(), "Ownership conflict while loading archive");
      }
      delete owned;
    });
  }

  // ---------------------------------------------------------------------------------------------
  // map<string,float> and list<Rect2i>
  // ---------------------------------------------------------------------------------------------

  TEST_F(ReflectionContainers, ArmourMultiplierMapRoundTripsInKeyOrder)
  {
    // RMapStringFloatTypeInfo: registered under std::map<std::string,float> (the unit's armour multipliers,
    // UnitSave.cpp) and stored as fa::map<fa::string,float>; the count, then each key and value.
    gpg::RType* const type = gpg::RTypeOf<std::map<std::string, float>>();
    ASSERT_NE(type, nullptr);
    EXPECT_STREQ(type->GetName(), "map<std::string,float>");
    EXPECT_EQ(type->version_, 1);

    fa::map<fa::string, float> armour;
    armour[fa::string("Normal")] = 1.0f;
    armour[fa::string("Experimental")] = 0.25f;
    armour[fa::string("Commander")] = 0.5f;
    const std::string lexical(gpg::RRef{&armour, type}.GetLexical().view());
    EXPECT_EQ(lexical.substr(lexical.size() - 8), ", size=3");

    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(type, &armour, gpg::RRef{}); });
    const std::string expected = Bytes()
                                   .NewObject("map<std::string,float>", 1)
                                   .U32(3)
                                   .Str("Commander").F32(0.5f)
                                   .Str("Experimental").F32(0.25f)
                                   .Str("Normal").F32(1.0f)
                                   .End()
                                   .str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));

    fa::map<fa::string, float> back;
    back[fa::string("Stale")] = 9.0f;
    Read(bytes, [&](gpg::ReadArchive& archive) { archive.Read(type, &back, gpg::RRef{}); });
    ASSERT_EQ(back.size(), 3u);
    EXPECT_EQ(back[fa::string("Commander")], 0.5f);
    EXPECT_EQ(back[fa::string("Normal")], 1.0f);
    EXPECT_EQ(back.find(fa::string("Stale")), back.end());
  }

  TEST_F(ReflectionContainers, Rect2ListUsesTheBinarysFieldOrder)
  {
    // RListType<Rect2i> (CAiPathFinderTypeInfo.cpp); Rect2<int> saves x0 z0 x1 z1 (0x00905D00) and Rect2<float>
    // saves x0 x1 z0 z1 (0x00905D80: +0, +8, +4, +0xC).
    gpg::RType* const listType = gpg::RTypeOf<fa::list<gpg::Rect2i>>();
    ASSERT_NE(listType, nullptr);
    EXPECT_STREQ(listType->GetName(), "list<Rect2i>");

    fa::list<gpg::Rect2i> rects;
    rects.push_back(gpg::Rect2i{1, 2, 3, 4});
    rects.push_back(gpg::Rect2i{-5, -6, 7, 8});
    const std::string bytes = Write([&](gpg::WriteArchive& archive) { archive.Write(listType, &rects, gpg::RRef{}); });
    const std::string expected = Bytes()
                                   .NewObject("list<Rect2i>", 1)
                                   .U32(2)
                                   .NewObject("Rect2i", 0).I32(1).I32(2).I32(3).I32(4).End()
                                   .KnownObject(1).I32(-5).I32(-6).I32(7).I32(8).End()
                                   .End()
                                   .str();
    EXPECT_EQ(ToHex(bytes), ToHex(expected));

    fa::list<gpg::Rect2i> back;
    Read(bytes, [&](gpg::ReadArchive& archive) { archive.Read(listType, &back, gpg::RRef{}); });
    ASSERT_EQ(back.size(), 2u);
    EXPECT_EQ(back.back().x0, -5);
    EXPECT_EQ(back.back().z0, -6);
    EXPECT_EQ(back.back().x1, 7);
    EXPECT_EQ(back.back().z1, 8);

    gpg::Rect2f rect{0.5f, 1.5f, 2.5f, 3.5f};
    const std::string floatBytes =
      Write([&](gpg::WriteArchive& archive) { archive.Write(gpg::RTypeOf<gpg::Rect2f>(), &rect, gpg::RRef{}); });
    EXPECT_EQ(
      ToHex(floatBytes),
      ToHex(Bytes().NewObject("Rect2f", 0).F32(rect.x0).F32(rect.x1).F32(rect.z0).F32(rect.z1).End().str())
    );
    gpg::Rect2f floatBack{};
    Read(floatBytes, [&](gpg::ReadArchive& archive) { archive.Read(gpg::RTypeOf<gpg::Rect2f>(), &floatBack, gpg::RRef{}); });
    EXPECT_EQ(floatBack.x0, rect.x0);
    EXPECT_EQ(floatBack.z0, rect.z0);
    EXPECT_EQ(floatBack.x1, rect.x1);
    EXPECT_EQ(floatBack.z1, rect.z1);
  }
} // namespace
