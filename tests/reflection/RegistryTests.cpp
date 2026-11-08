// The reflection type registry (Reflection.cpp, ReflectionTypes.cpp): registration by type_info and by name, the
// one-time Init of a looked-up type, field tables sorted by name (RType::Finish 0x008DF4A0, GetFieldNamed
// 0x008D94E0), bases flattened into the field table at their offset (RType::AddBase 0x008DF500), base relations and
// the offset to a base (RType::IsDerivedFrom 0x008DBFF0, REF_UpcastPtr 0x008D9590), and enum types (REnumType).
//
// The expected offsets come from the compiler's own layout of the test types (offsetof, static_cast to a base), so
// they hold on x86 and x64 alike.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <vector>
#include <gtest/gtest.h>
#include <gtest/gtest-spi.h>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/Entity.h"
#include "moho/entity/Prop.h"
#include "moho/unit/core/Unit.h"

#if defined(_WIN32)
#include "moho/ui/UiStateTypes.h"
#endif

namespace faf_reflection_tests
{
  struct ReflBase
  {
    int a = 0;
    float b = 0.0f;
  };

  struct ReflOther
  {
    int c = 0;
  };

  struct ReflDerived : ReflBase, ReflOther
  {
    int d = 0;
  };

  struct ReflPad
  {
    double pad = 0.0;
  };

  struct ReflGrand : ReflPad, ReflDerived
  {
    int e = 0;
  };

  struct ReflLeft : ReflBase
  {};

  struct ReflRight : ReflBase
  {};

  struct ReflDiamond : ReflLeft, ReflRight
  {};

  struct ReflSorted
  {
    int zeta = 0;
    int alpha = 0;
    int mid = 0;
  };

  struct ReflCounted
  {
    int value = 0;
  };

  struct ReflNeverRegistered
  {};

  enum ReflFlags : std::int32_t
  {
    TF_Alpha = 1,
    TF_Beta = 2,
    TF_Gamma = 4,
  };
} // namespace faf_reflection_tests

namespace
{
  using namespace faf_reflection_tests;
  using namespace std::string_view_literals;

  int gCountedInits = 0;

  /** A test type: its name, its size and whatever `AddMembers` registers, then `Finish`. */
  template <class T>
  class TestTypeInfo final : public gpg::RType
  {
  public:
    using AddMembersFn = void (*)(gpg::RType&);

    TestTypeInfo(const char* const name, const AddMembersFn addMembers)
      : mName(name)
      , mAddMembers(addMembers)
    {
      gpg::PreRegisterRType(typeid(T), this);
    }

    [[nodiscard]] const char* GetName() const override { return mName; }

    void Init() override
    {
      size_ = static_cast<int>(sizeof(T));
      gpg::RType::Init();
      mAddMembers(*this);
      Finish();
    }

  private:
    const char* mName;
    AddMembersFn mAddMembers;
  };

  template <class Derived, class Base>
  void AddTestBase(gpg::RType& type)
  {
    gpg::RType* const base = gpg::RTypeOf<Base>();
    type.AddBase(gpg::RField{base->GetName(), base, gpg::BaseSubobjectOffset<Derived, Base>()});
  }

  TestTypeInfo<ReflBase> gBaseType("faf_reflection_tests::ReflBase", [](gpg::RType& type) {
    type.AddField<int>("a", offsetof(ReflBase, a));
    type.AddField<float>("b", offsetof(ReflBase, b), 3, "the b field");
  });

  TestTypeInfo<ReflOther> gOtherType("faf_reflection_tests::ReflOther", [](gpg::RType& type) {
    type.AddField<int>("c", offsetof(ReflOther, c));
  });

  TestTypeInfo<ReflDerived> gDerivedType("faf_reflection_tests::ReflDerived", [](gpg::RType& type) {
    AddTestBase<ReflDerived, ReflBase>(type);
    AddTestBase<ReflDerived, ReflOther>(type);
    type.AddField<int>("d", offsetof(ReflDerived, d));
  });

  TestTypeInfo<ReflPad> gPadType("faf_reflection_tests::ReflPad", [](gpg::RType&) {});

  TestTypeInfo<ReflGrand> gGrandType("faf_reflection_tests::ReflGrand", [](gpg::RType& type) {
    AddTestBase<ReflGrand, ReflPad>(type);
    AddTestBase<ReflGrand, ReflDerived>(type);
  });

  TestTypeInfo<ReflLeft> gLeftType("faf_reflection_tests::ReflLeft", [](gpg::RType& type) {
    AddTestBase<ReflLeft, ReflBase>(type);
  });

  TestTypeInfo<ReflRight> gRightType("faf_reflection_tests::ReflRight", [](gpg::RType& type) {
    AddTestBase<ReflRight, ReflBase>(type);
  });

  TestTypeInfo<ReflDiamond> gDiamondType("faf_reflection_tests::ReflDiamond", [](gpg::RType& type) {
    AddTestBase<ReflDiamond, ReflLeft>(type);
    AddTestBase<ReflDiamond, ReflRight>(type);
  });

  TestTypeInfo<ReflSorted> gSortedType("faf_reflection_tests::ReflSorted", [](gpg::RType& type) {
    type.AddField<int>("zeta", offsetof(ReflSorted, zeta));
    type.AddField<int>("alpha", offsetof(ReflSorted, alpha));
    type.AddField<int>("mid", offsetof(ReflSorted, mid));
  });

  TestTypeInfo<ReflCounted> gCountedType("faf_reflection_tests::ReflCounted", [](gpg::RType&) { ++gCountedInits; });

  class FlagsTypeInfo final : public gpg::REnumType
  {
  public:
    FlagsTypeInfo() { gpg::PreRegisterRType(typeid(ReflFlags), this); }

    [[nodiscard]] const char* GetName() const override { return "faf_reflection_tests::ReflFlags"; }

    void Init() override
    {
      size_ = static_cast<int>(sizeof(ReflFlags));
      gpg::RType::Init();
      mPrefix = "TF_";
      AddEnum(StripPrefix("TF_Alpha"), TF_Alpha);
      AddEnum(StripPrefix("TF_Beta"), TF_Beta);
      AddEnum(StripPrefix("TF_Gamma"), TF_Gamma);
      Finish();
    }
  };

  FlagsTypeInfo gFlagsType;

  /** A type that is not preregistered, for the checks a registered one can no longer take. */
  class LooseType final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override { return "faf_reflection_tests::Loose"; }
  };

  std::vector<std::string> FieldNames(const gpg::RType* const type)
  {
    std::vector<std::string> names;
    for (const gpg::RField& field : type->fields_) {
      names.emplace_back(field.mName);
    }
    return names;
  }

  // ---------------------------------------------------------------------------------------------
  // The registry
  // ---------------------------------------------------------------------------------------------

  template <class T>
  void ExpectPrimitive(const char* const name)
  {
    gpg::RType* const type = gpg::RTypeOf<T>();
    ASSERT_NE(type, nullptr) << name;
    EXPECT_STREQ(type->GetName(), name);
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(T))) << name;
    EXPECT_TRUE(type->finished_) << name;
    EXPECT_TRUE(type->initFinished_) << name;
    EXPECT_EQ(gpg::REF_FindTypeNamed(name), type) << name;
    EXPECT_EQ(gpg::LookupRType(typeid(T)), type) << name;
    EXPECT_EQ(type->IsEnumType(), nullptr) << name;
    EXPECT_EQ(type->IsIndexed(), nullptr) << name;
    EXPECT_EQ(type->IsPointer(), nullptr) << name;
  }

  TEST(ReflectionRegistry, PrimitiveTypesHaveTheBinarysNames)
  {
    // The names the type infos return (RIntegerTypes.cpp charTypeInfo 0x008DFAD0 ..., floatTypeInfo 0x008E0410,
    // boolTypeInfo, stringTypeInfo): a saved archive names its types by these strings.
    ExpectPrimitive<bool>("bool");
    ExpectPrimitive<char>("char");
    ExpectPrimitive<signed char>("signed char");
    ExpectPrimitive<unsigned char>("unsigned char");
    ExpectPrimitive<short>("short");
    ExpectPrimitive<unsigned short>("unsigned short");
    ExpectPrimitive<int>("int");
    ExpectPrimitive<unsigned int>("unsigned int");
    ExpectPrimitive<long>("long");
    ExpectPrimitive<unsigned long>("unsigned long");
    ExpectPrimitive<float>("float");
    ExpectPrimitive<fa::string>("std::string");
  }

  TEST(ReflectionRegistry, UnknownAndNullNamesFindNothing)
  {
    EXPECT_EQ(gpg::REF_FindTypeNamed(nullptr), nullptr);
    EXPECT_EQ(gpg::REF_FindTypeNamed(""), nullptr);
    EXPECT_EQ(gpg::REF_FindTypeNamed("faf_reflection_tests::NoSuchType"), nullptr);
    EXPECT_EQ(gpg::REF_FindTypeNamed("INT"), nullptr); // names match exactly
    EXPECT_EQ(gpg::REF_FindFirstTypeNamed({nullptr, "faf_reflection_tests::NoSuchType", "int"}), gpg::RTypeOf<int>());
    EXPECT_EQ(gpg::REF_FindFirstTypeNamed({"faf_reflection_tests::NoSuchType"}), nullptr);
  }

  TEST(ReflectionRegistry, LookingUpAnUnregisteredTypeThrows)
  {
    try {
      (void)gpg::LookupRType(typeid(ReflNeverRegistered));
      FAIL() << "no throw";
    } catch (const std::runtime_error& error) {
      EXPECT_NE(std::string(error.what()).find("Attempting to lookup the RType for"), std::string::npos) << error.what();
      EXPECT_NE(std::string(error.what()).find("before it is registered."), std::string::npos) << error.what();
    }
  }

  TEST(ReflectionRegistry, ALookedUpTypeIsInitialisedAndIndexedOnce)
  {
    // Preregistration alone neither initialises the type nor makes it findable by name (unless another test
    // already registered every type).
    if (!gCountedType.finished_) {
      EXPECT_EQ(gpg::REF_FindTypeNamed("faf_reflection_tests::ReflCounted"), nullptr);
      EXPECT_EQ(gCountedInits, 0);
    }

    gpg::RType* const type = gpg::LookupRType(typeid(ReflCounted));
    ASSERT_EQ(type, &gCountedType);
    EXPECT_EQ(gCountedInits, 1);
    EXPECT_EQ(gpg::LookupRType(typeid(ReflCounted)), type);
    EXPECT_EQ(gCountedInits, 1);
    EXPECT_EQ(gpg::REF_FindTypeNamed("faf_reflection_tests::ReflCounted"), type);
    EXPECT_EQ(type->size_, static_cast<int>(sizeof(ReflCounted)));

    int seen = 0;
    const gpg::TypeVec& all = gpg::GetRTypeVec();
    for (std::size_t index = 0; index < all.size(); ++index) {
      if (all[index] == type) {
        ++seen;
        EXPECT_EQ(gpg::REF_GetTypeIndexed(static_cast<int>(index)), type);
      }
    }
    EXPECT_EQ(seen, 1);
  }

  TEST(ReflectionRegistry, RegisterAllTypesFinishesEveryPreregisteredType)
  {
    EXPECT_NO_THROW(gpg::REF_RegisterAllTypes());

    std::size_t unfinished = 0;
    for (const auto& entry : gpg::GetRTypePreregisteredMap()) {
      if (entry.second == nullptr || !entry.second->finished_ || !entry.second->initFinished_) {
        ++unfinished;
        ADD_FAILURE() << "not finished: " << entry.first->name();
      }
    }
    EXPECT_EQ(unfinished, 0u);
    EXPECT_EQ(gpg::REF_GetTypeCount(), gpg::GetRTypeMap().size());
    EXPECT_GE(gpg::GetRTypeVec().size(), gpg::REF_GetTypeCount());
  }

  TEST(ReflectionRegistry, EveryRegisteredNameFindsItsOwnType)
  {
    // An archive names a type by string and the reader finds it with REF_FindTypeNamed (ReadArchive's type
    // handle), so two types under one name would load one as the other.
    gpg::REF_RegisterAllTypes();
    std::set<std::string> clashes;
    for (const gpg::RType* const type : gpg::GetRTypeVec()) {
      ASSERT_NE(type, nullptr);
      if (gpg::REF_FindTypeNamed(type->GetName()) != type) {
        clashes.insert(type->GetName());
      }
    }
    std::string list;
    for (const std::string& name : clashes) {
      list += name + "\n";
    }
    EXPECT_TRUE(clashes.empty()) << clashes.size() << " names shared by more than one type:\n" << list;
  }

  TEST(ReflectionRegistry, RTypeIsItselfAReflectedObject)
  {
    gpg::RType* const typeClass = gpg::RType::StaticGetClass();
    ASSERT_NE(typeClass, nullptr);
    EXPECT_EQ(typeClass, gpg::RTypeOf<gpg::RType>());
    EXPECT_STREQ(typeClass->GetName(), "RType");

    gpg::RType* const intType = gpg::RTypeOf<int>();
    EXPECT_EQ(intType->GetClass(), typeClass);
    EXPECT_TRUE(intType->IsA(typeClass));
    EXPECT_FALSE(intType->IsA(gpg::RTypeOf<float>()));

    const gpg::RRef self = intType->GetDerivedObjectRef();
    EXPECT_EQ(self.mObj, intType);
    EXPECT_EQ(self.mType, typeClass);
  }

  TEST(ReflectionRegistry, NewRefWithoutAConstructorThrowsBadRefCast)
  {
    gpg::RType* const floatType = gpg::RTypeOf<float>();
    ASSERT_EQ(floatType->newRefFunc_, nullptr);
    try {
      (void)floatType->NewRef();
      FAIL() << "no throw";
    } catch (const gpg::BadRefCast& error) {
      EXPECT_STREQ(error.what(), "NewRef() on a type without a registered constructor");
    }
  }

  TEST(ReflectionRegistry, BaseLexicalIsTheNameAndAddress)
  {
    // RType::GetLexical 0x008DB100 formats "%s at 0x%p"; SetLexical 0x008D86E0 refuses.
    ReflSorted object;
    const gpg::RRef ref{&object, gpg::RTypeOf<ReflSorted>()};
    const fa::string text = ref.GetLexical();
    constexpr std::string_view kPrefix = "faf_reflection_tests::ReflSorted at 0x";
    EXPECT_EQ(text.view().substr(0, kPrefix.size()), kPrefix) << text.c_str();
    EXPECT_GT(text.view().size(), kPrefix.size()) << text.c_str();
    EXPECT_FALSE(ref.SetLexical("anything"));
  }

  TEST(ReflectionRegistry, Rect2TypesNameTheirEdgesXAndY)
  {
    // Rect2iTypeInfo::Init 0x00906270, Rect2fTypeInfo::Init 0x009062D0: fields x0/y0/x1/y1 over x0/z0/x1/z1.
    for (gpg::RType* const type : {gpg::RTypeOf<gpg::Rect2i>(), gpg::RTypeOf<gpg::Rect2f>()}) {
      ASSERT_NE(type, nullptr);
      EXPECT_EQ(FieldNames(type), (std::vector<std::string>{"x0", "x1", "y0", "y1"})) << type->GetName();
      EXPECT_EQ(type->size_, 16);
      const gpg::RField* const y0 = type->GetFieldNamed("y0");
      const gpg::RField* const y1 = type->GetFieldNamed("y1");
      ASSERT_NE(y0, nullptr);
      ASSERT_NE(y1, nullptr);
      EXPECT_EQ(y0->mOffset, static_cast<int>(offsetof(gpg::Rect2i, z0)));
      EXPECT_EQ(y1->mOffset, static_cast<int>(offsetof(gpg::Rect2i, z1)));
      EXPECT_EQ(type->GetFieldNamed("z0"), nullptr);
    }
    EXPECT_STREQ(gpg::RTypeOf<gpg::Rect2i>()->GetName(), "Rect2i");
    EXPECT_STREQ(gpg::RTypeOf<gpg::Rect2f>()->GetName(), "Rect2f");
    EXPECT_EQ(gpg::RTypeOf<gpg::Rect2i>()->GetFieldNamed("x0")->mType, gpg::RTypeOf<int>());
    EXPECT_EQ(gpg::RTypeOf<gpg::Rect2f>()->GetFieldNamed("x0")->mType, gpg::RTypeOf<float>());
  }

  // ---------------------------------------------------------------------------------------------
  // Fields, bases and casts
  // ---------------------------------------------------------------------------------------------

  TEST(ReflectionTypeLayout, FieldsAreSortedByNameAndFoundByName)
  {
    gpg::RType* const type = gpg::RTypeOf<ReflSorted>();
    EXPECT_EQ(FieldNames(type), (std::vector<std::string>{"alpha", "mid", "zeta"}));
    for (const char* const name : {"alpha", "mid", "zeta"}) {
      const gpg::RField* const field = type->GetFieldNamed(name);
      ASSERT_NE(field, nullptr) << name;
      EXPECT_STREQ(field->mName, name);
      EXPECT_EQ(field->mType, gpg::RTypeOf<int>());
    }
    EXPECT_EQ(type->GetFieldNamed("alpha")->mOffset, static_cast<int>(offsetof(ReflSorted, alpha)));
    EXPECT_EQ(type->GetFieldNamed("zeta")->mOffset, static_cast<int>(offsetof(ReflSorted, zeta)));
    EXPECT_EQ(type->GetFieldNamed("aaa"), nullptr);
    EXPECT_EQ(type->GetFieldNamed("mi"), nullptr);
    EXPECT_EQ(type->GetFieldNamed("zz"), nullptr);
    EXPECT_EQ(gpg::RTypeOf<ReflPad>()->GetFieldNamed("pad"), nullptr); // no fields at all
  }

  TEST(ReflectionTypeLayout, RRefWalksFieldsAtTheirAddresses)
  {
    ReflSorted object{1, 2, 3};
    const gpg::RRef ref{&object, gpg::RTypeOf<ReflSorted>()};
    ASSERT_EQ(ref.GetNumFields(), 3);
    EXPECT_STREQ(ref.GetFieldName(0), "alpha");
    EXPECT_STREQ(ref.GetFieldName(2), "zeta");
    EXPECT_EQ(ref.GetField(0).mObj, &object.alpha);
    EXPECT_EQ(ref.GetField(1).mObj, &object.mid);
    EXPECT_EQ(ref.GetField(2).mObj, &object.zeta);
    EXPECT_EQ(ref.GetField(1).GetLexical().view(), "3"sv);
    EXPECT_TRUE(ref.GetField(1).SetLexical("-9"));
    EXPECT_EQ(object.mid, -9);
    EXPECT_EQ(ref.GetNumBases(), 0);
    EXPECT_EQ(ref.GetRType(), gpg::RTypeOf<ReflSorted>());
    EXPECT_EQ(ref.GetCount(), 0u);
  }

  TEST(ReflectionTypeLayout, BasesFlattenTheirFieldsAtTheBaseOffset)
  {
    gpg::RType* const type = gpg::RTypeOf<ReflDerived>();
    ASSERT_EQ(type->bases_.size(), 2u);
    EXPECT_EQ(type->bases_[0].mType, gpg::RTypeOf<ReflBase>());
    EXPECT_STREQ(type->bases_[0].mName, "faf_reflection_tests::ReflBase");
    EXPECT_EQ(type->bases_[1].mType, gpg::RTypeOf<ReflOther>());

    EXPECT_EQ(FieldNames(type), (std::vector<std::string>{"a", "b", "c", "d"}));
    ReflDerived object;
    const auto offsetOf = [&](const void* const member) {
      return static_cast<int>(reinterpret_cast<const char*>(member) - reinterpret_cast<const char*>(&object));
    };
    EXPECT_EQ(type->GetFieldNamed("a")->mOffset, offsetOf(&object.a));
    EXPECT_EQ(type->GetFieldNamed("b")->mOffset, offsetOf(&object.b));
    EXPECT_EQ(type->GetFieldNamed("c")->mOffset, offsetOf(&object.c));
    EXPECT_EQ(type->GetFieldNamed("d")->mOffset, offsetOf(&object.d));

    // A base field keeps its flags and description.
    EXPECT_EQ(type->GetFieldNamed("b")->mFlags, 3);
    EXPECT_STREQ(type->GetFieldNamed("b")->mDesc, "the b field");
    EXPECT_EQ(type->GetFieldNamed("a")->mFlags, 0);
    EXPECT_EQ(type->GetFieldNamed("a")->mDesc, nullptr);

    const gpg::RRef ref{&object, type};
    ASSERT_EQ(ref.GetNumBases(), 2);
    EXPECT_EQ(ref.GetBase(0).mObj, static_cast<ReflBase*>(&object));
    EXPECT_EQ(ref.GetBase(1).mObj, static_cast<ReflOther*>(&object));
    EXPECT_EQ(ref.GetBase(1).mType, gpg::RTypeOf<ReflOther>());
  }

  TEST(ReflectionTypeLayout, IsDerivedFromAddsTheOffsetsAlongThePath)
  {
    gpg::RType* const grand = gpg::RTypeOf<ReflGrand>();
    gpg::RType* const derived = gpg::RTypeOf<ReflDerived>();
    gpg::RType* const other = gpg::RTypeOf<ReflOther>();
    gpg::RType* const base = gpg::RTypeOf<ReflBase>();

    std::int32_t offset = -1;
    EXPECT_TRUE(grand->IsDerivedFrom(grand, &offset));
    EXPECT_EQ(offset, 0);
    offset = -1;
    EXPECT_TRUE(grand->IsDerivedFrom(derived, &offset));
    EXPECT_EQ(offset, (gpg::BaseSubobjectOffset<ReflGrand, ReflDerived>()));
    offset = -1;
    EXPECT_TRUE(grand->IsDerivedFrom(other, &offset));
    EXPECT_EQ(offset, (gpg::BaseSubobjectOffset<ReflGrand, ReflOther>()));
    EXPECT_NE(offset, 0); // ReflPad first, then ReflOther after ReflBase: a real offset
    offset = -1;
    EXPECT_TRUE(grand->IsDerivedFrom(base, &offset));
    EXPECT_EQ(offset, (gpg::BaseSubobjectOffset<ReflGrand, ReflBase>()));

    EXPECT_TRUE(derived->IsDerivedFrom(other, nullptr));
    EXPECT_FALSE(base->IsDerivedFrom(derived, nullptr));
    EXPECT_FALSE(other->IsDerivedFrom(base, nullptr));
    EXPECT_FALSE(grand->IsDerivedFrom(gpg::RTypeOf<int>(), &offset));
  }

  TEST(ReflectionTypeLayout, AnAmbiguousBaseThrowsOnlyWhenTheOffsetIsAsked)
  {
    // 0x008DC089: a second matching base path throws; 0x008DC090: without an offset the first match returns.
    gpg::RType* const diamond = gpg::RTypeOf<ReflDiamond>();
    gpg::RType* const base = gpg::RTypeOf<ReflBase>();
    std::int32_t offset = 0;
    try {
      (void)diamond->IsDerivedFrom(base, &offset);
      FAIL() << "no throw";
    } catch (const std::runtime_error& error) {
      EXPECT_STREQ(error.what(), "Ambiguous base class");
    }
    EXPECT_TRUE(diamond->IsDerivedFrom(base, nullptr));
    offset = -1;
    EXPECT_TRUE(diamond->IsDerivedFrom(gpg::RTypeOf<ReflRight>(), &offset));
    EXPECT_EQ(offset, (gpg::BaseSubobjectOffset<ReflDiamond, ReflRight>()));
  }

  TEST(ReflectionTypeLayout, UpcastFindsTheBaseSubobject)
  {
    ReflGrand object;
    const gpg::RRef ref{&object, gpg::RTypeOf<ReflGrand>()};

    EXPECT_EQ(gpg::REF_UpcastPtr(ref, gpg::RTypeOf<ReflOther>()).mObj, static_cast<ReflOther*>(&object));
    EXPECT_EQ(gpg::REF_UpcastPtr(ref, gpg::RTypeOf<ReflOther>()).mType, gpg::RTypeOf<ReflOther>());
    EXPECT_EQ(gpg::REF_UpcastPtr(ref, gpg::RTypeOf<ReflBase>()).mObj, static_cast<ReflBase*>(&object));
    EXPECT_EQ(ref.Upcast<ReflDerived>(), static_cast<ReflDerived*>(&object));
    EXPECT_EQ(ref.Upcast<ReflPad>(), static_cast<ReflPad*>(&object));
    EXPECT_EQ(ref.Upcast<ReflGrand>(), &object);
    EXPECT_EQ(ref.Upcast<ReflSorted>(), nullptr);

    // Not a base: an empty reference. A null object: null of the target type.
    const gpg::RRef none = gpg::REF_UpcastPtr(ref, gpg::RTypeOf<ReflSorted>());
    EXPECT_EQ(none.mObj, nullptr);
    EXPECT_EQ(none.mType, nullptr);
    const gpg::RRef null = gpg::REF_UpcastPtr(gpg::RRef{nullptr, gpg::RTypeOf<ReflGrand>()}, gpg::RTypeOf<ReflOther>());
    EXPECT_EQ(null.mObj, nullptr);
    EXPECT_EQ(null.mType, gpg::RTypeOf<ReflOther>());
    const gpg::RRef untyped = gpg::REF_UpcastPtr(gpg::RRef{&object, nullptr}, gpg::RTypeOf<ReflOther>());
    EXPECT_EQ(untyped.mObj, nullptr);
    EXPECT_EQ(untyped.mType, nullptr);
  }

  TEST(ReflectionTypeLayout, EngineUnitAndPropSitOnEntityAtTheirLayoutOffsets)
  {
    // The registrations of real engine classes (UnitTypeInfo::AddBase_Entity 0x006B0F50, PropTypeInfo
    // 0x006FAD70) against the compiler's layout of the same classes.
    gpg::RType* const unit = gpg::RTypeOf<moho::Unit>();
    gpg::RType* const prop = gpg::RTypeOf<moho::Prop>();
    gpg::RType* const entity = gpg::RTypeOf<moho::Entity>();
    ASSERT_NE(unit, nullptr);
    ASSERT_NE(prop, nullptr);
    ASSERT_NE(entity, nullptr);
    EXPECT_STREQ(unit->GetName(), "Unit");
    EXPECT_STREQ(prop->GetName(), "Prop");
    EXPECT_STREQ(entity->GetName(), "Entity");

    std::int32_t offset = -1;
    EXPECT_TRUE(unit->IsDerivedFrom(entity, &offset));
    EXPECT_EQ(offset, (gpg::BaseSubobjectOffset<moho::Unit, moho::Entity>()));
    offset = -1;
    EXPECT_TRUE(prop->IsDerivedFrom(entity, &offset));
    EXPECT_EQ(offset, (gpg::BaseSubobjectOffset<moho::Prop, moho::Entity>()));
    EXPECT_FALSE(entity->IsDerivedFrom(unit, nullptr));
    EXPECT_FALSE(prop->IsDerivedFrom(unit, nullptr));
    EXPECT_GE(unit->size_, static_cast<int>(sizeof(moho::Entity)));
  }

  TEST(ReflectionTypeLayout, VersionIsSetOnceAndAConflictAsserts)
  {
    LooseType type;
    EXPECT_EQ(type.version_, 0);
    type.Version(2);
    EXPECT_EQ(type.version_, 2);
    type.Version(2);
    EXPECT_EQ(type.version_, 2);
    EXPECT_NONFATAL_FAILURE(type.Version(3), "version_ == 0 || version_ == version");
  }

  TEST(ReflectionTypeLayout, AddingToAFinishedTypeAsserts)
  {
    LooseType type;
    type.initFinished_ = true;
    EXPECT_NONFATAL_FAILURE((void)type.AddField<int>("late", 0), "!initFinished_");
    EXPECT_NONFATAL_FAILURE(type.AddBase(gpg::RField{"base", gpg::RTypeOf<ReflBase>(), 0}), "!initFinished_");
    EXPECT_NONFATAL_FAILURE(type.Finish(), "!initFinished_");
  }

  TEST(ReflectionTypeLayout, AxisAlignedBoxFieldsAreSixFloats)
  {
    // RType::AddBlueprintAxisAlignedBox3f 0x004EA0E0: min xyz at 0/4/8, max xyz at 0x0C/0x10/0x14.
    LooseType type;
    type.AddBlueprintAxisAlignedBox3f();
    ASSERT_EQ(type.fields_.size(), 6u);
    const char* const names[] = {"min0", "min1", "min2", "max0", "max1", "max2"};
    for (std::size_t index = 0; index < 6u; ++index) {
      EXPECT_STREQ(type.fields_[index].mName, names[index]);
      EXPECT_EQ(type.fields_[index].mOffset, static_cast<int>(index * 4u));
      EXPECT_EQ(type.fields_[index].mType, gpg::RTypeOf<float>());
    }
  }

  TEST(ReflectionTypeLayout, AddBaseIfPresentSkipsAMissingBase)
  {
    LooseType type;
    gpg::AddBaseIfPresent(&type, nullptr, 8);
    EXPECT_TRUE(type.bases_.empty());
    gpg::AddBaseIfPresent(&type, gpg::RTypeOf<ReflBase>(), 8);
    ASSERT_EQ(type.bases_.size(), 1u);
    EXPECT_EQ(type.bases_[0].mOffset, 8);
    ASSERT_EQ(type.fields_.size(), 2u); // a and b, moved by the base offset
    EXPECT_EQ(type.fields_[0].mOffset, 8 + static_cast<int>(offsetof(ReflBase, a)));
    EXPECT_EQ(type.fields_[1].mOffset, 8 + static_cast<int>(offsetof(ReflBase, b)));
  }

  TEST(ReflectionTypeLayout, FieldRecordsStartEmpty)
  {
    const gpg::RField empty;
    EXPECT_EQ(empty.mName, nullptr);
    EXPECT_EQ(empty.mType, nullptr);
    EXPECT_EQ(empty.mOffset, 0);
    EXPECT_EQ(empty.mFlags, 0);
    EXPECT_EQ(empty.mDesc, nullptr);
    const gpg::RField full{"n", gpg::RTypeOf<int>(), 12, 3, "d"};
    EXPECT_EQ(full.mOffset, 12);
    EXPECT_EQ(full.mFlags, 3);
    EXPECT_STREQ(full.mDesc, "d");

    const LooseType type;
    EXPECT_FALSE(type.finished_);
    EXPECT_FALSE(type.initFinished_);
    EXPECT_EQ(type.size_, 0);
    EXPECT_EQ(type.serSaveFunc_, nullptr);
    EXPECT_EQ(type.serLoadFunc_, nullptr);
    EXPECT_EQ(type.newRefFunc_, nullptr);
    EXPECT_TRUE(type.fields_.empty());
  }

  // ---------------------------------------------------------------------------------------------
  // Enum types
  // ---------------------------------------------------------------------------------------------

  TEST(ReflectionEnum, OptionsKeepTheirOrderWithThePrefixStripped)
  {
    const gpg::REnumType* const type = gpg::RTypeOf<ReflFlags>()->IsEnumType();
    ASSERT_NE(type, nullptr);
    EXPECT_EQ(type, &gFlagsType);
    const auto& options = type->GetEnumOptions();
    ASSERT_EQ(options.size(), 3u);
    EXPECT_STREQ(options[0].mName, "Alpha");
    EXPECT_EQ(options[0].mValue, 1);
    EXPECT_STREQ(options[2].mName, "Gamma");
    EXPECT_EQ(options[2].mValue, 4);

    EXPECT_STREQ(type->StripPrefix("TF_Beta"), "Beta");
    EXPECT_STREQ(type->StripPrefix("Beta"), "Beta");
    EXPECT_STREQ(type->StripPrefix("tf_Beta"), "tf_Beta"); // the prefix matches with case

    int value = 0;
    EXPECT_TRUE(type->GetEnumValue("gAmMa", &value));
    EXPECT_EQ(value, 4);
    EXPECT_FALSE(type->GetEnumValue("Delta", &value));
    EXPECT_EQ(value, 4);
  }

  TEST(ReflectionEnum, LexicalFormIsTheOptionNameOrTheNumber)
  {
    ReflFlags flags = TF_Beta;
    const gpg::RRef ref{&flags, gpg::RTypeOf<ReflFlags>()};
    EXPECT_EQ(ref.GetLexical().view(), "Beta"sv);
    flags = static_cast<ReflFlags>(7);
    EXPECT_EQ(ref.GetLexical().view(), "7"sv);
    flags = static_cast<ReflFlags>(-3);
    EXPECT_EQ(ref.GetLexical().view(), "-3"sv);
  }

  TEST(ReflectionEnum, SetLexicalTakesNamesNumbersAndOrs)
  {
    ReflFlags flags = TF_Alpha;
    const gpg::RRef ref{&flags, gpg::RTypeOf<ReflFlags>()};

    EXPECT_TRUE(ref.SetLexical("beta"));
    EXPECT_EQ(flags, TF_Beta);
    EXPECT_TRUE(ref.SetLexical("TF_Gamma"));
    EXPECT_EQ(flags, TF_Gamma);
    EXPECT_TRUE(ref.SetLexical("Alpha|Gamma"));
    EXPECT_EQ(static_cast<int>(flags), 5);
    EXPECT_TRUE(ref.SetLexical("TF_Alpha|TF_Beta|Gamma"));
    EXPECT_EQ(static_cast<int>(flags), 7);
    EXPECT_TRUE(ref.SetLexical("16"));
    EXPECT_EQ(static_cast<int>(flags), 16);
    EXPECT_TRUE(ref.SetLexical("Beta|8"));
    EXPECT_EQ(static_cast<int>(flags), 10);

    flags = TF_Alpha;
    EXPECT_FALSE(ref.SetLexical("Delta"));
    EXPECT_FALSE(ref.SetLexical("Alpha|Delta"));
    EXPECT_FALSE(ref.SetLexical("Alph")); // a name must match whole
    EXPECT_EQ(flags, TF_Alpha);           // a refused text leaves the value
    EXPECT_FALSE(ref.SetLexical(nullptr));
    EXPECT_FALSE(gpg::RTypeOf<ReflFlags>()->SetLexical(gpg::RRef{nullptr, gpg::RTypeOf<ReflFlags>()}, "Beta"));
  }

#if defined(_WIN32)
  TEST(ReflectionEnum, CurrentUiStateRefNamesTheEngineEnum)
  {
    // RRef::CurrentUIState 0x0084AB10 over moho::sUIState; EUIStateTypeInfo::AddEnums 0x0083CC60 ("UIS_" prefix).
    const moho::EUIState saved = moho::sUIState;
    gpg::RRef ref{};
    ASSERT_EQ(gpg::RRef::CurrentUIState(&ref), &ref);
    EXPECT_EQ(ref.mObj, &moho::sUIState);
    EXPECT_STREQ(ref.GetName(), "EUIState");
    ASSERT_NE(ref.mType->IsEnumType(), nullptr);

    moho::sUIState = moho::UIS_lobby;
    EXPECT_EQ(ref.GetLexical().view(), "lobby"sv);
    EXPECT_TRUE(ref.SetLexical("UIS_game"));
    EXPECT_EQ(moho::sUIState, moho::UIS_game);
    EXPECT_TRUE(ref.SetLexical("frontend"));
    EXPECT_EQ(moho::sUIState, moho::UIS_frontend);
    moho::sUIState = saved;
  }
#endif
} // namespace
