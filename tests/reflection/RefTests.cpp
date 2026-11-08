// RRef and the primitive reflected types: the lexical (text) form of bool, the integers, float and string, the
// value-lane callbacks the integer types install, the checked upcasts that throw BadRefCast, and the
// RRef_*/PackRRef_*/Assign*Ref adapters of ReflectionRefAdapters.cpp, which must hand back the reflected type the
// binary registers for their argument.
//
// Expected text comes from the binary: every integer type formats with "%d" (0x00E0425C, pushed by 0x008DDB50,
// 0x008DDF70, 0x008DEB40 and the other six GetLexical bodies), float with "%f" (0x00E293F8, 0x008DF080), bool as
// "true"/"false" (0x008DEF90) and reads "0"/"false"/"no"/"1"/"true"/"yes" (0x008DEEF0). The integer parser is
// 0x008DDA60: optional '-', "0x" for hex, a leading '0' for octal, 8-bit arithmetic for a char.

#include <climits>
#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <typeinfo>
#include <vector>
#include <gtest/gtest.h>

#include "gpg/core/containers/ArchiveTokenTypeInfo.h"
#include "gpg/core/reflection/BadRefCast.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "legacy/containers/String.h"

namespace
{
  using namespace std::string_view_literals;

  // ---------------------------------------------------------------------------------------------
  // Lexical forms
  // ---------------------------------------------------------------------------------------------

  template <class T>
  std::string LexicalOf(T value)
  {
    const gpg::RRef ref{&value, gpg::RTypeOf<T>()};
    return std::string(ref.GetLexical().view());
  }

  /** Parses `text` into a `T` that starts as `start`; returns whether it was taken and the value after. */
  template <class T>
  std::pair<bool, T> Parse(const char* const text, const T start)
  {
    T value = start;
    const gpg::RRef ref{&value, gpg::RTypeOf<T>()};
    const bool taken = ref.SetLexical(text);
    return {taken, value};
  }

  TEST(ReflectionPrimitives, BoolTextIsTrueOrFalse)
  {
    EXPECT_EQ(LexicalOf(true), "true");
    EXPECT_EQ(LexicalOf(false), "false");

    for (const char* const yes : {"1", "true", "TRUE", "yes", "Yes"}) {
      EXPECT_EQ(Parse<bool>(yes, false), (std::pair<bool, bool>{true, true})) << yes;
    }
    for (const char* const no : {"0", "false", "False", "no", "NO"}) {
      EXPECT_EQ(Parse<bool>(no, true), (std::pair<bool, bool>{true, false})) << no;
    }
    for (const char* const bad : {"2", "", "y", "truth", " true"}) {
      EXPECT_EQ(Parse<bool>(bad, true), (std::pair<bool, bool>{false, true})) << bad;
      EXPECT_EQ(Parse<bool>(bad, false), (std::pair<bool, bool>{false, false})) << bad;
    }
  }

  TEST(ReflectionPrimitives, IntegerTextIsDecimal)
  {
    EXPECT_EQ(LexicalOf<char>(-5), "-5");
    EXPECT_EQ(LexicalOf<signed char>(-128), "-128");
    EXPECT_EQ(LexicalOf<unsigned char>(200), "200");
    EXPECT_EQ(LexicalOf<short>(-300), "-300");
    EXPECT_EQ(LexicalOf<unsigned short>(65535), "65535");
    EXPECT_EQ(LexicalOf<int>(INT_MIN), "-2147483648");
    EXPECT_EQ(LexicalOf<int>(0), "0");
    EXPECT_EQ(LexicalOf<unsigned int>(123456u), "123456");
    EXPECT_EQ(LexicalOf<long>(-7L), "-7");
    EXPECT_EQ(LexicalOf<unsigned long>(42UL), "42");
  }

  TEST(ReflectionPrimitives, DISABLED_UnsignedTextUsesTheBinarysSignedFormat)
  {
    // Suspected deviation: the binary formats every integer type with "%d" (0x00E0425C; the unsigned int body
    // 0x008DEB40 pushes it too), so 0xFFFFFFFF reads "-1" there. RIntType<T>::GetLexical (RIntegerTypes.cpp)
    // formats with "%lld" after widening, which prints "4294967295". Minimal input: an unsigned int holding
    // 0xFFFFFFFF, or an unsigned long holding 0x80000000.
    EXPECT_EQ(LexicalOf<unsigned int>(0xFFFFFFFFu), "-1");
    EXPECT_EQ(LexicalOf<unsigned long>(0x80000000UL), "-2147483648");
  }

  TEST(ReflectionPrimitives, IntegerParserTakesDecimalHexAndOctal)
  {
    EXPECT_EQ(Parse<int>("123", 0), (std::pair<bool, int>{true, 123}));
    EXPECT_EQ(Parse<int>("-45", 0), (std::pair<bool, int>{true, -45}));
    EXPECT_EQ(Parse<int>("0x1f", 0), (std::pair<bool, int>{true, 31}));
    EXPECT_EQ(Parse<int>("0xff", 0), (std::pair<bool, int>{true, 255}));
    EXPECT_EQ(Parse<int>("-0x10", 0), (std::pair<bool, int>{true, -16}));
    EXPECT_EQ(Parse<int>("017", 0), (std::pair<bool, int>{true, 15}));
    EXPECT_EQ(Parse<int>("0", 9), (std::pair<bool, int>{true, 0}));
    EXPECT_EQ(Parse<int>("2147483647", 0), (std::pair<bool, int>{true, INT_MAX}));
    EXPECT_EQ(Parse<unsigned int>("4294967295", 0u), (std::pair<bool, unsigned int>{true, 0xFFFFFFFFu}));
    EXPECT_EQ(Parse<short>("-300", 0), (std::pair<bool, short>{true, static_cast<short>(-300)}));
    EXPECT_EQ(Parse<unsigned short>("0xbeef", 0), (std::pair<bool, unsigned short>{true, 0xBEEF}));
    EXPECT_EQ(Parse<long>("-99", 0L), (std::pair<bool, long>{true, -99L}));
    EXPECT_EQ(Parse<unsigned long>("077", 0UL), (std::pair<bool, unsigned long>{true, 63UL}));
    EXPECT_EQ(Parse<signed char>("-7", 0), (std::pair<bool, signed char>{true, static_cast<signed char>(-7)}));
    EXPECT_EQ(Parse<char>("65", 0), (std::pair<bool, char>{true, 'A'}));
  }

  TEST(ReflectionPrimitives, IntegerParserWrapsAtTheTypesWidth)
  {
    // 0x008DDACF: `imul dl` and `add al, cl`, so a char accumulates modulo 256.
    EXPECT_EQ(Parse<unsigned char>("300", 0), (std::pair<bool, unsigned char>{true, 44}));
    EXPECT_EQ(Parse<signed char>("200", 0), (std::pair<bool, signed char>{true, static_cast<signed char>(-56)}));
    EXPECT_EQ(Parse<unsigned short>("65537", 0), (std::pair<bool, unsigned short>{true, 1}));
  }

  TEST(ReflectionPrimitives, IntegerParserRefusesOtherTextAndKeepsTheValue)
  {
    for (const char* const bad : {"", "-", "08", "0x", "0X10", "12z", "1.5", " 1", "+1", "0xg"}) {
      EXPECT_EQ(Parse<int>(bad, 77), (std::pair<bool, int>{false, 77})) << '"' << bad << '"';
      EXPECT_EQ(Parse<unsigned char>(bad, 7), (std::pair<bool, unsigned char>{false, 7})) << '"' << bad << '"';
    }
  }

  TEST(ReflectionPrimitives, IntegerParserTakesAnUpperCaseAAsTheBinaryDoes)
  {
    // 0x008DDABC: after 'a'..'z' only 'A' passes, and its digit is 'A' - 0x57 = -22.
    EXPECT_EQ(Parse<int>("1A", 0), (std::pair<bool, int>{true, 10 - 22}));
    EXPECT_EQ(Parse<int>("1B", 0), (std::pair<bool, int>{false, 0}));
  }

  TEST(ReflectionPrimitives, FloatTextIsPrintfF)
  {
    EXPECT_EQ(LexicalOf(1.5f), "1.500000");
    EXPECT_EQ(LexicalOf(-0.25f), "-0.250000");
    EXPECT_EQ(LexicalOf(0.0f), "0.000000");
    EXPECT_EQ(LexicalOf(1234567.0f), "1234567.000000");

    // SetLexical 0x008DF060: atof, always taken.
    EXPECT_EQ(Parse<float>("2.25", 0.0f), (std::pair<bool, float>{true, 2.25f}));
    EXPECT_EQ(Parse<float>("-1e3", 0.0f), (std::pair<bool, float>{true, -1000.0f}));
    EXPECT_EQ(Parse<float>("junk", 5.0f), (std::pair<bool, float>{true, 0.0f}));
    EXPECT_EQ(Parse<float>("3.5abc", 0.0f), (std::pair<bool, float>{true, 3.5f}));
  }

  TEST(ReflectionPrimitives, StringTextIsTheStringItself)
  {
    fa::string text("hello world");
    const gpg::RRef ref{&text, gpg::RTypeOf<fa::string>()};
    EXPECT_EQ(ref.GetLexical().view(), "hello world"sv);
    EXPECT_TRUE(ref.SetLexical("replaced, longer than the small-string buffer of sixteen"));
    EXPECT_EQ(text.view(), "replaced, longer than the small-string buffer of sixteen"sv);
    EXPECT_TRUE(ref.SetLexical(""));
    EXPECT_EQ(text.view(), ""sv);
  }

  // ---------------------------------------------------------------------------------------------
  // Integer value lanes
  // ---------------------------------------------------------------------------------------------

  template <class T>
  void ExpectIntegerLanes(const T sample)
  {
    gpg::RType* const type = gpg::RTypeOf<T>();
    ASSERT_NE(type->newRefFunc_, nullptr) << type->GetName();
    ASSERT_NE(type->cpyRefFunc_, nullptr) << type->GetName();
    ASSERT_NE(type->ctorRefFunc_, nullptr) << type->GetName();
    ASSERT_NE(type->movRefFunc_, nullptr) << type->GetName();
    ASSERT_NE(type->deleteFunc_, nullptr) << type->GetName();
    ASSERT_NE(type->dtrFunc_, nullptr) << type->GetName();

    gpg::RRef fresh = type->NewRef();
    ASSERT_NE(fresh.mObj, nullptr);
    EXPECT_EQ(fresh.mType, type);
    *static_cast<T*>(fresh.mObj) = sample;

    gpg::RRef copy = type->cpyRefFunc_(&fresh);
    ASSERT_NE(copy.mObj, nullptr);
    EXPECT_NE(copy.mObj, fresh.mObj);
    EXPECT_EQ(copy.mType, type);
    EXPECT_EQ(*static_cast<T*>(copy.mObj), sample);

    T slot{};
    const gpg::RRef moved = type->movRefFunc_(&slot, &fresh);
    EXPECT_EQ(moved.mObj, &slot);
    EXPECT_EQ(moved.mType, type);
    EXPECT_EQ(slot, sample);

    const gpg::RRef constructed = type->ctorRefFunc_(&slot);
    EXPECT_EQ(constructed.mObj, &slot);
    EXPECT_EQ(constructed.mType, type);
    type->dtrFunc_(&slot); // trivially destructible: nothing to undo
    EXPECT_EQ(slot, sample);

    // A source of another type is refused before anything is written.
    float other = 1.0f;
    gpg::RRef wrong{&other, gpg::RTypeOf<float>()};
    EXPECT_THROW((void)type->cpyRefFunc_(&wrong), gpg::BadRefCast);
    EXPECT_THROW((void)type->movRefFunc_(&slot, &wrong), gpg::BadRefCast);
    EXPECT_EQ(slot, sample);

    copy.Delete();
    fresh.Delete();
  }

  TEST(ReflectionPrimitives, IntegerTypesCreateCopyMoveAndDeleteValues)
  {
    ExpectIntegerLanes<char>('x');
    ExpectIntegerLanes<signed char>(-3);
    ExpectIntegerLanes<unsigned char>(250);
    ExpectIntegerLanes<short>(-1234);
    ExpectIntegerLanes<unsigned short>(54321);
    ExpectIntegerLanes<int>(-123456);
    ExpectIntegerLanes<unsigned int>(0xDEADBEEFu);
    ExpectIntegerLanes<long>(-77L);
    ExpectIntegerLanes<unsigned long>(77UL);
  }

  // ---------------------------------------------------------------------------------------------
  // RRef
  // ---------------------------------------------------------------------------------------------

  TEST(ReflectionRef, AnEmptyRefIsNamedNull)
  {
    const gpg::RRef empty;
    EXPECT_EQ(empty.mObj, nullptr);
    EXPECT_EQ(empty.mType, nullptr);
    EXPECT_EQ(empty.GetObject(), nullptr);
    EXPECT_STREQ(empty.GetName(), "null");
    EXPECT_STREQ(empty.GetTypeName(), "null");

    int value = 3;
    const gpg::RRef ref{&value, gpg::RTypeOf<int>()};
    EXPECT_EQ(ref.GetObject(), &value);
    EXPECT_STREQ(ref.GetName(), "int");
    EXPECT_EQ(ref.GetRType(), gpg::RTypeOf<int>());
    EXPECT_EQ(ref.IsIndexed(), nullptr);
    EXPECT_EQ(ref.IsPointer(), nullptr);
    EXPECT_EQ(ref.GetCount(), 0u);
  }

  TEST(ReflectionRef, TypedConstructorsPickThePrimitiveType)
  {
    char c = 'a';
    short s = 1;
    long l = 2;
    signed char sc = 3;
    unsigned short us = 4;
    EXPECT_EQ(gpg::RRef(&c).mType, gpg::RTypeOf<char>());
    EXPECT_EQ(gpg::RRef(&c).mObj, &c);
    EXPECT_EQ(gpg::RRef(&s).mType, gpg::RTypeOf<short>());
    EXPECT_EQ(gpg::RRef(&l).mType, gpg::RTypeOf<long>());
    EXPECT_EQ(gpg::RRef(&sc).mType, gpg::RTypeOf<signed char>());
    EXPECT_EQ(gpg::RRef(&us).mType, gpg::RTypeOf<unsigned short>());
    EXPECT_EQ(gpg::RRef(&us).mObj, &us);

    gpg::ArchiveToken token = gpg::ArchiveToken::NewObjectToken;
    const gpg::RRef tokenRef(&token);
    EXPECT_EQ(tokenRef.mObj, &token);
    EXPECT_STREQ(tokenRef.GetName(), "ArchiveToken");
  }

  TEST(ReflectionRef, CheckedUpcastsReturnTheirOwnType)
  {
    char c = 0;
    short s = 0;
    int i = 0;
    signed char sc = 0;
    unsigned char uc = 0;
    unsigned short us = 0;
    unsigned int ui = 0;
    long l = 0;
    unsigned long ul = 0;
    EXPECT_EQ(gpg::MakeRRef(&c).TryUpcastChar(), &c);
    EXPECT_EQ(gpg::MakeRRef(&s).TryUpcastShort(), &s);
    EXPECT_EQ(gpg::MakeRRef(&i).TryUpcastInt(), &i);
    EXPECT_EQ(gpg::MakeRRef(&sc).TryUpcastSignedChar(), &sc);
    EXPECT_EQ(gpg::MakeRRef(&uc).TryUpcastUnsignedChar(), &uc);
    EXPECT_EQ(gpg::MakeRRef(&us).TryUpcastUnsignedShort(), &us);
    EXPECT_EQ(gpg::MakeRRef(&ui).TryUpcastUnsignedInt(), &ui);
    EXPECT_EQ(gpg::MakeRRef(&l).TryUpcastLong(), &l);
    EXPECT_EQ(gpg::MakeRRef(&ul).TryUpcastUnsignedLong(), &ul);
  }

  std::string CastMessage(const std::function<void()>& cast)
  {
    try {
      cast();
    } catch (const gpg::BadRefCast& error) {
      return error.what();
    }
    return "(no throw)";
  }

  TEST(ReflectionRef, ACheckedUpcastOfAnotherTypeThrowsBadRefCast)
  {
    // BadRefCast(nullptr, from, to) 0x008DD300 with the default prefix.
    float f = 1.0f;
    const gpg::RRef floatRef{&f, gpg::RTypeOf<float>()};
    EXPECT_EQ(CastMessage([&] { (void)floatRef.TryUpcastInt(); }), "type error: can't convert float to int");
    EXPECT_EQ(CastMessage([&] { (void)floatRef.TryUpcastChar(); }), "type error: can't convert float to char");
    EXPECT_EQ(CastMessage([&] { (void)floatRef.TryUpcastShort(); }), "type error: can't convert float to short");
    EXPECT_EQ(
      CastMessage([&] { (void)floatRef.TryUpcastUnsignedLong(); }), "type error: can't convert float to unsigned long"
    );

    int i = 0;
    const gpg::RRef intRef{&i, gpg::RTypeOf<int>()};
    EXPECT_EQ(CastMessage([&] { (void)intRef.TryUpcastLong(); }), "type error: can't convert int to long");
    EXPECT_EQ(
      CastMessage([&] { (void)intRef.TryUpcastUnsignedInt(); }), "type error: can't convert int to unsigned int"
    );
    EXPECT_EQ(
      CastMessage([&] { (void)intRef.TryUpcastSignedChar(); }), "type error: can't convert int to signed char"
    );
    EXPECT_EQ(
      CastMessage([&] { (void)intRef.TryUpcastUnsignedChar(); }), "type error: can't convert int to unsigned char"
    );
    EXPECT_EQ(
      CastMessage([&] { (void)intRef.TryUpcastUnsignedShort(); }), "type error: can't convert int to unsigned short"
    );

    const gpg::RRef untyped{&i, nullptr};
    EXPECT_EQ(CastMessage([&] { (void)untyped.TryUpcastInt(); }), "type error: can't convert null to int");
  }

  TEST(ReflectionRef, BadRefCastMessages)
  {
    EXPECT_STREQ(gpg::BadRefCast("plain").what(), "plain");
    EXPECT_STREQ(gpg::BadRefCast(nullptr, "A", "B").what(), "type error: can't convert A to B");
    EXPECT_STREQ(gpg::BadRefCast("cast ", "A", "B").what(), "cast A to B");
    EXPECT_STREQ(gpg::BadRefCast(nullptr, nullptr, nullptr).what(), "type error: can't convert  to ");
    const std::runtime_error source("from runtime");
    EXPECT_STREQ(gpg::BadRefCast(source).what(), "from runtime");
    const gpg::BadRefCast asBase("x");
    EXPECT_NE(dynamic_cast<const std::runtime_error*>(&asBase), nullptr);
  }

  TEST(ReflectionRef, SerializationErrorMessages)
  {
    EXPECT_STREQ(gpg::SerializationError("broken archive").what(), "broken archive");
    EXPECT_STREQ(gpg::SerializationError(std::runtime_error("wrapped")).what(), "wrapped");
    try {
      throw gpg::SerializationError("thrown");
    } catch (const std::runtime_error& error) {
      EXPECT_STREQ(error.what(), "thrown");
    }
  }

  TEST(ReflectionRef, DeleteOfANullObjectDoesNothing)
  {
    gpg::RRef none{nullptr, gpg::RTypeOf<int>()};
    none.Delete();
    gpg::RRef fresh = gpg::RTypeOf<int>()->NewRef();
    *static_cast<int*>(fresh.mObj) = 5;
    fresh.Delete(); // through int's delete lane
  }

  // ---------------------------------------------------------------------------------------------
  // RRef adapters (ReflectionRefAdapters.cpp)
  // ---------------------------------------------------------------------------------------------

  TEST(ReflectionRefAdapters, ValueAdaptersKeepTheObject)
  {
    gpg::RRef out{};
    int i = 1;
    EXPECT_EQ(gpg::PackRRef_int(&out, &i), &out);
    EXPECT_EQ(out.mObj, &i);
    EXPECT_STREQ(out.GetName(), "int");

    bool b = true;
    EXPECT_EQ(gpg::PackRRef_bool(&out, &b), &out);
    EXPECT_EQ(out.mObj, &b);
    EXPECT_STREQ(out.GetName(), "bool");
    EXPECT_EQ(out.GetLexical().view(), "true"sv);

    unsigned int ui = 2;
    EXPECT_EQ(gpg::AssignUIntRef(&out, &ui), &out);
    EXPECT_EQ(out.mObj, &ui);
    EXPECT_STREQ(out.GetName(), "unsigned int");

    unsigned long ul = 3;
    EXPECT_EQ(gpg::AssignULongRef(&out, &ul), &out);
    EXPECT_EQ(out.mObj, &ul);
    EXPECT_STREQ(out.GetName(), "unsigned long");

    gpg::ArchiveToken token = gpg::ArchiveToken::ObjectStart;
    const gpg::RRef tokenRef = gpg::RRef_ArchiveToken(&token);
    EXPECT_EQ(tokenRef.mObj, &token);
    EXPECT_EQ(tokenRef.GetLexical().view(), "OBJECT_START"sv);
  }

  struct AdapterCase
  {
    const char* adapter;
    const char* typeName;
    std::function<gpg::RRef*(gpg::RRef*)> call;
  };

  /** Each adapter given a null object: it must still name the reflected type the binary registers. */
  std::vector<AdapterCase> NullObjectCases()
  {
    // clang-format off
    return {
      {"RRef_CFootPlantManipulator", "CFootPlantManipulator", [](gpg::RRef* o) { return gpg::RRef_CFootPlantManipulator(o, nullptr); }},
      {"AssignCFootPlantManipulatorRef", "CFootPlantManipulator", [](gpg::RRef* o) { return gpg::AssignCFootPlantManipulatorRef(o, nullptr); }},
      {"RRef_CRotateManipulator", "CRotateManipulator", [](gpg::RRef* o) { return gpg::RRef_CRotateManipulator(o, nullptr); }},
      {"RRef_CStorageManipulator", "CStorageManipulator", [](gpg::RRef* o) { return gpg::RRef_CStorageManipulator(o, nullptr); }},
      {"RRef_CThrustManipulator", "CThrustManipulator", [](gpg::RRef* o) { return gpg::RRef_CThrustManipulator(o, nullptr); }},
      {"PackRRef_CAcquireTargetTask_P", "CAcquireTargetTask*", [](gpg::RRef* o) { return gpg::PackRRef_CAcquireTargetTask_P(o, nullptr); }},
      {"RRef_CEffectManagerImpl", "CEffectManagerImpl", [](gpg::RRef* o) { return gpg::RRef_CEffectManagerImpl(o, nullptr); }},
      {"PackRRef_CEffectManagerImpl", "CEffectManagerImpl", [](gpg::RRef* o) { return gpg::PackRRef_CEffectManagerImpl(o, nullptr); }},
      {"PackRRef_IEffect", "IEffect", [](gpg::RRef* o) { return gpg::PackRRef_IEffect(o, nullptr); }},
      {"PackRRef_CEfxBeam", "CEfxBeam", [](gpg::RRef* o) { return gpg::PackRRef_CEfxBeam(o, nullptr); }},
      {"PackRRef_CountedPtr_CParticleTexture", "CountedPtr<CParticleTexture>", [](gpg::RRef* o) { return gpg::PackRRef_CountedPtr_CParticleTexture(o, nullptr); }},
      {"PackRRef_SEfxCurve", "SEfxCurve", [](gpg::RRef* o) { return gpg::PackRRef_SEfxCurve(o, nullptr); }},
      {"RRef_CEfxEmitter", "CEfxEmitter", [](gpg::RRef* o) { return gpg::RRef_CEfxEmitter(o, nullptr); }},
      {"PackRRef_CEfxEmitter", "CEfxEmitter", [](gpg::RRef* o) { return gpg::PackRRef_CEfxEmitter(o, nullptr); }},
      {"RRef_CEfxTrailEmitter", "CEfxTrailEmitter", [](gpg::RRef* o) { return gpg::RRef_CEfxTrailEmitter(o, nullptr); }},
      {"PackRRef_CEfxTrailEmitter", "CEfxTrailEmitter", [](gpg::RRef* o) { return gpg::PackRRef_CEfxTrailEmitter(o, nullptr); }},
      {"PackRRef_IEffect_P", "IEffect*", [](gpg::RRef* o) { return gpg::PackRRef_IEffect_P(o, nullptr); }},
      {"AssignCollisionBeamEntityRef", "CollisionBeamEntity", [](gpg::RRef* o) { return gpg::AssignCollisionBeamEntityRef(o, nullptr); }},
      {"PackRRef_Prop", "Prop", [](gpg::RRef* o) { return gpg::PackRRef_Prop(o, nullptr); }},
      {"PackRRef_Entity_P", "Entity*", [](gpg::RRef* o) { return gpg::PackRRef_Entity_P(o, nullptr); }},
      {"PackRRef_WeakPtr_Entity", "WeakPtr<Entity>", [](gpg::RRef* o) { return gpg::PackRRef_WeakPtr_Entity(o, nullptr); }},
      {"AssignEntityDBRef", "EntityDB", [](gpg::RRef* o) { return gpg::AssignEntityDBRef(o, nullptr); }},
      {"PackRRef_SPhysConstantsA", "SPhysConstants", [](gpg::RRef* o) { return gpg::PackRRef_SPhysConstantsA(o, nullptr); }},
      {"PackRRef_SPhysConstantsB", "SPhysConstants", [](gpg::RRef* o) { return gpg::PackRRef_SPhysConstantsB(o, nullptr); }},
      {"AssignSPhysBodyRef", "SPhysBody", [](gpg::RRef* o) { return gpg::AssignSPhysBodyRef(o, nullptr); }},
      {"PackRRef_Unit", "Unit", [](gpg::RRef* o) { return gpg::PackRRef_Unit(o, nullptr); }},
      {"PackRRef_IUnit", "IUnit", [](gpg::RRef* o) { return gpg::PackRRef_IUnit(o, nullptr); }},
      {"PackRRef_WeakPtr_IUnit", "WeakPtr<IUnit>", [](gpg::RRef* o) { return gpg::PackRRef_WeakPtr_IUnit(o, nullptr); }},
      {"PackRRef_PathQueue", "PathQueue", [](gpg::RRef* o) { return gpg::PackRRef_PathQueue(o, nullptr); }},
      {"RRef_MotorSinkAway", "MotorSinkAway", [](gpg::RRef* o) { return gpg::RRef_MotorSinkAway(o, nullptr); }},
      {"PackRRef_RBlueprint", "RBlueprint", [](gpg::RRef* o) { return gpg::PackRRef_RBlueprint(o, nullptr); }},
      {"AssignRRuleGameRulesRef", "RRuleGameRules", [](gpg::RRef* o) { return gpg::AssignRRuleGameRulesRef(o, nullptr); }},
      {"AssignSRuleFootprintsBlueprintRef", "SRuleFootprintsBlueprint", [](gpg::RRef* o) { return gpg::AssignSRuleFootprintsBlueprintRef(o, nullptr); }},
      {"PackRRef_ResourceDeposit", "ResourceDeposit", [](gpg::RRef* o) { return gpg::PackRRef_ResourceDeposit(o, nullptr); }},
      {"PackRRef_REmitterBlueprint", "REmitterBlueprint", [](gpg::RRef* o) { return gpg::PackRRef_REmitterBlueprint(o, nullptr); }},
      {"PackRRef_RBeamBlueprint", "RBeamBlueprint", [](gpg::RRef* o) { return gpg::PackRRef_RBeamBlueprint(o, nullptr); }},
      {"PackRRef_RTrailBlueprint", "RTrailBlueprint", [](gpg::RRef* o) { return gpg::PackRRef_RTrailBlueprint(o, nullptr); }},
      {"AssignEntityCategoryRef", "EntityCategory", [](gpg::RRef* o) { return gpg::AssignEntityCategoryRef(o, nullptr); }},
      {"AssignCOGridRef", "COGrid", [](gpg::RRef* o) { return gpg::AssignCOGridRef(o, nullptr); }},
      {"PackRRef_CArmyImpl", "CArmyImpl", [](gpg::RRef* o) { return gpg::PackRRef_CArmyImpl(o, nullptr); }},
      {"PackRRef_SimArmy_P", "SimArmy*", [](gpg::RRef* o) { return gpg::PackRRef_SimArmy_P(o, nullptr); }},
      {"PackRRef_SimArmy", "SimArmy", [](gpg::RRef* o) { return gpg::PackRRef_SimArmy(o, nullptr); }},
      {"PackRRef_LaunchInfoNew", "LaunchInfoNew", [](gpg::RRef* o) { return gpg::PackRRef_LaunchInfoNew(o, nullptr); }},
      {"RRef_ArmyLaunchInfo", "ArmyLaunchInfo", [](gpg::RRef* o) { return gpg::RRef_ArmyLaunchInfo(o, nullptr); }},
      {"PackRRef_ArmyLaunchInfo", "ArmyLaunchInfo", [](gpg::RRef* o) { return gpg::PackRRef_ArmyLaunchInfo(o, nullptr); }},
      {"PackRRef_CSimResources", "CSimResources", [](gpg::RRef* o) { return gpg::PackRRef_CSimResources(o, nullptr); }},
      {"PackRRef_CAiBrain", "CAiBrain", [](gpg::RRef* o) { return gpg::PackRRef_CAiBrain(o, nullptr); }},
      {"RRef_SAssignedLocInfo", "SAssignedLocInfo", [](gpg::RRef* o) { return gpg::RRef_SAssignedLocInfo(o, nullptr); }},
      {"PackRRef_SAssignedLocInfo", "SAssignedLocInfo", [](gpg::RRef* o) { return gpg::PackRRef_SAssignedLocInfo(o, nullptr); }},
      {"RRef_SPickUpInfo", "SPickUpInfo", [](gpg::RRef* o) { return gpg::RRef_SPickUpInfo(o, nullptr); }},
      {"PackRRef_CUnitCommand", "CUnitCommand", [](gpg::RRef* o) { return gpg::PackRRef_CUnitCommand(o, nullptr); }},
      {"PackRRef_CUnitCommand_P", "CUnitCommand*", [](gpg::RRef* o) { return gpg::PackRRef_CUnitCommand_P(o, nullptr); }},
      {"PackRRef_WeakPtr_CUnitCommand", "WeakPtr<CUnitCommand>", [](gpg::RRef* o) { return gpg::PackRRef_WeakPtr_CUnitCommand(o, nullptr); }},
      {"PackRRef_CUnitCommandQueue", "CUnitCommandQueue", [](gpg::RRef* o) { return gpg::PackRRef_CUnitCommandQueue(o, nullptr); }},
      {"PackRRef_UnitWeapon", "UnitWeapon", [](gpg::RRef* o) { return gpg::PackRRef_UnitWeapon(o, nullptr); }},
      {"RRef_UnitWeaponInfo", "UnitWeaponInfo", [](gpg::RRef* o) { return gpg::RRef_UnitWeaponInfo(o, nullptr); }},
      {"PackRRef_UnitWeapon_P", "UnitWeapon*", [](gpg::RRef* o) { return gpg::PackRRef_UnitWeapon_P(o, nullptr); }},
      {"AssignIdPoolRef", "IdPool", [](gpg::RRef* o) { return gpg::AssignIdPoolRef(o, nullptr); }},
      {"RRef_SOffsetInfo", "SOffsetInfo", [](gpg::RRef* o) { return gpg::RRef_SOffsetInfo(o, nullptr); }},
      {"PackRRef_SOffsetInfo", "SOffsetInfo", [](gpg::RRef* o) { return gpg::PackRRef_SOffsetInfo(o, nullptr); }},
      {"AssignHPathCellRef", "HPathCell", [](gpg::RRef* o) { return gpg::AssignHPathCellRef(o, nullptr); }},
      {"AssignCArmyStatItemPointerRef", "CArmyStatItem*", [](gpg::RRef* o) { return gpg::AssignCArmyStatItemPointerRef(o, nullptr); }},
      {"PackRRef_CEconomyEvent_P", "CEconomyEvent*", [](gpg::RRef* o) { return gpg::PackRRef_CEconomyEvent_P(o, nullptr); }},
      {"AssignCEconomyEventRef", "CEconomyEvent", [](gpg::RRef* o) { return gpg::AssignCEconomyEventRef(o, nullptr); }},
      {"PackRRef_CDecalBuffer", "CDecalBuffer", [](gpg::RRef* o) { return gpg::PackRRef_CDecalBuffer(o, nullptr); }},
      {"PackRRef_CDecalHandle_P", "CDecalHandle*", [](gpg::RRef* o) { return gpg::PackRRef_CDecalHandle_P(o, nullptr); }},
      {"PackRRef_CDecalHandle", "CDecalHandle", [](gpg::RRef* o) { return gpg::PackRRef_CDecalHandle(o, nullptr); }},
      {"PackRRef_CAiAttackerImpl", "CAiAttackerImpl", [](gpg::RRef* o) { return gpg::PackRRef_CAiAttackerImpl(o, nullptr); }},
      {"PackRRef_CAiTransportImpl", "CAiTransportImpl", [](gpg::RRef* o) { return gpg::PackRRef_CAiTransportImpl(o, nullptr); }},
      {"PackRRef_CAiSteeringImpl", "CAiSteeringImpl", [](gpg::RRef* o) { return gpg::PackRRef_CAiSteeringImpl(o, nullptr); }},
      {"PackRRef_CAiSiloBuildImpl", "CAiSiloBuildImpl", [](gpg::RRef* o) { return gpg::PackRRef_CAiSiloBuildImpl(o, nullptr); }},
      {"PackRRef_SAiReservedTransportBone", "SAiReservedTransportBone", [](gpg::RRef* o) { return gpg::PackRRef_SAiReservedTransportBone(o, nullptr); }},
      {"PackRRef_SAttachPoint", "SAttachPoint", [](gpg::RRef* o) { return gpg::PackRRef_SAttachPoint(o, nullptr); }},
      {"PackRRef_SPointVector", "SPointVector", [](gpg::RRef* o) { return gpg::PackRRef_SPointVector(o, nullptr); }},
      {"PackRRef_RDebugNavPath", "RDebugNavPath", [](gpg::RRef* o) { return gpg::PackRRef_RDebugNavPath(o, nullptr); }},
      {"PackRRef_RDebugNavWaypoints", "RDebugNavWaypoints", [](gpg::RRef* o) { return gpg::PackRRef_RDebugNavWaypoints(o, nullptr); }},
      {"PackRRef_RDebugNavSteering", "RDebugNavSteering", [](gpg::RRef* o) { return gpg::PackRRef_RDebugNavSteering(o, nullptr); }},
      {"PackRRef_RDebugWeapons", "RDebugWeapons", [](gpg::RRef* o) { return gpg::PackRRef_RDebugWeapons(o, nullptr); }},
      {"AssignCIntelRef", "CIntel", [](gpg::RRef* o) { return gpg::AssignCIntelRef(o, nullptr); }},
      {"AssignCIntelPosHandleRef", "CIntelPosHandle", [](gpg::RRef* o) { return gpg::AssignCIntelPosHandleRef(o, nullptr); }},
      {"AssignPositionHistoryRef", "PositionHistory", [](gpg::RRef* o) { return gpg::AssignPositionHistoryRef(o, nullptr); }},
      {"PackRRef_CUnitMotion", "CUnitMotion", [](gpg::RRef* o) { return gpg::PackRRef_CUnitMotion(o, nullptr); }},
      {"PackRRef_Shield", "Shield", [](gpg::RRef* o) { return gpg::PackRRef_Shield(o, nullptr); }},
      {"PackRRef_Shield_P", "Shield*", [](gpg::RRef* o) { return gpg::PackRRef_Shield_P(o, nullptr); }},
      {"AssignCRandomStreamRef", "CRandomStream", [](gpg::RRef* o) { return gpg::AssignCRandomStreamRef(o, nullptr); }},
      {"AssignCPlatoonRef", "CPlatoon", [](gpg::RRef* o) { return gpg::AssignCPlatoonRef(o, nullptr); }},
      {"AssignTableRef", "Table", [](gpg::RRef* o) { return gpg::AssignTableRef(o, nullptr); }},
    };
    // clang-format on
  }

  TEST(ReflectionRefAdapters, NullObjectsKeepTheDeclaredType)
  {
    for (const AdapterCase& adapter : NullObjectCases()) {
      gpg::RRef out{reinterpret_cast<void*>(0x1), nullptr}; // overwritten
      EXPECT_EQ(adapter.call(&out), &out) << adapter.adapter;
      EXPECT_EQ(out.mObj, nullptr) << adapter.adapter;
      ASSERT_NE(out.mType, nullptr) << adapter.adapter;
      EXPECT_STREQ(out.GetName(), adapter.typeName) << adapter.adapter;
    }
  }

  template <class E>
  void ExpectEnumAdapter(
    const char* const adapter, gpg::RRef* (*const call)(gpg::RRef*, E*), const char* const typeName
  )
  {
    E value = static_cast<E>(0);
    gpg::RRef out{};
    EXPECT_EQ(call(&out, &value), &out) << adapter;
    EXPECT_EQ(out.mObj, &value) << adapter;
    ASSERT_NE(out.mType, nullptr) << adapter;
    EXPECT_STREQ(out.GetName(), typeName) << adapter;
    EXPECT_NE(out.mType->IsEnumType(), nullptr) << adapter;
    EXPECT_EQ(out.mType->size_, 4) << adapter;
  }

  TEST(ReflectionRefAdapters, EnumAdaptersPointAtTheEnumType)
  {
    ExpectEnumAdapter("AssignESTITargetTypeRef", &gpg::AssignESTITargetTypeRef, "ESTITargetType");
    ExpectEnumAdapter("AssignESquadClassRef", &gpg::AssignESquadClassRef, "ESquadClass");
    ExpectEnumAdapter("AssignEUnitCommandTypeRefPrimary", &gpg::AssignEUnitCommandTypeRefPrimary, "EUnitCommandType");
    ExpectEnumAdapter(
      "AssignEUnitCommandTypeRefSecondary", &gpg::AssignEUnitCommandTypeRefSecondary, "EUnitCommandType"
    );
    ExpectEnumAdapter("PackRRef_EUnitState", &gpg::PackRRef_EUnitState, "EUnitState");
    ExpectEnumAdapter("PackRRef_EFireState", &gpg::PackRRef_EFireState, "EFireState");
    ExpectEnumAdapter("AssignESpecialFileTypeRefAdapter", &gpg::AssignESpecialFileTypeRefAdapter, "ESpecialFileType");
    ExpectEnumAdapter("AssignEGenericIconTypeRef", &gpg::AssignEGenericIconTypeRef, "EGenericIconType");
#if defined(_WIN32)
    ExpectEnumAdapter("AssignEMauiScrollAxisRef", &gpg::AssignEMauiScrollAxisRef, "EMauiScrollAxis");
    ExpectEnumAdapter("AssignEMauiEventTypeRef", &gpg::AssignEMauiEventTypeRef, "EMauiEventType");
#endif
  }
} // namespace
