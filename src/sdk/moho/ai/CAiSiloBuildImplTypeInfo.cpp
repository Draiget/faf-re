#include "legacy/containers/Vector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiSiloBuildImplTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <list>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/RListType.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/CAiSiloBuildImplConstruct.h"
#include "moho/ai/CAiSiloBuildImplSerializer.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  class SSiloBuildInfoTypeInfo final : public gpg::RType
  {
  public:
    ~SSiloBuildInfoTypeInfo() override;
    [[nodiscard]] const char* GetName() const override;
    void Init() override;
  };

  static_assert(sizeof(SSiloBuildInfoTypeInfo) == 0x64, "SSiloBuildInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00BF7E40 (FUN_00BF7E40, atexit destructor of the SSiloBuildInfoTypeInfo object)
   */
  [[nodiscard]] SSiloBuildInfoTypeInfo* AcquireSSiloBuildInfoTypeInfo()
  {
    static SSiloBuildInfoTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00BF7ED0 (FUN_00BF7ED0, atexit destructor of the CAiSiloBuildImplTypeInfo object)
   */
  [[nodiscard]] CAiSiloBuildImplTypeInfo* AcquireCAiSiloBuildImplTypeInfo()
  {
    static CAiSiloBuildImplTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005CEB30 (FUN_005CEB30, preregister_SSiloBuildInfoTypeInfo)
   *
   * What it does:
   * Constructs and preregisters static `SSiloBuildInfoTypeInfo` storage.
   */
  [[nodiscard]] gpg::RType* preregister_SSiloBuildInfoTypeInfo()
  {
    SSiloBuildInfoTypeInfo* const typeInfo = AcquireSSiloBuildInfoTypeInfo();
    gpg::PreRegisterRType(typeid(SSiloBuildInfo), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x005CF670 (FUN_005CF670, sub_5CF670)
   *
   * What it does:
   * Constructs and preregisters static `CAiSiloBuildImplTypeInfo` storage.
   */
  [[nodiscard]] gpg::RType* preregister_CAiSiloBuildImplTypeInfo()
  {
    CAiSiloBuildImplTypeInfo* const typeInfo = AcquireCAiSiloBuildImplTypeInfo();
    gpg::PreRegisterRType(typeid(CAiSiloBuildImpl), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x005D0B00 (FUN_005D0B00, preregister_ESiloTypeListTypeInfo)
   * Address: 0x00BF7FC0 (FUN_00BF7FC0, atexit destructor of the list type object)
   *
   * What it does:
   * Constructs the `gpg::RListType<ESiloType>` static, which preregisters it
   * for `typeid(msvc8::list<ESiloType>)`, and returns it.
   *
   * `RListType<ESiloType>`, vtable 0x00E1DDA4:
   *
   * Address: 0x005D0C40 (FUN_005D0C40 -- the implicit scalar deleting destructor.)
   * Address: 0x005CFBD0 (FUN_005CFBD0 -- `GetName`.)
   * Address: 0x00BF7F90 (FUN_00BF7F90 -- the atexit destructor of `GetName`'s name string.)
   * Address: 0x005CFC90 (FUN_005CFC90 -- `GetLexical`.)
   * Address: 0x005CFC70 (FUN_005CFC70 -- `Init`.)
   * Address: 0x005D0020 (FUN_005D0020 -- `SerLoad`; the enum element is read uninitialised, the
   * `T value;` the template writes.)
   * Address: 0x005D00C0 (FUN_005D00C0 -- `SerSave`.)
   */
  [[nodiscard]] gpg::RType* preregister_ESiloTypeListTypeInfo()
  {
    static gpg::RListType<ESiloType> sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RType* CachedIAiSiloBuildType()
  {
    if (!IAiSiloBuild::sType) {
      IAiSiloBuild::sType = gpg::LookupRType(typeid(IAiSiloBuild));
    }
    return IAiSiloBuild::sType;
  }
} // namespace

/**
 * Address: 0x005CEBC0 (FUN_005CEBC0, scalar deleting thunk)
 */
SSiloBuildInfoTypeInfo::~SSiloBuildInfoTypeInfo() = default;

/**
 * Address: 0x005CEBB0 (FUN_005CEBB0, Moho::SSiloBuildInfoTypeInfo::GetName)
 */
const char* SSiloBuildInfoTypeInfo::GetName() const
{
  return "SSiloBuildInfo";
}

/**
 * Address: 0x005CEB90 (FUN_005CEB90, Moho::SSiloBuildInfoTypeInfo::Init)
 */
void SSiloBuildInfoTypeInfo::Init()
{
  size_ = sizeof(SSiloBuildInfo);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x005CF700 (FUN_005CF700, scalar deleting thunk)
 */
CAiSiloBuildImplTypeInfo::~CAiSiloBuildImplTypeInfo() = default;

/**
 * Address: 0x005CF6F0 (FUN_005CF6F0, ?GetName@CAiSiloBuildImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiSiloBuildImplTypeInfo::GetName() const
{
  return "CAiSiloBuildImpl";
}

/**
 * Address: 0x005D0810 (FUN_005D0810, Moho::CAiSiloBuildImplTypeInfo::AddBase_IAiSiloBuild)
 *
 * What it does:
 * Registers `IAiSiloBuild` as this type's reflected base at offset 0.
 */
void CAiSiloBuildImplTypeInfo::AddBase_IAiSiloBuild(gpg::RType* const typeInfo)
{
  gpg::AddBaseIfPresent(typeInfo, CachedIAiSiloBuildType(), 0);
}

/**
 * Address: 0x005CF6D0 (FUN_005CF6D0, ?Init@CAiSiloBuildImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiSiloBuildImplTypeInfo::Init()
{
  size_ = sizeof(CAiSiloBuildImpl);
  gpg::RType::Init();

  gpg::RType* const baseType = CachedIAiSiloBuildType();
  if (baseType) {
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    AddBase(baseField);
  }

  AddBase_IAiSiloBuild(this);
  Finish();
}

/**
 * Address: 0x00BCE090 (FUN_00BCE090, register_SSiloBuildInfoTypeInfo)
 *
 * What it does:
 * Registers `SSiloBuildInfo` RTTI type-info.
 */
void moho::register_SSiloBuildInfoTypeInfo()
{
  (void)preregister_SSiloBuildInfoTypeInfo();
}

/**
 * Address: 0x00BCE0F0 (FUN_00BCE0F0, register_CAiSiloBuildImplTypeInfo)
 *
 * What it does:
 * Registers `CAiSiloBuildImpl` RTTI type-info.
 */
void moho::register_CAiSiloBuildImplTypeInfo()
{
  (void)preregister_CAiSiloBuildImplTypeInfo();
}

/**
 * Address: 0x00BCE190 (FUN_00BCE190, register_ESiloTypeListTypeInfo)
 *
 * What it does:
 * Registers reflected `msvc8::list<ESiloType>` type-info.
 */
void moho::register_ESiloTypeListTypeInfo()
{
  (void)preregister_ESiloTypeListTypeInfo();
}

namespace
{
  struct CAiSiloBuildTypeInfoBootstrap
  {
    CAiSiloBuildTypeInfoBootstrap()
    {
      moho::register_SSiloBuildInfoTypeInfo();
      (void)moho::register_SSiloBuildInfoSerializer();
      moho::register_CAiSiloBuildImplTypeInfo();
      (void)moho::register_CAiSiloBuildImplConstruct();
      (void)moho::register_CAiSiloBuildImplSerializer();
      moho::register_ESiloTypeListTypeInfo();
    }
  };

  [[maybe_unused]] CAiSiloBuildTypeInfoBootstrap gCAiSiloBuildTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_SSiloBuildInfoTypeInfo_cefa38, moho::register_SSiloBuildInfoTypeInfo)
GPG_PREREGISTER_INIT(register_CAiSiloBuildImplTypeInfo_cefa38, moho::register_CAiSiloBuildImplTypeInfo)
GPG_PREREGISTER_INIT(register_ESiloTypeListTypeInfo_cefa38, moho::register_ESiloTypeListTypeInfo)

GPG_PREREGISTER_INIT(AcquireSSiloBuildInfoTypeInfo_cefa38, AcquireSSiloBuildInfoTypeInfo)
GPG_PREREGISTER_INIT(AcquireCAiSiloBuildImplTypeInfo_cefa38, AcquireCAiSiloBuildImplTypeInfo)
