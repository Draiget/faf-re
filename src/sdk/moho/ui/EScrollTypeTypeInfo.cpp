#include "moho/ui/EScrollTypeTypeInfo.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EScrollTypeTypeInfo> gEScrollTypeTypeInfoStorage{};
} // namespace

namespace moho
{
  /**
   * Address: 0x007771B0 (FUN_007771B0, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::REnumType* preregister_EScrollTypeTypeInfo()
  {
    return &gEScrollTypeTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x007771B0 (FUN_007771B0, Moho::EScrollTypeTypeInfo::ctor)
   *
   * What it does:
   * Preregisters the reflected `EScrollType` enum metadata.
   */
  EScrollTypeTypeInfo::EScrollTypeTypeInfo()
  {
    gpg::PreRegisterRType(typeid(EScrollType), this);
  }

  /**
   * Address: 0x00777240 (FUN_00777240, Moho::EScrollTypeTypeInfo::dtr)
   */
  EScrollTypeTypeInfo::~EScrollTypeTypeInfo() = default;

  /**
   * Address: 0x00777230 (FUN_00777230, Moho::EScrollTypeTypeInfo::GetName)
   */
  const char* EScrollTypeTypeInfo::GetName() const
  {
    return "EScrollType";
  }

  /**
   * Address: 0x00777210 (FUN_00777210, Moho::EScrollTypeTypeInfo::Init)
   */
  void EScrollTypeTypeInfo::Init()
  {
    size_ = sizeof(EScrollType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00777270 (FUN_00777270, Moho::EScrollTypeTypeInfo::AddEnums)
   */
  void EScrollTypeTypeInfo::AddEnums()
  {
    mPrefix = "SCROLLTYPE_";

    AddEnum(StripPrefix("SCROLLTYPE_None"), static_cast<std::int32_t>(SCROLLTYPE_None));
    AddEnum(StripPrefix("SCROLLTYPE_PingPong"), static_cast<std::int32_t>(SCROLLTYPE_PingPong));
    AddEnum(StripPrefix("SCROLLTYPE_Manual"), static_cast<std::int32_t>(SCROLLTYPE_Manual));
    AddEnum(StripPrefix("SCROLLTYPE_MotionDerived"), static_cast<std::int32_t>(SCROLLTYPE_MotionDerived));
  }
} // namespace moho

// Phase-1 pre-registration: CTextureScroller caches the reflected EScrollType
// through gpg::LookupRType, so the descriptor must exist before that consumer
// runs. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_EScrollTypeTypeInfo_7771b0, moho::preregister_EScrollTypeTypeInfo)
