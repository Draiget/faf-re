#include "moho/sim/SThreatTypeInfo.h"

#include "moho/sim/CInfluenceMap.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::SThreatTypeInfo> gSThreatTypeInfoStorage{};
} // namespace

namespace moho
{
  /**
   * Address: 0x007179B0 (FUN_007179B0, static-init lane)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::RType* preregister_SThreatTypeInfo()
  {
    return &gSThreatTypeInfoStorage.Ensure();
  }

  /**
   * Address: 0x007179B0 (FUN_007179B0, Moho::SThreatTypeInfo::SThreatTypeInfo)
   */
  SThreatTypeInfo::SThreatTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SThreat), this);
  }

  /**
   * Address: 0x00717A40 (FUN_00717A40, Moho::SThreatTypeInfo::dtr)
   */
  SThreatTypeInfo::~SThreatTypeInfo() = default;

  /**
   * Address: 0x00717A30 (FUN_00717A30, Moho::SThreatTypeInfo::GetName)
   */
  const char* SThreatTypeInfo::GetName() const
  {
    return "SThreat";
  }

  /**
   * Address: 0x00717A10 (FUN_00717A10, Moho::SThreatTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::SThreatTypeInfo::Init(gpg::RType *this);
   */
  void SThreatTypeInfo::Init()
  {
    size_ = sizeof(SThreat);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

// Phase-1 pre-registration: CInfluenceMap caches SThreat::sType through
// gpg::LookupRType, so the descriptor must exist before that consumer runs.
// See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SThreatTypeInfo_7179b0, moho::preregister_SThreatTypeInfo)
