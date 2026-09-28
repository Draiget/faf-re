#include "moho/sim/InfluenceGridTypeInfo.h"

#include "moho/sim/CInfluenceMap.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
} // namespace

namespace moho
{
  /**
   * Address: 0x00717BB0 (FUN_00717BB0, static-init lane)
   * Address: 0x00C00090 (FUN_00C00090, atexit destructor of the InfluenceGridTypeInfo object; registered by 0x00BDA7C0)
   *
   * What it does:
   * Constructs the static descriptor on first call; the constructor is what
   * performs the `PreRegisterRType`, so one construction is the whole
   * registration.
   */
  gpg::RType* preregister_InfluenceGridTypeInfo()
  {
    static moho::InfluenceGridTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x00717BB0 (FUN_00717BB0, Moho::InfluenceGridTypeInfo::InfluenceGridTypeInfo)
   */
  InfluenceGridTypeInfo::InfluenceGridTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(InfluenceGrid), this);
  }

  /**
   * Address: 0x00717C40 (FUN_00717C40, Moho::InfluenceGridTypeInfo::dtr)
   */
  InfluenceGridTypeInfo::~InfluenceGridTypeInfo() = default;

  /**
   * Address: 0x00717C30 (FUN_00717C30, Moho::InfluenceGridTypeInfo::GetName)
   */
  const char* InfluenceGridTypeInfo::GetName() const
  {
    return "InfluenceGrid";
  }

  /**
   * Address: 0x00717C10 (FUN_00717C10, Moho::InfluenceGridTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::InfluenceGridTypeInfo::Init(gpg::RType *this);
   */
  void InfluenceGridTypeInfo::Init()
  {
    size_ = sizeof(InfluenceGrid);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

// Phase-1 pre-registration: InfluenceGridSerializer and CInfluenceMap resolve
// InfluenceGrid through gpg::LookupRType, so the descriptor must exist before
// those consumers run. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_InfluenceGridTypeInfo_717bb0, moho::preregister_InfluenceGridTypeInfo)
