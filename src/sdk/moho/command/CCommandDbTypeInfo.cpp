#include "moho/command/CCommandDbTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/command/CCommandDb.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BFE940 (FUN_00BFE940, atexit destructor of the CCommandDBTypeInfo object)
   */
  [[nodiscard]] moho::CCommandDBTypeInfo& GetCCommandDBTypeInfo() noexcept
  {
    static moho::CCommandDBTypeInfo sInstance;
    return sInstance;
  }

  gpg::RType* gLegacyCCommandDbType = nullptr;

  /**
   * Address: 0x006E2290 (FUN_006E2290)
   *
   * What it does:
   * Resolves and caches RTTI for one `CCommandDB` lane.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveLegacyCCommandDbType()
  {
    gpg::RType* type = gLegacyCCommandDbType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandDb));
      gLegacyCCommandDbType = type;
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006E0880 (FUN_006E0880, sub_6E0880)
   */
  CCommandDBTypeInfo::CCommandDBTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CCommandDb), this);
  }

  /**
   * Address: 0x006E0970 (FUN_006E0970, CCommandDBTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `CCommandDBTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroyCCommandDbTypeInfoBody(CCommandDBTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x006E0910 (FUN_006E0910, Moho::CCommandDBTypeInfo::dtr)
   */
  CCommandDBTypeInfo::~CCommandDBTypeInfo()
  {
    DestroyCCommandDbTypeInfoBody(this);
  }

  /**
   * Address: 0x006E0900 (FUN_006E0900, Moho::CCommandDBTypeInfo::GetName)
   */
  const char* CCommandDBTypeInfo::GetName() const
  {
    return "CCommandDB";
  }

  /**
   * Address: 0x006E08E0 (FUN_006E08E0, Moho::CCommandDBTypeInfo::Init)
   */
  void CCommandDBTypeInfo::Init()
  {
    size_ = sizeof(CCommandDb);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BD8C40 (FUN_00BD8C40, sub_BD8C40)
   */
  void register_CCommandDBTypeInfo()
  {
    (void)GetCCommandDBTypeInfo();
  }
} // namespace moho

namespace
{
  struct CCommandDBTypeInfoBootstrap
  {
    CCommandDBTypeInfoBootstrap()
    {
      moho::register_CCommandDBTypeInfo();
    }
  };

  CCommandDBTypeInfoBootstrap gCCommandDBTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CCommandDBTypeInfo_4c172b, moho::register_CCommandDBTypeInfo)
