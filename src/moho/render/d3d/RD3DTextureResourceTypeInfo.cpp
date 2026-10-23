#include "moho/render/d3d/RD3DTextureResourceTypeInfo.h"

#include <typeinfo>

#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/resource/ResourceReflectionHelpers.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BEF2B0 (FUN_00BEF2B0, atexit destructor of the RD3DTextureResourceTypeInfo object)
   */
  [[nodiscard]] moho::RD3DTextureResourceTypeInfo& AcquireRD3DTextureResourceTypeInfo()
  {
    static moho::RD3DTextureResourceTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0043D5D0 (FUN_0043D5D0, Moho::RD3DTextureResourceTypeInfo::RD3DTextureResourceTypeInfo)
   */
  RD3DTextureResourceTypeInfo::RD3DTextureResourceTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RD3DTextureResource), this);
  }

  /**
   * Address: 0x0043D660 (FUN_0043D660, Moho::RD3DTextureResourceTypeInfo::dtr)
   */
  RD3DTextureResourceTypeInfo::~RD3DTextureResourceTypeInfo() = default;

  /**
   * Address: 0x0043D650 (FUN_0043D650, Moho::RD3DTextureResourceTypeInfo::GetName)
   */
  const char* RD3DTextureResourceTypeInfo::GetName() const
  {
    return "RD3DTextureResource";
  }

  /**
   * Address: 0x0043D630 (FUN_0043D630, Moho::RD3DTextureResourceTypeInfo::Init)
   */
  void RD3DTextureResourceTypeInfo::Init()
  {
    size_ = sizeof(RD3DTextureResource);
    gpg::RType::Init();
    AddBase_ID3DTextureSheet(this);
    Finish();
  }

  /**
   * Address: 0x004454B0 (FUN_004454B0, Moho::RD3DTextureResourceTypeInfo::AddBase_ID3DTextureSheet)
   */
  void RD3DTextureResourceTypeInfo::AddBase_ID3DTextureSheet(gpg::RType* const typeInfo)
  {
    resource_reflection::AddBase(typeInfo, resource_reflection::ResolveID3DTextureSheetType());
  }

  /**
   * Address: 0x00BC41F0 (FUN_00BC41F0, register_RD3DTextureResourceTypeInfo)
   *
   * What it does:
   * Constructs the process-global `RD3DTextureResourceTypeInfo` object.
   */
  void register_RD3DTextureResourceTypeInfo()
  {
    (void)AcquireRD3DTextureResourceTypeInfo();
  }
} // namespace moho

namespace
{
  struct RD3DTextureResourceTypeInfoBootstrap
  {
    RD3DTextureResourceTypeInfoBootstrap()
    {
      moho::register_RD3DTextureResourceTypeInfo();
    }
  };

  [[maybe_unused]] RD3DTextureResourceTypeInfoBootstrap gRD3DTextureResourceTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RD3DTextureResourceTypeInfo_5d5a4d, moho::register_RD3DTextureResourceTypeInfo)
