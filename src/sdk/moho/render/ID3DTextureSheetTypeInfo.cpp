#include "moho/render/ID3DTextureSheetTypeInfo.h"

#include <typeinfo>

#include "moho/render/ID3DTextureSheet.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BEF250 (FUN_00BEF250, atexit destructor of the ID3DTextureSheetTypeInfo object)
   */
  [[nodiscard]] moho::ID3DTextureSheetTypeInfo& AcquireID3DTextureSheetTypeInfo()
  {
    static moho::ID3DTextureSheetTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0043D490 (FUN_0043D490, Moho::ID3DTextureSheetTypeInfo::ID3DTextureSheetTypeInfo)
   */
  ID3DTextureSheetTypeInfo::ID3DTextureSheetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(ID3DTextureSheet), this);
  }

  /**
   * Address: 0x0043D520 (FUN_0043D520, Moho::ID3DTextureSheetTypeInfo::dtr)
   */
  ID3DTextureSheetTypeInfo::~ID3DTextureSheetTypeInfo() = default;

  /**
   * Address: 0x0043D510 (FUN_0043D510, Moho::ID3DTextureSheetTypeInfo::GetName)
   */
  const char* ID3DTextureSheetTypeInfo::GetName() const
  {
    return "ID3DTextureSheet";
  }

  /**
   * Address: 0x0043D4F0 (FUN_0043D4F0, Moho::ID3DTextureSheetTypeInfo::Init)
   */
  void ID3DTextureSheetTypeInfo::Init()
  {
    size_ = sizeof(ID3DTextureSheet);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC41D0 (FUN_00BC41D0, register_ID3DTextureSheetTypeInfo)
   *
   * What it does:
   * Constructs the process-global `ID3DTextureSheetTypeInfo` object.
   */
  void register_ID3DTextureSheetTypeInfo()
  {
    (void)AcquireID3DTextureSheetTypeInfo();
  }
} // namespace moho

namespace
{
  struct ID3DTextureSheetTypeInfoBootstrap
  {
    ID3DTextureSheetTypeInfoBootstrap()
    {
      moho::register_ID3DTextureSheetTypeInfo();
    }
  };

  [[maybe_unused]] ID3DTextureSheetTypeInfoBootstrap gID3DTextureSheetTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ID3DTextureSheetTypeInfo_d04b8a, moho::register_ID3DTextureSheetTypeInfo)
