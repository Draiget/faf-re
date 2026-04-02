#include "moho/serialization/typeinfo/SBatchTextureDataTypeInfo.h"

#include <typeinfo>

#include "moho/render/textures/SBatchTextureData.h"

namespace
{
  /**
   * Address: 0x00447CB0 (FUN_00447CB0)
   *
   * What it does:
   * Releases dynamic base/field storage lanes in one `RType` payload and
   * resets the vectors to empty.
   */
  void ResetSBatchTextureDataTypeStorage(gpg::RType& type)
  {
    type.fields_ = {};
    type.bases_ = {};
  }

  moho::SBatchTextureDataTypeInfo gSBatchTextureDataTypeInfo;
} // namespace

namespace moho
{
  /**
   * Address: 0x00447BC0 (FUN_00447BC0, Moho::SBatchTextureDataTypeInfo::SBatchTextureDataTypeInfo)
   */
  SBatchTextureDataTypeInfo::SBatchTextureDataTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SBatchTextureData), this);
  }

  /**
   * Address: 0x00447C50 (FUN_00447C50, Moho::SBatchTextureDataTypeInfo::dtr)
   * Address: 0x00BEF480 (FUN_00BEF480, global dtor lane)
   */
  SBatchTextureDataTypeInfo::~SBatchTextureDataTypeInfo()
  {
    ResetSBatchTextureDataTypeStorage(*this);
  }

  /**
   * Address: 0x00447C40 (FUN_00447C40, Moho::SBatchTextureDataTypeInfo::GetName)
   */
  const char* SBatchTextureDataTypeInfo::GetName() const
  {
    return "SBatchTextureData";
  }

  /**
   * Address: 0x00447C20 (FUN_00447C20, Moho::SBatchTextureDataTypeInfo::Init)
   */
  void SBatchTextureDataTypeInfo::Init()
  {
    size_ = sizeof(SBatchTextureData);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC4400 (FUN_00BC4400, register_SBatchTextureDataTypeInfo)
   */
  void register_SBatchTextureDataTypeInfo()
  {
    (void)gSBatchTextureDataTypeInfo;
  }
} // namespace moho

namespace
{
  struct SBatchTextureDataTypeInfoBootstrap
  {
    SBatchTextureDataTypeInfoBootstrap()
    {
      moho::register_SBatchTextureDataTypeInfo();
    }
  };

  SBatchTextureDataTypeInfoBootstrap gSBatchTextureDataTypeInfoBootstrap;
} // namespace
