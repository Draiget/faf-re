#include "moho/sim/SMinMaxTypeInfo.h"

#include <typeinfo>

#include "moho/sim/SMinMax.h"

#pragma init_seg(lib)

namespace
{
  moho::SMinMaxFloatTypeInfo gSMinMaxFloatTypeInfo;
  moho::SMinMaxUint32TypeInfo gSMinMaxUint32TypeInfo;

  /**
   * Address: 0x0040DDF0 (FUN_0040DDF0, sub_40DDF0)
   *
   * What it does:
   * Appends `"Min"` / `"Max"` float lanes to one `SMinMax<float>` type.
   */
  gpg::RField* AddSMinMaxFloatFields(gpg::RType* const type)
  {
    type->AddFieldFloat("Min", 0);
    return type->AddFieldFloat("Max", 4);
  }

  template <typename TObject>
  void MaterializeReflectionSingleton(TObject& singleton)
  {
    (void)singleton;
  }

  /**
   * Address: 0x00BC3260 (FUN_00BC3260, register_SMinMaxFloatTypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `SMinMax<float>`.
   */
  void RegisterSMinMaxFloatTypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gSMinMaxFloatTypeInfo);
  }

  /**
   * Address: 0x00BC3280 (FUN_00BC3280, register_SMinMaxUint32TypeInfo)
   *
   * What it does:
   * Materializes the global reflection descriptor for `SMinMax<uint32_t>`.
   */
  void RegisterSMinMaxUint32TypeInfoBootstrap()
  {
    MaterializeReflectionSingleton(gSMinMaxUint32TypeInfo);
  }

  struct SMinMaxTypeInfoBootstrap
  {
    SMinMaxTypeInfoBootstrap()
    {
      RegisterSMinMaxFloatTypeInfoBootstrap();
      RegisterSMinMaxUint32TypeInfoBootstrap();
    }
  };

  SMinMaxTypeInfoBootstrap gSMinMaxTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0040DCA0 (FUN_0040DCA0, Moho::SMinMaxFloatTypeInfo::SMinMaxFloatTypeInfo)
   */
  SMinMaxFloatTypeInfo::SMinMaxFloatTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SMinMax<float>), this);
  }

  /**
   * Address: 0x0040DD50 (FUN_0040DD50, Moho::SMinMaxFloatTypeInfo::dtr)
   */
  SMinMaxFloatTypeInfo::~SMinMaxFloatTypeInfo() = default;

  /**
   * Address: 0x0040DD40 (FUN_0040DD40, Moho::SMinMaxFloatTypeInfo::GetName)
   */
  const char* SMinMaxFloatTypeInfo::GetName() const
  {
    return "SMinMax<float>";
  }

  /**
   * Address: 0x0040DD00 (FUN_0040DD00, Moho::SMinMaxFloatTypeInfo::Init)
   */
  void SMinMaxFloatTypeInfo::Init()
  {
    size_ = sizeof(SMinMax<float>);
    gpg::RType::Init();
    AddSMinMaxFloatFields(this);
    Finish();
  }

  /**
   * Address: 0x0040DE10 (FUN_0040DE10, Moho::SMinMaxUint32TypeInfo::SMinMaxUint32TypeInfo)
   */
  SMinMaxUint32TypeInfo::SMinMaxUint32TypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SMinMax<std::uint32_t>), this);
  }

  /**
   * Address: 0x0040DEC0 (FUN_0040DEC0, Moho::SMinMaxUint32TypeInfo::dtr)
   */
  SMinMaxUint32TypeInfo::~SMinMaxUint32TypeInfo() = default;

  /**
   * Address: 0x0040DEB0 (FUN_0040DEB0, Moho::SMinMaxUint32TypeInfo::GetName)
   */
  const char* SMinMaxUint32TypeInfo::GetName() const
  {
    return "SMinMax<uint32>";
  }

  /**
   * Address: 0x0040DE70 (FUN_0040DE70, Moho::SMinMaxUint32TypeInfo::Init)
   */
  void SMinMaxUint32TypeInfo::Init()
  {
    size_ = sizeof(SMinMax<std::uint32_t>);
    gpg::RType::Init();
    AddFieldUInt("Min", 0);
    AddFieldUInt("Max", 4);
    Finish();
  }
} // namespace moho
