#include "gpg/core/reflection/RMapStringFloatTypeInfo.h"

#include <cstdlib>
#include <map>
#include <new>
#include <string>
#include <typeinfo>

namespace
{
  using TypeInfo = gpg::RMapStringFloatTypeInfo;

  alignas(TypeInfo) unsigned char gMapStringFloatTypeInfoStorage[sizeof(TypeInfo)];
  bool gMapStringFloatTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireMapStringFloatTypeInfo()
  {
    if (!gMapStringFloatTypeInfoConstructed) {
      new (gMapStringFloatTypeInfoStorage) TypeInfo();
      gMapStringFloatTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gMapStringFloatTypeInfoStorage);
  }

  void CleanupMapStringFloatTypeInfoAtExit()
  {
    gpg::cleanup_MapStringFloat_Type();
  }

  struct MapStringFloatTypeInfoBootstrap
  {
    MapStringFloatTypeInfoBootstrap()
    {
      (void)gpg::register_MapStringFloat_Type_AtExit();
    }
  };

  [[maybe_unused]] MapStringFloatTypeInfoBootstrap gMapStringFloatTypeInfoBootstrap;
} // namespace

namespace gpg
{
  /**
   * What it does:
   * Returns the reflected type label for `std::map<std::string,float>`.
   */
  const char* RMapStringFloatTypeInfo::GetName() const
  {
    return "std::map<std::string,float>";
  }

  /**
   * What it does:
   * Initializes reflected map-type metadata and finalizes the descriptor.
   */
  void RMapStringFloatTypeInfo::Init()
  {
    size_ = sizeof(std::map<std::string, float>);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x006B16B0 (FUN_006B16B0, register_MapStringFloat_Type_00)
   */
  gpg::RType* register_MapStringFloat_Type_00()
  {
    TypeInfo& typeInfo = AcquireMapStringFloatTypeInfo();
    gpg::PreRegisterRType(typeid(std::map<std::string, float>), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFDBE0 (FUN_00BFDBE0, cleanup_MapStringFloat_Type)
   */
  void cleanup_MapStringFloat_Type()
  {
    if (!gMapStringFloatTypeInfoConstructed) {
      return;
    }

    AcquireMapStringFloatTypeInfo().~RMapStringFloatTypeInfo();
    gMapStringFloatTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD6BC0 (FUN_00BD6BC0, register_MapStringFloat_Type_AtExit)
   */
  int register_MapStringFloat_Type_AtExit()
  {
    (void)register_MapStringFloat_Type_00();
    return std::atexit(&CleanupMapStringFloatTypeInfoAtExit);
  }
} // namespace gpg
