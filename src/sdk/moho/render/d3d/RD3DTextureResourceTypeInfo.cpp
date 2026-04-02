#include "moho/render/d3d/RD3DTextureResourceTypeInfo.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  template <typename T>
  struct TypeInfoStartupSlot
  {
    alignas(T) static std::byte storage[sizeof(T)];
    static bool constructed;
  };

  template <typename T>
  alignas(T) std::byte TypeInfoStartupSlot<T>::storage[sizeof(T)]{};

  template <typename T>
  bool TypeInfoStartupSlot<T>::constructed = false;

  template <typename T>
  [[nodiscard]] T& AccessTypeInfoStartupSlot() noexcept
  {
    auto* const slot = reinterpret_cast<T*>(TypeInfoStartupSlot<T>::storage);
    if (!TypeInfoStartupSlot<T>::constructed) {
      ::new (static_cast<void*>(slot)) T();
      TypeInfoStartupSlot<T>::constructed = true;
    }
    return *slot;
  }

  template <typename T>
  void DestroyTypeInfoStartupSlot() noexcept
  {
    if (!TypeInfoStartupSlot<T>::constructed) {
      return;
    }

    AccessTypeInfoStartupSlot<T>().~T();
    TypeInfoStartupSlot<T>::constructed = false;
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
   * Address: 0x00BEF2B0 (FUN_00BEF2B0, cleanup_RD3DTextureResourceTypeInfo)
   *
   * What it does:
   * Destroys the process-global `RD3DTextureResourceTypeInfo` slot when
   * startup registration constructed it.
   */
  void cleanup_RD3DTextureResourceTypeInfo()
  {
    DestroyTypeInfoStartupSlot<RD3DTextureResourceTypeInfo>();
  }

  /**
   * Address: 0x00BC41F0 (FUN_00BC41F0, register_RD3DTextureResourceTypeInfo)
   *
   * What it does:
   * Constructs the process-global `RD3DTextureResourceTypeInfo` slot and
   * registers process-exit teardown for that slot.
   */
  void register_RD3DTextureResourceTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<RD3DTextureResourceTypeInfo>();
    (void)std::atexit(&cleanup_RD3DTextureResourceTypeInfo);
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
