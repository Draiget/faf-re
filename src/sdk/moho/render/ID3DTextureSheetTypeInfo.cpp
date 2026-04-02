#include "moho/render/ID3DTextureSheetTypeInfo.h"

#include <cstddef>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/render/ID3DTextureSheet.h"

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
   * Address: 0x00BEF250 (FUN_00BEF250, cleanup_ID3DTextureSheetTypeInfo)
   *
   * What it does:
   * Destroys the process-global `ID3DTextureSheetTypeInfo` slot when startup
   * registration constructed it.
   */
  void cleanup_ID3DTextureSheetTypeInfo()
  {
    DestroyTypeInfoStartupSlot<ID3DTextureSheetTypeInfo>();
  }

  /**
   * Address: 0x00BC41D0 (FUN_00BC41D0, register_ID3DTextureSheetTypeInfo)
   *
   * What it does:
   * Constructs the process-global `ID3DTextureSheetTypeInfo` slot and
   * registers process-exit teardown for that slot.
   */
  void register_ID3DTextureSheetTypeInfo()
  {
    (void)AccessTypeInfoStartupSlot<ID3DTextureSheetTypeInfo>();
    (void)std::atexit(&cleanup_ID3DTextureSheetTypeInfo);
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
