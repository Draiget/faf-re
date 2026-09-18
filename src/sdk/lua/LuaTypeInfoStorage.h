#pragma once

#include <new>
#include <type_traits>

namespace lua
{
  /**
   * Raw storage for one reflection descriptor that registers itself from its
   * own constructor.
   *
   * Those descriptors have to exist before anything calls `gpg::LookupRType`
   * and must not be destroyed while the reflection map still points at them,
   * so they cannot be ordinary globals with ordinary static destructors. The
   * shape is always the same - aligned bytes, a construct-once flag,
   * placement new, and an `atexit` teardown guarded by that flag - and it is
   * the same for every descriptor type, so it belongs in one template rather
   * than being written out per type.
   *
   * The `bool` lives beside the bytes rather than inside the descriptor: the
   * object under construction must occupy exactly `sizeof(TTypeInfo)`, since
   * that is what the reflection map hands out pointers to.
   */
  template <class TTypeInfo>
  struct TypeInfoStorage
  {
    alignas(TTypeInfo) unsigned char bytes[sizeof(TTypeInfo)];
    bool constructed;
  };

  /// Constructs the descriptor on first call and returns it thereafter.
  template <class TTypeInfo>
  [[nodiscard]] TTypeInfo& EnsureTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      new (storage.bytes) TTypeInfo();
      storage.constructed = true;
    }

    return *reinterpret_cast<TTypeInfo*>(storage.bytes);
  }

  /**
   * Full teardown: runs the descriptor's destructor.
   *
   * Correct only where nothing can still reach the descriptor through the
   * reflection map - use ReleaseTypeInfoFieldStorage otherwise.
   */
  template <class TTypeInfo>
  void DestroyTypeInfo(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      return;
    }

    reinterpret_cast<TTypeInfo*>(storage.bytes)->~TTypeInfo();
    storage.constructed = false;
  }

  /**
   * Partial teardown: gives back the heap the field and base tables hold,
   * leaving the descriptor itself alive and registered.
   *
   * This is what a descriptor that stays in the reflection map for the life
   * of the process needs - destroying it would leave the map dangling, but
   * its two vectors are the only things in it that own memory.
   *
   * The member types are deduced rather than named so this header does not
   * have to pull in the reflection and container headers.
   */
  template <class TTypeInfo>
  void ReleaseTypeInfoFieldStorage(TypeInfoStorage<TTypeInfo>& storage) noexcept
  {
    if (!storage.constructed) {
      return;
    }

    TTypeInfo& typeInfo = *reinterpret_cast<TTypeInfo*>(storage.bytes);
    typeInfo.fields_ = std::remove_reference_t<decltype(typeInfo.fields_)>{};
    typeInfo.bases_ = std::remove_reference_t<decltype(typeInfo.bases_)>{};
  }
} // namespace lua
