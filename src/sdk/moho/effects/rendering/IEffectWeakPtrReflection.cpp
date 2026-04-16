#include "moho/effects/rendering/IEffectWeakPtrReflection.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/Global.h"
#include "moho/effects/rendering/IEffect.h"

#pragma init_seg(lib)

namespace
{
  using WeakPtrIEffectType = moho::RWeakPtrType<moho::IEffect>;

  alignas(WeakPtrIEffectType) unsigned char gWeakPtrIEffectTypeStorage[sizeof(WeakPtrIEffectType)];
  bool gWeakPtrIEffectTypeConstructed = false;

  msvc8::string gWeakPtrIEffectTypeName;
  bool gWeakPtrIEffectTypeNameCleanupRegistered = false;

  [[nodiscard]] WeakPtrIEffectType* AcquireWeakPtrIEffectType()
  {
    if (!gWeakPtrIEffectTypeConstructed) {
      new (gWeakPtrIEffectTypeStorage) WeakPtrIEffectType();
      gWeakPtrIEffectTypeConstructed = true;
    }
    return reinterpret_cast<WeakPtrIEffectType*>(gWeakPtrIEffectTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedIEffectType()
  {
    gpg::RType* cached = moho::IEffect::sType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IEffect));
      moho::IEffect::sType = cached;
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeIEffectRef(moho::IEffect* effect)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIEffectType();
    if (!effect) {
      return out;
    }

    gpg::RType* dynamicType = CachedIEffectType();
    try {
      dynamicType = gpg::LookupRType(typeid(*effect));
    } catch (...) {
      dynamicType = CachedIEffectType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived =
      dynamicType != nullptr && CachedIEffectType() != nullptr && dynamicType->IsDerivedFrom(CachedIEffectType(), &baseOffset);

    out.mObj = isDerived
      ? reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(effect) - static_cast<std::uintptr_t>(baseOffset))
      : static_cast<void*>(effect);
    out.mType = dynamicType ? dynamicType : CachedIEffectType();
    return out;
  }

  [[nodiscard]] moho::IEffect* ReadPointerIEffect(gpg::ReadArchive* const archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIEffectType());
    if (upcast.mObj) {
      return static_cast<moho::IEffect*>(upcast.mObj);
    }

    const char* const expected = CachedIEffectType() ? CachedIEffectType()->GetName() : "IEffect";
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" instead",
      expected ? expected : "IEffect",
      actual ? actual : "null"
    );
    throw gpg::SerializationError(msg.c_str());
  }

  /**
   * Address: 0x00BFC400 (FUN_00BFC400, cleanup_WeakPtrIEffectTypeName)
   */
  void cleanup_WeakPtrIEffectTypeName()
  {
    gWeakPtrIEffectTypeName = msvc8::string{};
    gWeakPtrIEffectTypeNameCleanupRegistered = false;
  }

  struct IEffectWeakPtrReflectionBootstrap
  {
    IEffectWeakPtrReflectionBootstrap()
    {
      (void)moho::register_WeakPtr_IEffect_Type_AtExit();
    }
  };

  IEffectWeakPtrReflectionBootstrap gIEffectWeakPtrReflectionBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0066A1D0 (FUN_0066A1D0)
   *
   * What it does:
   * Rebinds one `WeakPtr<IEffect>` node to a new owner link and updates the
   * intrusive owner chain in-place without allocating.
   */
  WeakPtr<IEffect>* RelinkWeakPtrIEffect(WeakPtr<IEffect>* const weak, IEffect* const effect) noexcept
  {
    if (weak == nullptr) {
      return nullptr;
    }

    weak->ResetFromObject(effect);
    return weak;
  }

  /**
   * Address: 0x006751B0 (FUN_006751B0, Moho::WeakPtr_IEffect::Deserialize)
   */
  void WeakPtr_IEffect::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<IEffect>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    (void)RelinkWeakPtrIEffect(weak, ReadPointerIEffect(archive, owner));
  }

  /**
   * Address: 0x006751E0 (FUN_006751E0, Moho::WeakPtr_IEffect::Serialize)
   */
  void WeakPtr_IEffect::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef* ownerRef)
  {
    auto* const weak = reinterpret_cast<WeakPtr<IEffect>*>(objectPtr);
    if (!archive || !weak) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    const gpg::RRef objectRef = MakeIEffectRef(weak->GetObjectPtr());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, owner);
  }

  /**
   * Address: 0x006748B0 (FUN_006748B0, Moho::RWeakPtrType_IEffect::GetName)
   */
  const char* RWeakPtrType<IEffect>::GetName() const
  {
    if (gWeakPtrIEffectTypeName.empty()) {
      const char* const pointeeName = CachedIEffectType() ? CachedIEffectType()->GetName() : "IEffect";
      gWeakPtrIEffectTypeName = gpg::STR_Printf("WeakPtr<%s>", pointeeName ? pointeeName : "IEffect");
      if (!gWeakPtrIEffectTypeNameCleanupRegistered) {
        gWeakPtrIEffectTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_WeakPtrIEffectTypeName);
      }
    }

    return gWeakPtrIEffectTypeName.c_str();
  }

  /**
   * Address: 0x00674970 (FUN_00674970, Moho::RWeakPtrType_IEffect::GetLexical)
   */
  msvc8::string RWeakPtrType<IEffect>::GetLexical(const gpg::RRef& ref) const
  {
    auto* const weak = static_cast<const WeakPtr<IEffect>*>(ref.mObj);
    if (!weak || !weak->HasValue()) {
      return msvc8::string("NULL");
    }

    const gpg::RRef pointeeRef = MakeIEffectRef(weak->GetObjectPtr());
    if (!pointeeRef.mObj) {
      return msvc8::string("NULL");
    }

    const msvc8::string inner = pointeeRef.GetLexical();
    return gpg::STR_Printf("[%s]", inner.c_str());
  }

  /**
   * Address: 0x00674B00 (FUN_00674B00, Moho::RWeakPtrType_IEffect::IsIndexed)
   */
  const gpg::RIndexed* RWeakPtrType<IEffect>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00674B10 (FUN_00674B10, Moho::RWeakPtrType_IEffect::IsPointer)
   */
  const gpg::RIndexed* RWeakPtrType<IEffect>::IsPointer() const
  {
    return this;
  }

  /**
   * Address: 0x00674950 (FUN_00674950, Moho::RWeakPtrType_IEffect::Init)
   */
  void RWeakPtrType<IEffect>::Init()
  {
    size_ = sizeof(WeakPtr<IEffect>);
    version_ = 1;
    serLoadFunc_ = &WeakPtr_IEffect::Deserialize;
    serSaveFunc_ = &WeakPtr_IEffect::Serialize;
  }

  /**
   * Address: 0x00674B50 (FUN_00674B50, Moho::RWeakPtrType_IEffect::SubscriptIndex)
   */
  gpg::RRef RWeakPtrType<IEffect>::SubscriptIndex(void* const obj, const int ind) const
  {
    GPG_ASSERT(ind == 0);

    auto* const weak = static_cast<WeakPtr<IEffect>*>(obj);
    return MakeIEffectRef(weak ? weak->GetObjectPtr() : nullptr);
  }

  /**
   * Address: 0x00674B20 (FUN_00674B20, Moho::RWeakPtrType_IEffect::GetCount)
   */
  size_t RWeakPtrType<IEffect>::GetCount(void* const obj) const
  {
    auto* const weak = static_cast<WeakPtr<IEffect>*>(obj);
    return (weak && weak->HasValue()) ? 1u : 0u;
  }

  /**
   * Address: 0x00675A50 (FUN_00675A50, register_WeakPtr_IEffect_Type_00)
   */
  gpg::RType* register_WeakPtr_IEffect_Type_00()
  {
    WeakPtrIEffectType* const type = AcquireWeakPtrIEffectType();
    gpg::PreRegisterRType(typeid(WeakPtr<IEffect>), type);
    return type;
  }

  /**
   * Address: 0x00BFC4F0 (FUN_00BFC4F0, cleanup_WeakPtr_IEffect_Type)
   */
  void cleanup_WeakPtr_IEffect_Type()
  {
    if (!gWeakPtrIEffectTypeConstructed) {
      return;
    }

    AcquireWeakPtrIEffectType()->~WeakPtrIEffectType();
    gWeakPtrIEffectTypeConstructed = false;
  }

  /**
   * Address: 0x00BD4DD0 (FUN_00BD4DD0, register_WeakPtr_IEffect_Type_AtExit)
   */
  int register_WeakPtr_IEffect_Type_AtExit()
  {
    (void)register_WeakPtr_IEffect_Type_00();
    return std::atexit(&cleanup_WeakPtr_IEffect_Type);
  }
} // namespace moho
