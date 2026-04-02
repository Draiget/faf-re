#include "moho/net/INetNATTraversalProviderWeakPtrReflection.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

namespace
{
  using WeakProviderPtr = boost::weak_ptr<moho::INetNATTraversalProvider>;

  [[nodiscard]] gpg::RType* CachedProviderType()
  {
    return moho::INetNATTraversalProvider::StaticGetClass();
  }

  [[nodiscard]] gpg::RType* CachedWeakProviderType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(WeakProviderPtr));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeWeakProviderRef(WeakProviderPtr* weakProvider)
  {
    gpg::RRef out{};
    out.mObj = weakProvider;
    out.mType = CachedWeakProviderType();
    return out;
  }

  /**
   * Address: 0x004821F0 (FUN_004821F0)
   *
   * What it does:
   * Upcasts generic reflection reference to weak-pointer storage or throws on
   * type mismatch.
   */
  [[nodiscard]] WeakProviderPtr* TryUpcastWeakProviderOrThrow(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedWeakProviderType());
    if (!upcast.mObj) {
      throw std::bad_cast{};
    }
    return static_cast<WeakProviderPtr*>(upcast.mObj);
  }

  /**
   * Address: 0x004823B0 (FUN_004823B0)
   *
   * What it does:
   * Builds reflected object reference for NAT traversal provider pointer and
   * preserves most-derived complete-object pointer semantics.
   */
  [[nodiscard]] gpg::RRef MakeProviderRef(moho::INetNATTraversalProvider* provider)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedProviderType();
    if (!provider) {
      return out;
    }

    gpg::RType* dynamicType = CachedProviderType();
    try {
      dynamicType = gpg::LookupRType(typeid(*provider));
    } catch (...) {
      dynamicType = CachedProviderType();
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType->IsDerivedFrom(CachedProviderType(), &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mObj = provider;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(provider) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x00481ED0 (FUN_00481ED0)
   */
  gpg::RRef NewWeakProviderRef()
  {
    return MakeWeakProviderRef(new WeakProviderPtr{});
  }

  /**
   * Address: 0x00481F20 (FUN_00481F20)
   */
  gpg::RRef CopyWeakProviderRef(gpg::RRef* sourceRef)
  {
    auto* const weakProvider = new WeakProviderPtr{};
    if (sourceRef) {
      *weakProvider = *TryUpcastWeakProviderOrThrow(*sourceRef);
    }
    return MakeWeakProviderRef(weakProvider);
  }

  /**
   * Address: 0x00481FC0 (FUN_00481FC0)
   */
  void DeleteWeakProvider(void* storage)
  {
    delete static_cast<WeakProviderPtr*>(storage);
  }

  /**
   * Address: 0x00481FF0 (FUN_00481FF0)
   */
  gpg::RRef CtorWeakProviderRef(void* storage)
  {
    auto* const weakProvider = static_cast<WeakProviderPtr*>(storage);
    if (weakProvider) {
      new (weakProvider) WeakProviderPtr{};
    }
    return MakeWeakProviderRef(weakProvider);
  }

  /**
   * Address: 0x00482030 (FUN_00482030)
   */
  gpg::RRef MoveWeakProviderRef(void* storage, gpg::RRef* sourceRef)
  {
    auto* const weakProvider = static_cast<WeakProviderPtr*>(storage);
    if (weakProvider) {
      new (weakProvider) WeakProviderPtr{};
      if (sourceRef) {
        *weakProvider = *TryUpcastWeakProviderOrThrow(*sourceRef);
      }
    }
    return MakeWeakProviderRef(weakProvider);
  }

  /**
   * Address: 0x004820C0 (FUN_004820C0)
   */
  void DtrWeakProvider(void* storage)
  {
    auto* const weakProvider = static_cast<WeakProviderPtr*>(storage);
    if (weakProvider) {
      weakProvider->~WeakProviderPtr();
    }
  }

  gpg::RWeakPointerType<moho::INetNATTraversalProvider> gWeakProviderType;

  struct WeakProviderTypeRegistration
  {
    WeakProviderTypeRegistration()
    {
      gpg::PreRegisterRType(typeid(WeakProviderPtr), &gWeakProviderType);
    }
  };

  WeakProviderTypeRegistration gWeakProviderTypeRegistration;
} // namespace

gpg::RType* gpg::ResolveWeakPtrINetNATTraversalProviderType()
{
  return gpg::LookupRType(typeid(WeakProviderPtr));
}

/**
 * Address: 0x00482350 (FUN_00482350)
 */
gpg::RWeakPointerType<moho::INetNATTraversalProvider>::~RWeakPointerType() = default;

/**
 * Address: 0x00481A00 (FUN_00481A00, gpg::RWeakPointerType_INetNATTraversalProvider::GetName)
 */
const char* gpg::RWeakPointerType<moho::INetNATTraversalProvider>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const char* const providerTypeName = CachedProviderType()->GetName();
    sName = gpg::STR_Printf("boost::weak_ptr<%s>", providerTypeName ? providerTypeName : "INetNATTraversalProvider");
  }
  return sName.c_str();
}

/**
 * Address: 0x00481AE0 (FUN_00481AE0)
 */
msvc8::string gpg::RWeakPointerType<moho::INetNATTraversalProvider>::GetLexical(const gpg::RRef& ref) const
{
  auto* const weakProvider = static_cast<const WeakProviderPtr*>(ref.mObj);
  if (!weakProvider) {
    return msvc8::string("NULL");
  }

  const boost::shared_ptr<moho::INetNATTraversalProvider> locked = weakProvider->lock();
  if (!locked) {
    return msvc8::string("NULL");
  }

  const gpg::RRef providerRef = MakeProviderRef(locked.get());
  if (!providerRef.mObj) {
    return msvc8::string("NULL");
  }

  const msvc8::string inner = providerRef.GetLexical();
  return gpg::STR_Printf("[%s]", inner.c_str());
}

/**
 * Address: 0x00481AA0 (FUN_00481AA0)
 */
void gpg::RWeakPointerType<moho::INetNATTraversalProvider>::Init()
{
  size_ = 0x08;
  newRefFunc_ = &NewWeakProviderRef;
  cpyRefFunc_ = &CopyWeakProviderRef;
  deleteFunc_ = &DeleteWeakProvider;
  ctorRefFunc_ = &CtorWeakProviderRef;
  movRefFunc_ = &MoveWeakProviderRef;
  dtrFunc_ = &DtrWeakProvider;
}

