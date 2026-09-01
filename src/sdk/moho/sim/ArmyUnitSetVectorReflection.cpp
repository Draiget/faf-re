#include "moho/sim/ArmyUnitSetVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/entity/Entity.h"
#include "moho/unit/core/Unit.h"

namespace
{
  using EntitySetVector = msvc8::vector<moho::SEntitySetTemplateUnit>;
  using EntitySetVectorType = gpg::RVectorType<moho::SEntitySetTemplateUnit>;

  alignas(EntitySetVectorType) unsigned char gEntitySetVectorTypeStorage[sizeof(EntitySetVectorType)];
  bool gEntitySetVectorTypeConstructed = false;

  [[nodiscard]] EntitySetVectorType* AcquireEntitySetVectorType()
  {
    if (!gEntitySetVectorTypeConstructed) {
      new (gEntitySetVectorTypeStorage) EntitySetVectorType();
      gEntitySetVectorTypeConstructed = true;
    }
    return reinterpret_cast<EntitySetVectorType*>(gEntitySetVectorTypeStorage);
  }

  [[nodiscard]] EntitySetVectorType* PeekEntitySetVectorType() noexcept
  {
    if (!gEntitySetVectorTypeConstructed) {
      return nullptr;
    }
    return reinterpret_cast<EntitySetVectorType*>(gEntitySetVectorTypeStorage);
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetTemplateUnitType()
  {
    // UnitSetTypeInfo pre-registers this descriptor under
    // typeid(EntitySetTemplate<Unit>), and the binary resolves it the same way
    // (FUN_005EBA40 looks up `Moho::EntitySetTemplate<Moho::Unit>`).
    // SEntitySetTemplateUnit is this recovery's own name for that type, so
    // nothing ever registers it - and since LookupRType throws on a miss, the
    // name-based candidate search that used to follow was unreachable.
    return gpg::LookupRType(typeid(moho::EntitySetTemplate<moho::Unit>));
  }

  /**
   * Cached lookup of the same `EntitySetTemplate<Unit>` RTTI descriptor,
   * mirroring the binary's own `sType`-style cache (confirmed against
   * FUN_00705320's disassembly: a static slot checked before falling back to
   * `LookupRType`). `ResolveEntitySetTemplateUnitType()` above re-resolves on
   * every call and is kept as-is for its own existing callers; this cached
   * accessor is for the `MakeDerivedRef` path below, which the binary calls
   * far more often (every vector-subscript access).
   */
  [[nodiscard]] gpg::RType* CachedEntitySetTemplateUnitReflType()
  {
    gpg::RType* type = moho::EntitySetTemplate<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetTemplate<moho::Unit>));
      moho::EntitySetTemplate<moho::Unit>::sType = type;
    }
    return type;
  }

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
  }

  /**
   * Address: 0x00BFF470 (FUN_00BFF470, sub_BFF470)
   *
   * What it does:
   * Tears down `vector<EntitySetTemplate<Unit>>` reflection storage lanes
   * at process exit.
   */
  void cleanup_EntitySetTemplateUnitVectorType()
  {
    EntitySetVectorType* const type = PeekEntitySetVectorType();
    if (type == nullptr) {
      return;
    }

    type->~EntitySetVectorType();
    gEntitySetVectorTypeConstructed = false;
  }

  msvc8::string gEntitySetTemplateUnitVectorTypeName;

  /**
   * Address: 0x00BFF440 (FUN_00BFF440, vector<EntitySetTemplate<Unit>> name-cache cleanup)
   *
   * What it does:
   * Releases the cached lexical name for `vector<EntitySetTemplate<Unit>>`
   * during process teardown.
   */
  void cleanup_EntitySetTemplateUnitVectorTypeName()
  {
    gEntitySetTemplateUnitVectorTypeName = msvc8::string{};
  }

  struct EntitySetTemplateUnitVectorTypeBootstrap
  {
    EntitySetTemplateUnitVectorTypeBootstrap()
    {
      (void)moho::register_EntitySetTemplateUnitVectorType_AtExit();
    }
  };

  EntitySetTemplateUnitVectorTypeBootstrap gEntitySetTemplateUnitVectorTypeBootstrap;
} // namespace

/**
 * Address: 0x00704B40 (FUN_00704B40, gpg::RRef_EntitySetTemplateUnit)
 *
 * What it does:
 * Builds one reflected reference lane for `SEntitySetTemplateUnit`.
 */
gpg::RRef* gpg::RRef_SEntitySetTemplateUnit(gpg::RRef* const outRef, moho::SEntitySetTemplateUnit* const value)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  outRef->mObj = value;
  outRef->mType = ResolveEntitySetTemplateUnitType();
  return outRef;
}

/**
 * Address: 0x00705320 (FUN_00705320, gpg::RRef_EntitySetTemplate_Unit)
 *
 * What it does:
 * Builds one reflected reference for `EntitySetTemplate<Unit>`, resolving
 * the value's dynamic type and adjusting the object pointer to the base
 * offset `IsDerivedFrom` reports (the general derived-ref pattern used
 * throughout this codebase's reflection glue, `MakeDerivedRef`). This is
 * the version `RVectorType<SEntitySetTemplateUnit>::SubscriptIndex`
 * (0x00701850) actually calls per-element on every vector subscript;
 * `RRef_SEntitySetTemplateUnit` above is a separate, simpler binary
 * function used by other callers.
 */
gpg::RRef* gpg::RRef_EntitySetTemplate_Unit(gpg::RRef* const outRef, moho::SEntitySetTemplateUnit* const value)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  *outRef = MakeDerivedRef(value, CachedEntitySetTemplateUnitReflType());
  return outRef;
}

gpg::RType* gpg::ResolveEntitySetTemplateUnitVectorType()
{
  return moho::register_EntitySetTemplateUnitVectorType();
}

/**
 * Address: 0x00704C60 (FUN_00704C60, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::dtr)
 *
 * What it does:
 * Tears down one `RVectorType<SEntitySetTemplateUnit>` descriptor and
 * releases inherited `gpg::RType` reflection storage lanes.
 */
gpg::RVectorType<moho::SEntitySetTemplateUnit>::~RVectorType() = default;

/**
 * Address: 0x00701680 (FUN_00701680, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::GetName)
 *
 * What it does:
 * Lazily resolves the reflected `EntitySetTemplate<Unit>` element type name
 * through the shared `EntitySetTemplate<Unit>::sType` cache, formats
 * "vector<%s>", caches the result, and registers its teardown with
 * `atexit` -- all under one once-guard, matching the binary's static-init
 * guard byte.
 */
const char* gpg::RVectorType<moho::SEntitySetTemplateUnit>::GetName() const
{
  if (gEntitySetTemplateUnitVectorTypeName.empty()) {
    gEntitySetTemplateUnitVectorTypeName =
      gpg::STR_Printf("vector<%s>", CachedEntitySetTemplateUnitReflType()->GetName());
    (void)std::atexit(&cleanup_EntitySetTemplateUnitVectorTypeName);
  }
  return gEntitySetTemplateUnitVectorTypeName.c_str();
}

/**
 * Address: 0x00701740 (FUN_00701740, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::GetLexical)
 *
 * What it does:
 * Appends the element count to the base `RType::GetLexical` text, matching
 * the binary's `"%s, size=%d"` formatting of the inherited lexical form.
 */
msvc8::string gpg::RVectorType<moho::SEntitySetTemplateUnit>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

const gpg::RIndexed* gpg::RVectorType<moho::SEntitySetTemplateUnit>::IsIndexed() const
{
  return this;
}

void gpg::RVectorType<moho::SEntitySetTemplateUnit>::Init()
{
  size_ = sizeof(EntitySetVector);
  version_ = 1;
}

gpg::RRef gpg::RVectorType<moho::SEntitySetTemplateUnit>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<EntitySetVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  gpg::RRef_EntitySetTemplate_Unit(&out, nullptr);
  if (storage == nullptr || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_EntitySetTemplate_Unit(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

size_t gpg::RVectorType<moho::SEntitySetTemplateUnit>::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const EntitySetVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType<moho::SEntitySetTemplateUnit>::SetCount(void* const obj, const int count) const
{
  auto* const storage = static_cast<EntitySetVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(count >= 0);
  if (storage == nullptr || count < 0) {
    return;
  }

  storage->resize(static_cast<std::size_t>(count));
}

/**
 * Address: 0x00704B90 (FUN_00704B90, sub_704B90)
 *
 * What it does:
 * Constructs/preregisters RTTI for `vector<EntitySetTemplate<Unit>>`.
 */
gpg::RType* moho::register_EntitySetTemplateUnitVectorType()
{
  EntitySetVectorType* const type = AcquireEntitySetVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SEntitySetTemplateUnit>), type);
  return type;
}

/**
 * Address: 0x00BD9C60 (FUN_00BD9C60, sub_BD9C60)
 *
 * What it does:
 * Registers `vector<EntitySetTemplate<Unit>>` reflection and installs
 * process-exit teardown via `atexit`.
 */
int moho::register_EntitySetTemplateUnitVectorType_AtExit()
{
  (void)register_EntitySetTemplateUnitVectorType();
  return std::atexit(&cleanup_EntitySetTemplateUnitVectorType);
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EntitySetTemplateUnitVectorType_50022b, moho::register_EntitySetTemplateUnitVectorType)
