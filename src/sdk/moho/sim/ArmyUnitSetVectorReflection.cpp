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
  using EntitySetVector = msvc8::vector<moho::EntitySetTemplate<moho::Unit>>;
  using EntitySetVectorType = gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>;

  /**
   * Address: 0x00BFF470 (FUN_00BFF470, atexit destructor of the RVectorType<EntitySetTemplate<Unit>> object)
   */
  [[nodiscard]] EntitySetVectorType* AcquireEntitySetVectorType()
  {
    static EntitySetVectorType sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetTemplateUnitType()
  {
    // UnitSetTypeInfo pre-registers this descriptor under
    // typeid(EntitySetTemplate<Unit>), and the binary resolves it the same way
    // (FUN_005EBA40 looks up `Moho::EntitySetTemplate<Moho::Unit>`).
    // EntitySetTemplate<Unit> is this recovery's own name for that type, so
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

  struct EntitySetTemplateUnitVectorTypeBootstrap
  {
    EntitySetTemplateUnitVectorTypeBootstrap()
    {
      (void)moho::register_EntitySetTemplateUnitVectorTypeStartup();
    }
  };

  EntitySetTemplateUnitVectorTypeBootstrap gEntitySetTemplateUnitVectorTypeBootstrap;
} // namespace

/**
 * Address: 0x00704B40 (FUN_00704B40, gpg::RRef_EntitySetTemplateUnit)
 *
 * What it does:
 * Builds one reflected reference lane for `EntitySetTemplate<Unit>`.
 */
gpg::RRef* gpg::RRef_UnitSetBase(gpg::RRef* const outRef, moho::EntitySetTemplate<moho::Unit>* const value)
{
  if (outRef == nullptr) {
    return nullptr;
  }

  outRef->mObj = value;
  outRef->mType = ResolveEntitySetTemplateUnitType();
  return outRef;
}

/**
 * Address: 0x00705320 (FUN_00705320, gpg::MakeUnitSetDerivedRef)
 *
 * What it does:
 * Builds one reflected reference for `EntitySetTemplate<Unit>`, resolving
 * the value's dynamic type and adjusting the object pointer to the base
 * offset `IsDerivedFrom` reports (the general derived-ref pattern used
 * throughout this codebase's reflection glue, `MakeDerivedRef`). This is
 * the version `RVectorType<EntitySetTemplate<Unit>>::SubscriptIndex`
 * (0x00701850) actually calls per-element on every vector subscript;
 * `RRef_UnitSetBase` above is a separate, simpler binary
 * function used by other callers.
 */
gpg::RRef* gpg::MakeUnitSetDerivedRef(gpg::RRef* const outRef, moho::EntitySetTemplate<moho::Unit>* const value)
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
 * Address: 0x00704C60 (FUN_00704C60, gpg::RVectorType<Moho::EntitySetTemplate<Unit>>::dtr)
 *
 * What it does:
 * Tears down one `RVectorType<EntitySetTemplate<Unit>>` descriptor and
 * releases inherited `gpg::RType` reflection storage lanes.
 */
gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::~RVectorType() = default;

/**
 * Address: 0x00701680 (FUN_00701680, gpg::RVectorType<Moho::EntitySetTemplate<Unit>>::GetName)
 * Address: 0x00BFF440 (FUN_00BFF440, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds `vector<EntitySetTemplate<Unit>>` once, through the shared
 * `EntitySetTemplate<Unit>::sType` cache, and returns it.
 */
const char* gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::GetName() const
{
  static const msvc8::string sName = gpg::STR_Printf("vector<%s>", CachedEntitySetTemplateUnitReflType()->GetName());
  return sName.c_str();
}

/**
 * Address: 0x00701740 (FUN_00701740, gpg::RVectorType<Moho::EntitySetTemplate<Unit>>::GetLexical)
 *
 * What it does:
 * Appends the element count to the base `RType::GetLexical` text, matching
 * the binary's `"%s, size=%d"` formatting of the inherited lexical form.
 */
msvc8::string gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

const gpg::RIndexed* gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::IsIndexed() const
{
  return this;
}

void gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::Init()
{
  size_ = sizeof(EntitySetVector);
  version_ = 1;
}

gpg::RRef gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::SubscriptIndex(void* const obj, const int ind) const
{
  auto* const storage = static_cast<EntitySetVector*>(obj);
  GPG_ASSERT(storage != nullptr);
  GPG_ASSERT(ind >= 0);
  GPG_ASSERT(static_cast<std::size_t>(ind) < storage->size());

  gpg::RRef out{};
  gpg::MakeUnitSetDerivedRef(&out, nullptr);
  if (storage == nullptr || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::MakeUnitSetDerivedRef(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

size_t gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const EntitySetVector*>(obj);
  return storage ? storage->size() : 0u;
}

void gpg::RVectorType<moho::EntitySetTemplate<moho::Unit>>::SetCount(void* const obj, const int count) const
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
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::EntitySetTemplate<moho::Unit>>), type);
  return type;
}

/**
 * Address: 0x00BD9C60 (FUN_00BD9C60, sub_BD9C60)
 *
 * What it does:
 * Registers `vector<EntitySetTemplate<Unit>>` reflection.
 */
void moho::register_EntitySetTemplateUnitVectorTypeStartup()
{
  (void)register_EntitySetTemplateUnitVectorType();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EntitySetTemplateUnitVectorType_50022b, moho::register_EntitySetTemplateUnitVectorType)
