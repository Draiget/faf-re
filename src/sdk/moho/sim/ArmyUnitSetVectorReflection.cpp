#include "moho/sim/ArmyUnitSetVectorReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>
#include <utility>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"

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
    gpg::RType* type = gpg::LookupRType(typeid(moho::SEntitySetTemplateUnit));
    if (type != nullptr) {
      return type;
    }

    constexpr const char* kTypeNameCandidates[] = {
      "Moho::EntitySetTemplate<Moho::Unit>",
      "EntitySetTemplate<Unit>",
      "SEntitySetTemplateUnit"
    };
    for (const char* const name : kTypeNameCandidates) {
      type = gpg::REF_FindTypeNamed(name);
      if (type != nullptr) {
        return type;
      }
    }

    return nullptr;
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

gpg::RType* gpg::ResolveEntitySetTemplateUnitVectorType()
{
  return moho::register_EntitySetTemplateUnitVectorType();
}

const char* gpg::RVectorType<moho::SEntitySetTemplateUnit>::GetName() const
{
  static msvc8::string sName;
  if (sName.empty()) {
    const gpg::RType* const elementType = ResolveEntitySetTemplateUnitType();
    const char* const elementName = elementType ? elementType->GetName() : "EntitySetTemplate<Unit>";
    sName = gpg::STR_Printf("vector<%s>", elementName ? elementName : "EntitySetTemplate<Unit>");
  }
  return sName.c_str();
}

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
  gpg::RRef_SEntitySetTemplateUnit(&out, nullptr);
  if (storage == nullptr || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SEntitySetTemplateUnit(&out, &(*storage)[static_cast<std::size_t>(ind)]);
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
