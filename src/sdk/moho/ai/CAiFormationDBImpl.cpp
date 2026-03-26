#include "moho/ai/CAiFormationDBImpl.h"

#include <cstddef>
#include <cstdint>

#include "lua/LuaObject.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/Sim.h"

using namespace moho;

namespace
{
  constexpr const char* kFormationModulePath = "/lua/formations.lua";
  constexpr const char* kFormationBuckets[] = {
    "SurfaceFormations",
    "AirFormations",
  };
  constexpr int kFormationBucketCount = static_cast<int>(sizeof(kFormationBuckets) / sizeof(kFormationBuckets[0]));

  [[nodiscard]] int ToFormationBucketIndex(const EFormationType type)
  {
    const int bucket = static_cast<int>(type);
    if (bucket < 0 || bucket >= kFormationBucketCount) {
      return 0;
    }
    return bucket;
  }

  [[nodiscard]] LuaPlus::LuaObject ResolveFormationBucket(LuaPlus::LuaState* state, const EFormationType formationType)
  {
    LuaPlus::LuaObject module = SCR_ImportLuaModule(state, kFormationModulePath);
    if (!module || !module.IsTable()) {
      return {};
    }

    const char* const bucketName = kFormationBuckets[ToFormationBucketIndex(formationType)];
    LuaPlus::LuaObject bucket = SCR_GetLuaTableField(state, module, bucketName);
    if (!bucket.IsTable()) {
      return {};
    }

    return bucket;
  }

  void UnlinkLinkedIUnitRef(SFormationLinkedUnitRef& linkRef) noexcept
  {
    if (!linkRef.ownerChainHead) {
      return;
    }

    std::uint32_t* cursor = linkRef.ownerChainHead;
    const std::uint32_t selfWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&linkRef));
    while (*cursor != selfWord) {
      cursor = SFormationLinkedUnitRef::NextChainLinkSlot(*cursor);
    }

    *cursor = linkRef.nextChainLink;
    linkRef.ownerChainHead = nullptr;
    linkRef.nextChainLink = 0;
  }

  class ScopedLinkedIUnitRefs final
  {
  public:
    explicit ScopedLinkedIUnitRefs(const SFormationUnitWeakRefSet* const unitWeakSet)
    {
      if (!unitWeakSet) {
        return;
      }

      const SFormationUnitWeakRef* const begin = unitWeakSet->begin();
      const SFormationUnitWeakRef* const end = unitWeakSet->end();
      if (!begin || begin == end) {
        return;
      }

      const std::size_t count = static_cast<std::size_t>(end - begin);
      mLinkedRefs.Reserve(count);
      for (const SFormationUnitWeakRef* src = begin; src != end; ++src) {
        SFormationLinkedUnitRef linkedValue{};
        mLinkedRefs.Append(linkedValue);
        SFormationLinkedUnitRef& linked = mLinkedRefs.back();
        linked.ownerChainHead = src->DecodeOwnerChainHead();
        if (!linked.ownerChainHead) {
          linked.nextChainLink = 0;
          continue;
        }

        linked.nextChainLink = *linked.ownerChainHead;
        *linked.ownerChainHead = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(&linked));
      }
    }

    ~ScopedLinkedIUnitRefs()
    {
      for (SFormationLinkedUnitRef* it = mLinkedRefs.begin(); it != mLinkedRefs.end(); ++it) {
        UnlinkLinkedIUnitRef(*it);
      }
    }

    [[nodiscard]] const gpg::fastvector_n<SFormationLinkedUnitRef, 4>& refs() const noexcept
    {
      return mLinkedRefs;
    }

  private:
    gpg::fastvector_n<SFormationLinkedUnitRef, 4> mLinkedRefs;
  };

  [[nodiscard]] CAiFormationInstance* TryConstructFormationInstance(
    CAiFormationDBImpl& formationDb,
    const char* scriptName,
    const SCoordsVec2* formationCenter,
    const float orientX,
    const float orientY,
    const float orientZ,
    const float orientW,
    const int commandType,
    const gpg::fastvector_n<SFormationLinkedUnitRef, 4>& linkedUnits
  )
  {
    (void)formationDb;
    (void)scriptName;
    (void)formationCenter;
    (void)orientX;
    (void)orientY;
    (void)orientZ;
    (void)orientW;
    (void)commandType;
    (void)linkedUnits;

    // Full constructor lift remains blocked on unresolved CFormationInstance path:
    // - FUN_005694B0 (constructor)
    // - FUN_0056B200 and dependent container helpers it initializes.
    return nullptr;
  }
} // namespace

/**
 * Address: 0x0059C340 (FUN_0059C340)
 */
CAiFormationDBImpl::~CAiFormationDBImpl()
{
  // Mirrors FUN_0059BFE0 storage teardown semantics before base destruction.
  mFormInstances.ResetStorageToInline();
}

/**
 * Address: 0x0059C030 (FUN_0059C030)
 */
void CAiFormationDBImpl::Update()
{
  for (CAiFormationInstance** it = mFormInstances.begin(); it != mFormInstances.end(); ++it) {
    (*it)->Update();
  }
}

/**
 * Address: 0x0059C060 (FUN_0059C060)
 */
void CAiFormationDBImpl::RemoveFormation(CAiFormationInstance* const formation)
{
  CAiFormationInstance** begin = mFormInstances.begin();
  CAiFormationInstance** end = mFormInstances.end();
  for (CAiFormationInstance** it = begin; it != end; ++it) {
    if (*it != formation) {
      continue;
    }

    for (CAiFormationInstance **src = it + 1, **dst = it; src != end; ++src, ++dst) {
      *dst = *src;
    }

    const std::size_t newSize = static_cast<std::size_t>((end - begin) - 1);
    mFormInstances.SetSizeUnchecked(newSize);
    return;
  }
}

/**
 * Address: 0x0059C0C0 (FUN_0059C0C0)
 */
const char* CAiFormationDBImpl::GetScriptName(const int scriptIndex, const EFormationType formationType)
{
  if (!mSim || !mSim->GetLuaState()) {
    return nullptr;
  }

  LuaPlus::LuaObject scripts = ResolveFormationBucket(mSim->GetLuaState(), formationType);
  if (!scripts || !scripts.IsTable()) {
    return nullptr;
  }

  const int scriptCount = scripts.GetN();
  if (scriptCount <= 0) {
    return nullptr;
  }

  const int clampedIndex = (scriptIndex >= 0 && scriptIndex < scriptCount) ? (scriptIndex + 1) : 1;
  LuaPlus::LuaObject scriptObj = scripts.GetByIndex(clampedIndex);
  if (!scriptObj.IsString()) {
    return nullptr;
  }

  return scriptObj.GetString();
}

/**
 * Address: 0x0059C0F0 (FUN_0059C0F0)
 */
int CAiFormationDBImpl::GetScriptIndex(const gpg::StrArg scriptName, const EFormationType formationType)
{
  if (!mSim || !mSim->GetLuaState()) {
    return 0;
  }

  LuaPlus::LuaObject scripts = ResolveFormationBucket(mSim->GetLuaState(), formationType);
  if (!scripts || !scripts.IsTable()) {
    return 0;
  }

  if (!scriptName || !*scriptName) {
    return -1;
  }

  const int scriptCount = scripts.GetN();
  for (int luaIndex = 1; luaIndex <= scriptCount; ++luaIndex) {
    LuaPlus::LuaObject scriptObj = scripts.GetByIndex(luaIndex);
    if (!scriptObj.IsString()) {
      continue;
    }

    const char* const candidate = scriptObj.GetString();
    if (gpg::STR_EqualsNoCase(candidate, scriptName)) {
      return luaIndex - 1;
    }
  }

  return -1;
}

/**
 * Address: 0x0059C120 (FUN_0059C120)
 */
CAiFormationInstance* CAiFormationDBImpl::NewFormation(
  const SFormationUnitWeakRefSet* const unitWeakSet,
  const char* const scriptName,
  const SCoordsVec2* const formationCenter,
  const float orientX,
  const float orientY,
  const float orientZ,
  const float orientW,
  const int commandType
)
{
  ScopedLinkedIUnitRefs linkedUnits(unitWeakSet);
  CAiFormationInstance* const formation = TryConstructFormationInstance(
    *this, scriptName, formationCenter, orientX, orientY, orientZ, orientW, commandType, linkedUnits.refs()
  );
  if (!formation) {
    return nullptr;
  }

  CAiFormationInstance* formationForAppend = formation;
  mFormInstances.Append(formationForAppend);
  return formation;
}
