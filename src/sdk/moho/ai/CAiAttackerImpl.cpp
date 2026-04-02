// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"

#include <cstddef>
#include <cstring>
#include <cstdint>

using namespace moho;

namespace moho
{
  struct WeaponExtraRefSubobject
  {
    std::uint8_t pad_00[0x64];
    std::int32_t extraValue; // +0x64 (subobject-relative payload word)
  };

  static_assert(
    offsetof(WeaponExtraRefSubobject, extraValue) == 0x64,
    "WeaponExtraRefSubobject::extraValue offset must be 0x64"
  );
} // namespace moho

namespace
{
  constexpr std::int32_t kExtraDataMissingValue = static_cast<std::int32_t>(0xF0000000u);
  std::int32_t gRecoveredCScrLuaMetatableFactoryCAiAttackerImplIndex = 0;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormPrev_off_F59A00 = nullptr;
  moho::CScrLuaInitForm* gRecoveredSimLuaInitFormAnchor_off_F599F0 = nullptr;

  struct WeaponEmitterEntryView
  {
    std::uint8_t pad_00[0xA8];
    std::int32_t extraKey; // +0xA8
    std::uint8_t pad_AC[0x24];
    WeaponExtraRefSubobject* extraRef; // +0xD0 (secondary-subobject pointer)
  };
  static_assert(
    offsetof(WeaponEmitterEntryView, extraKey) == 0xA8, "WeaponEmitterEntryView::extraKey offset must be 0xA8"
  );
  static_assert(
    offsetof(WeaponEmitterEntryView, extraRef) == 0xD0, "WeaponEmitterEntryView::extraRef offset must be 0xD0"
  );

  template <CScrLuaInitForm* (*Target)()>
  [[nodiscard]] CScrLuaInitForm* ForwardAiAttackerLuaThunk() noexcept
  {
    return Target();
  }

  template <std::int32_t* TargetIndex>
  int RegisterRecoveredFactoryIndex() noexcept
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    *TargetIndex = index;
    return index;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet* FindSimLuaInitSet() noexcept
  {
    for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
      if (set->mSetName != nullptr && std::strcmp(set->mSetName, "sim") == 0) {
        return set;
      }
    }

    return nullptr;
  }

  struct CAiAttackerImplLuaFunctionThunksBootstrap
  {
    CAiAttackerImplLuaFunctionThunksBootstrap()
    {
      (void)moho::register_CAiAttackerImplLuaInitFormAnchor();
      (void)moho::register_CAiAttackerImplGetUnit_LuaFuncDef();
      (void)moho::register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetWeaponCount_LuaFuncDef();
      (void)moho::register_CAiAttackerImplSetDesiredTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetDesiredTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplStop_LuaFuncDef();
      (void)moho::register_CAiAttackerImplCanAttackTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplFindBestEnemy_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetTargetWeapon_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef();
      (void)moho::register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef();
      (void)moho::register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef();
      (void)moho::register_CAiAttackerImplIsTooClose_LuaFuncDef();
      (void)moho::register_CAiAttackerImplIsTargetExempt_LuaFuncDef();
      (void)moho::register_CAiAttackerImplHasSlavedTarget_LuaFuncDef();
      (void)moho::register_CAiAttackerImplResetReportingState_LuaFuncDef();
      (void)moho::register_CAiAttackerImplForceEngage_LuaFuncDef();
      (void)moho::register_CScrLuaMetatableFactory_CAiAttackerImpl_Index();
    }
  };

  [[maybe_unused]] CAiAttackerImplLuaFunctionThunksBootstrap gCAiAttackerImplLuaFunctionThunksBootstrap;
} // namespace

bool CAiAttackerImpl::TryGetWeaponExtraData(const int index, WeaponExtraData& out) const
{
  out.key = 0;
  out.ref = nullptr;

  if (index < 0) {
    return false;
  }

  auto* self = const_cast<CAiAttackerImpl*>(this);
  if (!self) {
    return false;
  }

  const int count = self->GetWeaponCount();
  if (index >= count) {
    return false;
  }

  const void* rawWeapon = self->GetWeapon(index);
  if (!rawWeapon) {
    return false;
  }

  const auto* entry = reinterpret_cast<const WeaponEmitterEntryView*>(rawWeapon);
  out.key = entry->extraKey;
  out.ref = entry->extraRef;
  return true;
}

std::int32_t CAiAttackerImpl::ReadExtraDataValue(const WeaponExtraRefSubobject* const ref)
{
  if (!ref) {
    return kExtraDataMissingValue;
  }

  return ref->extraValue;
}

/**
 * Address: 0x00BCE970 (FUN_00BCE970, register_CAiAttackerImplLuaInitFormAnchor)
 *
 * What it does:
 * Saves current `sim` Lua-init form head and re-links it to recovered
 * attacker-Lua anchor lane `off_F599F0`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplLuaInitFormAnchor()
{
  CScrLuaInitFormSet* const simSet = FindSimLuaInitSet();
  if (simSet == nullptr) {
    gRecoveredSimLuaInitFormPrev_off_F59A00 = nullptr;
    return nullptr;
  }

  CScrLuaInitForm* const previousHead = simSet->mForms;
  gRecoveredSimLuaInitFormPrev_off_F59A00 = previousHead;
  simSet->mForms = reinterpret_cast<CScrLuaInitForm*>(&gRecoveredSimLuaInitFormAnchor_off_F599F0);
  return previousHead;
}

/**
 * Address: 0x00BCE990 (FUN_00BCE990, register_CAiAttackerImplGetUnit_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetUnit_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetUnit_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetUnit_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9A0 (FUN_00BCE9A0, register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplAttackerWeaponsBusy_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9B0 (FUN_00BCE9B0, register_CAiAttackerImplGetWeaponCount_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetWeaponCount_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetWeaponCount_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetWeaponCount_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9C0 (FUN_00BCE9C0, register_CAiAttackerImplSetDesiredTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplSetDesiredTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplSetDesiredTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplSetDesiredTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9D0 (FUN_00BCE9D0, register_CAiAttackerImplGetDesiredTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetDesiredTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetDesiredTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetDesiredTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9E0 (FUN_00BCE9E0, register_CAiAttackerImplStop_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplStop_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplStop_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplStop_LuaFuncDef>();
}

/**
 * Address: 0x00BCE9F0 (FUN_00BCE9F0, register_CAiAttackerImplCanAttackTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplCanAttackTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplCanAttackTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplCanAttackTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA00 (FUN_00BCEA00, register_CAiAttackerImplFindBestEnemy_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplFindBestEnemy_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplFindBestEnemy_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplFindBestEnemy_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA10 (FUN_00BCEA10, register_CAiAttackerImplGetTargetWeapon_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetTargetWeapon_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetTargetWeapon_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetTargetWeapon_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA20 (FUN_00BCEA20, register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetPrimaryWeapon_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA30 (FUN_00BCEA30, register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplGetMaxWeaponRange_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA40 (FUN_00BCEA40, register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplIsWithinAttackRange_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplIsWithinAttackRange_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA50 (FUN_00BCEA50, register_CAiAttackerImplIsTooClose_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplIsTooClose_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplIsTooClose_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplIsTooClose_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA60 (FUN_00BCEA60, register_CAiAttackerImplIsTargetExempt_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplIsTargetExempt_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplIsTargetExempt_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplIsTargetExempt_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA70 (FUN_00BCEA70, register_CAiAttackerImplHasSlavedTarget_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplHasSlavedTarget_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplHasSlavedTarget_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplHasSlavedTarget_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA80 (FUN_00BCEA80, register_CAiAttackerImplResetReportingState_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplResetReportingState_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplResetReportingState_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplResetReportingState_LuaFuncDef>();
}

/**
 * Address: 0x00BCEA90 (FUN_00BCEA90, register_CAiAttackerImplForceEngage_LuaFuncDef)
 *
 * What it does:
 * Forwards the startup thunk to `func_CAiAttackerImplForceEngage_LuaFuncDef`.
 */
CScrLuaInitForm* moho::register_CAiAttackerImplForceEngage_LuaFuncDef()
{
  return ForwardAiAttackerLuaThunk<&func_CAiAttackerImplForceEngage_LuaFuncDef>();
}

/**
 * Address: 0x00BCEB20 (FUN_00BCEB20, register_CScrLuaMetatableFactory_CAiAttackerImpl_Index)
 *
 * What it does:
 * Allocates and stores the recovered startup Lua factory index lane for
 * `CScrLuaMetatableFactory<CAiAttackerImpl>`.
 */
int moho::register_CScrLuaMetatableFactory_CAiAttackerImpl_Index()
{
  return RegisterRecoveredFactoryIndex<&gRecoveredCScrLuaMetatableFactoryCAiAttackerImplIndex>();
}
