// Auto-generated from IDA VFTABLE/RTTI scan.
#include "moho/ai/CAiAttackerImpl.h"

#include <cstddef>
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
