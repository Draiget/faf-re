#include "moho/sim/ESTITargetTypeTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

using namespace moho;

namespace
{
  alignas(ESTITargetTypeTypeInfo) unsigned char gStorage[sizeof(ESTITargetTypeTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] ESTITargetTypeTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) ESTITargetTypeTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<ESTITargetTypeTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<ESTITargetTypeTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct Bootstrap { Bootstrap() { moho::register_ESTITargetTypeTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x0055AE70 (FUN_0055AE70, sub_55AE70)
 *
 * What it does:
 * Constructs the REnumType base, registers under typeid(ESTITargetType),
 * and installs the typeinfo vtable.
 */
ESTITargetTypeTypeInfo::ESTITargetTypeTypeInfo()
  : gpg::REnumType()
{
  gpg::PreRegisterRType(typeid(ESTITargetType), this);
}

ESTITargetTypeTypeInfo::~ESTITargetTypeTypeInfo() = default;

/** Address: 0x0055AEF0 */
const char* ESTITargetTypeTypeInfo::GetName() const { return "ESTITargetType"; }

/**
 * Address: 0x0055AED0 (FUN_0055AED0)
 *
 * What it does:
 * Sets size = sizeof(ESTITargetType), invokes RType::Init(), populates
 * named enum values via AddEnums, and finalizes.
 */
void ESTITargetTypeTypeInfo::Init()
{
  size_ = sizeof(ESTITargetType);
  gpg::RType::Init();
  AddEnums(this);
  Finish();
}

/**
 * Address: 0x0055AF30 (FUN_0055AF30, AddEnums)
 *
 * What it does:
 * Sets enum prefix `STITARGET_` and registers None=0, Entity=1, Position=2.
 */
void ESTITargetTypeTypeInfo::AddEnums(gpg::REnumType* const enumType)
{
  enumType->mPrefix = "STITARGET_";
  enumType->AddEnum(enumType->StripPrefix("STITARGET_None"), 0);
  enumType->AddEnum(enumType->StripPrefix("STITARGET_Entity"), 1);
  enumType->AddEnum(enumType->StripPrefix("STITARGET_Position"), 2);
}

/**
 * Address: 0x0055B310 (FUN_0055B310, PrimitiveSerHelper<ESTITargetType>::Deserialize)
 */
void ESTITargetTypePrimitiveSerializer::Deserialize(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef*
)
{
  int value = 0;
  archive->ReadInt(&value);
  *reinterpret_cast<ESTITargetType*>(static_cast<std::uintptr_t>(objectPtr)) = static_cast<ESTITargetType>(value);
}

/**
 * Address: 0x0055B330 (FUN_0055B330, PrimitiveSerHelper<ESTITargetType>::Serialize)
 */
void ESTITargetTypePrimitiveSerializer::Serialize(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef*
)
{
  const auto value = *reinterpret_cast<const ESTITargetType*>(static_cast<std::uintptr_t>(objectPtr));
  archive->WriteInt(static_cast<int>(value));
}

void ESTITargetTypePrimitiveSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = gpg::LookupRType(typeid(ESTITargetType));
  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
  type->serLoadFunc_ = mDeserialize;
  type->serSaveFunc_ = mSerialize;
}

void moho::register_ESTITargetTypeTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}
