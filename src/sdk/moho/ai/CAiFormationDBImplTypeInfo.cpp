#include "moho/ai/CAiFormationDBImplTypeInfo.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/misc/Stats.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF6830 (FUN_00BF6830, atexit destructor of the CAiFormationDBImplTypeInfo object)
   */
  [[nodiscard]] CAiFormationDBImplTypeInfo* AcquireCAiFormationDBImplTypeInfo()
  {
    static CAiFormationDBImplTypeInfo sInstance;
    return &sInstance;
  }

  [[nodiscard]] gpg::RRef MakeCAiFormationDBImplRef(CAiFormationDBImpl* const object) noexcept
  {
    gpg::RRef out{};
    out = gpg::MakeRRef<moho::CAiFormationDBImpl>(object);
    return out;
  }

} // namespace

/**
 * Address: 0x0059C510 (FUN_0059C510, ctor)
 *
 * What it does:
 * Preregisters `CAiFormationDBImpl` RTTI so lookup resolves to this type
 * helper.
 */
CAiFormationDBImplTypeInfo::CAiFormationDBImplTypeInfo()
{
  gpg::PreRegisterRType(typeid(CAiFormationDBImpl), this);
}

/**
 * Address: 0x0059C5C0 (FUN_0059C5C0, scalar deleting thunk)
 */
CAiFormationDBImplTypeInfo::~CAiFormationDBImplTypeInfo() = default;

/**
 * Address: 0x0059C5B0 (FUN_0059C5B0, ?GetName@CAiFormationDBImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiFormationDBImplTypeInfo::GetName() const
{
  return "CAiFormationDBImpl";
}

/**
 * Address: 0x0059DB80 (FUN_0059DB80, Moho::CAiFormationDBImplTypeInfo::AddBase_IAiFormationDB)
 *
 * What it does:
 * Registers `IAiFormationDB` as this type's reflected base at offset 0.
 *
 * The null guard on the looked-up type is ours; the binary dereferences
 * unconditionally. Kept because a failed lookup would otherwise crash here.
 */
void CAiFormationDBImplTypeInfo::AddBase_IAiFormationDB(gpg::RType* const typeInfo)
{
  static gpg::RType* sCachedIAiFormationDBType = nullptr;
  if (!sCachedIAiFormationDBType) {
    sCachedIAiFormationDBType = gpg::LookupRType(typeid(IAiFormationDB));
  }

  gpg::RType* const baseType = sCachedIAiFormationDBType;
  if (baseType == nullptr) {
    return;
  }

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.mFlags = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x0059C570 (FUN_0059C570, ?Init@CAiFormationDBImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiFormationDBImplTypeInfo::Init()
{
  size_ = sizeof(CAiFormationDBImpl);
  (void)InitializeAllocationCallbacks(this);
  gpg::RType::Init();

  AddBase_IAiFormationDB(this);

  Finish();
}

/**
 * Address: 0x0059CB50 (FUN_0059CB50)
 *
 * What it does:
 * Wires `newRef/ctorRef/delete/dtr` callback lanes for
 * `CAiFormationDBImpl` reflection ownership.
 */
gpg::RType* CAiFormationDBImplTypeInfo::InitializeAllocationCallbacks(gpg::RType* const typeInfo)
{
  typeInfo->newRefFunc_ = &CAiFormationDBImplTypeInfo::NewRef;
  typeInfo->ctorRefFunc_ = &CAiFormationDBImplTypeInfo::CtrRef;
  typeInfo->deleteFunc_ = &CAiFormationDBImplTypeInfo::Delete;
  typeInfo->dtrFunc_ = &CAiFormationDBImplTypeInfo::Destruct;
  return typeInfo;
}

/**
 * Address: 0x0059D390 (FUN_0059D390, Moho::CAiFormationDBImplTypeInfo::NewRef)
 *
 * What it does:
 * Allocates a reflected `CAiFormationDBImpl` (its constructor nulls `mSim` and
 * arms the inline `mFormInstances` storage) and returns it as a typed `gpg::RRef`.
 */
gpg::RRef CAiFormationDBImplTypeInfo::NewRef()
{
  CAiFormationDBImpl* const object = new (std::nothrow) CAiFormationDBImpl();
  return MakeCAiFormationDBImplRef(object);
}

/**
 * Address: 0x0059D430 (FUN_0059D430, Moho::CAiFormationDBImplTypeInfo::CtrRef)
 *
 * What it does:
 * Placement-constructs one `CAiFormationDBImpl` in caller storage and returns
 * a typed `gpg::RRef`.
 */
gpg::RRef CAiFormationDBImplTypeInfo::CtrRef(void* const objectStorage)
{
  CAiFormationDBImpl* const object = static_cast<CAiFormationDBImpl*>(objectStorage);
  if (object) {
    new (object) CAiFormationDBImpl();
  }

  return MakeCAiFormationDBImplRef(object);
}

/**
 * Address: 0x0059D410 (FUN_0059D410, Moho::CAiFormationDBImplTypeInfo::Delete)
 *
 * What it does:
 * Runs deleting-dtor behavior for one reflected `CAiFormationDBImpl`
 * storage lane.
 */
void CAiFormationDBImplTypeInfo::Delete(void* const objectStorage)
{
  auto* const object = static_cast<CAiFormationDBImpl*>(objectStorage);
  if (!object) {
    return;
  }

  object->~CAiFormationDBImpl();
  ::operator delete(object);
}

/**
 * Address: 0x0059D4B0 (FUN_0059D4B0, Moho::CAiFormationDBImplTypeInfo::Destruct)
 *
 * What it does:
 * Runs in-place teardown for one reflected `CAiFormationDBImpl` storage lane
 * without freeing the backing allocation.
 */
void CAiFormationDBImplTypeInfo::Destruct(void* const objectStorage)
{
  auto* const object = static_cast<CAiFormationDBImpl*>(objectStorage);
  if (!object) {
    return;
  }

  object->~CAiFormationDBImpl();
}

/**
 * Address: 0x00BCC1B0 (FUN_00BCC1B0, register_CAiFormationDBImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiFormationDBImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiFormationDBImplTypeInfo()
{
  (void)AcquireCAiFormationDBImplTypeInfo();
}

namespace
{
  struct CAiFormationDBImplTypeInfoBootstrap
  {
    CAiFormationDBImplTypeInfoBootstrap()
    {
      moho::register_CAiFormationDBImplTypeInfo();
    }
  };

  [[maybe_unused]] CAiFormationDBImplTypeInfoBootstrap gCAiFormationDBImplTypeInfoBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiFormationDBImplTypeInfo_700dc3, moho::register_CAiFormationDBImplTypeInfo)
