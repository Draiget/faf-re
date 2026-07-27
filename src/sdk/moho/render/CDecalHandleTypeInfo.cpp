#include "moho/render/CDecalHandleTypeInfo.h"

#include <cstdlib>
#include <new>

#include "gpg/core/reflection/StaticInitPhase.h"

#include "moho/render/CDecalHandle.h"
#include "moho/script/CScriptObject.h"

namespace
{
  // Storage for the descriptor singleton. Placement-new'd on first use and
  // torn down through atexit, matching the other recovered TypeInfo lanes.
  alignas(moho::CDecalHandleTypeInfo) unsigned char gCDecalHandleTypeInfoStorage
    [sizeof(moho::CDecalHandleTypeInfo)];
  bool gCDecalHandleTypeInfoConstructed = false;

  [[nodiscard]] moho::CDecalHandleTypeInfo& AcquireCDecalHandleTypeInfo()
  {
    if (!gCDecalHandleTypeInfoConstructed) {
      new (gCDecalHandleTypeInfoStorage) moho::CDecalHandleTypeInfo();
      gCDecalHandleTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::CDecalHandleTypeInfo*>(gCDecalHandleTypeInfoStorage);
  }

  /**
   * Address: 0x00C028E0 (sub_C028E0, atexit thunk for the descriptor)
   *
   * What it does:
   * Releases the descriptor's field/base tables at shutdown.
   */
  void cleanup_CDecalHandleTypeInfo()
  {
    if (!gCDecalHandleTypeInfoConstructed) {
      return;
    }

    auto& typeInfo = *reinterpret_cast<moho::CDecalHandleTypeInfo*>(gCDecalHandleTypeInfoStorage);
    typeInfo.fields_ = msvc8::vector<gpg::RField>{};
    typeInfo.bases_ = msvc8::vector<gpg::RField>{};
  }

  /**
   * Address: 0x0077C7F0 (FUN_0077C7F0, Moho::CDecalHandle::operator new)
   */
  gpg::RRef NewRef_CDecalHandle()
  {
    gpg::RRef out{};
    out.mObj = new (std::nothrow) moho::CDecalHandle();
    out.mType = moho::CDecalHandle::StaticGetClass();
    return out;
  }

  /**
   * Address: 0x0077C890 (FUN_0077C890)
   */
  gpg::RRef CtrRef_CDecalHandle(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalHandle*>(objectStorage);
    if (object != nullptr) {
      new (object) moho::CDecalHandle();
    }

    gpg::RRef out{};
    out.mObj = object;
    out.mType = moho::CDecalHandle::StaticGetClass();
    return out;
  }

  /**
   * Address: 0x0077C870 (FUN_0077C870)
   */
  void Delete_CDecalHandle(void* const objectStorage)
  {
    delete static_cast<moho::CDecalHandle*>(objectStorage);
  }

  /**
   * Address: 0x0077C900 (FUN_0077C900)
   */
  void Dtr_CDecalHandle(void* const objectStorage)
  {
    auto* const object = static_cast<moho::CDecalHandle*>(objectStorage);
    if (object != nullptr) {
      object->~CDecalHandle();
    }
  }

  /**
   * Address: 0x0077AB70 (FUN_0077AB70)
   *
   * What it does:
   * Binds `CDecalHandle` new/construct/delete/destruct callback lanes into
   * the reflected type callback slots.
   */
  [[maybe_unused]] moho::CDecalHandleTypeInfo* BindDecalHandleTypeCallbackSlots(
    moho::CDecalHandleTypeInfo* const typeInfo
  )
  {
    typeInfo->newRefFunc_ = &NewRef_CDecalHandle;
    typeInfo->ctorRefFunc_ = &CtrRef_CDecalHandle;
    typeInfo->deleteFunc_ = &Delete_CDecalHandle;
    typeInfo->dtrFunc_ = &Dtr_CDecalHandle;
    return typeInfo;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00779E40 (FUN_00779E40, Moho::CDecalHandleTypeInfo::CDecalHandleTypeInfo)
   */
  CDecalHandleTypeInfo::CDecalHandleTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CDecalHandle), this);
  }

  /**
   * Address: 0x00779EF0 (FUN_00779EF0, Moho::CDecalHandleTypeInfo::dtr)
   */
  CDecalHandleTypeInfo::~CDecalHandleTypeInfo() = default;

  /**
   * Address: 0x00BDD8C0 (FUN_00BDD8C0, register_CDecalHandleTypeInfo)
   *
   * IDA signature:
   * void __cdecl register_CDecalHandleTypeInfo();
   *
   * What it does:
   * Constructs the process-wide `CDecalHandleTypeInfo` singleton - whose
   * constructor pre-registers `typeid(CDecalHandle)` - and installs the
   * matching `atexit` teardown. This is CRT dynamic initializer #3557 in the
   * shipped binary.
   *
   * Without it nothing ever constructs the descriptor, so
   * `RPointerType<CDecalHandle>::GetPointeeType` throws "Attempting to lookup
   * the RType for ... before it is registered" during REF_RegisterAllTypes.
   */
  void register_CDecalHandleTypeInfo()
  {
    (void)AcquireCDecalHandleTypeInfo();
    (void)std::atexit(&cleanup_CDecalHandleTypeInfo);
  }

  /**
   * Address: 0x00779EE0 (FUN_00779EE0, Moho::CDecalHandleTypeInfo::GetName)
   */
  const char* CDecalHandleTypeInfo::GetName() const
  {
    return "CDecalHandle";
  }

  /**
   * Address: 0x00779EA0 (FUN_00779EA0, Moho::CDecalHandleTypeInfo::Init)
   */
  void CDecalHandleTypeInfo::Init()
  {
    size_ = sizeof(CDecalHandle);
    (void)BindDecalHandleTypeCallbackSlots(this);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0077D8B0 (FUN_0077D8B0, Moho::CDecalHandleTypeInfo::AddBase_CScriptObject)
   */
  void CDecalHandleTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CScriptObject::StaticGetClass();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CDecalHandleTypeInfo, moho::register_CDecalHandleTypeInfo)
