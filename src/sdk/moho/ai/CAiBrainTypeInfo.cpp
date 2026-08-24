#include "moho/ai/CAiBrainTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"
#include "moho/script/CScriptObject.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(CAiBrainTypeInfo) unsigned char gCAiBrainTypeInfoStorage[sizeof(CAiBrainTypeInfo)];
  bool gCAiBrainTypeInfoConstructed = false;

  [[nodiscard]] CAiBrainTypeInfo& AcquireCAiBrainTypeInfo()
  {
    if (!gCAiBrainTypeInfoConstructed) {
      new (gCAiBrainTypeInfoStorage) CAiBrainTypeInfo();
      gCAiBrainTypeInfoConstructed = true;
    }

    return *reinterpret_cast<CAiBrainTypeInfo*>(gCAiBrainTypeInfoStorage);
  }

  [[nodiscard]] CAiBrainTypeInfo* PeekCAiBrainTypeInfo() noexcept
  {
    if (!gCAiBrainTypeInfoConstructed) {
      return nullptr;
    }

    return reinterpret_cast<CAiBrainTypeInfo*>(gCAiBrainTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CScriptObject));
    }
    return cached;
  }

  /**
   * Address: 0x00581830 (FUN_00581830)
   *
   * What it does:
   * Registers `CScriptObject` as one reflected base lane for `CAiBrain` at
   * offset `+0x00`.
   */
  void AddCScriptObjectBaseToCAiBrainType(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    if (!baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00581890 (FUN_00581890)
   *
   * What it does:
   * Generic, type-erased "delete this reflected object" callback: reads the
   * object's own vtable slot 2 (`+0x08`) and calls it with the scalar-delete
   * flag hardcoded to 1 -- `gpg::RObject::~RObject()` sits at exactly that
   * slot (VFTable SLOT: 2, per its declaration in Reflection.h), so this is
   * the same generic dispatch every `RObject`-derived class's own
   * compiler-generated scalar deleting destructor performs, just invoked
   * through a `void*` rather than a statically-typed pointer. Suitable as a
   * `gpg::RType::delete_func_t` callback for reflected types that don't
   * need (or don't yet have) their own typed specialization, matching how
   * `moho::CAiBrainConstruct::mDeleteCallback` uses a typed
   * `DeleteConstructedCAiBrain` instead for that specific registration
   * (CAiBrainConstruct.cpp) -- both compile to the same real dispatch when
   * the concrete type has a virtual destructor at this slot.
   *
   * DB-integrity fix: this previously cast to `gpg::RType*` (a reflection
   * type *descriptor*, unrelated to the objects being reflected) instead of
   * `gpg::RObject*` (the actual base every reflected object derives from,
   * whose own destructor is confirmed at this exact vtable slot) -- the cast
   * target didn't match the binary's `[vtable+8]` dispatch at all.
   */
  [[maybe_unused]] void DeleteReflectedObjectViaVirtualDtor(void* const object)
  {
    if (object == nullptr) {
      return;
    }

    delete static_cast<gpg::RObject*>(object);
  }

  void cleanup_CAiBrainTypeInfoStartup()
  {
    CAiBrainTypeInfo* const typeInfo = PeekCAiBrainTypeInfo();
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = msvc8::vector<gpg::RField>{};
    typeInfo->bases_ = msvc8::vector<gpg::RField>{};
  }

  struct CAiBrainTypeInfoStartupBootstrap
  {
    CAiBrainTypeInfoStartupBootstrap()
    {
      moho::register_CAiBrainTypeInfoStartup();
    }
  };

  CAiBrainTypeInfoStartupBootstrap gCAiBrainTypeInfoStartupBootstrap;
} // namespace

/**
 * Address: 0x00579B20 (FUN_00579B20, ??0CAiBrainTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `CAiBrain` RTTI for this type-info helper.
 */
CAiBrainTypeInfo::CAiBrainTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAiBrain), this);
}

/**
 * Address: 0x00579BB0 (FUN_00579BB0, scalar deleting thunk)
 */
CAiBrainTypeInfo::~CAiBrainTypeInfo() = default;

/**
 * Address: 0x00579BA0 (FUN_00579BA0, ?GetName@CAiBrainTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiBrainTypeInfo::GetName() const
{
  return "CAiBrain";
}

/**
 * Address: 0x00579B80 (FUN_00579B80, ?Init@CAiBrainTypeInfo@Moho@@UAEXXZ)
 */
void CAiBrainTypeInfo::Init()
{
  size_ = sizeof(CAiBrain);
  gpg::RType::Init();
  AddCScriptObjectBaseToCAiBrainType(this);
  Finish();
}

/**
 * Address: 0x00BCB3D0 (FUN_00BCB3D0, register_Moho::CAiBrainTypeInfo)
 *
 * What it does:
 * Ensures startup construction of `CAiBrainTypeInfo` and installs process-exit cleanup.
 */
void moho::register_CAiBrainTypeInfoStartup()
{
  (void)AcquireCAiBrainTypeInfo();
  (void)std::atexit(&cleanup_CAiBrainTypeInfoStartup);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiBrainTypeInfoStartup_776a4f, moho::register_CAiBrainTypeInfoStartup)
