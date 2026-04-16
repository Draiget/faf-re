#include "moho/sim/SSessionSaveDataTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/CWldSession.h"

using namespace moho;

namespace
{
  alignas(SSessionSaveDataTypeInfo) unsigned char gSSessionSaveDataTypeInfoStorage[sizeof(SSessionSaveDataTypeInfo)];
  bool gSSessionSaveDataTypeInfoConstructed = false;

  [[nodiscard]] gpg::RRef MakeSSessionSaveDataRef(SSessionSaveData* const object)
  {
    gpg::RRef out{};
    gpg::RRef_SSessionSaveData(&out, object);
    return out;
  }

  /**
   * Address: 0x008991D0 (FUN_008991D0)
   *
   * What it does:
   * Installs one `SSessionSaveDataTypeInfo` lifecycle callback set into one reflected type record.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* InstallSSessionSaveDataTypeInfoLifecycleCallbacks(
    gpg::RType* const typeInfo
  )
  {
    typeInfo->newRefFunc_ = &SSessionSaveDataTypeInfo::NewRef;
    typeInfo->ctorRefFunc_ = &SSessionSaveDataTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &SSessionSaveDataTypeInfo::Delete;
    typeInfo->dtrFunc_ = &SSessionSaveDataTypeInfo::Destruct;
    return typeInfo;
  }

  [[nodiscard]] SSessionSaveDataTypeInfo& AcquireSSessionSaveDataTypeInfo()
  {
    if (!gSSessionSaveDataTypeInfoConstructed) {
      new (gSSessionSaveDataTypeInfoStorage) SSessionSaveDataTypeInfo();
      gSSessionSaveDataTypeInfoConstructed = true;
    }
    return *reinterpret_cast<SSessionSaveDataTypeInfo*>(gSSessionSaveDataTypeInfoStorage);
  }

  void cleanup_SSessionSaveDataTypeInfo()
  {
    if (!gSSessionSaveDataTypeInfoConstructed) return;
    auto& ti = *reinterpret_cast<SSessionSaveDataTypeInfo*>(gSSessionSaveDataTypeInfoStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
  }

  struct SSessionSaveDataTypeInfoBootstrap
  {
    SSessionSaveDataTypeInfoBootstrap() { moho::register_SSessionSaveDataTypeInfoStartup(); }
  };
  SSessionSaveDataTypeInfoBootstrap gSSessionSaveDataTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x00897300 (Moho::SSessionSaveDataTypeInfo::SSessionSaveDataTypeInfo)
 */
SSessionSaveDataTypeInfo::SSessionSaveDataTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(SSessionSaveData), this);
}

/**
 * Address: 0x008973B0
 */
SSessionSaveDataTypeInfo::~SSessionSaveDataTypeInfo() = default;

/**
 * Address: 0x008973A0
 */
const char* SSessionSaveDataTypeInfo::GetName() const
{
  return "SSessionSaveData";
}

/**
 * Address: 0x00897360
 */
void SSessionSaveDataTypeInfo::Init()
{
  size_ = 0x0C;
  gpg::RType::Init();
  (void)gpg::BindRTypeLifecycleCallbacks(
    this,
    &SSessionSaveDataTypeInfo::NewRef,
    &SSessionSaveDataTypeInfo::CtrRef,
    &SSessionSaveDataTypeInfo::Delete,
    &SSessionSaveDataTypeInfo::Destruct
  );
  Finish();
}

/**
 * Address: 0x0089A2E0 (FUN_0089A2E0, Moho::SSessionSaveDataTypeInfo::NewRef)
 */
gpg::RRef SSessionSaveDataTypeInfo::NewRef()
{
  SSessionSaveData* const object = new (std::nothrow) SSessionSaveData();
  return MakeSSessionSaveDataRef(object);
}

/**
 * Address: 0x0089A3C0 (FUN_0089A3C0, Moho::SSessionSaveDataTypeInfo::CtrRef)
 */
gpg::RRef SSessionSaveDataTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const object = static_cast<SSessionSaveData*>(objectStorage);
  if (object != nullptr) {
    new (object) SSessionSaveData();
  }
  return MakeSSessionSaveDataRef(object);
}

/**
 * Address: 0x0089A380 (FUN_0089A380, Moho::SSessionSaveDataTypeInfo::Delete)
 */
void SSessionSaveDataTypeInfo::Delete(void* const objectStorage)
{
  auto* const object = static_cast<SSessionSaveData*>(objectStorage);
  if (object == nullptr) {
    return;
  }

  delete object;
}

/**
 * Address: 0x0089A450 (FUN_0089A450, Moho::SSessionSaveDataTypeInfo::Destruct)
 */
void SSessionSaveDataTypeInfo::Destruct(void* const objectStorage)
{
  auto* const object = static_cast<SSessionSaveData*>(objectStorage);
  object->~SSessionSaveData();
}

/**
 * Address: 0x00BE7770
 */
void moho::register_SSessionSaveDataTypeInfoStartup()
{
  (void)AcquireSSessionSaveDataTypeInfo();
  (void)std::atexit(&cleanup_SSessionSaveDataTypeInfo);
}
