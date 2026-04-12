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
  Finish();
}

/**
 * Address: 0x00BE7770
 */
void moho::register_SSessionSaveDataTypeInfoStartup()
{
  (void)AcquireSSessionSaveDataTypeInfo();
  (void)std::atexit(&cleanup_SSessionSaveDataTypeInfo);
}
