#include "gpg/core/containers/ArchiveTokenTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x0094F4D0 (FUN_0094F4D0)
   *
   * What it does:
   * Lazily resolves and caches reflection RTTI for `gpg::ArchiveToken`.
   */
  [[maybe_unused]] gpg::RType* CachedArchiveTokenType()
  {
    static gpg::RType* cached = nullptr;
    if (cached == nullptr) {
      cached = gpg::LookupRType(typeid(gpg::ArchiveToken));
    }
    return cached;
  }

  /**
   * Address: 0x00C0A210 (FUN_00C0A210, atexit destructor of the gpg::ArchiveTokenTypeInfo object)
   */
  [[nodiscard]] gpg::ArchiveTokenTypeInfo* AcquireArchiveTokenTypeInfo()
  {
    static gpg::ArchiveTokenTypeInfo sInstance;
    return &sInstance;
  }

  struct ArchiveTokenTypeInfoBootstrap
  {
    ArchiveTokenTypeInfoBootstrap()
    {
      (void)gpg::register_ArchiveTokenTypeInfoStartup();
    }
  };

  [[maybe_unused]] ArchiveTokenTypeInfoBootstrap gArchiveTokenTypeInfoBootstrap;
} // namespace

namespace gpg
{
  /**
   * Address: 0x00952AB0 (FUN_00952AB0, ArchiveTokenTypeInfo::ArchiveTokenTypeInfo)
   */
  ArchiveTokenTypeInfo::ArchiveTokenTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(ArchiveToken), this);
  }

  /**
   * Address: 0x00C0A210 (FUN_00C0A210, ArchiveTokenTypeInfo::~ArchiveTokenTypeInfo)
   */
  ArchiveTokenTypeInfo::~ArchiveTokenTypeInfo() = default;

  /**
   * Address: 0x00952B40 (FUN_00952B40)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `ArchiveTokenTypeInfo`, forwarding
   * through non-deleting `REnumType` teardown and optional storage release.
   */
  [[nodiscard]] gpg::REnumType* DestroyArchiveTokenTypeInfoDeleting(
    ArchiveTokenTypeInfo* const typeInfo,
    const unsigned char deleteFlag
  )
  {
    typeInfo->gpg::REnumType::~REnumType();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(typeInfo));
    }
    return typeInfo;
  }

  /**
   * Address: 0x00952B10 (FUN_00952B10, ArchiveTokenTypeInfo::GetName)
   */
  const char* ArchiveTokenTypeInfo::GetName() const
  {
    return "ArchiveToken";
  }

  /**
   * Address: 0x00952B20 (FUN_00952B20, ArchiveTokenTypeInfo::Init)
   */
  void ArchiveTokenTypeInfo::Init()
  {
    size_ = sizeof(ArchiveToken);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x0094E990 (FUN_0094E990, ArchiveTokenTypeInfo::AddEnums)
   */
  void ArchiveTokenTypeInfo::AddEnums()
  {
    AddEnum(StripPrefix("OBJECT_TERMINATOR"), static_cast<int>(ArchiveToken::ObjectTerminator));
    AddEnum(StripPrefix("NEW_OBJECT_TOKEN"), static_cast<int>(ArchiveToken::NewObjectToken));
    AddEnum(StripPrefix("NULL_POINTER_TOKEN"), static_cast<int>(ArchiveToken::NullPointerToken));
    AddEnum(StripPrefix("EXISTING_POINTER_TOKEN"), static_cast<int>(ArchiveToken::ExistingPointerToken));
    AddEnum(StripPrefix("OBJECT_START"), static_cast<int>(ArchiveToken::ObjectStart));
  }

  /**
   * Address: 0x00BEAAB0 (FUN_00BEAAB0, register_ArchiveTokenTypeInfo)
   */
  void register_ArchiveTokenTypeInfoStartup()
  {
    (void)AcquireArchiveTokenTypeInfo();
  }
} // namespace gpg

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ArchiveTokenTypeInfoStartup_20b238, gpg::register_ArchiveTokenTypeInfoStartup)
