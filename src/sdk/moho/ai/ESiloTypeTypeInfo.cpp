#include "moho/ai/ESiloTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::ESiloTypeTypeInfo) unsigned char gESiloTypeTypeInfoStorage[sizeof(moho::ESiloTypeTypeInfo)]{};
  bool gESiloTypeTypeInfoConstructed = false;
  bool gESiloTypeTypeInfoPreregistered = false;

  [[nodiscard]] moho::ESiloTypeTypeInfo* AcquireESiloTypeTypeInfo()
  {
    if (!gESiloTypeTypeInfoConstructed) {
      new (gESiloTypeTypeInfoStorage) moho::ESiloTypeTypeInfo();
      gESiloTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ESiloTypeTypeInfo*>(gESiloTypeTypeInfoStorage);
  }

  /**
   * Address: 0x00BF1FD0 (FUN_00BF1FD0, cleanup_ESiloTypeTypeInfo)
   */
  void cleanup_ESiloTypeTypeInfo()
  {
    if (!gESiloTypeTypeInfoConstructed) {
      return;
    }

    AcquireESiloTypeTypeInfo()->~ESiloTypeTypeInfo();
    gESiloTypeTypeInfoConstructed = false;
    gESiloTypeTypeInfoPreregistered = false;
  }

  // Address: 0x010AA0FC -- process-global `PrimitiveSerHelper<ESiloType,int>`
  // singleton (constructed by FUN_00BC7B50, self-registering via `__xc_a`; see
  // ESiloTypeTypeInfo.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
  moho::ESiloTypePrimitiveSerializer gESiloTypePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00BF1FD0 (FUN_00BF1FD0, Moho::ESiloTypeTypeInfo::dtr)
   * Address: 0x0050A300 (FUN_0050A300, vtable-slot-2 scalar deleting
   * destructor: tail-calls `gpg::REnumType::~REnumType(this)` then
   * conditionally frees the object -- ordinary C++ `delete` semantics, not
   * modeled as a separate function here)
   */
  ESiloTypeTypeInfo::~ESiloTypeTypeInfo() = default;

  /**
   * Address: 0x0050A2F0 (FUN_0050A2F0, Moho::ESiloTypeTypeInfo::GetName)
   */
  const char* ESiloTypeTypeInfo::GetName() const
  {
    return "ESiloType";
  }

  /**
   * Address: 0x0050A2D0 (FUN_0050A2D0, Moho::ESiloTypeTypeInfo::Init)
   */
  void ESiloTypeTypeInfo::Init()
  {
    size_ = sizeof(ESiloType);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0050A270 (FUN_0050A270, preregister_ESiloTypeTypeInfo)
   */
  gpg::REnumType* preregister_ESiloTypeTypeInfo()
  {
    auto* const typeInfo = AcquireESiloTypeTypeInfo();
    if (!gESiloTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ESiloType), typeInfo);
      gESiloTypeTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BC7B30 (FUN_00BC7B30, register_ESiloTypeTypeInfo)
   */
  int register_ESiloTypeTypeInfo()
  {
    (void)preregister_ESiloTypeTypeInfo();
    return std::atexit(&cleanup_ESiloTypeTypeInfo);
  }
} // namespace moho

namespace
{
  struct ESiloTypeTypeInfoBootstrap
  {
    ESiloTypeTypeInfoBootstrap()
    {
      (void)moho::register_ESiloTypeTypeInfo();
    }
  };

  [[maybe_unused]] ESiloTypeTypeInfoBootstrap gESiloTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_ESiloTypeTypeInfo_9672e7, moho::register_ESiloTypeTypeInfo)

GPG_PREREGISTER_INIT(preregister_ESiloTypeTypeInfo_9672e7, moho::preregister_ESiloTypeTypeInfo)
