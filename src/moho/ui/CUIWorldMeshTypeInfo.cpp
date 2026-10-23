#include "moho/ui/CUIWorldMeshTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/debug/RDebugOverlayReflectionHelpers.h"
#include "moho/ui/CUIWorldMesh.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00C07730 (FUN_00C07730, atexit destructor of the CUIWorldMeshTypeInfo object)
   */
  [[nodiscard]] CUIWorldMeshTypeInfo& Acquire()
  {
    static CUIWorldMeshTypeInfo sInstance;
    return sInstance;
  }

  struct Bootstrap { Bootstrap() { moho::register_CUIWorldMeshTypeInfoStartup(); } };
  Bootstrap gBootstrap;
} // namespace

/**
 * Address: 0x0086B090 (Moho::CUIWorldMeshTypeInfo::CUIWorldMeshTypeInfo)
 */
CUIWorldMeshTypeInfo::CUIWorldMeshTypeInfo() : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CUIWorldMesh), this);
}

CUIWorldMeshTypeInfo::~CUIWorldMeshTypeInfo() = default;

const char* CUIWorldMeshTypeInfo::GetName() const { return "CUIWorldMesh"; }

void CUIWorldMeshTypeInfo::Init()
{
  static_assert(sizeof(moho::CUIWorldMesh) == 0x38, "moho::CUIWorldMesh is 0x38 bytes on x86");
  size_ = sizeof(moho::CUIWorldMesh);
  debug_reflection::AddBaseCScriptObject(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00BE64C0 (FUN_00BE64C0, register_CUIWorldMeshTypeInfoStartup)
 *
 * What it does:
 * Constructs the `CUIWorldMesh` type-info object.
 */
void moho::register_CUIWorldMeshTypeInfoStartup()
{
  (void)Acquire();
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUIWorldMeshTypeInfoStartup_9897a7, moho::register_CUIWorldMeshTypeInfoStartup)
