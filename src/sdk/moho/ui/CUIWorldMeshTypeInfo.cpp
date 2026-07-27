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
  alignas(CUIWorldMeshTypeInfo) unsigned char gStorage[sizeof(CUIWorldMeshTypeInfo)];
  bool gConstructed = false;

  [[nodiscard]] CUIWorldMeshTypeInfo& Acquire()
  {
    if (!gConstructed) {
      new (gStorage) CUIWorldMeshTypeInfo();
      gConstructed = true;
    }
    return *reinterpret_cast<CUIWorldMeshTypeInfo*>(gStorage);
  }

  void cleanup()
  {
    if (!gConstructed) return;
    auto& ti = *reinterpret_cast<CUIWorldMeshTypeInfo*>(gStorage);
    ti.fields_ = msvc8::vector<gpg::RField>{};
    ti.bases_ = msvc8::vector<gpg::RField>{};
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
  size_ = 0x38;
  debug_reflection::AddBaseCScriptObject(this);
  gpg::RType::Init();
  Finish();
}

void moho::register_CUIWorldMeshTypeInfoStartup()
{
  (void)Acquire();
  (void)std::atexit(&cleanup);
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CUIWorldMeshTypeInfoStartup_9897a7, moho::register_CUIWorldMeshTypeInfoStartup)
