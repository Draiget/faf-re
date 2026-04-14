#include "moho/ui/CUIWorldMesh.h"

#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/mesh/Mesh.h"

namespace moho
{
  gpg::RType* CUIWorldMesh::sType = nullptr;

  /**
   * Address: 0x0086ADC0 (FUN_0086ADC0, Moho::CUIWorldMesh::GetClass)
   *
   * What it does:
   * Returns cached reflection descriptor for `CUIWorldMesh`.
   */
  gpg::RType* CUIWorldMesh::GetClass() const
  {
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(CUIWorldMesh));
    }
    return sType;
  }

  /**
   * Address: 0x0086ADE0 (FUN_0086ADE0, Moho::CUIWorldMesh::GetDerivedObjectRef)
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef CUIWorldMesh::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x0086B1E0 (FUN_0086B1E0, ??0CUIWorldMesh@Moho@@QAE@@Z)
   * Mangled: ??0CUIWorldMesh@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one script-visible world-mesh owner and binds the provided
   * Lua object.
   */
  CUIWorldMesh::CUIWorldMesh(const LuaPlus::LuaObject& luaObject)
    : CScriptObject()
    , mMeshInstance(nullptr)
  {
    SetLuaObject(luaObject);
  }

  /**
   * Address: 0x0086B250 (FUN_0086B250, ??1CUIWorldMesh@Moho@@QAE@@Z)
   * Deleting thunk: 0x0086B230 (FUN_0086B230, Moho::CUIWorldMesh::dtr)
   *
   * What it does:
   * Releases the owned mesh-instance lane when the mesh renderer runtime is
   * still available, then tears down base script-object storage.
   */
  CUIWorldMesh::~CUIWorldMesh()
  {
    if (mMeshInstance != nullptr && MeshRenderer::GetInstance() != nullptr) {
      delete mMeshInstance;
      mMeshInstance = nullptr;
    }
  }
} // namespace moho
