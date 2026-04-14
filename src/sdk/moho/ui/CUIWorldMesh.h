#pragma once

#include <cstddef>

#include "moho/script/CScriptObject.h"

namespace moho
{
  class MeshInstance;

  class CUIWorldMesh : public CScriptObject
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0086ADC0 (FUN_0086ADC0, Moho::CUIWorldMesh::GetClass)
     *
     * What it does:
     * Returns cached reflection descriptor for `CUIWorldMesh`.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x0086ADE0 (FUN_0086ADE0, Moho::CUIWorldMesh::GetDerivedObjectRef)
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x0086B1E0 (FUN_0086B1E0, ??0CUIWorldMesh@Moho@@QAE@@Z)
     * Mangled: ??0CUIWorldMesh@Moho@@QAE@@Z
     *
     * What it does:
     * Initializes one script-visible world-mesh owner and binds the provided
     * Lua object.
     */
    explicit CUIWorldMesh(const LuaPlus::LuaObject& luaObject);

    /**
     * Address: 0x0086B250 (FUN_0086B250, ??1CUIWorldMesh@Moho@@QAE@@Z)
     * Deleting thunk: 0x0086B230 (FUN_0086B230, Moho::CUIWorldMesh::dtr)
     *
     * What it does:
     * Releases the owned mesh-instance lane when the mesh renderer runtime is
     * still available, then tears down base script-object storage.
     */
    ~CUIWorldMesh() override;

  public:
    MeshInstance* mMeshInstance = nullptr; // +0x34
  };

  static_assert(offsetof(CUIWorldMesh, mMeshInstance) == 0x34, "CUIWorldMesh::mMeshInstance offset must be 0x34");
  static_assert(sizeof(CUIWorldMesh) == 0x38, "CUIWorldMesh size must be 0x38");
} // namespace moho
