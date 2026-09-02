#pragma once

#include <cstddef>

#include "moho/script/CScriptObject.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Sphere3.h"

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

    /**
     * Address: 0x0086AE00 (FUN_0086AE00)
     *
     * What it does:
     * Builds one stance transform from position/orientation components and
     * applies it to the owned mesh instance as both start and end stance.
     */
    void SetStanceFromComponents(
      float positionX,
      float positionY,
      float positionZ,
      float orientationX,
      float orientationY,
      float orientationZ,
      float orientationW
    );

    /**
     * Address: 0x0086B2C0 (FUN_0086B2C0, Moho::CUIWorldMesh::SetMesh)
     *
     * What it does:
     * Resolves one world-mesh descriptor table and updates the owned mesh
     * instance from either direct model/material lanes or unit blueprint data.
     */
    void SetMesh(const LuaPlus::LuaObject& meshDescriptor);

    /**
     * Address: 0x0086AF80 (FUN_0086AF80)
     *
     * IDA signature:
     * Wm3::Sphere3f *__usercall GetWorldSphere@<eax>(CUIWorldMesh *this@<eax>,
     *                                                Wm3::Sphere3f *out@<edi>);
     *
     * What it does:
     * Refreshes the owned mesh instance's interpolated lanes and copies its
     * current world-space bounding sphere into `outSphere`. Leaves `outSphere`
     * untouched when no mesh instance is bound, and returns it either way.
     */
    Wm3::Sphere3f& GetWorldSphere(Wm3::Sphere3f& outSphere) const;

    /**
     * Address: 0x0086AFC0 (FUN_0086AFC0)
     *
     * IDA signature:
     * Wm3::AxisAlignedBox3f *__usercall GetWorldBounds@<eax>(
     *     CUIWorldMesh *this@<eax>, Wm3::AxisAlignedBox3f *out@<edi>);
     *
     * What it does:
     * Refreshes the owned mesh instance's interpolated lanes and copies its
     * current world-space axis-aligned bounds into `outBounds`. Leaves
     * `outBounds` untouched when no mesh instance is bound.
     */
    Wm3::AxisAlignedBox3f& GetWorldBounds(Wm3::AxisAlignedBox3f& outBounds) const;

  public:
    MeshInstance* mMeshInstance = nullptr; // +0x34
  };

  static_assert(offsetof(CUIWorldMesh, mMeshInstance) == 0x34, "CUIWorldMesh::mMeshInstance offset must be 0x34");
  static_assert(sizeof(CUIWorldMesh) == 0x38, "CUIWorldMesh size must be 0x38");
} // namespace moho
