#include "moho/ui/UiRuntimeTypes.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <typeinfo>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/mesh/MeshThumbnailRenderer.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/resource/RResId.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  namespace
  {
    /// Format the thumbnail sheet is created with (`push 2` at 0x0079E1C6):
    /// gal format 2 is D3DFMT_A8R8G8B8.
    constexpr int kThumbnailSheetFormat = 2;
  } // namespace

  gpg::RType* CMauiMesh::sType = nullptr;

  /**
   * Address: 0x0079DC10 (FUN_0079DC10, Moho::CMauiMesh::GetClass)
   *
   * What it does:
   * Returns the cached reflection descriptor for `CMauiMesh`, looked up by RTTI
   * on first use.
   */
  gpg::RType* CMauiMesh::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CMauiMesh));
    }
    return sType;
  }

  /**
   * Address: 0x0079DC30 (FUN_0079DC30, Moho::CMauiMesh::GetDerivedObjectRef)
   *
   * What it does:
   * Packs `{this, GetClass()}` into a reflection reference handle.
   */
  gpg::RRef CMauiMesh::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x0079DDB0 (FUN_0079DDB0, Moho::CMauiMesh::CMauiMesh)
   *
   * What it does:
   * Constructs a "Mesh" control with no sheet, no mesh, the identity
   * orientation and color 0xFFFFFFFF, and asks for per-frame updates.
   */
  CMauiMesh::CMauiMesh(LuaPlus::LuaObject* const luaObject, CMauiControl* const parent)
    : CMauiControl(luaObject, parent, "Mesh")
    , mThumbnailSheet()
    , mThumbnailDirty(false)
    , mMeshBlueprint(nullptr)
    , mOrientation(Wm3::Quaternionf::Identity())
    , mThumbnailColor(0xFFFFFFFFu)
  {
    CMauiControlFrameUpdateRuntimeView::FromControl(this)->mNeedsFrameUpdate = true;
  }

  /**
   * Address: 0x0079DE70 (FUN_0079DE70, Moho::CMauiMesh::dtr)
   * Address: 0x0079DE50 (FUN_0079DE50, scalar deleting destructor)
   *
   * What it does:
   * Releases the thumbnail sheet (the member's own destructor) and continues
   * into `~CMauiControl`.
   */
  CMauiMesh::~CMauiMesh() = default;

  /**
   * Address: 0x0079DF40 (FUN_0079DF40, Moho::CMauiMesh::SetMesh)
   *
   * What it does:
   * Resolves the mesh blueprint by name from the active session's rules and
   * marks the thumbnail dirty.
   */
  void CMauiMesh::SetMesh(const char* const meshBlueprintName)
  {
    CWldSession* const worldSession = WLD_GetActiveSession();
    if (worldSession == nullptr) {
      return;
    }

    RResId meshId{};
    gpg::STR_InitFilename(&meshId.name, meshBlueprintName != nullptr ? meshBlueprintName : "");
    mMeshBlueprint = worldSession->mRules->GetMeshBlueprint(meshId);
    mThumbnailDirty = true;
  }

  /**
   * Address: 0x0079E0B0 (FUN_0079E0B0)
   *
   * What it does:
   * Locks the thumbnail sheet, zeroes `GetTextureSizeInBytes()` bytes of it
   * and unlocks it, so a new thumbnail starts from a transparent sheet.
   */
  void CMauiMesh::ClearThumbnailSheet()
  {
    if (!mThumbnailSheet) {
      return;
    }

    std::uint32_t pitch = 0;
    void* bits = nullptr;
    if (mThumbnailSheet->Lock(&pitch, &bits)) {
      std::memset(bits, 0, static_cast<std::size_t>(mThumbnailSheet->GetTextureSizeInBytes()));
      (void)mThumbnailSheet->Unlock();
    }
  }

  /**
   * Address: 0x0079E100 (FUN_0079E100, Moho::CMauiMesh::OnFrame)
   *
   * What it does:
   * Keeps the thumbnail sheet the size of the control: creates it on the first
   * frame, and releases and recreates it (marking the thumbnail dirty) when the
   * control's width or height no longer match the sheet's dimensions. While the
   * thumbnail is dirty and a mesh is set, clears the sheet and queues a
   * thumbnail render of the mesh at the current orientation into it.
   *
   * The sheet comes from `D3D_GetDevice()->GetResources()` vtable +0x3C,
   * `NewDynamicTextureSheet` (0x0079E1C6..0x0079E203), and the old one is
   * released first (`reset`, 0x0043A860). Only a resize marks the thumbnail
   * dirty; the first creation leaves that to `SetMesh`/`SetOrientation`.
   */
  void CMauiMesh::Frame(const float deltaSeconds)
  {
    (void)deltaSeconds;
    const CMauiControlRuntimeView* const layout = CMauiControlRuntimeView::FromControl(this);

    const auto newThumbnailSheet = [layout] {
      ID3DDeviceResources::DynamicTextureSheetHandle sheet;
      (void)D3D_GetDevice()->GetResources()->NewDynamicTextureSheet(
        sheet,
        static_cast<int>(CScriptLazyVar_float::GetValue(&layout->mWidthLV)),
        static_cast<int>(CScriptLazyVar_float::GetValue(&layout->mHeightLV)),
        kThumbnailSheetFormat
      );
      return sheet;
    };

    if (mThumbnailSheet) {
      Wm3::Vector3f dimensions{};
      (void)mThumbnailSheet->GetDimensions(&dimensions);
      if (dimensions.x != CScriptLazyVar_float::GetValue(&layout->mWidthLV)
          || dimensions.y != CScriptLazyVar_float::GetValue(&layout->mHeightLV)) {
        mThumbnailSheet.reset();
        mThumbnailSheet = newThumbnailSheet();
        mThumbnailDirty = true;
      }
    } else {
      mThumbnailSheet = newThumbnailSheet();
    }

    if (mThumbnailDirty && mMeshBlueprint != nullptr) {
      ClearThumbnailSheet();
      (void)REN_RequestThumbnail(
        mMeshBlueprint,
        mOrientation,
        mThumbnailColor,
        Wm3::Vec3f{1.0f, 1.0f, 1.0f},
        mThumbnailSheet,
        gpg::Rect2f{0.0f, 0.0f, 1.0f, 1.0f}
      );
      mThumbnailDirty = false;
    }
  }

  /**
   * Address: 0x0079E430 (FUN_0079E430, Moho::CMauiMesh::Draw)
   *
   * What it does:
   * Binds the thumbnail sheet (the `shared_ptr<ID3DTextureSheet>` overload of
   * `SetTexture`, 0x00438870) and draws it as one quad over the control's
   * rectangle with 0..1 UVs.
   */
  void CMauiMesh::DoRender(CD3DPrimBatcher* const primBatcher, const std::int32_t drawMask)
  {
    (void)drawMask;
    const CMauiControlRuntimeView* const layout = CMauiControlRuntimeView::FromControl(this);

    const float left = CScriptLazyVar_float::GetValue(&layout->mLeftLV);
    const float top = CScriptLazyVar_float::GetValue(&layout->mTopLV);
    const float right = CScriptLazyVar_float::GetValue(&layout->mRightLV);
    const float bottom = CScriptLazyVar_float::GetValue(&layout->mBottomLV);

    primBatcher->SetTexture(mThumbnailSheet);

    const auto corner = [](const float x, const float y, const float u, const float v) {
      CD3DPrimBatcher::Vertex vertex{};
      vertex.mX = x;
      vertex.mY = y;
      vertex.mZ = 0.0f;
      vertex.mColor = 0xFFFFFFFFu;
      vertex.mU = u;
      vertex.mV = v;
      return vertex;
    };
    primBatcher->DrawQuad(
      corner(left, top, 0.0f, 0.0f),
      corner(right, top, 1.0f, 0.0f),
      corner(right, bottom, 1.0f, 1.0f),
      corner(left, bottom, 0.0f, 1.0f)
    );
  }

  /**
   * Address: 0x0079E580 (FUN_0079E580, Moho::CMauiMesh::Dump)
   *
   * What it does:
   * Nothing; the mesh control's dump override is empty.
   */
  void CMauiMesh::Dump() {}

  void CMauiMesh::SetOrientation(const Wm3::Quaternionf& orientation)
  {
    mOrientation = orientation;
    mThumbnailDirty = true;
  }
} // namespace moho
