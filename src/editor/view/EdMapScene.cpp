#include "editor/view/EdMapScene.h"

#include <algorithm>
#include <cmath>

#include <windowsx.h>

#include "editor/doc/EdDocument.h"
#include "gpg/core/utils/Logging.h"
#include "moho/render/RCamManager.h"
#include "moho/render/SimpleRenderWorldView.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace faf::editor
{
  namespace
  {
    constexpr float kPi = 3.14159265f;
    constexpr float kMinPitch = 0.12f;
    constexpr float kMaxPitch = kPi * 0.5f;
  } // namespace

  EdMapScene::EdMapScene(EdDocument& document)
    : mDocument(document)
  {}

  EdMapScene::~EdMapScene()
  {
    Detach();
  }

  void EdMapScene::Attach(moho::CWldMap& map)
  {
    if (moho::ren_Viewport == nullptr || map.mTerrainRes == nullptr || map.mTerrainRes->mMap == nullptr ||
        mDocument.Lua() == nullptr) {
      return;
    }
    // The map first: the world view's terrain renderer is made over `REN_GetTerrainRes()` (AddWorldView).
    moho::REN_SetWldMap(&map);
    const moho::STIMap& terrain = *map.mTerrainRes->mMap;
    // The camera publishes a script object, so it needs a Lua state: the document's, which outlives it
    // (the document calls Detach before it drops its map and state).
    mCamera = moho::CAM_GetManager()->CreateCamera("Map editor camera", terrain, mDocument.Lua());
    const Wm3::AxisAlignedBox3f bounds = terrain.GetBounds3D();
    mMapExtent = std::max(bounds.Max.x - bounds.Min.x, bounds.Max.z - bounds.Min.z);
    mMap = &map;
    mWidth = 0;
    mHeight = 0;
    FrameWholeMap();
    mWorldView = std::make_unique<moho::SimpleRenderWorldView>(const_cast<moho::GeomCamera3*>(&mCamera->CameraGetView()));
    moho::ren_Viewport->AddWorldView(mWorldView.get(), 0, 0);
    gpg::Logf("editor: the viewport shows %s", mDocument.Path().c_str());
  }

  void EdMapScene::Detach()
  {
    if (mMap == nullptr) {
      return;
    }
    if (moho::ren_Viewport != nullptr && mWorldView != nullptr) {
      moho::ren_Viewport->RemoveWorldView(mWorldView.get());
    }
    if (moho::sWldMap == mMap) {
      moho::REN_SetWldMap(nullptr);
    }
    mWorldView.reset();
    // ~CameraImpl takes the camera out of the camera manager (as RenderPreviewImage relies on).
    delete mCamera;
    mCamera = nullptr;
    mMap = nullptr;
    mDrag = Drag::None;
  }

  void EdMapScene::Update(const float frameSeconds, const bool playIdle)
  {
    moho::CWldMap* const wanted =
      playIdle && mDocument.GetState() == EdDocument::State::Open ? mDocument.Map() : nullptr;
    if (mMap != nullptr && mMap != wanted) {
      Detach();
    }
    // A play's session clears the renderer's map when it ends (0x00893BE6); attach once it has.
    if (mMap == nullptr && wanted != nullptr && moho::sWldMap == nullptr) {
      Attach(*wanted);
    }
    if (mMap == nullptr) {
      return;
    }
    if (moho::CD3DDevice* const device = moho::D3D_GetDevice(); device != nullptr) {
      const int width = device->GetHeadWidth(0);
      const int height = device->GetHeadHeight(0);
      if (width != mWidth || height != mHeight) {
        mWidth = width;
        mHeight = height;
        mCamera->CameraSetViewport(
          Wm3::Vector2f(0.0f, 0.0f), Wm3::Vector2f(static_cast<float>(width), static_cast<float>(height))
        );
        ApplyCamera();
      }
    }
    // A session runs the camera manager from its own frame; between plays the editor does.
    moho::CAM_GetManager()->Frame(0.0f, frameSeconds);
  }

  void EdMapScene::FrameWholeMap()
  {
    if (mMap == nullptr) {
      return;
    }
    const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
    mTargetX = (bounds.Min.x + bounds.Max.x) * 0.5f;
    mTargetZ = (bounds.Min.z + bounds.Max.z) * 0.5f;
    mHeading = kPi;
    mPitch = 1.1f;
    mDistance = mMapExtent * 1.05f;
    ApplyCamera();
  }

  void EdMapScene::ApplyCamera()
  {
    if (mCamera == nullptr) {
      return;
    }
    const Wm3::AxisAlignedBox3f bounds = mMap->mTerrainRes->mMap->GetBounds3D();
    mTargetX = std::clamp(mTargetX, bounds.Min.x, bounds.Max.x);
    mTargetZ = std::clamp(mTargetZ, bounds.Min.z, bounds.Max.z);
    mTargetY = mMap->mTerrainRes->GetHeightAt(static_cast<std::int32_t>(mTargetX), static_cast<std::int32_t>(mTargetZ));
    mPitch = std::clamp(mPitch, kMinPitch, kMaxPitch);
    mDistance = std::clamp(mDistance, 15.0f, mMapExtent * 2.5f);
    mCamera->TargetManual(Wm3::Vec3f{mTargetX, mTargetY, mTargetZ}, mHeading, mPitch, mDistance, 0.0f);
  }

  bool EdMapScene::OnWindowMessage(const HWND window, const UINT message, const WPARAM wParam, const LPARAM lParam)
  {
    if (mMap == nullptr) {
      return false;
    }
    const POINT at{GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam)};
    switch (message) {
    case WM_RBUTTONDOWN:
    case WM_MBUTTONDOWN:
      // Middle drag orbits, Shift + middle drag pans; the right button pans.
      mDrag = (message == WM_MBUTTONDOWN && (wParam & MK_SHIFT) == 0) ? Drag::Orbit : Drag::Pan;
      mDragFrom = at;
      ::SetCapture(window);
      ::SetFocus(window);
      return true;
    case WM_RBUTTONUP:
    case WM_MBUTTONUP:
      if (mDrag != Drag::None) {
        mDrag = Drag::None;
        ::ReleaseCapture();
      }
      return true;
    case WM_MOUSEMOVE: {
      if (mDrag == Drag::None) {
        return false;
      }
      const float dx = static_cast<float>(at.x - mDragFrom.x);
      const float dy = static_cast<float>(at.y - mDragFrom.y);
      mDragFrom = at;
      if (mDrag == Drag::Orbit) {
        mHeading -= dx * 0.006f;
        mPitch += dy * 0.006f;
      } else {
        // Along the ground as the camera faces it, scaled so the ground follows the cursor roughly.
        const float scale = mDistance * 0.0018f;
        const float sinH = std::sin(mHeading);
        const float cosH = std::cos(mHeading);
        mTargetX -= (dx * cosH - dy * sinH) * scale;
        mTargetZ -= (-dx * sinH - dy * cosH) * scale;
      }
      ApplyCamera();
      return true;
    }
    case WM_MOUSEWHEEL: {
      const float steps = static_cast<float>(GET_WHEEL_DELTA_WPARAM(wParam)) / WHEEL_DELTA;
      mDistance *= std::pow(0.85f, steps);
      ApplyCamera();
      return true;
    }
    case WM_KEYDOWN:
      if (wParam == VK_HOME) {
        FrameWholeMap();
        return true;
      }
      return false;
    case WM_CAPTURECHANGED:
      mDrag = Drag::None;
      return false;
    default:
      return false;
    }
  }
} // namespace faf::editor
