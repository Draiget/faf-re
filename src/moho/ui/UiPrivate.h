#pragma once

// Private to moho/ui: helpers the pieces of the former UiRuntimeTypes.cpp share.

#include "moho/ui/UiRuntimeTypes.h"
#include "legacy/math/X87Math.h"

#include "moho/sim/BuildQueueCommandDecrement.h"
#include "platform/BinaryObjectBytes.h"

#include <boost/bind.hpp>
#include <Windows.h>

#include <algorithm>
#include <bit>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/BitArray2D.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "lua/LuaAssertion.h"
#include "lua/LuaTableIterator.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/command/CommandManager.h"
#include "moho/console/CConCommand.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/containers/TDatList.h"
#include "moho/core/Thread.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/entity/UserEntity.h"
#include "moho/lua/CScrLuaBaseClassSpec.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/GridPos.h"
#include "moho/math/Vector3f.h"
#include "moho/mesh/Mesh.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/WeakPtr.h"
#include "moho/movie/CMovie.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/net/IClient.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/IRenderWorldView.h"
#include "moho/render/RCamManager.h"
#include "moho/render/SelectionBracketRenderer.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "moho/render/WRenViewport.h"
#include "moho/resource/blueprints/RBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/IResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "moho/sim/CFormation.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SimDriver.h"
#include "moho/sim/STIMap.h"
#include "moho/task/CTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "moho/ui/CUIManager.h"
#include "moho/ui/CUIWorldMesh.h"
#include "moho/ui/EMauiKeyCodeTypeInfo.h"
#include "moho/ui/EMauiScrollAxisTypeInfo.h"
#include "moho/ui/IUIManager.h"
#include "moho/ui/SelectionDragger.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"
#include "Wm3Box3.h"
#include "moho/math/Wm3Queries.h"
#include "Wm3Line3.h"
#include "lua/LuaCrashDump.h"

namespace
{
  /**
   * The UI classes here are thin: their real layout lives in the matching
   * a deleted-overlay, so placement-new runs only the vptr-carrying constructors
   * and none of the member constructors the binary's real classes have.
   * `operator new` hands back uninitialised bytes, so lanes such as
   * `CScriptObject::cObject` (+0x0C) and `mLuaObj` (+0x20) start as garbage.
   *
   * `CScriptObject::SetLuaObject` then assigns to them, and
   * `LuaPlus::LuaObject::operator=` sees a non-null `m_state`, takes its unlink
   * branch, and executes `*m_prev = m_next` through a garbage pointer. That
   * wild write lands in the root state's used-object list, and the Lua GC walks
   * off the end of it on the next collection.
   *
   * Zeroing first is what the binary's constructor chain leaves behind for
   * those lanes - null links and `tt = LUA_TNIL = 0`.
   *
   * `binaryByteSize` is the binary's x86 allocation size; on x64 the block is
   * widened to fit the same layout with 8-byte pointers.
   */
  template <typename T>
  [[nodiscard]] T* AllocateZeroedUiObject(
    const std::size_t binaryByteSize
  )
  {
    const std::size_t byteSize = platform::BinaryObjectBytes<T>(binaryByteSize);
    void* const storage = ::operator new(byteSize);
    std::memset(storage, 0, byteSize);
    return static_cast<T*>(storage);
  }
}

namespace moho
{
  bool WIN_CopyToClipboard(const wchar_t* text);
}


moho::CommandModeData* func_GetRightMouseButtonAction(
  moho::CommandModeData* commandData,
  moho::MouseInfo* mouseInfo,
  int modifiers,
  moho::CWldSession* wldSession
);
namespace moho
{
  int cfunc_IN_ClearKeyMap(lua_State* luaContext);
  int func_FlushEvents(lua_State* luaContext);

  template <>
  class CScrLuaMetatableFactory<CLuaWldUIProvider> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CUIWorldMesh> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CUIWorldView> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CUIMapPreview> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiControl> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00783070 (FUN_00783070, Moho::CScrLuaMetatableFactory<Moho::CMauiControl>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiControl`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiBorder> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00786180 (FUN_00786180, Moho::CScrLuaMetatableFactory<Moho::CMauiBorder>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiBorder`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiBitmap> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00783040 (FUN_00783040, Moho::CScrLuaMetatableFactory<Moho::CMauiBitmap>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiBitmap`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiCursor> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x0078D940 (FUN_0078D940, Moho::CScrLuaMetatableFactory<Moho::CMauiCursor>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiCursor`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiLuaDragger> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x0078E660 (FUN_0078E660, Moho::CScrLuaMetatableFactory<Moho::CMauiLuaDragger>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiLuaDragger`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiEdit> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x00794E90 (FUN_00794E90, Moho::CScrLuaMetatableFactory<Moho::CMauiEdit>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiEdit`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiScrollbar> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x007A2470 (FUN_007A2470, Moho::CScrLuaMetatableFactory<Moho::CMauiScrollbar>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiScrollbar`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  template <>
  class CScrLuaMetatableFactory<CMauiText> final : public CScrLuaObjectFactory
  {
  public:
    CScrLuaMetatableFactory();

    [[nodiscard]] static CScrLuaMetatableFactory& Instance();

  protected:
    /**
     * Address: 0x007A4250 (FUN_007A4250, Moho::CScrLuaMetatableFactory<Moho::CMauiText>::Create)
     *
     * What it does:
     * Builds one simple Lua metatable object for `CMauiText`.
     */
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CLuaWldUIProvider>) == 0x8,
    "CScrLuaMetatableFactory<CLuaWldUIProvider> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUIWorldMesh>) == 0x8,
    "CScrLuaMetatableFactory<CUIWorldMesh> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUIWorldView>) == 0x8,
    "CScrLuaMetatableFactory<CUIWorldView> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CUIMapPreview>) == 0x8,
    "CScrLuaMetatableFactory<CUIMapPreview> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiControl>) == 0x8,
    "CScrLuaMetatableFactory<CMauiControl> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiBorder>) == 0x8,
    "CScrLuaMetatableFactory<CMauiBorder> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiBitmap>) == 0x8,
    "CScrLuaMetatableFactory<CMauiBitmap> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiCursor>) == 0x8,
    "CScrLuaMetatableFactory<CMauiCursor> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiLuaDragger>) == 0x8,
    "CScrLuaMetatableFactory<CMauiLuaDragger> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiEdit>) == 0x8,
    "CScrLuaMetatableFactory<CMauiEdit> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiScrollbar>) == 0x8,
    "CScrLuaMetatableFactory<CMauiScrollbar> size must be 0x8"
  );

  static_assert(
    sizeof(CScrLuaMetatableFactory<CMauiText>) == 0x8,
    "CScrLuaMetatableFactory<CMauiText> size must be 0x8"
  );
  int cfunc_CMauiLuaDraggerDestroyL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewFontL(LuaPlus::LuaState* state);

  int cfunc_CLuaWldUIProviderDestroyL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshDestroyL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetMeshL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetStanceL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetHiddenL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshIsHiddenL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetAuxiliaryParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetFractionCompleteParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetFractionHealthParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetLifetimeParameterL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetColorL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshSetScaleL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedPositionL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedSphereL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedAlignedBoxL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedOrientedBoxL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldMeshGetInterpolatedScrollL(LuaPlus::LuaState* state);
  int cfunc_CUIWorldViewGetScreenPosL(LuaPlus::LuaState* state);
  /**
   * Address: 0x00857BE0 (FUN_00857BE0, cfunc_AddCommandFeedbackBlipL)
   *
   * What it does:
   * Reads one blip descriptor table + duration and appends one temporary mesh
   * marker into the command-feedback runtime list.
   */
  int cfunc_AddCommandFeedbackBlipL(LuaPlus::LuaState* state);

  int cfunc_CMauiBitmapInternalSetSolidColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitMapGetNumFramesL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetNewTextureL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetUVL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapUseAlphaHitTestL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetTiledL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapLoopL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapPlayL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapStopL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapGetFrameL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetForwardPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetBackwardPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetPingPongPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetLoopPingPongPatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapSetFramePatternL(LuaPlus::LuaState* state);
  int cfunc_CMauiBitmapShareTexturesL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorSetNewTextureL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorResetToDefaultL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorHideL(LuaPlus::LuaState* state);
  int cfunc_CMauiCursorShowL(LuaPlus::LuaState* state);
  int register_CScrLuaMetatableFactory_CMauiHistogram_Index();
  int register_CScrLuaMetatableFactory_CMauiScrollbar_Index();
  int register_CScrLuaMetatableFactory_CLuaWldUIProvider_Index();
  int register_CScrLuaMetatableFactory_CUIWorldMesh_Index();
  int register_CScrLuaMetatableFactory_CUIWorldView_Index();
  int cfunc_CMauiEditSetNewForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditShowBackgroundL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditIsBackgroundVisibleL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditIsEnabledL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditEnableInputL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditDisableInputL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewHighlightForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetHighlightForegroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetNewHighlightBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetHighlightBackgroundColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetFontHeightL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetMaxCharsL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetMaxCharsL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditAcquireFocusL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditAbandonFocusL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditSetDropShadowL(LuaPlus::LuaState* state);
  int cfunc_CMauiEditGetStringAdvanceL(LuaPlus::LuaState* state);
  int cfunc_CMauiHistogramSetDataL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateGroupL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateFrameL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateDraggerL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateHistogramL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateBitmapL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateBorderL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateEditL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateScrollbarL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateItemListL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateMeshL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateMovieL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateTextL(LuaPlus::LuaState* state);
  int cfunc_InternalCreateMapPreviewL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListSetNewFontL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListModifyItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListDeleteItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListDeleteAllItemsL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListGetSelectionL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListGetItemCountL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListEmptyL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListScrollToTopL(LuaPlus::LuaState* state);
  int cfunc_CMauiListItemScrollToBottomL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListShowItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListGetRowHeightL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListShowMouseoverItemL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListShowSelectionL(LuaPlus::LuaState* state);
  int cfunc_CMauiItemListNeedsScrollBarL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetNewFontL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextGetTextL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetNewColorL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetDropShadowL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetCenteredHorizontallyL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetCenteredVerticallyL(LuaPlus::LuaState* state);
  int cfunc_CMauiTextSetNewClipToWidthL(LuaPlus::LuaState* state);
  int cfunc_IsKeyDownL(LuaPlus::LuaState* state);
  int cfunc_KeycodeMauiToMSWL(LuaPlus::LuaState* state);
  int cfunc_KeycodeMSWToMauiL(LuaPlus::LuaState* state);
}

namespace
{
  using moho::CD3DFont;
  using moho::CMauiCursor;
  using moho::CMauiEdit;
  using moho::CScriptLazyVar_float;

  [[maybe_unused]] moho::CMauiBitmap*
  SetBitmapAlphaHitTestEnabled(moho::CMauiBitmap* bitmap, bool enabled) noexcept;
  [[maybe_unused]] moho::CMauiBitmap* SetBitmapTiledEnabled(moho::CMauiBitmap* bitmap, bool enabled) noexcept;
  [[maybe_unused]] moho::CMauiBitmap* SetBitmapLoopEnabled(moho::CMauiBitmap* bitmap, bool enabled) noexcept;
  [[maybe_unused]] std::int32_t ReadBitmapCurrentFrame(const moho::CMauiBitmap* bitmap) noexcept;
  [[maybe_unused]] std::int32_t CountBitmapFramePatternEntries(const moho::CMauiBitmap* bitmap) noexcept;
  [[maybe_unused]] std::uint32_t EnableBitmapAnimationIfMultipleTextures(moho::CMauiBitmap* bitmap) noexcept;

  /// The state a control's layout lazy vars are created in: the control's
  /// Lua object's, or none.
  [[maybe_unused]] [[nodiscard]] LuaPlus::LuaState* LuaStateOf(const LuaPlus::LuaObject* const luaObject) noexcept
  {
    return luaObject != nullptr ? luaObject->m_state : nullptr;
  }

  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";

  using UiKeyMask = std::uint32_t;
  using UiKeyActionMapBase = fa::map<UiKeyMask, fa::string>;
  using UiKeyRepeatMap = fa::map<UiKeyMask, bool>;

  /**
   * Owns the legacy action map while compensating for `fa::string`'s
   * intentionally destructor-less compatibility wrapper. The shipped map
   * destroys each mapped string before freeing its node; this same-size owner
   * performs that release before delegating node destruction to `fa::map`.
   */
  class UiKeyActionMap final : public UiKeyActionMapBase
  {
  public:
    ~UiKeyActionMap();

    size_type erase(const key_type& key);
    void clear() noexcept;

  private:
    void ReleaseStrings() noexcept;
  };

  UiKeyActionMap::size_type UiKeyActionMap::erase(
    const key_type& key
  )
  {
    const iterator found = find(key);
    if (found == end()) {
      return 0u;
    }

    found->second.tidy(true, 0u);
    (void)UiKeyActionMapBase::erase(found);
    return 1u;
  }

  void UiKeyActionMap::clear() noexcept
  {
    ReleaseStrings();
    UiKeyActionMapBase::clear();
  }

  void UiKeyActionMap::ReleaseStrings() noexcept
  {
    for (auto& entry : *this) {
      entry.second.tidy(true, 0u);
    }
  }

  static_assert(sizeof(UiKeyActionMapBase) == 0x0C, "UI key action map base size must be 0x0C");
  static_assert(sizeof(UiKeyActionMap) == 0x0C, "UI key action map size must be 0x0C");
  static_assert(sizeof(UiKeyRepeatMap) == 0x0C, "UI key repeat map size must be 0x0C");

  [[maybe_unused]] [[nodiscard]] LuaPlus::LuaState* ResolveUiManagerLuaState() noexcept
  {
    return moho::g_UIManager->mLuaState;
  }

  template <typename TInvoke>
  bool InvokeUiLuaCallback(
    LuaPlus::LuaState* const state,
    const char* const modulePath,
    const char* const callbackName,
    TInvoke&& invoke
  )
  {
    try {
      const LuaPlus::LuaObject moduleObject = moho::SCR_Import(state, modulePath);
      const LuaPlus::LuaObject callbackObject = moduleObject[callbackName];
      LuaPlus::LuaFunction<void> callbackFunction(callbackObject);
      invoke(callbackFunction);
      return true;
    } catch (const std::exception& exception) {
      gpg::Warnf(
        "Error running '%s:%s':\n%s",
        modulePath != nullptr ? modulePath : "",
        callbackName != nullptr ? callbackName : "",
        exception.what() != nullptr ? exception.what() : ""
      );
      return false;
    }
  }

  using CMauiControlListNode = moho::TDatListItem<moho::CMauiControl, void>;

  /// The control one node of a parent's `mChildrenList` is the base of.
  [[maybe_unused]] [[nodiscard]] moho::CMauiControl* ControlFromParentListNode(
    CMauiControlListNode* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }
    return static_cast<moho::CMauiControl*>(node);
  }

  [[maybe_unused]] [[nodiscard]] const moho::CMauiControl* ControlFromParentListNode(
    const CMauiControlListNode* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }
    return static_cast<const moho::CMauiControl*>(node);
  }

  /**
   * Address: 0x0078CFA0 (FUN_0078CFA0)
   *
   * What it does:
   * Updates cursor-showing lane and marks cursor state dirty when value changes.
   */
  [[maybe_unused]] CMauiCursor* SetCursorShowingAndMarkDirty(
    CMauiCursor* const cursor,
    const bool isShowing
  ) noexcept
  {
    if (cursor->mIsShowing != isShowing) {
      cursor->mIsShowing = isShowing;
      cursor->mNeedsUpdate = true;
    }
    return cursor;
  }

  [[maybe_unused]] [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(
    lua_State* const luaContext
  ) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  using IMauiDragger = moho::IMauiDragger;
  /**
   * What a `CameraDragger` does with each frame's drag delta: a `CameraImpl`
   * member, called through the camera. `CameraImpl` has more than one base,
   * so MSVC stores a pointer to one of its members as `{code, this
   * adjustment}` - the two words at +0x18/+0x1C, which the constructor takes
   * as two stack arguments (0x0086E0AE/0x0086E0B1) and `DragMove` turns into
   * `ecx = mCamera + [+0x1C]; call [+0x18]` (0x0086E146..0x0086E18D).
   */
  using CameraDragDeltaFn = void (moho::CameraImpl::*)(const Wm3::Vector2f&);
  static_assert(sizeof(CameraDragDeltaFn) == 0x8, "a CameraImpl member pointer must be {code, this adjustment}");

  /**
   * The middle-button camera drag.
   *
   * RTTI evidence (`??_R0?AVCameraDragger@Moho@@`, complete-object locator for
   * `??_7CameraDragger@Moho@@6B@` at 0x00E49060): a single non-virtual base
   * `Moho::IMauiDragger` at `mdisp = 0`, whose own `Moho::WeakObject` base sits
   * at `mdisp = 4`, and a 4-slot primary vtable
   *   +0x00 0x0086E250 (scalar deleting dtor)
   *   +0x04 0x0086E140 `DragMove`
   *   +0x08 0x0086E220 `DragRelease`
   *   +0x0C 0x0086E1F0 `OnCurrentDraggerReplaced`
   * which is exactly `IMauiDragger`'s slot order. The constructor
   * (0x0086E060) installs that table at `[this]` (0x0086E096) and the sole
   * allocation site asks for `operator new(0x20)` (0x00870B43 in
   * `CUIWorldView::HandleEvent`), which is the size asserted below.
   *
   * This was previously modelled as a vtable-less `CameraDragger`
   * aggregate whose helpers were all unreachable. Since `HandleEvent` hands the
   * instance to `func_PostDragger`, which dispatches
   * `OnCurrentDraggerReplaced` through slot +0x0C on the *previous* dragger,
   * a missing vptr would fault on the very next drag - so the class is
   * expressed as the real `IMauiDragger` subclass the binary constructs.
   */
  class CameraDragger final : public moho::IMauiDragger
  {
  public:
    /**
     * Address: 0x0086E060 (FUN_0086E060, ??0CameraDragger@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one camera dragger with its drag target camera/lane and
     * enables mouse-scrub mode for the owning control.
     */
    CameraDragger(
      moho::CameraImpl* camera,
      const Wm3::Vector2f& mousePos,
      moho::CMauiControl* ownerControl,
      CameraDragDeltaFn dragDelta
    );

    /**
     * Address: 0x0086E0D0 (FUN_0086E0D0, Moho::CameraDragger::~CameraDragger)
     * Scalar deleting destructor: 0x0086E250 (slot +0x00)
     *
     * What it does:
     * Disables mouse-scrub mode; the `IMauiDragger` base then drains the
     * weak-reference chain behind the vptr.
     */
    ~CameraDragger() override;

    /**
     * Address: 0x0086E140 (FUN_0086E140, Moho::CameraDragger::DragMove)
     * Slot: +0x04
     *
     * What it does:
     * Applies the camera drag delta from either raw mouse motion (cursor-fixing
     * disabled) or the accumulated scrub delta, then resets the scrub lanes.
     */
    void DragMove(const moho::SMauiEventData* eventData) override;

    /**
     * Address: 0x0086E220 (FUN_0086E220, Moho::CameraDragger::DragRelease)
     * Slot: +0x08
     *
     * What it does:
     * Reverts a held camera rotation when free-look is off, then destroys this
     * dragger.
     */
    void DragRelease(const moho::SMauiEventData* eventData) override;

    /**
     * Address: 0x0086E1F0 (FUN_0086E1F0, Moho::CameraDragger::DragCancel)
     * Slot: +0x0C
     *
     * What it does:
     * Mirrors `DragRelease`: conditionally reverts camera rotation, then
     * destroys this dragger.
     */
    void OnCurrentDraggerReplaced() override;

    moho::CameraImpl* mCamera = nullptr;     // +0x08
    Wm3::Vector2f mPos{};                    // +0x0C
    // Neither the constructor nor any of the four slots reads or writes it.
    std::uint32_t mUnknown14 = 0;            // +0x14
    /**
     * The one delta handler ever stored here is `&CameraImpl::CameraPan`
     * (`CUIWorldView::HandleEvent`'s middle-button press). It is virtual, so
     * the code word is the compiler's vcall thunk for slot 32, 0x00873BD0
     * (cited on `CameraImpl::CameraPan`). That thunk used to be recovered as
     * `CameraDraggerPanCamera`, a stand-in free function taking the camera as
     * an explicit argument.
     */
    CameraDragDeltaFn mDragDelta = nullptr;  // +0x18 code, +0x1C this adjustment
  };

  static_assert(offsetof(CameraDragger, mCamera) == 0x8, "CameraDragger::mCamera offset must be 0x8");
  static_assert(offsetof(CameraDragger, mPos) == 0xC, "CameraDragger::mPos offset must be 0xC");
  static_assert(offsetof(CameraDragger, mDragDelta) == 0x18, "CameraDragger::mDragDelta offset must be 0x18");
  static_assert(sizeof(CameraDragger) == 0x20, "CameraDragger size must be 0x20");

  /**
   * The minimap click-drag: retargets a named camera at whatever world point
   * the cursor is over.
   *
   * Same evidence shape as `CameraDragger` above
   * (`??_7CMiniMapDragger@Moho@@6B@` at 0x00E49144, 4 slots:
   * +0x00 0x0086E410 deleting dtor, +0x04 0x0086E2F0 `DragMove`,
   * +0x08 0x0086E3F0 `DragRelease`, +0x0C 0x0086E3E0
   * `OnCurrentDraggerReplaced`). The constructor at 0x0086E270 installs that
   * table at `[this]` (0x0086E29B) and re-bases to `[this+8]` for the camera
   * name (`lea ecx,[esi+8]` at 0x0086E298, then `_Mysize` at `[ecx+0x14]` and
   * `_Myres` at `[ecx+0x18]`), so the string starts immediately after the
   * 8-byte `IMauiDragger` base and the object ends at 0x08 + 0x1C == 0x24 -
   * exactly the `operator new(0x24)` the sole allocation site issues
   * (0x00870D8C in `CUIWorldView::HandleEvent`).
   *
   * The previous a deleted overlay modelling put a spare dword at
   * +0x08 and the string at +0x0C, which made the object 0x28 bytes; that
   * offset is corrected here against the constructor disassembly.
   */
  class CMiniMapDragger final : public moho::IMauiDragger
  {
  public:
    /**
     * Address: 0x0086E270 (FUN_0086E270, ??0CMiniMapDragger@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one minimap dragger and copies its camera-name lane from the
     * incoming string payload.
     */
    explicit CMiniMapDragger(fa::string cameraName);

    /**
     * Address: 0x0086E430 (FUN_0086E430, Moho::CMiniMapDragger::~CMiniMapDragger)
     * Scalar deleting destructor: 0x0086E410 (slot +0x00)
     *
     * What it does:
     * Releases the camera-name storage; the `IMauiDragger` base then drains the
     * weak-reference chain behind the vptr.
     */
    ~CMiniMapDragger() override;

    /**
     * Address: 0x0086E2F0 (FUN_0086E2F0, Moho::CMiniMapDragger::DragMove)
     * Slot: +0x04
     *
     * What it does:
     * Updates the world-session cursor screen lanes from the incoming Maui
     * event coords and retargets the named minimap camera at the current cursor
     * world point.
     */
    void DragMove(const moho::SMauiEventData* eventData) override;

    /**
     * Address: 0x0086E3F0 (FUN_0086E3F0, Moho::CMiniMapDragger::DragRelease)
     * Slot: +0x08
     */
    void DragRelease(const moho::SMauiEventData* eventData) override;

    /**
     * Address: 0x0086E3E0 (FUN_0086E3E0, Moho::CMiniMapDragger::DragCancel)
     * Slot: +0x0C
     */
    void OnCurrentDraggerReplaced() override;

    fa::string mCameraName{}; // +0x08
  };

  static_assert(offsetof(CMiniMapDragger, mCameraName) == 0x8, "CMiniMapDragger::mCameraName offset must be 0x8");
  static_assert(sizeof(CMiniMapDragger) == 0x24, "CMiniMapDragger size must be 0x24");
  constexpr std::int32_t kPostDraggerLeftButton = 1;
  constexpr std::int32_t kPostDraggerMiddleButton = 2;
  constexpr std::int32_t kPostDraggerRightButton = 3;
}


  /// The dragger that owns the mouse until it is released or replaced. A
  /// weak link, so a dragger that deletes itself drops out of it.
  // Address: 0x0078E540 (FUN_0078E540 -- this global's constructor emitted
  // out of line: both words zeroed, `this` returned.)
  // Address: 0x0078E560 (FUN_0078E560 -- its destructor, `~WeakPtr`; ICF twin
  // 0x00C02D50 is the copy the exit list runs. Formerly the uncalled statics
  // `func_ResetCurrentDraggerLink` / `func_UnlinkCurrentDraggerLink`, removed
  // 2026-09-30.)
  extern moho::WeakPtr<IMauiDragger> sCurrentDragger;
  extern std::int32_t sCurrentDraggerKeycode;
  extern std::uint8_t sMouseIsCaptured;
  extern std::uint8_t sMouseIsScrubbing;
  extern POINT sMouseMoveStart;
  extern POINT sMouseScrubDelta;
  extern bool sInvertMidMouseScrub;
  extern POINT sMouseScrubAnchor;
  // Engine addition, not in the binary: where the latest
  // SetCursorPos(sMouseScrubAnchor) actually put the cursor, re-read after
  // every warp. Under DPI scaling, or when the anchor falls outside the
  // window's ClipCursor rect, the cursor lands elsewhere, and not always on
  // the same spot; measuring against the requested anchor counted that gap as
  // mouse motion on every warp (a tiny drag spun the camera by hundreds of
  // pixels). Where the warp lands exactly, this equals the anchor and nothing
  // changes.
  extern POINT sMouseScrubLanded;

  extern fa::vector<moho::WeakPtr<moho::CMauiControl>> sInputCapture;
namespace
{

  /**
   * Address: inlined at 0x007A4713 (inside CompactInputCaptureStack,
   * FUN_007A4720) and 0x007A57F3 (inside func_RemoveInputCapture's chain,
   * FUN_007A45D0) -- both are `owner=<none>` chunks per the callgraph
   * index's xref data, not a standalone out-of-line body: this operation
   * is inlined at each of its two call sites, both of which tail directly
   * into EraseInputCaptureRangeCompacting (FUN_007A58C0). A third xref from
   * `Moho::CUIManager::SetNewLuaState` (FUN_0084CC50) reaches
   * EraseInputCaptureRangeCompacting directly rather than through this
   * inlined shape.
   *
   * What it does:
   * Erases the weak-control entry at `index` from the global input-capture
   * stack, unlinking it first and then compacting the tail down over it.
   */
  void RemoveInputCaptureAt(
    const std::size_t index
  ) noexcept
  {
    if (index >= sInputCapture.size()) {
      return;
    }
    // The tail shifts down through WeakPtr's relinking assignment and the
    // vacated last slot is unlinked by its destructor.
    (void)sInputCapture.erase(sInputCapture.begin() + static_cast<std::ptrdiff_t>(index));
  }


  /**
   * Address: 0x007A4720 (FUN_007A4720, sub_7A4720)
   *
   * What it does:
   * Compacts global input-capture weak-pointer lanes by erasing stale
   * entries whose owner link resolves to null/sentinel.
   */
  void CompactInputCaptureStack() noexcept
  {
    // The binary collects the stale indices first and then erases them in
    // ascending order, without re-basing the later ones after an erase shifts
    // the tail down - so with two stale entries the second erase lands one
    // slot high. That order is kept. Where the binary would then erase one
    // past the end (two stale entries at the very top) and walk its copy loop
    // off the buffer, RemoveInputCaptureAt's bounds check stops it instead.
    fa::vector<std::int32_t> staleIndices;
    const std::int32_t count = static_cast<std::int32_t>(sInputCapture.size());
    for (std::int32_t index = 0; index < count; ++index) {
      if (sInputCapture[static_cast<std::size_t>(index)].GetObjectPtr() == nullptr) {
        staleIndices.push_back(index);
      }
    }

    for (const std::int32_t index : staleIndices) {
      RemoveInputCaptureAt(static_cast<std::size_t>(index));
    }
  }

  /**
   * Address: 0x007A4680 (FUN_007A4680, sub_7A4680)
   *
   * What it does:
   * Returns the top control currently in the global input-capture stack
   * after compacting stale weak-pointer entries.
   */
  [[maybe_unused]] [[nodiscard]] moho::CMauiControl* ResolveTopInputCaptureControl() noexcept
  {
    if (sInputCapture.empty()) {
      return nullptr;
    }
    CompactInputCaptureStack();
    return sInputCapture.empty() ? nullptr : sInputCapture.back().GetObjectPtr();
  }

  /**
   * Alias of FUN_0040D820 (non-canonical helper lane).
   *
   * What it does:
   * Applies x87-style nearby-int rounding and adjusts down by one when the
   * original value sits below the rounded lane.
   */
  [[maybe_unused]] [[nodiscard]] int FloorFrndintAdjustDown(
    const float value
  ) noexcept
  {
    const float rounded = std::nearbyintf(value);
    return static_cast<int>(rounded) + ((value < rounded) ? -1 : 0);
  }

  // CUIWorldMesh used to sit here: a pad-to-0x34 struct whose only
  // member aliased CUIWorldMesh::mMeshInstance. That member is public and
  // typed on the class, at the same offset and with its own static_assert, so
  // the twelve call sites below now read `worldMesh->mMeshInstance` directly
  // instead of reinterpret_casting the object to a parallel layout.

  void ReleaseIntrusiveFont(
    CD3DFont*& font
  ) noexcept
  {
    if (!font) {
      return;
    }

    --font->mRefCount;
    if (font->mRefCount == 0) {
      font->Release(1);
    }
    font = nullptr;
  }

  [[maybe_unused]] void AssignIntrusiveFont(
    CD3DFont*& destination,
    CD3DFont* const source
  ) noexcept
  {
    if (destination == source) {
      return;
    }

    ReleaseIntrusiveFont(destination);
    destination = source;
    if (destination) {
      ++destination->mRefCount;
    }
  }

  [[maybe_unused]] [[nodiscard]] moho::CD3DPrimBatcher::Vertex MakeBorderVertex(
    const float x,
    const float y,
    const std::uint32_t color,
    const float u,
    const float v
  ) noexcept
  {
    moho::CD3DPrimBatcher::Vertex vertex{};
    vertex.mX = x;
    vertex.mY = y;
    vertex.mZ = 0.0f;
    vertex.mColor = color;
    vertex.mU = u;
    vertex.mV = v;
    return vertex;
  }
}


// Forward declaration: defined later in this file (address 0x00823F00,
// see its own doc comment there). UICommandDragger::DragRelease below is
// its only caller in the binary.
void func_OnCommandDragEnd(moho::SMauiEventData* eventData, std::int32_t commandId, LuaPlus::LuaState* state);

// Forward declaration: defined later in this file (address 0x00823E40, see its
// own doc comment there). The UICommandDragger constructor below is its only
// caller in the binary (call site 0x00824037).
[[maybe_unused]] static void func_OnCommandDragBegin(LuaPlus::LuaState* state);

struct SBuildDragStep
{
  float mX;                // +0x00
  float mZ;                // +0x04
  float mXStep;            // +0x08
  float mZStep;            // +0x0C
  std::int32_t mStepCount; // +0x10
};

static_assert(sizeof(SBuildDragStep) == 0x14, "SBuildDragStep size must be 0x14");
static_assert(
  offsetof(SBuildDragStep, mStepCount) == 0x10,
  "SBuildDragStep::mStepCount offset must be 0x10"
);

/**
 * Address: 0x0078DDC0 (FUN_0078DDC0, sub_78DDC0)
 *
 * What it does:
 * Returns the currently active dragger lane from global dragger sentinel
 * links, or null when no dragger is active.
 */
static IMauiDragger* func_GetCurrentDraggerFromMouseMoveLane()
{
  return sCurrentDragger.GetObjectPtr();
}

/**
 * Address: 0x0078E600 (FUN_0078E600, func_GetCurrentDragger)
 *
 * What it does:
 * Returns the current dragger lane from global dragger sentinel links.
 */
static IMauiDragger* func_GetCurrentDragger()
{
  return func_GetCurrentDraggerFromMouseMoveLane();
}

/**
 * Address: 0x0078E610 (FUN_0078E610, func_GetCurrentDragger2)
 *
 * What it does:
 * Alias entry that returns the same current dragger lane as
 * `func_GetCurrentDragger`.
 */
static IMauiDragger* func_GetCurrentDragger2()
{
  return func_GetCurrentDragger();
}

/**
 * Address: 0x0086DE30 (FUN_0086DE30, func_StartMouseScrubbing)
 *
 * What it does:
 * Toggles mouse-scrub mode, updates cursor visibility/default state, and when
 * enabling scrub mode recenters the cursor to the control midpoint inside the
 * active UI head rectangle.
 */
[[maybe_unused]] static void func_StartMouseScrubbing(
  const bool doStart,
  moho::CMauiControl* const control
)
{
  if (moho::ui_DisableCursorFixing || sMouseIsScrubbing == static_cast<std::uint8_t>(doStart)) {
    return;
  }

  sMouseIsScrubbing = static_cast<std::uint8_t>(doStart);

  auto* const cursor = moho::g_UIManager->GetCursor();
  (void)SetCursorShowingAndMarkDirty(cursor, !doStart);

  if (!doStart) {
    ::SetCursorPos(sMouseMoveStart.x, sMouseMoveStart.y);
    return;
  }

  POINT cursorPoint{};
  ::GetCursorPos(&cursorPoint);
  sMouseMoveStart = cursorPoint;
  sMouseScrubDelta.x = 0;
  sMouseScrubDelta.y = 0;

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const context = device->GetDeviceContext();

  HWND secondHeadWindow = nullptr;
  if (static_cast<unsigned int>(context->GetHeadCount()) > 1u) {
    secondHeadWindow = reinterpret_cast<HWND>(context->GetHead(1u).mWindow);
  }

  RECT viewportRect{};
  const HWND mainWindowHandle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
  ::GetWindowRect(mainWindowHandle, &viewportRect);

  if (
    cursorPoint.x < viewportRect.left || cursorPoint.x > viewportRect.right || cursorPoint.y < viewportRect.top ||
    cursorPoint.y > viewportRect.bottom
  ) {
    if (secondHeadWindow != nullptr) {
      ::GetWindowRect(secondHeadWindow, &viewportRect);
    }
  }

  const float top = moho::CScriptLazyVar_float::GetValue(&control->mTopLV);
  const float height = moho::CScriptLazyVar_float::GetValue(&control->mHeightLV);
  const LONG scrubY = static_cast<LONG>(top + static_cast<float>(viewportRect.top) + (height * 0.5f));

  const float left = moho::CScriptLazyVar_float::GetValue(&control->mLeftLV);
  const float width = moho::CScriptLazyVar_float::GetValue(&control->mWidthLV);
  sMouseScrubAnchor.x = static_cast<LONG>(left + static_cast<float>(viewportRect.left) + (width * 0.5f));
  sMouseScrubAnchor.y = scrubY;
  ::SetCursorPos(sMouseScrubAnchor.x, sMouseScrubAnchor.y);
  ::GetCursorPos(&sMouseScrubLanded);
}

/**
 * Address: 0x0078E590 (FUN_0078E590, func_SetCurDragger)
 *
 * What it does:
 * Relinks the global current-dragger sentinel to track one dragger lane.
 */
static moho::WeakPtr<IMauiDragger>* func_SetCurDragger(
  IMauiDragger* const dragger
)
{
  sCurrentDragger.ResetFromObject(dragger);
  return &sCurrentDragger;
}

/**
 * Address: 0x007A4920 (FUN_007A4920, func_SetMouseCapture)
 *
 * What it does:
 * Applies Win32 mouse capture transitions for the active Maui event mapper.
 */
static std::uint8_t func_SetMouseCapture(
  const bool shouldCapture,
  moho::CMauiWxEventMapper* const eventMapper
)
{
  std::uint8_t result = sMouseIsCaptured;
  if (static_cast<std::uint8_t>(shouldCapture) != sMouseIsCaptured) {
    if (sMouseIsCaptured != 0) {
      result = static_cast<std::uint8_t>(::ReleaseCapture());
      sMouseIsCaptured = 0;
    }
    if (shouldCapture) {
      const HWND capturedWindow = ::SetCapture(reinterpret_cast<HWND>(static_cast<std::uintptr_t>(eventMapper->mWindow->GetHWND())));
      result = static_cast<std::uint8_t>(reinterpret_cast<std::uintptr_t>(capturedWindow));
      sMouseIsCaptured = 1;
    }
  }
  return result;
}

/**
 * Address: 0x0078DDE0 (FUN_0078DDE0, func_PostDragger)
 *
 * What it does:
 * Switches active dragger ownership, updates Win32 mouse-capture state, and
 * records the keycode lane used by the current dragger.
 */
[[maybe_unused]] static void func_PostDragger(
  moho::CMauiFrame* const originFrame,
  IMauiDragger* const dragger,
  const moho::SMauiEventData* const eventData
)
{
  IMauiDragger* const currentDragger = func_GetCurrentDragger();
  if (dragger == currentDragger) {
    return;
  }

  if (currentDragger != nullptr) {
    currentDragger->OnCurrentDraggerReplaced();
  }

  (void)func_SetCurDragger(dragger);

  if (originFrame != nullptr) {
    (void)func_SetMouseCapture(dragger != nullptr, originFrame->mEventHandler);
  }

  if (func_GetCurrentDragger2() == nullptr) {
    sCurrentDraggerKeycode = 0;
  } else {
    sCurrentDraggerKeycode = eventData->mKeyCode;
  }
}
  /**
   * Depth of MAUI event dispatch currently on the stack. `PurgeDeleted` skips
   * the delete while this is non-zero, so a control cannot be freed underneath
   * an event walk that still holds a pointer to it. Single-threaded: every
   * dispatch runs on the wx message loop.
   */
  extern int gMauiEventDispatchDepth;
namespace
{

  [[maybe_unused]] [[nodiscard]] bool MauiEventDispatchInProgress() noexcept
  {
    return gMauiEventDispatchDepth > 0;
  }
}


namespace ui_detail
{
  using FactoryQueueItem = moho::FactoryQueueDisplayItem;
  using FactoryQueueLanes = moho::FactoryQueueDisplaySnapshot;

  [[nodiscard]] inline FactoryQueueLanes& CurrentBuildQueueLanes() noexcept
  {
    return moho::sCurrentBuildQueue;
  }
  /// One `AddCommandFeedbackBlip` mesh: shown for `mDuration` seconds, aged by
  /// `UI_UpdateCommandFeedbackBlips`.
  struct SCommandFeedbackBlip final
  {
    moho::MeshInstance* mMeshInstance; // +0x00
    float mDuration;                   // +0x04
    float mCurTime;                    // +0x08
  };

  static_assert(
    offsetof(SCommandFeedbackBlip, mDuration) == 0x04,
    "SCommandFeedbackBlip::mDuration offset must be 0x04"
  );
  static_assert(
    offsetof(SCommandFeedbackBlip, mCurTime) == 0x08,
    "SCommandFeedbackBlip::mCurTime offset must be 0x08"
  );
  static_assert(sizeof(SCommandFeedbackBlip) == 0x0C, "SCommandFeedbackBlip size must be 0x0C");
}
using namespace ui_detail;


  extern fa::list<SCommandFeedbackBlip> sCommandFeedbackBlips;
