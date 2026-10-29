// Engine addition (dedicated-server plan WPL.4, WPR.11): CDebugCanvas::Render,
// which draws a sim debug canvas with the D3D primitive batcher and font, moved
// unchanged out of Sim.cpp. The canvas and its Add* calls stay with the
// simulation; drawing it is the client's.
#include "moho/sim/Sim.h"
#include "legacy/math/X87Math.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/SimDriver.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include <Windows.h>
#include <intrin.h>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiBuilderImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/sim/UnitUpdateFill.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/CUserSoundManager.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "moho/command/CCommandDb.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/sim/BuildQueueCommandDecrement.h"
#include "moho/sim/CDamage.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CVarAccess.h"
#include "moho/debug/RDebugOverlayClass.h"
#include "moho/entity/Entity.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/EntityPositionWatchEntry.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "lua/LuaError.h"
#include "lua/LuaRuntimeTypes.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/CWldMap.h"
#include "moho/task/CLuaTask.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/BlueprintLoaderContext.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "gpg/core/containers/BitArray2D.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/PathPreviewFinder.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/math/Vector3f.h"
#include "moho/containers/BVSet.h"

using namespace moho;

/**
 * Address: 0x004516C0 (FUN_004516C0, ?Render@CDebugCanvas@Moho@@QBEXPAVCD3DPrimBatcher@2@ABVGeomCamera3@2@HH@Z)
 */
void CDebugCanvas::Render(
  CD3DPrimBatcher* const primBatcher,
  const GeomCamera3& camera,
  const int viewportWidth,
  const int viewportHeight
) const
{
  if (primBatcher == nullptr) {
    return;
  }

  if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
    device->SelectFxFile("primbatcher");
    device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");
  }

  primBatcher->SetProjectionMatrix(camera.projection);
  primBatcher->SetViewMatrix(camera.view);
  primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));

  for (const SDebugLine& line : lines) {
    CD3DPrimBatcher::Vertex start{};
    start.mX = line.p0.x;
    start.mY = line.p0.y;
    start.mZ = line.p0.z;
    start.mColor = static_cast<std::uint32_t>(line.depth0);
    start.mU = 0.0f;
    start.mV = 0.0f;

    CD3DPrimBatcher::Vertex end{};
    end.mX = line.p1.x;
    end.mY = line.p1.y;
    end.mZ = line.p1.z;
    end.mColor = static_cast<std::uint32_t>(line.depth1);
    end.mU = 1.0f;
    end.mV = 0.0f;

    primBatcher->DrawLine(start, end);
  }

  const float kNoMaxAdvance = gpg::NaN;
  for (const SDebugScreenText& text : screenText) {
    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(text.pointSize, "Ariel");
    CD3DFont* const font = rawFont.px;
    if (font != nullptr) {
      (void)font->Render(text.text.raw_data_unsafe(), primBatcher, text.origin, text.xAxis, text.yAxis, text.color, 0.0f, kNoMaxAdvance);
    }
    rawFont.release();
  }

  for (const SDebugDecal& decal : decals) {
    primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(decal.color));

    CD3DPrimBatcher::Vertex corner0{};
    corner0.mX = decal.corner0.x;
    corner0.mY = decal.corner0.y;
    corner0.mZ = decal.corner0.z;
    corner0.mColor = 0xFFFFFFFFu;
    corner0.mU = 0.0f;
    corner0.mV = 0.0f;

    CD3DPrimBatcher::Vertex corner1{};
    corner1.mX = decal.corner1.x;
    corner1.mY = decal.corner1.y;
    corner1.mZ = decal.corner1.z;
    corner1.mColor = 0xFFFFFFFFu;
    corner1.mU = 1.0f;
    corner1.mV = 0.0f;

    CD3DPrimBatcher::Vertex corner2{};
    corner2.mX = decal.corner2.x;
    corner2.mY = decal.corner2.y;
    corner2.mZ = decal.corner2.z;
    corner2.mColor = 0xFFFFFFFFu;
    corner2.mU = 1.0f;
    corner2.mV = 1.0f;

    CD3DPrimBatcher::Vertex corner3{};
    corner3.mX = decal.corner3.x;
    corner3.mY = decal.corner3.y;
    corner3.mZ = decal.corner3.z;
    corner3.mColor = 0xFFFFFFFFu;
    corner3.mU = 0.0f;
    corner3.mV = 1.0f;

    primBatcher->DrawQuad(corner0, corner1, corner2, corner3);
  }

  primBatcher->Flush();

  const float widthF = static_cast<float>(viewportWidth);
  const float heightF = static_cast<float>(viewportHeight);
  VMatrix4 projection{};
  projection.r[0] = {2.0f / widthF, 0.0f, 0.0f, 0.0f};
  projection.r[1] = {0.0f, 2.0f / (-heightF), 0.0f, 0.0f};
  projection.r[2] = {0.0f, 0.0f, -0.5f, 0.0f};
  projection.r[3] = {
    (widthF / (-widthF)) - (1.0f / widthF),
    (heightF / heightF) + (1.0f / heightF),
    0.5f,
    1.0f,
  };

  primBatcher->SetProjectionMatrix(projection);
  primBatcher->SetViewMatrix(VMatrix4::Identity());

  constexpr Wm3::Vector3f kScreenTextXAxis{1.0f, 0.0f, 0.0f};
  constexpr Wm3::Vector3f kScreenTextYAxis{0.0f, -1.0f, 0.0f};
  for (const SDebugWorldText& worldEntry : worldText) {
    const float clipX =
      (worldEntry.position.x * camera.viewProjection.r[0].x) + (worldEntry.position.y * camera.viewProjection.r[1].x) +
      (worldEntry.position.z * camera.viewProjection.r[2].x) + camera.viewProjection.r[3].x;
    const float clipY =
      (worldEntry.position.x * camera.viewProjection.r[0].y) + (worldEntry.position.y * camera.viewProjection.r[1].y) +
      (worldEntry.position.z * camera.viewProjection.r[2].y) + camera.viewProjection.r[3].y;
    const float clipW =
      (worldEntry.position.x * camera.viewProjection.r[0].w) + (worldEntry.position.y * camera.viewProjection.r[1].w) +
      (worldEntry.position.z * camera.viewProjection.r[2].w) + camera.viewProjection.r[3].w;
    const float inverseW = 1.0f / clipW;

    const float ndcX = clipX * inverseW;
    const float ndcY = clipY * inverseW;
    const float screenX = ((ndcX - -1.0f) * widthF) * 0.5f;
    const float screenY = (((ndcY - -1.0f) * (-heightF)) * 0.5f) + heightF;
    const Wm3::Vector3f screenOrigin{
      static_cast<float>(std::floor(screenX)),
      static_cast<float>(std::floor(screenY)),
      0.0f,
    };

    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(worldEntry.style, "Ariel");
    CD3DFont* const font = rawFont.px;
    if (font != nullptr) {
      (void)font->Render(
        worldEntry.text.raw_data_unsafe(),
        primBatcher,
        screenOrigin,
        kScreenTextXAxis,
        kScreenTextYAxis,
        worldEntry.depth,
        0.0f,
        kNoMaxAdvance
      );
    }
    rawFont.release();
  }

  primBatcher->Flush();
}
