#include "moho/particles/BeamRenderHelpers.h"

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>

#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "moho/console/CConCommand.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/RD3DTextureResource.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/d3d/CD3DVertexFormat.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/d3d/D3DSingletonCleanup.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/particles/ParticleRenderBuckets.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/resource/CParticleTexture.h"

namespace moho
{
  extern bool ren_Beams;
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  moho::TConVar<bool> gTConVar_ren_Beams("ren_Beams", "", &moho::ren_Beams);

  constexpr const char* kParticleRendererSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\ParticleRenderer.cpp";
  constexpr const char* kUnreachableAssertText = "Reached the supposably unreachable.";
  constexpr int kParticleSelectTechniqueAssertLine = 1359;
  constexpr int kParticleSelectTechniqueWithDragAssertLine = 1026;

  /**
   * Address: 0x00BF0030 (FUN_00BF0030, Moho::TConVar_ren_Beams::~TConVar_ren_Beams)
   *
   * What it does:
   * Tears down the static `ren_Beams` console-variable registration via the
   * shared `TeardownConCommandRegistration` helper. Registered via `atexit`
   * from the convar startup path.
   */
  void CleanupTConVar_ren_Beams() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_ren_Beams);
  }

  template <typename TType>
  [[nodiscard]] bool IsSharedHandleLessForBucket(
    const boost::shared_ptr<TType>& lhs, const boost::shared_ptr<TType>& rhs
  ) noexcept
  {
    using SharedHandleRaw = boost::SharedPtrLayoutView<TType>;
    const auto* const lhsRaw = reinterpret_cast<const SharedHandleRaw*>(&lhs);
    const auto* const rhsRaw = reinterpret_cast<const SharedHandleRaw*>(&rhs);
    if (lhsRaw->px == rhsRaw->px) {
      return false;
    }
    return lhsRaw->pi < rhsRaw->pi;
  }

  template <typename TType>
  [[nodiscard]] bool AreSharedHandlesEquivalentForBucket(
    const boost::shared_ptr<TType>& lhs, const boost::shared_ptr<TType>& rhs
  ) noexcept
  {
    return lhs.get() == rhs.get();
  }

  [[nodiscard]] bool IsMsvc8StringLess(const msvc8::string& lhs, const msvc8::string& rhs) noexcept
  {
    const char* const lhsData = lhs.data();
    const char* const rhsData = rhs.data();
    return std::lexicographical_compare(
      lhsData,
      lhsData + lhs.size(),
      rhsData,
      rhsData + rhs.size()
    );
  }

  [[nodiscard]] Wm3::Vector3<float> LerpVector3(
    const Wm3::Vector3<float>& from, const Wm3::Vector3<float>& to, const float alpha
  ) noexcept
  {
    return Wm3::Vector3<float>{
      from.x + ((to.x - from.x) * alpha),
      from.y + ((to.y - from.y) * alpha),
      from.z + ((to.z - from.z) * alpha),
    };
  }

  [[nodiscard]] Wm3::Vector3<float> RotateVectorByOrientation(
    const Wm3::Vector3<float>& vector, const Wm3::Quaternion<float>& orientation
  ) noexcept
  {
    Wm3::Vector3<float> out{};
    // Ground truth (FUN_00491760.c, EmitInterpolatedBeamQuadVertices) rotates
    // via Moho::MultQuadVec, not the generic Wm3::MultiplyQuaternionVector --
    // same quaternion-convention mismatch as the other orient_-consuming
    // sites. `orientation` here is a Wm3::Quaternion::Nlerp of two orient_
    // fields; Nlerp treats all four lanes symmetrically (component-wise lerp
    // + Dot-based hemisphere check + normalize), so it preserves whatever
    // convention its inputs were in, and orient_ is always in
    // VMatrix4::Set's convention.
    moho::MultQuadVec(&out, &vector, &orientation);
    return out;
  }

  [[nodiscard]] moho::BeamRenderVertexRuntime BuildBeamRenderVertex(
    const Wm3::Vector3<float>& worldPosition,
    const Wm3::Vector3<float>& axis,
    const float width,
    const moho::Vector4f& color,
    const float sideSign,
    const float repeatCoord,
    const float uShift,
    const float vShift
  ) noexcept
  {
    moho::BeamRenderVertexRuntime vertex{};
    vertex.worldPosition = worldPosition;
    vertex.axis = axis;
    vertex.width = width;
    vertex.color = color;
    vertex.sideSign = sideSign;
    vertex.repeatCoord = repeatCoord;
    vertex.uShift = uShift;
    vertex.vShift = vShift;
    return vertex;
  }

  /**
   * Address: 0x00495A20 (FUN_00495A20, func_register_ShaderVar_3)
   *
   * What it does:
   * Registers one particle shader-var lane and returns the same shader-var
   * storage pointer.
   */
  [[nodiscard]] moho::ShaderVar* RegisterParticleShaderVarSlotA(
    const char* const effectFileName,
    const char* const variableName,
    moho::ShaderVar* const shaderVar
  )
  {
    moho::RegisterShaderVar(variableName, shaderVar, effectFileName);
    return shaderVar;
  }

  /**
   * Address: 0x00495A50 (FUN_00495A50, func_register_ShaderVar_4)
   *
   * What it does:
   * Registers one particle shader-var lane and returns the same shader-var
   * storage pointer.
   */
  [[nodiscard]] moho::ShaderVar* RegisterParticleShaderVarSlotB(
    const char* const effectFileName,
    const char* const variableName,
    moho::ShaderVar* const shaderVar
  )
  {
    moho::RegisterShaderVar(variableName, shaderVar, effectFileName);
    return shaderVar;
  }

  [[nodiscard]] moho::ShaderVar& GetParticleTexture0ShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static bool initialized = false;
    if (!initialized) {
      (void)RegisterParticleShaderVarSlotA("particle", "ParticleTexture0", &shaderVar);
      initialized = true;
    }
    return shaderVar;
  }

  [[nodiscard]] moho::ShaderVar& GetParticleTexture1ShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static bool initialized = false;
    if (!initialized) {
      (void)RegisterParticleShaderVarSlotB("particle", "ParticleTexture1", &shaderVar);
      initialized = true;
    }
    return shaderVar;
  }

  [[nodiscard]] moho::ShaderVar& GetParticleDragEnabledShaderVar()
  {
    static moho::ShaderVar shaderVar{};
    static bool initialized = false;
    if (!initialized) {
      moho::RegisterShaderVar("DragEnabled", &shaderVar, "particle");
      initialized = true;
    }
    return shaderVar;
  }

  [[nodiscard]] const char* ResolveParticleTechniqueSuffix(
    const std::int32_t blendMode, const bool allowRefractSuffix, const int unreachableLine
  )
  {
    switch (blendMode) {
      case 0:
        return "_ALPHABLEND";
      case 1:
        return "_MODULATEINVERSE";
      case 2:
        return "_MODULATE2XINVERSE";
      case 3:
        return "_ADD";
      case 4:
        return "_PREMODALPHA";
      case 5:
        if (allowRefractSuffix) {
          return "_REFRACT";
        }
        break;
      default:
        break;
    }

    gpg::HandleAssertFailure(kUnreachableAssertText, unreachableLine, kParticleRendererSourcePath);
    return "_ALPHABLEND";
  }

  [[nodiscard]] std::string BuildBeamTechniqueName(const std::int32_t blendMode, const bool hasTwoTextures)
  {
    std::string techniqueName = hasTwoTextures ? "TBeam_TwoTexture" : "TBeam_OneTexture";
    techniqueName += ResolveParticleTechniqueSuffix(blendMode, false, 301);
    return techniqueName;
  }

  void BindBeamTextureShaderVar(moho::ShaderVar& shaderVar, const moho::TextureSheetHandle& textureSheet)
  {
    shaderVar.GetTexture(textureSheet);
  }

  void BindBeamTextureShaderVar(
    moho::ShaderVar& shaderVar,
    const moho::CParticleTexture::TextureResourceHandle& textureResource
  )
  {
    // RD3DTextureResource is an ID3DTextureSheet - bind it through the sheet
    // binder rather than resolving the texture handle by hand.
    shaderVar.GetTexture(textureResource);
  }
} // namespace

namespace moho
{
  bool ren_Beams = true;

  bool BeamTextureBucketKeyLess::operator()(
    const BeamTextureBucketKeyRuntime& lhs, const BeamTextureBucketKeyRuntime& rhs
  ) const noexcept
  {
    if (lhs.blendMode != rhs.blendMode) {
      return lhs.blendMode < rhs.blendMode;
    }

    if (IsSharedHandleLessForBucket(lhs.texture0, rhs.texture0)) {
      return true;
    }
    return IsSharedHandleLessForBucket(lhs.texture1, rhs.texture1);
  }

  /**
   * Address: 0x00BC5530 (FUN_00BC5530, register_TConVar_ren_Beams)
   *
   * What it does:
   * Registers the beam-render enable convar and schedules process-exit teardown.
   */
  void register_TConVar_ren_Beams()
  {
    RegisterConCommand(gTConVar_ren_Beams);
    (void)std::atexit(&CleanupTConVar_ren_Beams);
  }

  /**
   * Address: 0x00491440 (FUN_00491440, func_NewVertexSheet)
   *
   * What it does:
   * Allocates one beam-particle vertex sheet from device resources and swaps it
   * into the caller slot, deleting the old sheet when replaced.
   */
  void RecreateBeamParticleVertexSheet(CD3DVertexSheet*& vertexSheet, CD3DVertexFormat* const vertexFormat)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexSheet* const newSheet = resources->NewVertexSheet(1U, 1000, vertexFormat);

    CD3DVertexSheet* const oldSheet = vertexSheet;
    if (newSheet != oldSheet && oldSheet != nullptr) {
      delete oldSheet;
    }

    vertexSheet = newSheet;
  }

  /**
   * Address: 0x00491540 (FUN_00491540, sub_491540)
   *
   * What it does:
   * Resolves beam textures into one bucket key and appends the beam payload
   * into the matching texture/blend bucket.
   */
  void AddBeamToTextureBuckets(BeamTextureBucketMapRuntime& buckets, const SWorldBeam& beam)
  {
    if (!ren_Beams) {
      return;
    }

    BeamTextureBucketKeyRuntime bucketKey{};

    CParticleTexture::TextureResourceHandle texture0{};
    if (beam.mTexture1.tex != nullptr) {
      beam.mTexture1.tex->GetTexture(texture0);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&bucketKey.texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&texture0)
    );

    CParticleTexture::TextureResourceHandle texture1{};
    if (beam.mTexture2.tex != nullptr) {
      beam.mTexture2.tex->GetTexture(texture1);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&bucketKey.texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&texture1)
    );
    bucketKey.blendMode = static_cast<std::int32_t>(beam.mBlendMode);

    buckets[bucketKey].push_back(beam);
  }

  /**
   * Address: 0x00494740 (FUN_00494740, func_ParticleSelectTechnique)
   *
   * What it does:
   * Binds this trail bucket's two textures and selects its technique suffix by
   * blend mode. Declared on the bucket (ParticleRenderBuckets.h); defined here
   * because the shader-variable accessors and the suffix table are this file's.
   */
  void TrailRenderBucketRuntime::SelectTechnique() const
  {
    BindBeamTextureShaderVar(GetParticleTexture0ShaderVar(), texture0);
    BindBeamTextureShaderVar(GetParticleTexture1ShaderVar(), texture1);

    std::string techniqueName(tag.data(), tag.size());
    techniqueName += ResolveParticleTechniqueSuffix(blendMode, false, kParticleSelectTechniqueAssertLine);

    CD3DDevice* const device = D3D_GetDevice();
    if (device != nullptr) {
      device->SelectTechnique(techniqueName.c_str());
    }
  }

  /**
   * Address: 0x00493AE0 (FUN_00493AE0, func_ParticleSelectTechnique2)
   *
   * What it does:
   * As above for a particle bucket, plus the drag flag -- which the shader
   * variable takes as a 4-byte payload even though the lane is one byte -- and
   * the extra `_REFRACT` suffix.
   */
  void ParticleRenderBucketRuntime::SelectTechnique() const
  {
    const bool drag = dragEnabled;
    ShaderVar& dragEnabledShaderVar = GetParticleDragEnabledShaderVar();
    if (dragEnabledShaderVar.Exists()) {
      dragEnabledShaderVar.mEffectVariable->SetPtr(&drag, 4U);
    }

    BindBeamTextureShaderVar(GetParticleTexture0ShaderVar(), texture0);
    BindBeamTextureShaderVar(GetParticleTexture1ShaderVar(), texture1);

    std::string techniqueName(tag.data(), tag.size());
    techniqueName += ResolveParticleTechniqueSuffix(blendMode, true, kParticleSelectTechniqueWithDragAssertLine);

    CD3DDevice* const device = D3D_GetDevice();
    if (device != nullptr) {
      device->SelectTechnique(techniqueName.c_str());
    }
  }

  /**
   * Address: 0x00491760 (FUN_00491760, sub_491760)
   *
   * What it does:
   * Interpolates one beam segment and emits four packed render vertices that
   * form one billboarded beam quad.
   */
  void EmitInterpolatedBeamQuadVertices(
    const SWorldBeam& beam, const float frameAlpha, BeamRenderVertexArrayRuntime& outVertices
  )
  {
    const float interpolation = std::min(beam.mLastInterpolation * frameAlpha, 1.0f);

    const Wm3::Quaternion<float> startOrientation =
      Wm3::Quaternion<float>::Nlerp(beam.mLastStart.orient_, beam.mCurStart.orient_, interpolation);
    const Wm3::Vector3<float> startBasePosition = LerpVector3(beam.mLastStart.pos_, beam.mCurStart.pos_, interpolation);
    const Wm3::Vector3<float> startWorldPosition = Wm3::Vector3<float>::Add(
      startBasePosition, RotateVectorByOrientation(beam.mStart, startOrientation)
    );

    Wm3::Quaternion<float> endOrientation = startOrientation;
    Wm3::Vector3<float> endBasePosition = startBasePosition;
    if (beam.mFromStart) {
      endOrientation = Wm3::Quaternion<float>::Nlerp(beam.mLastEnd.orient_, beam.mCurEnd.orient_, interpolation);
      endBasePosition = LerpVector3(beam.mLastEnd.pos_, beam.mCurEnd.pos_, interpolation);
    }

    const Wm3::Vector3<float> endWorldPosition =
      Wm3::Vector3<float>::Add(endBasePosition, RotateVectorByOrientation(beam.mEnd, endOrientation));

    Wm3::Vector3<float> axis = Wm3::Vector3<float>::Sub(startWorldPosition, endWorldPosition);
    float repeatCoord = 1.0f;
    if (beam.mRepeatRate != 0.0f) {
      repeatCoord = Wm3::Vector3<float>::Length(axis) * beam.mRepeatRate;
    }
    Wm3::Vector3<float>::Normalize(axis);
    const Wm3::Vector3<float> oppositeAxis = Wm3::Vector3<float>::Scale(axis, -1.0f);

    outVertices.push_back(
      BuildBeamRenderVertex(startWorldPosition, axis, beam.mWidth, beam.mStartColor, 1.0f, 0.0f, beam.mUShift, beam.mVShift)
    );
    outVertices.push_back(
      BuildBeamRenderVertex(endWorldPosition, axis, beam.mWidth, beam.mEndColor, 1.0f, repeatCoord, beam.mUShift, beam.mVShift)
    );
    outVertices.push_back(
      BuildBeamRenderVertex(
        endWorldPosition,
        oppositeAxis,
        beam.mWidth,
        beam.mEndColor,
        0.0f,
        repeatCoord,
        beam.mUShift,
        beam.mVShift
      )
    );
    outVertices.push_back(
      BuildBeamRenderVertex(
        startWorldPosition,
        oppositeAxis,
        beam.mWidth,
        beam.mStartColor,
        0.0f,
        0.0f,
        beam.mUShift,
        beam.mVShift
      )
    );
  }

  /**
   * Address: 0x00491E40 (FUN_00491E40, func_DrawBeamParticle)
   *
   * What it does:
   * Renders the active beam buckets into the shared vertex/index sheets using
   * beam-technique selection and 1000-vertex batching.
   */
  [[nodiscard]] bool DrawBeamParticle(BeamBucketContainerRuntime& beams, const float frameAlpha, const bool disable)
  {
    if (!ren_Beams || disable) {
      return false;
    }

    if (beams.mVertexSheet == nullptr) {
      CD3DDevice* const device = D3D_GetDevice();
      if (device == nullptr) {
        return false;
      }

      ID3DDeviceResources* const resources = device->GetResources();
      if (resources == nullptr) {
        return false;
      }

      CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(13);
      if (vertexFormat == nullptr) {
        return false;
      }

      RecreateBeamParticleVertexSheet(beams.mVertexSheet, vertexFormat);
    }

    if (beams.mVertexSheet == nullptr) {
      return false;
    }

    // 0x00492078-0x0049209E: beams index through `sIndexSheet`, the sheet
    // `func_InitSharedIndexSheet` (0x0043C800) fills FORWARD - quad q at
    // indices [6q, 6q+6) - which is why the draw below starts at index 0.
    // That is a different singleton from `indexSheet1`, the trail sheet
    // `func_CreateIndexSheet1` (0x004986F0) fills back to front so that
    // `DrawTrailSegmentBatch` can read it from the tail. Using the trail sheet
    // here handed every beam the indices of quad 0x3FFF downwards - vertex
    // numbers around 65532 against a 1000-vertex beam buffer - so no beam
    // produced a visible triangle.
    ID3DIndexSheet* const sharedIndexSheet = func_GetSharedIndexSheet();
    if (sharedIndexSheet == nullptr) {
      return false;
    }

    bool didDraw = false;
    BeamRenderVertexArrayRuntime vertices{};

    for (auto bucketIt = beams.mBuckets.begin(); bucketIt != beams.mBuckets.end(); ++bucketIt) {
      const BeamTextureBucketKeyRuntime& bucketKey = bucketIt->first;
      const msvc8::vector<SWorldBeam>& beamList = bucketIt->second;
      if (beamList.empty()) {
        continue;
      }

      vertices.clear();
      for (const SWorldBeam& beam : beamList) {
        EmitInterpolatedBeamQuadVertices(beam, frameAlpha, vertices);
      }

      const std::int32_t totalVertices = static_cast<std::int32_t>(vertices.size());
      if (totalVertices <= 0) {
        continue;
      }

      BindBeamTextureShaderVar(GetParticleTexture0ShaderVar(), bucketKey.texture0);
      BindBeamTextureShaderVar(GetParticleTexture1ShaderVar(), bucketKey.texture1);

      CD3DDevice* const device = D3D_GetDevice();
      if (device == nullptr) {
        continue;
      }

      const std::string techniqueName = BuildBeamTechniqueName(
        bucketKey.blendMode,
        bucketKey.texture1.get() != nullptr
      );
      device->SelectTechnique(techniqueName.c_str());

      const BeamRenderVertexRuntime* const sourceVertices = vertices.empty() ? nullptr : &vertices[0];
      std::int32_t remainingVertices = totalVertices;
      std::int32_t vertexOffset = 0;

      while (remainingVertices > 0 && sourceVertices != nullptr) {
        const std::int32_t batchVertices = std::min<std::int32_t>(remainingVertices, 1000);
        const std::int32_t quadCount = batchVertices / 4;
        if (quadCount <= 0) {
          break;
        }

        ID3DVertexStream* const vertexStream = beams.mVertexSheet->GetVertStream(0U);
        if (vertexStream == nullptr) {
          break;
        }

        void* const mappedVertices = vertexStream->Lock(0, batchVertices, false, true);
        if (mappedVertices == nullptr) {
          break;
        }

        std::memcpy(
          mappedVertices,
          sourceVertices + vertexOffset,
          static_cast<std::size_t>(batchVertices) * sizeof(BeamRenderVertexRuntime)
        );
        vertexStream->Unlock();

        CD3DVertexSheetViewRuntime vertexSheetView{};
        vertexSheetView.sheet = beams.mVertexSheet;
        vertexSheetView.startVertex = 0;
        vertexSheetView.baseVertex = 0;
        vertexSheetView.endVertex = batchVertices - 1;

        CD3DIndexSheetViewRuntime indexSheetView{};
        indexSheetView.sheet = sharedIndexSheet;
        indexSheetView.startIndex = 0;
        indexSheetView.indexCount = 6 * quadCount;

        std::int32_t primitiveType = 4;
        (void)device->DrawTriangleList(&vertexSheetView, &indexSheetView, &primitiveType);

        didDraw = true;
        vertexOffset += batchVertices;
        remainingVertices -= batchVertices;
      }
    }

    return didDraw;
  }

  /**
   * Address: 0x00492290 (FUN_00492290, sub_492290)
   *
   * What it does:
   * Strict-weak ordering comparator for world-particle bucket keys.
   */
  bool IsParticleBucketKeyRhsLessThanLhs(
    const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs
  ) noexcept
  {
    if (lhs.sortScalar != rhs.sortScalar) {
      return lhs.sortScalar > rhs.sortScalar;
    }

    if (lhs.dragEnabled != rhs.dragEnabled) {
      return rhs.dragEnabled < lhs.dragEnabled;
    }

    if (lhs.blendMode != rhs.blendMode) {
      return rhs.blendMode < lhs.blendMode;
    }

    if (lhs.zMode != rhs.zMode) {
      return rhs.zMode < lhs.zMode;
    }

    if (AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0)) {
      if (AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1)) {
        return IsMsvc8StringLess(rhs.tag, lhs.tag);
      }
      return IsSharedHandleLessForBucket(rhs.texture1, lhs.texture1);
    }

    return IsSharedHandleLessForBucket(rhs.texture0, lhs.texture0);
  }

  /**
   * Address: 0x00492310 (FUN_00492310, sub_492310)
   *
   * What it does:
   * Equality comparator for world-particle bucket keys.
   */
  bool AreParticleBucketKeysEquivalent(const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs) noexcept
  {
    return lhs.sortScalar == rhs.sortScalar &&
           lhs.dragEnabled == rhs.dragEnabled &&
           lhs.blendMode == rhs.blendMode &&
           lhs.zMode == rhs.zMode &&
           AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0) &&
           AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1) &&
           lhs.tag == rhs.tag;
  }

  /**
   * Address: 0x00494B90 (FUN_00494B90, sub_494B90)
   *
   * What it does:
   * Copies one world-particle bucket key into destination storage while
   * preserving weak-handle control semantics for both texture lanes.
   */
  ParticleBucketKeyRuntime* CopyParticleBucketKey(
    ParticleBucketKeyRuntime* const destination,
    const ParticleBucketKeyRuntime* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->sortScalar = source->sortScalar;
    destination->dragEnabled = source->dragEnabled;

    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture0)
    );
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture1)
    );

    destination->tag = source->tag;
    destination->blendMode = source->blendMode;
    destination->zMode = source->zMode;
    return destination;
  }

  /**
   * Address: 0x00492390 (FUN_00492390, sub_492390)
   *
   * What it does:
   * Builds one trail bucket key from one `STrail` runtime payload.
   */
  TrailBucketKeyRuntime* InitializeTrailBucketKeyFromTrail(TrailBucketKeyRuntime* const key, const SWorldTrail& trail)
  {
    if (key == nullptr) {
      return nullptr;
    }

    key->texture0.reset();
    key->texture1.reset();
    key->tag = msvc8::string{};

    key->sortScalar = trail.mSortOrder;

    CParticleTexture::TextureResourceHandle texture0{};
    if (trail.mTexture.tex != nullptr) {
      trail.mTexture.tex->GetTexture(texture0);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&key->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&texture0)
    );

    CParticleTexture::TextureResourceHandle texture1{};
    if (trail.mRampTexture.tex != nullptr) {
      trail.mRampTexture.tex->GetTexture(texture1);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&key->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&texture1)
    );

    key->tag.assign_owned(trail.mTypeTag != nullptr ? trail.mTypeTag : "");
    key->blendMode = trail.mBlendMode;
    return key;
  }

  /**
   * Address: 0x00492520 (FUN_00492520, sub_492520)
   *
   * What it does:
   * Strict-weak ordering comparator for trail bucket keys.
   */
  bool IsTrailBucketKeyRhsLessThanLhs(
    const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs
  ) noexcept
  {
    if (lhs.sortScalar != rhs.sortScalar) {
      return lhs.sortScalar > rhs.sortScalar;
    }

    // Signed integer compare, as 0x0049253F spells it (`mov`/`cmp`/`setl`) --
    // not the float compare the sort scalar above gets at 0x00492528.
    if (lhs.blendMode != rhs.blendMode) {
      return rhs.blendMode < lhs.blendMode;
    }

    if (AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0)) {
      if (AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1)) {
        return IsMsvc8StringLess(rhs.tag, lhs.tag);
      }
      return IsSharedHandleLessForBucket(rhs.texture1, lhs.texture1);
    }

    return IsSharedHandleLessForBucket(rhs.texture0, lhs.texture0);
  }

  /**
   * Address: 0x00492590 (FUN_00492590, sub_492590)
   *
   * What it does:
   * Equality comparator for trail bucket keys.
   */
  bool AreTrailBucketKeysEquivalent(const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs) noexcept
  {
    return lhs.sortScalar == rhs.sortScalar &&
           lhs.blendMode == rhs.blendMode &&
           AreSharedHandlesEquivalentForBucket(lhs.texture0, rhs.texture0) &&
           AreSharedHandlesEquivalentForBucket(lhs.texture1, rhs.texture1) &&
           lhs.tag == rhs.tag;
  }

  /**
   * Address: 0x00494D90 (FUN_00494D90, sub_494D90)
   *
   * What it does:
   * Copies one world-trail bucket key into destination storage while
   * preserving weak-handle control semantics for both texture lanes.
   */
  TrailBucketKeyRuntime* CopyTrailBucketKey(
    TrailBucketKeyRuntime* const destination,
    const TrailBucketKeyRuntime* const source
  ) noexcept
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    destination->sortScalar = source->sortScalar;
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture0)
    );
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source->texture1)
    );
    destination->tag = source->tag;
    destination->blendMode = source->blendMode;
    return destination;
  }

  /**
   * Address: 0x00492EF0 (FUN_00492EF0, sub_492EF0)
   *
   * What it does:
   * Releases one world-particle bucket key resource lane.
   */
  void ResetParticleBucketKeyResources(ParticleBucketKeyRuntime& key)
  {
    key.tag.tidy(true, 0U);
    key.texture1.reset();
    key.texture0.reset();
  }

  /**
   * Address: 0x00492FC0 (FUN_00492FC0, sub_492FC0)
   *
   * What it does:
   * Releases one world-trail bucket key resource lane.
   */
  void ResetTrailBucketKeyResources(TrailBucketKeyRuntime& key)
  {
    key.tag.tidy(true, 0U);
    key.texture1.reset();
    key.texture0.reset();
  }
} // namespace moho

namespace
{
  struct BeamRenderHelpersStartupBootstrap
  {
    BeamRenderHelpersStartupBootstrap()
    {
      moho::register_TConVar_ren_Beams();
    }
  };

  [[maybe_unused]] BeamRenderHelpersStartupBootstrap gBeamRenderHelpersStartupBootstrap;
} // namespace

namespace moho
{
  namespace
  {
    /// Fetches the first stream of `sheet` through its typed virtual
    /// `GetVertStream(0)` slot, matching the binary's slot-8 dispatch.
    [[nodiscard]] ID3DVertexStream* FetchPrimaryVertexStream(CD3DVertexSheet* const sheet)
    {
      return sheet->GetVertStream(0u);
    }
  } // namespace

  /**
   * Address: 0x0043C3D0 (FUN_0043C3D0, sub_43C3D0)
   *
   * IDA signature:
   * int __usercall sub_43C3D0@<eax>(_DWORD *a1@<esi>);
   *
   * What it does:
   * Locks the first vertex stream of `sheet` for exclusive
   * write access over the full requested vertex count, stores the
   * returned map pointer into the context write cursor, and resets
   * the running quad count to zero.
   */
  void BeamDrawContext::BeginMap()
  {
    ID3DVertexStream* const stream = FetchPrimaryVertexStream(sheet);
    void* const mapped = stream->Lock(0, maxVertexCount, true, true);
    writeCursor = static_cast<float*>(mapped);
    quadCount = 0;
  }

  /**
   * Address: 0x0043C400 (FUN_0043C400, sub_43C400)
   *
   * IDA signature:
   * void __usercall sub_43C400(_DWORD *a1@<esi>);
   *
   * What it does:
   * If the context currently holds a live write cursor, unlocks the
   * first vertex stream of `sheet` and clears the cursor.
   */
  void BeamDrawContext::EndMap()
  {
    if (writeCursor != nullptr) {
      ID3DVertexStream* const stream = FetchPrimaryVertexStream(sheet);
      stream->Unlock();
      writeCursor = nullptr;
    }
  }

  /**
   * Address: 0x0043C390 (FUN_0043C390, sub_43C390)
   *
   * IDA signature:
   * void __usercall sub_43C390(_DWORD *a1@<esi>);
   *
   * What it does:
   * Ends any active map session, then releases the owning vertex
   * sheet through its deleting-destructor thunk (vtable slot 0 with
   * `deleteFlag = 1`, matching the binary) and nulls the sheet
   * pointer so the context is safe to reinitialize.
   */
  void BeamDrawContext::Teardown()
  {
    EndMap();
    if (sheet != nullptr) {
      delete sheet;
      sheet = nullptr;
    }
  }

  /**
   * Address: 0x0043C430 (FUN_0043C430, sub_43C430)
   *
   * IDA signature:
   * float *__userpurge sub_43C430@<eax>(
   *   float *a1@<eax>, int a2@<ecx>, float a3, float a4, float a5);
   *
   * What it does:
   * Builds four translated vertices from one unit-box corner pair
   * and writes them into the active write cursor in the order the
   * binary emits:
   *   v0 = ( boxCorners[0] + dx, boxCorners[4] + dy, boxCorners[2] + dz )
   *   v1 = ( boxCorners[3] + dx, boxCorners[4] + dy, boxCorners[2] + dz )
   *   v2 = ( boxCorners[3] + dx, boxCorners[1] + dy, boxCorners[5] + dz )
   *   v3 = ( boxCorners[0] + dx, boxCorners[1] + dy, boxCorners[5] + dz )
   * The cursor is then advanced by 48 bytes (four 3-float vertices)
   * and the running quad count is bumped.
   */
  float* BeamDrawContext::WriteTranslatedQuad(
    const float* const boxCorners,
    const float dx,
    const float dy,
    const float dz)
  {
    const float boxX0 = boxCorners[0];
    const float boxY0 = boxCorners[1];
    const float boxZ0 = boxCorners[2];
    const float boxX1 = boxCorners[3];
    const float boxY1 = boxCorners[4];
    const float boxZ1 = boxCorners[5];

    float* v0 = writeCursor;
    v0[0] = boxX0 + dx;
    v0[1] = boxY1 + dy;
    v0[2] = boxZ0 + dz;

    float* v1 = writeCursor + 3;
    v1[0] = boxX1 + dx;
    v1[1] = boxY1 + dy;
    v1[2] = boxZ0 + dz;

    float* v2 = writeCursor + 6;
    v2[0] = boxX1 + dx;
    v2[1] = boxY0 + dy;
    v2[2] = boxZ1 + dz;

    float* v3 = writeCursor + 9;
    v3[0] = boxX0 + dx;
    v3[1] = boxY0 + dy;
    v3[2] = boxZ1 + dz;

    writeCursor += 12;
    ++quadCount;
    return v3;
  }

  /**
   * Address: 0x0043C510 (FUN_0043C510, sub_43C510)
   *
   * IDA signature:
   * float *__usercall sub_43C510@<eax>(float *result@<eax>, int a2@<ecx>);
   *
   * What it does:
   * Copies four packed 3-float vertices (12 floats, 48 bytes) from
   * `packedQuad` into the active write cursor, advances the cursor
   * by 48 bytes, and bumps the running quad count.
   */
  const float* BeamDrawContext::WritePackedQuad(const float* const packedQuad)
  {
    for (std::size_t i = 0; i < 12; ++i) {
      writeCursor[i] = packedQuad[i];
    }
    writeCursor += 12;
    ++quadCount;
    return packedQuad;
  }

  namespace
  {
    [[nodiscard]] bool FlushBeamQuadDrawImpl(moho::BeamDrawContext& context, const int quadCount)
    {
      if (context.writeCursor != nullptr) {
        ID3DVertexStream* const stream = FetchPrimaryVertexStream(context.sheet);
        stream->Unlock();
        context.writeCursor = nullptr;
      }

      CD3DVertexSheetViewRuntime vertexView{};
      vertexView.sheet = context.sheet;
      vertexView.startVertex = 0;
      vertexView.baseVertex = 0;
      vertexView.endVertex = (4 * quadCount) - 1;

      CD3DIndexSheetViewRuntime indexView{};
      // 0x0043C580 reads the forward-filled `sIndexSheet` singleton, not the
      // back-to-front trail sheet - same distinction as `DrawBeamParticle`.
      indexView.sheet = func_GetSharedIndexSheet();
      indexView.startIndex = 0;
      indexView.indexCount = 6 * quadCount;

      std::int32_t primitiveType = 4; // D3DPT_TRIANGLELIST
      CD3DDevice* const device = D3D_GetDevice();
      return device->DrawTriangleList(&vertexView, &indexView, &primitiveType);
    }
  } // namespace

  /**
   * Address: 0x0043C580 (FUN_0043C580, sub_43C580)
   *
   * IDA signature:
   * int __usercall sub_43C580@<eax>(_DWORD *a1@<eax>);
   *
   * What it does:
   * Ends any pending write session on the context (unlocking the
   * vertex stream when mapped) and submits one indexed triangle-list
   * draw covering `quadCount` quads through the shared
   * `sIndexSheet`.
   */
  bool BeamDrawContext::FlushQuadDraw()
  {
    return FlushBeamQuadDrawImpl(*this, quadCount);
  }

  /**
   * Address: 0x0043C610 (FUN_0043C610, sub_43C610)
   *
   * IDA signature:
   * int __usercall sub_43C610@<eax>(int a1@<edi>, _DWORD *a2@<esi>);
   *
   * What it does:
   * Same as `FlushQuadDraw` but uses a caller-supplied
   * `quadCount` for the view bounds instead of the context's own
   * running count.
   */
  bool BeamDrawContext::FlushQuadDraw(const int quadCountOverride)
  {
    return FlushBeamQuadDrawImpl(*this, quadCountOverride);
  }

  /**
   * Address: 0x0043C760 (FUN_0043C760, sub_43C760)
   *
   * IDA signature:
   * int (__thiscall ***__usercall sub_43C760@<eax>(int a1@<edi>))(_DWORD, int);
   *
   * What it does:
   * Fetches vertex format 3 from the device resources, ensures the
   * shared `sVertexStream` singleton is live (creating it via
   * `func_CreateSharedVertexStream` on first miss), then builds one
   * new vertex sheet from the `[nullptr, sVertexStream]` stream pair
   * and the fetched format through `ID3DDeviceResources::Func6`. The
   * new sheet replaces `sheet`; the previous sheet (when
   * different and non-null) is released through its deleting dtor.
   */
  CD3DVertexSheet* BeamDrawContext::CreateVertexSheet()
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(3);

    if (SharedVertexStreamSlot() == nullptr) {
      func_CreateSharedVertexStream(vertexFormat);
    }

    CD3DVertexStream* streamArray[2]{nullptr, SharedVertexStreamSlot()};
    CD3DDevice* const device2 = D3D_GetDevice();
    ID3DDeviceResources* const resources2 = device2->GetResources();
    CD3DVertexSheet* const newSheet = resources2->Func6(
      1u,
      maxVertexCount,
      vertexFormat,
      streamArray);

    CD3DVertexSheet* const oldSheet = sheet;
    if (newSheet != oldSheet && oldSheet != nullptr) {
      delete oldSheet;
    }
    sheet = newSheet;
    return oldSheet;
  }

  /**
   * Address: 0x0043C360 (FUN_0043C360, sub_43C360)
   *
   * IDA signature:
   * void __usercall sub_43C360(int a1@<eax>, _DWORD *a2@<ecx>);
   *
   * What it does:
   * Lazy first-use initializer: when the context has no sheet, seeds
   * the quad-count / vertex-count / cursor lanes, builds the shared
   * vertex sheet, and primes the shared index sheet.
   */
  void BeamDrawContext::Initialize(const int quadCapacity)
  {
    if (sheet != nullptr) {
      return;
    }
    maxQuadCount = quadCapacity;
    maxVertexCount = 4 * quadCapacity;
    writeCursor = nullptr;
    (void)CreateVertexSheet();
    func_InitSharedIndexSheet();
  }
} // namespace moho
