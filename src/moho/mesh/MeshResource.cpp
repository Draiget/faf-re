#include "moho/mesh/MeshPrivate.h"

namespace moho
{
  float ren_MeshDissolve = 20.0f;      // 0x00F57F00 (shipped .data)
  float ren_MeshDissolveCutoff = 0.2f; // 0x00F57F04

  /**
   * Address: 0x007E5150 (FUN_007E5150, boost::shared_ptr_MeshMaterial::shared_ptr_MeshMaterial)
   *
   * What it does:
   * Constructs one `shared_ptr<MeshMaterial>` from one raw material pointer
   * lane.
   */
  boost::shared_ptr<MeshMaterial>* ConstructSharedMeshMaterialFromRaw(
    boost::shared_ptr<MeshMaterial>* const outMaterial,
    MeshMaterial* const material
  )
  {
    return ::new (outMaterial) boost::shared_ptr<MeshMaterial>(material);
  }

  /**
   * Address: 0x007E5420 (FUN_007E5420, boost::shared_ptr_Mesh::shared_ptr_Mesh)
   *
   * What it does:
   * Constructs one `shared_ptr<Mesh>` from one raw mesh pointer lane.
   */
  boost::shared_ptr<Mesh>* ConstructSharedMeshFromRaw(
    boost::shared_ptr<Mesh>* const outMesh,
    Mesh* const mesh
  )
  {
    return ::new (outMesh) boost::shared_ptr<Mesh>(mesh);
  }

  /**
   * Address: 0x007E6280 (FUN_007E6280, boost::shared_ptr_MeshBatch::shared_ptr_MeshBatch)
   *
   * What it does:
   * Constructs one `shared_ptr<MeshBatch>` from one raw batch pointer lane.
   */
  boost::shared_ptr<MeshBatch>* ConstructSharedMeshBatchFromRaw(
    boost::shared_ptr<MeshBatch>* const outBatch,
    MeshBatch* const batch
  )
  {
    return ::new (outBatch) boost::shared_ptr<MeshBatch>(batch);
  }

  /**
   * Address: 0x007E6D20 (FUN_007E6D20, sub_7E6D20)
   *
   * IDA signature:
   * float *__usercall sub_7E6D20@<eax>(float *result@<eax>, float *a2@<ecx>);
   *
   * What it does:
   * Copies one whole 4x4 transform, element by element, and returns the
   * destination. MSVC emitted the `VMatrix4` copy assignment out of line for the
   * two batch-fill call sites (`HardwareMeshBatch::FillBatch`, 0x007E7EA0), which
   * stage a per-instance transform into an unaligned vertex record; the sixteen
   * scalar stores are what that emission looks like.
   */
  VMatrix4* CopyTransform4x4(VMatrix4* const destination, const VMatrix4& source)
  {
    for (std::size_t row = 0; row < 4; ++row) {
      destination->r[row].x = source.r[row].x;
      destination->r[row].y = source.r[row].y;
      destination->r[row].z = source.r[row].z;
      destination->r[row].w = source.r[row].w;
    }

    return destination;
  }

  // Two dead reach-in lanes and their view structs used to live here.
  // 0x0086AF80 and 0x0086AFC0 both read the owning object through a
  // a deleted overlay whose only member sat at +0x34 -- which is
  // exactly `CUIWorldMesh::mMeshInstance`. They are `CUIWorldMesh` accessors,
  // not free functions over an offset struct, and they now live there as
  // `GetWorldSphere` / `GetWorldBounds` against real `Wm3::Sphere3f` and
  // `Wm3::AxisAlignedBox3f` (spatial locality agrees: both predict
  // `moho/ui/CUIWorldMesh.cpp`). The sphere/bounds view structs they copied
  // into were stand-ins for those same Wm3 types.
  //
  // 0x004FE260 went with them: it expanded one of those sphere views into one
  // of those bounds views, so it has no reason to exist once both are real Wm3
  // types. Nothing in the tree referenced any of the three -- each was counted
  // with `grep -rc` across `src`, and all three report `xrefs_total: 0`
  // with no code, data, vtable or RTTI reference in the binary either.


  /**
   * Address: 0x007E51E0 (FUN_007E51E0, boost::shared_ptr_MeshBatch::operator=)
   *
   * What it does:
   * Rebinds one `shared_ptr<MeshBatch>` from a raw batch pointer and releases
   * the previous ownership lane.
   */
  boost::shared_ptr<MeshBatch>* AssignSharedMeshBatchFromRaw(
    boost::shared_ptr<MeshBatch>* const outBatchHandle,
    MeshBatch* const batch
  )
  {
    outBatchHandle->reset(batch);
    return outBatchHandle;
  }

  // The shard/map/database types that used to be defined here now live in
  // moho/mesh/SpatialDb.h, so the owners that embed a SpatialDB<T> by value
  // can see its layout. Their bodies stay in this file.
}

namespace
{

  [[nodiscard]] std::uintptr_t PointerOrderKey(const void* const ptr) noexcept
  {
    return reinterpret_cast<std::uintptr_t>(ptr);
  }

  void AssignMaterialTextureSheet(
    boost::shared_ptr<moho::ID3DTextureSheet>& destination,
    const fa::string& textureName,
    moho::CResourceWatcher* const resourceWatcher
  )
  {
    // 0x007DC280: an empty path skips the lookup entirely -- the field keeps
    // whatever it already held. 0x007DC2AE dispatches vtable slot 10 on the
    // device's resource set, with the fallback flag set (`push 1`, 0x007DC292),
    // so a missing texture resolves to the fallback rather than to null.
    if (textureName.empty()) {
      return;
    }

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr) {
      return;
    }

    moho::ID3DDeviceResources* const resources = device->GetResources();
    if (resources == nullptr) {
      return;
    }

    moho::ID3DDeviceResources::TextureResourceHandle texture{};
    resources->GetTexture(texture, textureName.c_str(), resourceWatcher, true);
    destination = texture;
  }
}

namespace moho
{


  /**
   * Address: 0x007DBEE0 (FUN_007DBEE0, ??0MeshMaterial@Moho@@QAE@XZ)
   */
  MeshMaterial::MeshMaterial()
    : mShaderAnnotation()
    , mAlbedoSheet()
    , mNormalsSheet()
    , mSpecularSheet()
    , mLookupSheet()
    , mSecondarySheet()
    , mEnvironmentSheet()
    , mShaderIndex(-1)
    , mCartographicTechnique()
    , mDepthTechnique()
    , mCartographicTechniqueResolved(false)
    , mDepthTechniqueResolved(false)
    , mPad8E_8F{}
  {}

  /**
   * Address: 0x007DBFC0 (FUN_007DBFC0, ??1MeshMaterial@Moho@@UAE@XZ)
   * Deleting thunk: 0x007DBFA0 (FUN_007DBFA0)
   */
  MeshMaterial::~MeshMaterial()
  {
    mDepthTechnique.tidy(true, 0U);
    mCartographicTechnique.tidy(true, 0U);
    mEnvironmentSheet.reset();
    mSecondarySheet.reset();
    mLookupSheet.reset();
    mSpecularSheet.reset();
    mNormalsSheet.reset();
    mAlbedoSheet.reset();
    mShaderAnnotation.tidy(true, 0U);
  }

  /**
   * Address: 0x007DCBF0 (FUN_007DCBF0, ??4MeshMaterial@Moho@@QAEAAV01@ABV01@@Z)
   *
   * What it does:
   * Copies annotation/texture-sheet handles and runtime tags from one material.
   */
  MeshMaterial& MeshMaterial::operator=(const MeshMaterial& rhs)
  {
    if (this == &rhs) {
      return *this;
    }

    mShaderAnnotation.assign_owned(rhs.mShaderAnnotation.view());
    mAlbedoSheet = rhs.mAlbedoSheet;
    mNormalsSheet = rhs.mNormalsSheet;
    mSpecularSheet = rhs.mSpecularSheet;
    mLookupSheet = rhs.mLookupSheet;
    mSecondarySheet = rhs.mSecondarySheet;
    mEnvironmentSheet = rhs.mEnvironmentSheet;
    mShaderIndex = rhs.mShaderIndex;
    mCartographicTechnique.assign_owned(rhs.mCartographicTechnique.view());
    mDepthTechnique.assign_owned(rhs.mDepthTechnique.view());
    mCartographicTechniqueResolved = rhs.mCartographicTechniqueResolved;
    mDepthTechniqueResolved = rhs.mDepthTechniqueResolved;
    return *this;
  }

  /**
   * Address: 0x007DC760 (FUN_007DC760,
   * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABVRMeshBlueprintLOD@2@PAVCResourceWatcher@2@@Z)
   *
   * What it does:
   * Builds one material from one mesh LOD blueprint descriptor.
   */
  boost::shared_ptr<MeshMaterial>
  MeshMaterial::Create(const RMeshBlueprintLOD& blueprintLod, CResourceWatcher* const resourceWatcher)
  {
    return Create(
      blueprintLod.mShaderName,
      blueprintLod.mAlbedoName,
      blueprintLod.mNormalsName,
      blueprintLod.mSpecularName,
      blueprintLod.mLookupName,
      blueprintLod.mSecondaryName,
      resourceWatcher
    );
  }

  /**
   * Address: 0x007DC1B0 (FUN_007DC1B0,
   * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00000PAVCResourceWatcher@2@@Z)
   *
   * What it does:
   * Creates one mesh material and resolves per-texture sheet handles from paths.
   */
  boost::shared_ptr<MeshMaterial> MeshMaterial::Create(
    const fa::string& shaderName,
    const fa::string& albedoName,
    const fa::string& normalsName,
    const fa::string& specularName,
    const fa::string& lookupName,
    const fa::string& secondaryName,
    CResourceWatcher* const resourceWatcher
  )
  {
    boost::shared_ptr<MeshMaterial> material(new MeshMaterial());
    const fa::string resolvedShaderName = ResolveShaderAnnotationName(shaderName);
    material->mShaderAnnotation.assign_owned(resolvedShaderName.view());
    AssignMaterialTextureSheet(material->mAlbedoSheet, albedoName, resourceWatcher);
    AssignMaterialTextureSheet(material->mNormalsSheet, normalsName, resourceWatcher);
    AssignMaterialTextureSheet(material->mSpecularSheet, specularName, resourceWatcher);
    AssignMaterialTextureSheet(material->mLookupSheet, lookupName, resourceWatcher);
    AssignMaterialTextureSheet(material->mSecondarySheet, secondaryName, resourceWatcher);

    // Pump the sound engine after the texture loads above, so a long material
    // build cannot starve audio. MSVC inlined this at 0x007DC71E: gate on
    // `snd_ExtraDoWorkCalls`, then `sSoundConfiguration->mTime
    // .ElapsedMilliseconds()` against flt_E4F744 (0000c842 = 100.0f, verified
    // from the PE) with `fcomip`/`jbe`, i.e. fire only when elapsed > 100ms.
    // That is exactly SND_FrameExtraDoWorkTick (0x004D8F90), so the source line
    // is the call to it.
    SND_FrameExtraDoWorkTick();

    return material;
  }

  /**
   * Address: 0x007DC7A0 (FUN_007DC7A0, ??0MeshLOD@Moho@@IAE@XZ)
   *
   * What it does:
   * Initializes one empty runtime LOD lane with default cutoff/material state
   * and null shared-resource handles.
   */
  MeshLOD::MeshLOD()
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res()
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {}

  /**
   * Address: 0x007DC8C0 (FUN_007DC8C0,
   * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@ABVRMeshBlueprintLOD@1@V?$shared_ptr@VMeshMaterial@Moho@@@3@PAVCResourceWatcher@1@@Z)
   *
   * What it does:
   * Initializes one runtime LOD from blueprint/material/resource fallback state.
   */
  MeshLOD::MeshLOD(
    const RMeshBlueprintLOD& blueprintLod,
    const boost::shared_ptr<RScmResource> previousResourceArg,
    const boost::shared_ptr<MeshMaterial> materialArg,
    CResourceWatcher* const ownerWatcher
  )
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res()
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {
    Load(blueprintLod, previousResourceArg, materialArg, ownerWatcher);
  }

  /**
   * Address: 0x007DCA40 (FUN_007DCA40,
   * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
   *
   * What it does:
   * Initializes one runtime LOD from already-resolved resource/material
   * pointers and clears batch/runtime flag lanes.
   */
  MeshLOD::MeshLOD(const boost::shared_ptr<RScmResource> resourceArg, const boost::shared_ptr<MeshMaterial> materialArg)
    : useDissolve(0)
    , cutoff(1000.0f)
    , mat()
    , previousResource()
    , res(resourceArg)
    , scrolling(0)
    , occlude(0)
    , silhouette(0)
    , pad_AF(0)
    , lodBlueprintCopy()
    , staticBatch()
    , dynamicBatch()
  {
    if (materialArg) {
      mat = *materialArg;
      return;
    }

    MeshMaterial defaultMaterial;
    mat = defaultMaterial;
  }

  /**
   * Address: 0x007DD4D0 (FUN_007DD4D0)
   *
   * What it does:
   * Releases loaded resource/material state for this LOD.
   */
  void MeshLOD::Clear()
  {
    res.reset();
    lodBlueprintCopy.reset();
    mat = MeshMaterial();
    ResetBatches();
    cutoff = 1000.0f;
  }

  /**
   * Address: 0x007DD190 (FUN_007DD190)
   *
   * What it does:
   * Clears cached batch handles for this LOD.
   */
  void MeshLOD::ResetBatches()
  {
    staticBatch.reset();
    dynamicBatch.reset();
  }
namespace
{
    /**
     * Address: 0x007E8C70 (FUN_007E8C70, sub_7E8C70)
     *
     * IDA signature:
     * Moho::HardwareMeshBatch* __usercall sub_7E8C70@<eax>(
     *   char remap@<bl>, int lod@<edi>,
     *   boost::shared_ptr<RScmResource> referenceResource,
     *   boost::shared_ptr<RScmResource> currentResource);
     *
     * What it does:
     * Shared lazy-init factory behind MeshLOD::GetStaticBatch/GetSkinnedBatch.
     * Allocates and initializes one GPU-instanced HardwareMeshBatch for a LOD,
     * but only when the LOD has a current mesh resource, the batch is either
     * non-remapped or has a reference resource, and runtime mesh instancing is
     * enabled for the active device. Returns the batch, or nullptr when the
     * batch cannot be built. The `boost::shared_ptr` reference/current arguments
     * are consumed (released) exactly once, so the caller passes retained copies.
     */
    MeshBatch* BuildHardwareMeshBatchForLod(
      const bool remapToReferenceResource,
      MeshLOD* const lod,
      boost::shared_ptr<RScmResource> referenceResource,
      boost::shared_ptr<RScmResource> currentResource
    )
    {
      // Gate (binary: `a2 && a4.res && (!a1 || result.res)`): need a LOD, a
      // current resource, and — for remapped batches — a reference resource.
      if (lod == nullptr || !currentResource || (remapToReferenceResource && !referenceResource)) {
        return nullptr;
      }

      // Instancing capability gate: with no hardware instancing the LOD keeps a
      // null cached batch and falls back to the non-batched draw path.
      if (!gpg::gal::MeshInstancingEnabled()) {
        return nullptr;
      }

      return new HardwareMeshBatch(lod, remapToReferenceResource, referenceResource, currentResource);
    }
}


  /**
   * Address: 0x007DD220 (FUN_007DD220,
   * ?GetStaticBatch@MeshLOD@Moho@@QAE?AV?$shared_ptr@VMeshBatch@Moho@@@boost@@XZ)
   *
   * IDA signature:
   * boost::shared_ptr<MeshBatch>* __stdcall Moho::MeshLOD::GetStaticBatch(
   *   MeshLOD* this, boost::shared_ptr<MeshBatch>* out);
   *
   * What it does:
   * Lazily builds and caches this LOD's static (non-remapped) hardware mesh
   * batch, then returns a retained copy in `outBatch`. The reference resource is
   * the LOD's `previousResource`, the current resource is `res`.
   */
  boost::shared_ptr<MeshBatch>& MeshLOD::GetStaticBatch(boost::shared_ptr<MeshBatch>& outBatch)
  {
    if (!staticBatch) {
      MeshBatch* const built = BuildHardwareMeshBatchForLod(false, this, previousResource, res);
      staticBatch.reset(built);
    }
    outBatch = staticBatch;
    return outBatch;
  }

  /**
   * Address: 0x007DD420 (FUN_007DD420,
   * ?GetSkinnedBatch@MeshLOD@Moho@@QAE?AV?$shared_ptr@VMeshBatch@Moho@@@boost@@XZ)
   *
   * IDA signature:
   * boost::shared_ptr<MeshBatch>* __userpurge Moho::MeshLOD::GetSkinnedBatch(
   *   MeshLOD* this, boost::shared_ptr<MeshBatch>* out);
   *
   * What it does:
   * Lazily builds and caches this LOD's skinned (bone-remapped) hardware mesh
   * batch, then returns a retained copy in `outBatch`. Identical to
   * GetStaticBatch except the reference-resource bone remap is enabled.
   */
  boost::shared_ptr<MeshBatch>& MeshLOD::GetSkinnedBatch(boost::shared_ptr<MeshBatch>& outBatch)
  {
    if (!dynamicBatch) {
      MeshBatch* const built = BuildHardwareMeshBatchForLod(true, this, previousResource, res);
      dynamicBatch.reset(built);
    }
    outBatch = dynamicBatch;
    return outBatch;
  }

  /**
   * Address: 0x007DD5D0 (FUN_007DD5D0, ?SetCutoff@MeshLOD@Moho@@QAEXM@Z)
   *
   * What it does:
   * Stores one LOD cutoff distance threshold.
   */
  void MeshLOD::SetCutoff(const float cutoffValue)
  {
    cutoff = cutoffValue;
  }

  /**
   * Address: 0x007DCED0 (FUN_007DCED0)
   *
   * What it does:
   * Reloads model/material resources from one blueprint LOD entry.
   */
  void MeshLOD::Load(
    const RMeshBlueprintLOD& blueprintLod,
    const boost::shared_ptr<RScmResource> previousResourceArg,
    const boost::shared_ptr<MeshMaterial> materialArg,
    CResourceWatcher* const ownerWatcher
  )
  {
    Clear();

    lodBlueprintCopy.reset(new RMeshBlueprintLOD(blueprintLod));
    // 0x007DCF58: the LOD's model path goes straight through the shared
    // `GetModel` resource lane; there is no local caching or empty-path guard.
    res = GetModel(blueprintLod.mMeshName.c_str(), ownerWatcher);
    previousResource = previousResourceArg ? previousResourceArg : res;
    cutoff = blueprintLod.mLodCutoff;
    scrolling = blueprintLod.mScrolling;
    occlude = blueprintLod.mOcclude;
    silhouette = blueprintLod.mSilhouette;

    if (materialArg) {
      mat = *materialArg;
    } else {
      const boost::shared_ptr<MeshMaterial> createdMaterial = MeshMaterial::Create(blueprintLod, ownerWatcher);
      if (createdMaterial) {
        mat = *createdMaterial;
      }
    }
  }

  /**
   * Address: 0x007DCD60 (FUN_007DCD60, ??1MeshLOD@Moho@@UAE@XZ)
   */
  MeshLOD::~MeshLOD()
  {
    Clear();
  }

  /**
   * Address: 0x007DD5E0 (FUN_007DD5E0, ??0Mesh@Moho@@IAE@XZ)
   *
   * What it does:
   * Initializes base mesh lanes and clears resource/material/LOD ownership.
   */
  Mesh::Mesh()
    : bp(nullptr)
    , material()
    , unk2C(0)
    , lods()
    , unk3C(0)
  {
  }

  /**
   * Address: 0x007DD680 (FUN_007DD680,
   * ??0Mesh@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  Mesh::Mesh(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg)
    : Mesh()
  {
    Load(blueprint, materialArg);
  }

  /**
   * Address: 0x007DD750 (FUN_007DD750,
   * ??0Mesh@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
   *
   * What it does:
   * Initializes one mesh with a pre-resolved resource/material LOD lane.
   */
  Mesh::Mesh(const boost::shared_ptr<RScmResource> resourceArg, const boost::shared_ptr<MeshMaterial> materialArg)
    : Mesh()
  {
    (void)CreateLOD(resourceArg, materialArg);
  }

  /**
   * Address: 0x007DDAC0 (FUN_007DDAC0)
   * Address: 0x007E5250/0x0087CFF0/0x0087D020/0x0087D050 (FUN_007E5250,
   * FUN_0087CFF0, FUN_0087D020, FUN_0087D050 -- the out-of-line bodies emitted
   * for this owned-LOD delete loop at its Clear/dtor/clone sites)
   */
  void Mesh::Clear()
  {
    for (MeshLOD* lod : lods) {
      delete lod;
    }
    lods.clear();
    material.reset();
    bp = nullptr;
  }

  /**
   * Address: 0x007DE030 (FUN_007DE030)
   *
   * What it does:
   * Resets cached batch handles for every loaded LOD.
   */
  void Mesh::ResetBatches()
  {
    for (MeshLOD** it = lods.begin(); it && it != lods.end(); ++it) {
      if (*it) {
        (*it)->ResetBatches();
      }
    }
  }

  /**
   * Address: 0x007DD880 (FUN_007DD880, ??1Mesh@Moho@@UAE@XZ)
   */
  Mesh::~Mesh()
  {
    Clear();
  }

  /**
   * Address: 0x007DDB50 (FUN_007DDB50,
   * ?Load@Mesh@Moho@@AAEXPBVRMeshBlueprint@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  void Mesh::Load(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    Clear();
    bp = blueprint;
    material = materialArg;

    if (!bp) {
      return;
    }

    const RMeshBlueprintLOD* const begin = bp->mLods.begin();
    if (!begin) {
      return;
    }

    for (const RMeshBlueprintLOD* lod = begin; lod != bp->mLods.end(); ++lod) {
      CreateLOD(*lod, materialArg);
    }

    if (!lods.empty() && lods.back()) {
      lods.back()->useDissolve = 1;
    }
  }

  /**
   * Address: 0x007DDC50 (FUN_007DDC50,
   * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@ABVRMeshBlueprintLOD@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshLOD* Mesh::CreateLOD(const RMeshBlueprintLOD& blueprintLod, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    boost::shared_ptr<RScmResource> previousResource;
    if (!lods.empty() && lods.front()) {
      previousResource = lods.front()->res;
    }

    MeshLOD* const lod = new MeshLOD(blueprintLod, previousResource, materialArg, this);
    lods.push_back(lod);
    return lod;
  }

  /**
   * Address: 0x007DDE50 (FUN_007DDE50,
   * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@5@@Z)
   *
   * What it does:
   * Adds one direct resource/material-backed mesh LOD entry.
   */
  MeshLOD* Mesh::CreateLOD(const boost::shared_ptr<RScmResource> resourceArg, const boost::shared_ptr<MeshMaterial> materialArg)
  {
    MeshLOD* const lod = new MeshLOD(resourceArg, materialArg);
    lods.push_back(lod);
    return lod;
  }

  /**
   * Address: 0x007DD930 (FUN_007DD930, Moho::Mesh::GetSortOrder)
   *
   * What it does:
   * Returns the mesh blueprint sort-order lane when present, else `0.0f`.
   */
  float Mesh::GetSortOrder() const
  {
    return bp != nullptr ? bp->mSortOrder : 0.0f;
  }

  /**
   * Address: 0x007DD950 (FUN_007DD950, ?GetResource@Mesh@Moho@@QBE?AV?$shared_ptr@VRScmResource@Moho@@@boost@@H@Z)
   */
  boost::shared_ptr<RScmResource> Mesh::GetResource(const std::int32_t /*lodIndex*/) const
  {
    MeshLOD* const* const begin = lods.begin();
    if (!begin || begin == lods.end() || !*begin) {
      return {};
    }

    return (*begin)->res;
  }

  /**
   * Address: 0x007DDA50 (FUN_007DDA50, ?ComputeLOD@Mesh@Moho@@QBEPBVMeshLOD@2@M@Z)
   *
   * What it does:
   * Walks mesh LODs in order and returns the first lane accepted by cutoff
   * and dissolve rules for the supplied distance.
   */
  const MeshLOD* Mesh::ComputeLOD(const float distance) const
  {
    MeshLOD* const* const begin = lods.begin();
    if (begin == nullptr) {
      return nullptr;
    }

    MeshLOD* const* const end = lods.end();
    if (begin == end) {
      return nullptr;
    }

    for (MeshLOD* const* it = begin; it != end; ++it) {
      const MeshLOD* const lod = *it;
      if (lod == nullptr) {
        continue;
      }

      const float cutoff = lod->cutoff;
      if (cutoff <= 0.0f) {
        return lod;
      }

      if (lod->useDissolve != 0u) {
        if (distance <= (cutoff + ren_MeshDissolve)) {
          return lod;
        }
        return nullptr;
      }

      if (distance <= cutoff) {
        return lod;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x007DDA20 (FUN_007DDA20, ?GetMaxCutoff@Mesh@Moho@@QBEMXZ)
   *
   * What it does:
   * Returns the cutoff value from the last loaded mesh LOD, or zero when no
   * LODs are available.
   */
  float Mesh::GetMaxCutoff() const
  {
    MeshLOD* const* const begin = lods.begin();
    if (begin == nullptr) {
      return 0.0f;
    }

    MeshLOD* const* const end = lods.end();
    if (begin == end) {
      return 0.0f;
    }

    const MeshLOD* const lastLod = *(end - 1);
    return lastLod != nullptr ? lastLod->cutoff : 0.0f;
  }

  /**
   * Address: 0x007DDFC0 (FUN_007DDFC0, ?OnResourceChanged@Mesh@Moho@@EAEXVStrArg@gpg@@@Z)
   */
  void Mesh::OnResourceChanged(const gpg::StrArg /*resourcePath*/)
  {
    // Binary path may resync global resource manager before reloading watched assets.
    Load(bp, material);
  }

  /**
   * Address: 0x007DAF00 (FUN_007DAF00,
   * ??0MeshKey@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshKey::MeshKey(const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> meshMaterial)
    : blueprint(blueprint)
    , meshMaterial(meshMaterial)
  {}

  /**
   * Address: 0x007DF6E0 (FUN_007DF6E0, copy ctor)
   */
  MeshKey::MeshKey(const MeshKey& rhs)
    : blueprint(rhs.blueprint)
    , meshMaterial(rhs.meshMaterial)
  {}

  /**
   * Address: 0x007DAF60 (FUN_007DAF60, ??1MeshKey@Moho@@QAE@XZ)
   * Deleting thunk: 0x007DAFC0 (FUN_007DAFC0, sub_7DAFC0)
   */
  MeshKey::~MeshKey() = default;

  bool MeshKey::Equals(const MeshKey& rhs) const noexcept
  {
    return !LessThan(rhs) && !rhs.LessThan(*this);
  }

  /**
   * No standalone binary address: this trivial two-field comparison is
   * compiler-inlined at every call site. `0x007E5B20` (FUN_007E5B20) was
   * previously cited here in error -- that address is actually an RB-tree
   * lower-bound/insertion-point traversal (distinct from the already-typed
   * `MeshCacheTreeLowerBound` at 0x007E6050) that happens to inline this
   * same two-field comparison internally; see the by-source reconstruction
   * report for the traced evidence.
   *
   * What it does:
   * Orders keys lexicographically by (blueprint pointer, material object pointer).
   */
  bool MeshKey::LessThan(const MeshKey& rhs) const noexcept
  {
    const std::uintptr_t lhsBlueprint = PointerOrderKey(blueprint);
    const std::uintptr_t rhsBlueprint = PointerOrderKey(rhs.blueprint);
    if (lhsBlueprint < rhsBlueprint) {
      return true;
    }
    if (lhsBlueprint > rhsBlueprint) {
      return false;
    }

    return PointerOrderKey(meshMaterial.get()) < PointerOrderKey(rhs.meshMaterial.get());
  }
namespace
{
    /**
     * `Moho::RefCountedCache<MeshKey,Mesh>::Deleter` (address block on
     * `ConstructSharedMeshWithCacheEvictingDeleter`, Mesh.h). Erases the
     * mesh's cache-tree entry the moment its last strong reference drops,
     * then destroys the mesh itself through its own virtual destructor --
     * matching `dispose()`'s real two-step body (`sub_7E69E0`): `erase_node`
     * on the tree, then `Mesh`'s own scalar deleting destructor.
     */
    struct MeshCacheEvictingDeleter
    {
      MeshRendererMeshCacheTree* tree;
      MeshKey key;

      void operator()(Mesh* const mesh) const
      {
        if (tree != nullptr) {
          tree->erase(key);
        }
        delete mesh;
      }
    };
}


  void ConstructSharedMeshWithCacheEvictingDeleter(
    boost::shared_ptr<Mesh>& out,
    Mesh* const raw,
    MeshRendererMeshCacheTree& tree,
    const MeshKey& key)
  {
    out.reset(raw, MeshCacheEvictingDeleter{&tree, key});
  }
}

