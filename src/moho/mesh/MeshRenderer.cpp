#include "moho/mesh/MeshPrivate.h"

#include "moho/console/CConCommand.h"

namespace moho
{

  class IWldTerrainRes;

  // Active render-time terrain resource accessor (defined in WxRuntimeTypes.cpp,
  // 0x007FA170) — returns `sWldMap->mTerrainRes` or nullptr when no map/terrain.
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  // Mesh-pass inclusion flags read by MeshRenderer::Batch. Byte-verified
  // defaults from ForgedAlliance.exe: ?ren_MeshSkinned@Moho@@3_NA = 1 and
  // ?ren_MeshStatic@Moho@@3_NA = 1 (both `bool`, .data VA 0xF57E56/0xF57E57).
  bool ren_MeshSkinned = true;
  bool ren_MeshStatic = true;

  // Shadow depth bias read by MeshRenderer::ConfigureShader's shadow lane
  // (?ren_ShadowBias@Moho@@3MA). Byte-verified default from ForgedAlliance.exe:
  // .data VA 0x00F57DFC = 0.005f.
  float ren_ShadowBias = 0.005f;

  ShadowCasterRegion gShadowCasterRegion{};

  /**
   * Engine change: `ren_MeshParallelInterp`. MeshRenderer::Batch places every gathered mesh between
   * ticks (MeshInstance::UpdateInterpolatedFields: position, orientation, pose blend, bounds) on the
   * user worker pool before its serial walk, whose own calls then find the work done. Each instance
   * writes only its own fields and pose, and the result doesn't depend on the order.
   */
  bool ren_MeshParallelInterp = true;
  TConVar<bool> gTConVar_ren_MeshParallelInterp(
    "ren_MeshParallelInterp",
    "Place the meshes a pass gathers between ticks on worker threads (1, the default), or one by one in the pass (0).",
    &ren_MeshParallelInterp
  );
}

namespace
{

  // The mesh-cache tree is `fa::map<MeshKey, boost::weak_ptr<Mesh>,
  // MeshKeyLess>` (Mesh.h). Its storage lifecycle - header sentinel
  // allocation (0x007E4770/0x007E2B50), buy_node (0x007E6090),
  // insert_unique/insert_at/link_and_rebalance (0x007E5B20/0x007E5DF0),
  // rb_decrement (0x007E60F0), lower_bound_node/find_node (0x007E6050/
  // 0x007E5C00), and the full tidy that frees every node plus the header
  // (0x007DF2D0) - is the container's own ctor / dtor, all cited on the
  // matching `rb_tree<Traits>` members in RbTree.h. The hand-rolled copies
  // that used to live here re-implemented all of that a second time over
  // the same nodes, so they are gone; call sites use the map's own API
  // (FindOrCreateMesh, below).

  // The mesh-batch bucket tree is `fa::map<MeshBatchKey,
  // fa::vector<MeshInstance*>, MeshBatchKeyLess>` (MeshBatchKey.h). Its
  // storage lifecycle - header sentinel allocation (0x007E2C30), the recursive
  // payload teardown plus header relink (0x007E2D90) and the full tidy that
  // frees the header too (0x007E2B20) - is the container's own ctor / `clear()`
  // / dtor, and `fa::vector` owns the bucket payload's growth and release.
  // The hand-rolled copies that used to live here re-implemented all of that a
  // second time over the same nodes, so they are gone; call sites use the
  // container operations directly.

  /**
   * Drops every live instance's cached LOD batches -- the loop `Reset`
   * (0x007E1370) and `Shutdown` (0x007E1510) both carry inline: walk the
   * ring, downcast each node to its `MeshInstance` (`node - 4`, the base's
   * offset), and reset every LOD of an instance that has a mesh.
   */
  void ResetInstanceBatches(moho::TDatList<moho::MeshInstance, void>& instances) noexcept
  {
    for (moho::MeshInstance* const instance : instances.owners()) {
      if (moho::Mesh* const mesh = instance->mesh.get(); mesh != nullptr) {
        for (moho::MeshLOD* const lod : mesh->lods) {
          lod->ResetBatches();
        }
      }
    }
  }
}

namespace moho
{
namespace
{
    MeshRenderer* gMeshRendererInstance = nullptr;

    /// Engine addition (water bodies): the level the next mirrored passes reflect at, when set.
    bool sMirrorElevationSet = false;
    float sMirrorElevation = 0.0f;
}

  void MESH_SetMirrorElevation(const bool set, const float elevation) noexcept
  {
    sMirrorElevationSet = set;
    sMirrorElevation = elevation;
  }


  /**
   * Address: 0x007DF150 (FUN_007DF150, ??0MeshRenderer@Moho@@QAE@XZ)
   */
  MeshRenderer::MeshRenderer()
    : meshEnvironment()
    , meshCacheTree()
    , dissolveTex()
    , meshEnvironmentTex()
    , anisotropiclookupTex()
    , insectlookupTex()
    , instances()
    , instanceListSize(0)
    , deltaFrame(0.0f)
    , instanceListStateFlags(0)
    , meshes()
    , meshSpatialDb{}
  {
    // `meshCacheTree` and `meshes` both stand their own header sentinel up in
    // the map constructor (0x007E4770+0x007E2B50 / 0x007E2C30 `_Tree::_Tree`
    // emissions the binary's ctor inlines here).

    // The binary's constructor ends by constructing this member:
    //   0x007DF23A  push offset Moho__sMeshRenderer.bd   ; +0xAC
    //   0x007DF244  call ??0SpatialDB_MeshInstance@Moho@@QAE@@Z
    // which is InitializeStorage (0x00501D80). Without it the shard vector is
    // never brought to a consistent empty state and the first CollectAllInVolume
    // of the first world-view frame walks from a null begin to a garbage end.

    gMeshRendererInstance = this;
  }

  /**
   * Address: 0x007DF330 (FUN_007DF330, ??1MeshRenderer@Moho@@UAE@XZ)
   * Address: 0x007DF260 (FUN_007DF260, the scalar deleting destructor in
   * vftable 0xE3F494's only slot; it was hand-written as a static
   * `DeleteWithFlag`.)
   */
  MeshRenderer::~MeshRenderer()
  {
    Reset();
    // meshSpatialDb tears itself down: 0x00501E50 is SpatialDB<T>::~SpatialDB,
    // which runs as ordinary member destruction after this body.
    // `meshes` frees its nodes and header sentinel right here, inline
    // (0x007E2B20's tidy) - confirmed from FUN_007DF330.c: `sub_7E3E20` +
    // `operator delete(this->mMeshes._Myhead)` fire immediately after
    // ~SpatialDB_MeshInstance, before the instance-list unlink below. Real,
    // automatic here via implicit member destruction (meshSpatialDb is the
    // last-declared member with a destructor, meshes the next).
    //
    // `meshCacheTree` (the binary's `mMap`) frees its own nodes and header
    // sentinel (0x007DF2D0's tidy) LAST, right before ~MeshEnvironment's
    // inline string cleanup - confirmed the same way: `sub_7E3B70` +
    // `operator delete(this->mMap._Myhead)` are the last two statements in
    // FUN_007DF330.c before mEnvironment's teardown, AFTER all four texture
    // shared_ptr releases. The previous recovery here called
    // DestroyMeshCacheTree(meshCacheTree) explicitly, right after the
    // instance-list unlink below - years too early relative to the real
    // binary's actual reverse-declaration-order destruction sequence. Both
    // trees are real typed `fa::map` members now, so both teardowns are
    // just implicit member destruction, naturally landing in the same
    // reverse-declaration order the binary shows: meshSpatialDb, meshes,
    // ..., insectlookupTex, anisotropiclookupTex, meshEnvironmentTex,
    // dissolveTex, meshCacheTree, meshEnvironment - no explicit call needed
    // for either, and none for meshCacheTree specifically fixes the
    // ordering bug. `instances` unlinks the same way, in its own
    // destructor between `meshes` and the textures (0x007DF2B0 is that
    // destructor's unwind copy).
    if (gMeshRendererInstance == this) {
      gMeshRendererInstance = nullptr;
    }
  }

  /**
   * Address: 0x007E16C0 (FUN_007E16C0, ?GetInstance@MeshRenderer@Moho@@SAPAV12@XZ)
   */
  MeshRenderer* MeshRenderer::GetInstance()
  {
    if (!gMeshRendererInstance) {
      static MeshRenderer sMeshRenderer;
      gMeshRendererInstance = &sMeshRenderer;
    }

    return gMeshRendererInstance;
  }

  /**
   * Address: 0x007E1370 (FUN_007E1370, ?Reset@MeshRenderer@Moho@@QAEXXZ)
   *
   * What it does:
   * Releases global sheet handles, clears per-instance LOD batches, and resets batch-bucket state.
   */
  void MeshRenderer::Reset()
  {
    dissolveTex.reset();
    meshEnvironmentTex.reset();
    anisotropiclookupTex.reset();
    insectlookupTex.reset();
    ResetInstanceBatches(instances);
    meshes.clear();

    // FAF: the default-pool buffers the hardware batches share go too; a
    // device reset needs every one of them released.
    HardwareMeshBatch::ReleaseSharedBuffers();
  }

  /**
   * Address: 0x007E1510 (FUN_007E1510, ?Shutdown@MeshRenderer@Moho@@QAEXXZ)
   *
   * What it does:
   * Performs reset-time cleanup and detaches the intrusive instance-list sentinel.
   */
  void MeshRenderer::Shutdown()
  {
    dissolveTex.reset();
    meshEnvironmentTex.reset();
    anisotropiclookupTex.reset();
    insectlookupTex.reset();
    ResetInstanceBatches(instances);
    instances.ListUnlink();
    meshes.clear();

    // FAF: see Reset.
    HardwareMeshBatch::ReleaseSharedBuffers();
  }

  /**
   * Address: 0x007DF510 (FUN_007DF510, ?UpdateMapSize@MeshRenderer@Moho@@QAEXHH@Z)
   *
   * What it does:
   * Resizes renderer-owned mesh spatial-db storage for current map dimensions.
   */
  void MeshRenderer::UpdateMapSize(const std::int32_t width, const std::int32_t height)
  {
    meshSpatialDb.ResizeForMap(width, height);
  }

  /**
   * Address: 0x007E5280 (FUN_007E5280,
   * ?FindOrCreateMesh@MeshRenderer@Moho@@QAE?AV?$shared_ptr@VMesh@Moho@@@boost@@PBVRMeshBlueprint@2@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
   * Address: 0x007E59C0 (FUN_007E59C0, the compiler-outlined cold-path chunk
   * for the cache-miss branch: reserves the tree slot with a placeholder
   * `weak_ptr`, builds the new `Mesh` + evicting-deleter `shared_ptr`, then
   * fills the slot's weak reference in)
   *
   * What it does:
   * Looks up an existing cached mesh by (blueprint, material) key and, if its
   * weak entry is still alive, locks and returns it. On a genuine miss, or a
   * key whose cached mesh has since been destroyed (the ground truth, FUN_
   * 007E5900, checks the found node's control block use_count_ before
   * trusting it - a `weak_ptr<Mesh>::lock()` in every way but name), inserts
   * (or reuses) the tree slot for `key` first -- matching FUN_007E59C0's real
   * operand order, and its exception safety: if `new Mesh(...)` throws, the
   * placeholder `weak_ptr` left in the tree is already empty/expired rather
   * than leaking a stray strong reference -- then builds the new `Mesh`
   * with its cache-evicting deleter and fills the slot's weak reference in.
   * The unconditional final assignment is correct for both outcomes of
   * `insert`: a fresh slot starts out default-constructed-empty, and an
   * existing slot only reaches here when the top check has already proven it
   * expired (single-threaded -- nothing runs between that check and here),
   * so `insert_unique`'s own find-or-insert semantics (RbTree.h) need no
   * extra conditional on this side.
   */
  boost::shared_ptr<Mesh> MeshRenderer::FindOrCreateMesh(
    const RMeshBlueprint* const blueprint, const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    MeshKey key(blueprint, materialArg);
    if (boost::weak_ptr<Mesh>* const found = meshCacheTree.try_get(key)) {
      if (boost::shared_ptr<Mesh> locked = found->lock()) {
        return locked;
      }
    }

    const std::pair<MeshRendererMeshCacheTree::iterator, bool> result =
      meshCacheTree.insert({key, boost::weak_ptr<Mesh>()});

    boost::shared_ptr<Mesh> mesh;
    ConstructSharedMeshWithCacheEvictingDeleter(mesh, new Mesh(blueprint, materialArg), meshCacheTree, key);
    result.first->second = mesh;

    return mesh;
  }

  /**
   * Address: 0x007DF530 (FUN_007DF530,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIPBVRMeshBlueprint@2@ABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const RMeshBlueprint* const blueprint,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<MeshMaterial> materialArg
  )
  {
    if (!blueprint) {
      return nullptr;
    }

    const RMeshBlueprintLOD* const lodBegin = blueprint->mLods.begin();
    if (!lodBegin || lodBegin == blueprint->mLods.end()) {
      return nullptr;
    }

    // 0x007DF5AB..0x007DF5BC: the front LOD's model is resolved up front and
    // the whole call is abandoned when it does not load. Without this the
    // renderer hands back an instance whose mesh has a LOD but no resource,
    // and `UserEntity::CreateMeshInstance` faults on the null skeleton.
    if (!GetModel(lodBegin->mMeshName.c_str(), nullptr)) {
      return nullptr;
    }

    boost::shared_ptr<Mesh> mesh = FindOrCreateMesh(blueprint, materialArg);
    return CreateMeshInstance(gameTick, color, scale, isStaticPose, mesh);
  }

  /**
   * Address: 0x007DF8E0 (FUN_007DF8E0,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMesh@Moho@@@boost@@@Z)
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<Mesh> meshArg
  )
  {
    if (!meshArg) {
      return nullptr;
    }

    MeshInstance* const instance = new MeshInstance(scale, &meshSpatialDb, gameTick, color, isStaticPose, meshArg);
    instance->ListLinkBefore(&instances);
    return instance;
  }

  /**
   * Address: 0x007DF710 (FUN_007DF710,
   * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIV?$shared_ptr@VRScmResource@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMeshMaterial@Moho@@@5@M@Z)
   *
   * IDA signature:
   * Moho::MeshInstance *__userpurge CreateMeshInstance(
   *   Moho::MeshRenderer *this@<ecx>, int gameTick, unsigned int color,
   *   boost::shared_ptr<RScmResource> resource, const Wm3::Vector3<float> &scale,
   *   bool isStaticPose, boost::shared_ptr<MeshMaterial> material, float lodCutoff);
   *
   * What it does:
   * Constructs a standalone one-LOD mesh from an already-resolved
   * resource/material pair, applies the LOD cutoff distance to that single
   * LOD, then creates and links a mesh instance via the shared_ptr<Mesh>
   * overload. The resource/material ctor (0x007DD750) always creates exactly
   * one LOD, so the front LOD is always valid.
   */
  MeshInstance* MeshRenderer::CreateMeshInstance(
    const std::int32_t gameTick,
    const std::int32_t color,
    const boost::shared_ptr<RScmResource> resource,
    const Wm3::Vec3f& scale,
    const bool isStaticPose,
    const boost::shared_ptr<MeshMaterial> material,
    const float lodCutoff
  )
  {
    boost::shared_ptr<Mesh> mesh(new Mesh(resource, material));
    mesh->lods.front()->SetCutoff(lodCutoff);
    return CreateMeshInstance(gameTick, color, scale, isStaticPose, mesh);
  }

  /**
   * Constructs the mesh-render shader-var set, registering every variable
   * against the `"mesh"` effect file. The HLSL names are byte-verified as the
   * exact strings passed to the binary's per-var `RegisterShaderVar` calls
   * (`register_ShaderVarMesh*`, 0x00BE0540..0x00BE0840) — read directly from
   * bin/2025.7.1/ForgedAlliance.exe. The two cartographic elevation vars are
   * registered by register_ShaderVarMeshMinimumElevation (0x00BE0780, literal
   * "minimumElevation" @VA 0xE3F66C, global 0x010BED78) and
   * register_ShaderVarMeshMaximumElevation (0x00BE07A0, literal
   * "maximumElevation" @VA 0xE3F680, global 0x010BE9D0). Mirrors
   * `TerrainShaderVarSet`.
   */
  MeshShaderVarSet::MeshShaderVarSet()
  {
    RegisterShaderVar("anisotropicTexture", &anisotropicTexture, "mesh"); // 0x00BE0540
    RegisterShaderVar("insectTexture", &insectTexture, "mesh");           // 0x00BE0560
    RegisterShaderVar("dissolveTexture", &dissolveTexture, "mesh");
    RegisterShaderVar("time", &time, "mesh");
    RegisterShaderVar("mirrored", &mirrored, "mesh");
    RegisterShaderVar("lodBasis", &lodBasis, "mesh");
    RegisterShaderVar("viewMatrix", &viewMatrix, "mesh");
    RegisterShaderVar("projMatrix", &projMatrix, "mesh");
    RegisterShaderVar("terrainScale", &terrainScale, "mesh");
    RegisterShaderVar("lightMultiplier", &lightMultiplier, "mesh");
    RegisterShaderVar("sunDirection", &sunDirection, "mesh");
    RegisterShaderVar("sunDiffuse", &sunDiffuse, "mesh");
    RegisterShaderVar("sunAmbient", &sunAmbient, "mesh");
    RegisterShaderVar("shadowFill", &shadowFill, "mesh");
    RegisterShaderVar("surfaceElevation", &surfaceElevation, "mesh");
    RegisterShaderVar("abyssElevation", &abyssElevation, "mesh");
    RegisterShaderVar("minimumElevation", &minimumElevation, "mesh"); // 0x00BE0780
    RegisterShaderVar("maximumElevation", &maximumElevation, "mesh"); // 0x00BE07A0
    RegisterShaderVar("waterRamp", &waterRamp, "mesh");
    RegisterShaderVar("shadowsEnabled", &shadowsEnabled, "mesh");
    RegisterShaderVar("shadowMatrix", &shadowMatrix, "mesh");
    RegisterShaderVar("shadowTexture", &shadowTexture, "mesh");
    RegisterShaderVar("shadowBias", &shadowBias, "mesh");
    RegisterShaderVar("shadowSize", &shadowSize, "mesh");
    RegisterShaderVar("shadowBlur", &shadowBlur, "mesh"); // 0x00BE0840
  }

  MeshShaderVarSet& GetMeshShaderVars()
  {
    static MeshShaderVarSet shaderVars{};
    return shaderVars;
  }
namespace
{

  // ---------------------------------------------------------------------------
  // Per-material mesh-texture shader-vars.
  //
  // Distinct from the 23-entry MeshShaderVarSet above, the binary holds these
  // six texture sampler shader-vars as standalone process-wide `ShaderVar`
  // globals, each installed by its own CRT init thunk (byte-verified from
  // bin/2025.7.1/ForgedAlliance.exe): register thunks at 0x00BE0520
  // (environmentTexture, global 0x010BEDC0), 0x00BE0860 (albedoTexture, global
  // 0x010BE670), 0x00BE0880 (normalsTexture, global 0x010BEAA8), 0x00BE08A0
  // (specularTexture, global 0x010BEC10), 0x00BE08C0 (lookupTexture, global
  // 0x010BE820) and 0x00BE08E0 (secondaryTexture, global 0x010BE8F8). Every
  // thunk calls `RegisterShaderVar(<name>, &global, "mesh")` (0x00438000), so
  // all six register against the "mesh" effect. The HLSL name strings are the
  // exact null-terminated `.rdata` literals passed to those calls (VAs
  // 0x00E3F580 / 0x00E3F6E0 / 0x00E3F6F0 / 0x00E3F700 / 0x00E3F710 /
  // 0x00E3F720). MeshRenderer::Render binds all six per LOD material; the
  // recovered model groups them into one set exposed through
  // GetMeshTextureShaderVars(), mirroring MeshShaderVarSet.
  // ---------------------------------------------------------------------------
      struct MeshTextureShaderVarSet
    {
      ShaderVar environmentTexture; // "environmentTexture" &0x010BEDC0
      ShaderVar albedoTexture;      // "albedoTexture"      &0x010BE670
      ShaderVar specularTexture;    // "specularTexture"    &0x010BEC10
      ShaderVar lookupTexture;      // "lookupTexture"      &0x010BE820
      ShaderVar secondaryTexture;   // "secondaryTexture"   &0x010BE8F8
      ShaderVar normalsTexture;     // "normalsTexture"     &0x010BEAA8

      MeshTextureShaderVarSet()
      {
        RegisterShaderVar("environmentTexture", &environmentTexture, "mesh"); // 0x00BE0520
        RegisterShaderVar("albedoTexture", &albedoTexture, "mesh");           // 0x00BE0860
        RegisterShaderVar("specularTexture", &specularTexture, "mesh");       // 0x00BE08A0
        RegisterShaderVar("lookupTexture", &lookupTexture, "mesh");           // 0x00BE08C0
        RegisterShaderVar("secondaryTexture", &secondaryTexture, "mesh");     // 0x00BE08E0
        RegisterShaderVar("normalsTexture", &normalsTexture, "mesh");         // 0x00BE0880
      }
    };

    MeshTextureShaderVarSet& GetMeshTextureShaderVars()
    {
      static MeshTextureShaderVarSet textureVars{};
      return textureVars;
    }
}


  // ---------------------------------------------------------------------------
  // GPU mesh skinning-palette shader-vars (translation + rotation palettes).
  //
  // These are two process-wide `MeshShaderPaletteVar` globals the binary holds
  // separately from the 23-entry `MeshShaderVarSet` above (distinct CRT init
  // thunks at 0x00BE0900 / 0x00BE0920, distinct global addresses 0x010BEEF8 /
  // 0x010BEE50). Each is a `ShaderVar` extended with an inline palette buffer
  // reserved to 80 (`kPaletteCapacity`) 16-byte entries at registration time.
  // ---------------------------------------------------------------------------

  // AppendDefaultPaletteEntries removed: MeshShaderPaletteBuffer is
  // fa::vector<SkinPaletteEntry> (see Mesh.h), so its 0x007E9280 body is
  // this template's own insert(pos,count,value) member for the 16-byte
  // element -- see the Address: citations added there.

  /**
   * Address: 0x007E96A0 (FUN_007E96A0, sub_7E96A0)
   *
   * What it does:
   * Uninitialized-move relocation for palette entries: copies each 16-byte
   * `SkinPaletteEntry` in `[first, last)` into `dest`, four floats at a time, and
   * returns the one-past-end destination pointer.
   */
  SkinPaletteEntry* RelocatePaletteEntries(
    SkinPaletteEntry* dest,
    SkinPaletteEntry* first,
    SkinPaletteEntry* const last
  )
  {
    while (first != last) {
      dest->x = first->x;
      dest->y = first->y;
      dest->z = first->z;
      dest->w = first->w;
      ++first;
      ++dest;
    }
    return dest;
  }

  void MeshShaderPaletteBuffer::ReserveToPaletteCapacity()
  {
    const std::size_t count = size();
    if (count < kPaletteCapacity) {
      insert(end(), kPaletteCapacity - count, SkinPaletteEntry{});
    } else if (count > kPaletteCapacity) {
      erase(begin() + kPaletteCapacity, end());
    }
  }

  /**
   * Address: 0x007E9050 (FUN_007E9050, register_MeshShaderVar)
   *
   * IDA signature:
   * struct_MeshShaderVar* __thiscall register_MeshShaderVar(
   *     const char* name, struct_MeshShaderVar* a2);
   *
   * What it does:
   * Registers one mesh skinning-palette shader-var against the `"mesh"` effect
   * file (via `RegisterShaderVar`), clears its embedded palette buffer triplet,
   * and reserves the palette to `kPaletteCapacity` (80) entries.
   */
  MeshShaderPaletteVar* register_MeshShaderVar(const char* const name, MeshShaderPaletteVar* const paletteVar)
  {
    RegisterShaderVar(name, paletteVar, "mesh");

    // No explicit triplet reset needed: mPalette is a real
    // fa::vector<SkinPaletteEntry> here, already empty from
    // MeshShaderPaletteVar's own (implicit) default construction.
    paletteVar->mPalette.ReserveToPaletteCapacity();
    return paletteVar;
  }

  // The two palette globals are defined ahead of the bootstrap object below:
  // C++ constructs a translation unit's namespace-scope objects in definition
  // order, so each one is default-constructed before its registrar runs
  // `register_MeshShaderVar` on it. No other translation unit reads them
  // during static initialization.

  /**
   * Address: 0x00C03E40 (FUN_00C03E40, dynamic atexit destructor for `meshShaderVarTransPalette`)
   *
   * What it does:
   * Translation skinning-palette shader-var (binary global 0x010BEEF8).
   */
  MeshShaderPaletteVar meshShaderVarTransPalette;

  /**
   * Address: 0x00C03E80 (FUN_00C03E80, dynamic atexit destructor for `meshShaderVarRotPalette`)
   *
   * What it does:
   * Rotation skinning-palette shader-var (binary global 0x010BEE50).
   */
  MeshShaderPaletteVar meshShaderVarRotPalette;
namespace
{
    /**
     * CRT static-init bootstrap mirroring the two `__xc_a` entries at
     * 0x00BE0900 / 0x00BE0920: registering both palette shader-vars at process
     * startup. This is the source-level invocation site for the palette cluster
     * (FRAMEWORK_DISPATCH via static init).
     */
    struct MeshPaletteShaderVarBootstrap
    {
      MeshPaletteShaderVarBootstrap()
      {
        moho::register_MeshShaderVarTransPalette();
        moho::register_MeshShaderVarRotPalette();
      }
    };

    [[maybe_unused]] MeshPaletteShaderVarBootstrap gMeshPaletteShaderVarBootstrap;
}


  /**
   * Address: 0x00BE0900 (FUN_00BE0900, register_MeshShaderVarTransPalette)
   *
   * What it does:
   * CRT static-init registration thunk: registers `meshShaderVarTransPalette`
   * under the byte-verified HLSL name `"transPalette"`.
   */
  void register_MeshShaderVarTransPalette()
  {
    register_MeshShaderVar("transPalette", &meshShaderVarTransPalette);
  }

  /**
   * Address: 0x00BE0920 (FUN_00BE0920, register_MeshShaderVarRotPalette)
   *
   * What it does:
   * CRT static-init registration thunk: registers `meshShaderVarRotPalette`
   * under the byte-verified HLSL name `"rotPalette"`.
   */
  void register_MeshShaderVarRotPalette()
  {
    register_MeshShaderVar("rotPalette", &meshShaderVarRotPalette);
  }

  /**
   * Address: 0x007E1720 (FUN_007E1720, Moho::MeshRenderer::LoadGlobalTextures)
   * Mangled: ?LoadGlobalTextures@MeshRenderer@Moho@@AAEXXZ
   *
   * IDA signature:
   * private: void __thiscall Moho::MeshRenderer::LoadGlobalTextures(void);
   *
   * What it does:
   * Lazily resolves the renderer's four global texture resources from the
   * active D3D device resources and stores each retained
   * `boost::shared_ptr<RD3DTextureResource>` into its lane. Each lane is only
   * (re)loaded when still empty, matching the binary's `if (!lane.obj)` guards,
   * so repeated calls after the first successful load are no-ops per lane. The
   * mesh-environment cube map path comes from the renderer's
   * `MeshEnvironment::mCubeMapPath`; the other three are fixed engine texture
   * paths transcribed verbatim from the binary. `allowCreate=0, allowFallback=1`
   * for every lookup.
   */
  void MeshRenderer::LoadGlobalTextures()
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    if (!dissolveTex) {
      resources->GetTexture(dissolveTex, "/textures/environment/dissolve.dds", 0, true);
    }
    if (!meshEnvironmentTex) {
      resources->GetTexture(meshEnvironmentTex, meshEnvironment.mCubeMapPath.c_str(), 0, true);
    }
    if (!anisotropiclookupTex) {
      resources->GetTexture(anisotropiclookupTex, "/textures/engine/anisotropiclookup.dds", 0, true);
    }
    if (!insectlookupTex) {
      resources->GetTexture(insectlookupTex, "/textures/engine/insectlookup.dds", 0, true);
    }
  }

  /**
   * Address: 0x007E19D0 (FUN_007E19D0, Moho::MeshRenderer::ConfigureShader)
   * Mangled: ?ConfigureShader@MeshRenderer@Moho@@AAEXABVGeomCamera3@2@PAVShadow@2@_N@Z
   *
   * IDA signature:
   * private: void __thiscall Moho::MeshRenderer::ConfigureShader(
   *     const GeomCamera3& camera, Shadow* shadow, bool mirrored);
   *
   * What it does:
   * Binds the whole mesh-render shader-constant lane for one render pass. Reads
   * the active water surface elevation (falling back to -1000/-10000 when no
   * terrain/water is present), loads the global lookup textures, binds the
   * anisotropic/insect/dissolve textures, uploads the frame time, mirror flag,
   * (optionally mirror-flipped) view matrix and projection matrix, then either
   * the active terrain's terrain-scale/sun/shadow/water lighting lanes or the
   * renderer's fallback mesh-environment lighting lanes, and finally the
   * optional shadow-map lane. All float constants and HLSL names are byte-
   * verified from bin/2025.7.1/ForgedAlliance.exe.
   */
  void MeshRenderer::ConfigureShader(const GeomCamera3& camera, Shadow* const shadow, const bool mirrored)
  {
    MeshShaderVarSet& sv = GetMeshShaderVars();

    // Select the active terrain resource (nullptr when there is no world map or
    // no terrain). The binary reads the `sWldMap` global directly; the recovered
    // `REN_GetTerrainRes` folds in both the map and terrain null checks and
    // returns `sWldMap->mTerrainRes` (mirrors 0x007E1A0B..0x007E1A25).
    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();

    // Surface (water) elevation lane: current water elevation when water is
    // enabled on the active map, else -10000; -1000 when there is no terrain.
    float surfaceElevation;
    if (terrainRes != nullptr) {
      const STIMap* const map = terrainRes->mMap;
      surfaceElevation = (map->mWaterEnabled != 0) ? map->mWaterElevation : -10000.0f;
    } else {
      surfaceElevation = -1000.0f;
    }
    // Engine addition (water bodies): a reflection pass for a lake mirrors at the lake's level.
    if (mirrored && sMirrorElevationSet) {
      surfaceElevation = sMirrorElevation;
    }

    // Global lookup textures + the three per-frame texture binds.
    LoadGlobalTextures();
    BindTextureShaderVar(sv.anisotropicTexture, boost::static_pointer_cast<ID3DTextureSheet>(anisotropiclookupTex));
    BindTextureShaderVar(sv.insectTexture, boost::static_pointer_cast<ID3DTextureSheet>(insectlookupTex));

    // Frame time: fold the frame counter into a float (with the unsigned int
    // fixup the binary applies to negative counters), add the accumulated delta
    // frame, then wrap into the shader time window (fmod by 36000).
    const auto frameCounter = static_cast<std::int32_t>(instanceListSize);
    double frameSeconds = static_cast<double>(frameCounter);
    if (frameCounter < 0) {
      frameSeconds += 4294967296.0; // 2^32 unsigned fixup (dbl_E4F710)
    }
    frameSeconds += deltaFrame;
    // `fmod(float, float)` (0x00422920 -> _CIfmod): the time is stored to a
    // float argument before the call.
    const float shaderTime = static_cast<float>(fa::fmod(static_cast<float>(frameSeconds), 36000.0f)); // flt_F57F08
    if (sv.time.Exists()) {
      sv.time.SetFloat(shaderTime);
    }

    if (sv.mirrored.Exists()) {
      const int mirroredFlag = mirrored ? 1 : 0;
      SetShaderVarPtr(sv.mirrored, &mirroredFlag, 4);
    }

    // Copy the camera view matrix; when mirrored, reflect it about the water
    // plane (translate row along the up axis by 2*surfaceElevation and negate
    // the up-axis row). Row layout: r[row].{x,y,z,w}.
    VMatrix4 viewMatrixCopy = camera.view;
    if (mirrored) {
      const float translate = surfaceElevation * 2.0f; // flt_DFEB0C = 2.0
      viewMatrixCopy.r[3].x += (viewMatrixCopy.r[2].x + viewMatrixCopy.r[0].x) * 0.0f + viewMatrixCopy.r[1].x * translate;
      viewMatrixCopy.r[3].y += (viewMatrixCopy.r[2].y + viewMatrixCopy.r[0].y) * 0.0f + viewMatrixCopy.r[1].y * translate;
      viewMatrixCopy.r[3].z += (viewMatrixCopy.r[2].z + viewMatrixCopy.r[0].z) * 0.0f + viewMatrixCopy.r[1].z * translate;
      viewMatrixCopy.r[3].w += (viewMatrixCopy.r[2].w + viewMatrixCopy.r[0].w) * 0.0f + viewMatrixCopy.r[1].w * translate;
      viewMatrixCopy.r[1].x *= -1.0f; // flt_E4F6E8 = -1.0
      viewMatrixCopy.r[1].y *= -1.0f;
      viewMatrixCopy.r[1].z *= -1.0f;
      viewMatrixCopy.r[1].w *= -1.0f;
    }

    // LOD basis = viewport matrix row 1 (camera.viewport.r[1], 4 floats).
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&viewMatrixCopy);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    BindTextureShaderVar(sv.dissolveTexture, boost::static_pointer_cast<ID3DTextureSheet>(dissolveTex));

    if (terrainRes != nullptr) {
      const STIMap* const map = terrainRes->mMap;
      const CHeightField* const heightField = map->mHeightField.get();

      // Terrain scale = {1/(width-1), 0, 1/(height-1), 1}.
      const float terrainScaleValues[4] = {
        1.0f / static_cast<float>(heightField->width - 1),
        0.0f,
        1.0f / static_cast<float>(heightField->height - 1),
        1.0f
      };
      if (sv.terrainScale.Exists()) {
        SetShaderVarMem(sv.terrainScale, 4, terrainScaleValues);
      }

      const float lightingMultiplier = terrainRes->GetLightingMultiplier();
      if (sv.lightMultiplier.Exists()) {
        sv.lightMultiplier.SetFloat(lightingMultiplier);
      }

      // Sun direction: negated when mirrored (reflected across the water plane).
      Wm3::Vector3f sunDirection = terrainRes->GetSunDirection();
      if (mirrored) {
        sunDirection.x = -0.0f - sunDirection.x; // dword_E4F748 = -0.0
        sunDirection.y = -0.0f - sunDirection.y;
        sunDirection.z = -0.0f - sunDirection.z;
      }
      if (sv.sunDirection.Exists()) {
        SetShaderVarMem(sv.sunDirection, 3, &sunDirection.x);
      }

      const Wm3::Vector3f sunColor = terrainRes->GetSunColor();
      if (sv.sunDiffuse.Exists()) {
        SetShaderVarMem(sv.sunDiffuse, 3, &sunColor.x);
      }
      const Wm3::Vector3f sunAmbience = terrainRes->GetSunAmbience();
      if (sv.sunAmbient.Exists()) {
        SetShaderVarMem(sv.sunAmbient, 3, &sunAmbience.x);
      }
      const Wm3::Vector3f shadowFillColor = terrainRes->GetShadowFillColor();
      if (sv.shadowFill.Exists()) {
        SetShaderVarMem(sv.shadowFill, 3, &shadowFillColor.x);
      }

      CWaterShaderProperties* const waterProperties = terrainRes->GetWaterShaderProperties();
      if (sv.surfaceElevation.Exists()) {
        sv.surfaceElevation.SetFloat(surfaceElevation);
      }

      const float abyssElevation = (map->mWaterEnabled != 0) ? map->mWaterElevationAbyss : -10000.0f;
      if (sv.abyssElevation.Exists()) {
        sv.abyssElevation.SetFloat(abyssElevation);
      }

      BindTextureShaderVar(sv.waterRamp, waterProperties->GetWaterRamp());
    } else {
      // Fallback (no terrain): use the renderer's mesh-environment lighting.
      if (sv.lightMultiplier.Exists()) {
        sv.lightMultiplier.SetFloat(meshEnvironment.mFallbackLightMultiplier);
      }
      if (sv.sunDirection.Exists()) {
        SetShaderVarMem(sv.sunDirection, 3, &meshEnvironment.mFallbackSunDirection.x);
      }
      if (sv.sunDiffuse.Exists()) {
        SetShaderVarMem(sv.sunDiffuse, 3, &meshEnvironment.mFallbackSunDiffuseColor.x);
      }
      if (sv.sunAmbient.Exists()) {
        SetShaderVarMem(sv.sunAmbient, 3, &meshEnvironment.mFallbackSunAmbientColor.x);
      }
      if (sv.shadowFill.Exists()) {
        SetShaderVarMem(sv.shadowFill, 3, &meshEnvironment.mFallbackShadowFillColor.x);
      }
      if (sv.surfaceElevation.Exists()) {
        sv.surfaceElevation.SetFloat(surfaceElevation);
      }
      if (sv.abyssElevation.Exists()) {
        sv.abyssElevation.SetFloat(-1000.0f); // dword_E4F8D8
      }

      // No terrain water-ramp resource: resolve the fixed engine water ramp.
      CD3DDevice* const device = D3D_GetDevice();
      ID3DDeviceResources* const resources = device->GetResources();
      ID3DDeviceResources::TextureResourceHandle waterRampResource;
      resources->GetTexture(waterRampResource, "/textures/engine/waterramp.dds", 0, true);
      BindTextureShaderVar(sv.waterRamp, boost::static_pointer_cast<ID3DTextureSheet>(waterRampResource));
    }

    // Shadow-map lane: only when a shadow object with fidelity > 1 is supplied.
    if (shadow != nullptr && shadow->mShadowFidelity > 1) {
      const int shadowsEnabledFlag = 1;
      if (sv.shadowsEnabled.Exists()) {
        SetShaderVarPtr(sv.shadowsEnabled, &shadowsEnabledFlag, 4);
      }
      if (sv.shadowMatrix.Exists()) {
        sv.shadowMatrix.SetMatrix4x4(&shadow->mCamera.viewProjection);
      }

      // Bind the shadow map for sampling. The binary reaches it through
      // Shadow::GetShadowMap (sub_7DB350), which takes a *strong* reference -
      // it increments the control block's use_count_ at +0x04 - and hands the
      // retained render target to the render-target binder (0x00491280), which
      // pulls the GAL surface off the target's own vtable. The retained copy is
      // released when it leaves scope, matching the binary's trailing
      // shared_ptr teardown.
      boost::shared_ptr<CD3DRenderTarget> shadowMap{};
      shadow->GetShadowMap(shadowMap);
      sv.shadowTexture.SetRenderTargetTexture(shadowMap);

      const float shadowBias = ren_ShadowBias; // 0.005
      if (sv.shadowBias.Exists()) {
        sv.shadowBias.SetFloat(shadowBias);
      }
      // Engine change (ren_ShadowCascades): the whole-view map's texels, which is mShadowSize without the atlas.
      const int shadowSize = ShadowMapTexels(*shadow);
      if (sv.shadowSize.Exists()) {
        sv.shadowSize.SetFloat(static_cast<float>(shadowSize));
      }
      const int shadowBlurFlag = (shadow->mShadowBlurEnabled && shadow->mShadowFidelity == 3) ? 1 : 0;
      if (sv.shadowBlur.Exists()) {
        SetShaderVarPtr(sv.shadowBlur, &shadowBlurFlag, 4);
      }
    } else {
      const int shadowsEnabledFlag = 0;
      if (sv.shadowsEnabled.Exists()) {
        SetShaderVarPtr(sv.shadowsEnabled, &shadowsEnabledFlag, 4);
      }
    }
  }
namespace
{
    /**
     * Resolves the MeshLOD associated with one batch bucket.
     *
     * The batch key's `mLod` lane (`MeshBatchKey` +0x08) stores the owning
     * `MeshLOD*` directly (the binary reads `key.lod` at 0x007DFCDC).
     */
    [[nodiscard]] MeshLOD* MeshBatchEntryLod(const MeshBatchBucket& bucket) noexcept
    {
      return bucket.first.mLod;
    }

    /**
     * True when a batch bucket holds skinned (static-pose) instances.
     *
     * The batch key's `mIsStaticPose` byte (`MeshBatchKey` +0x04) selects the
     * skinned batch path when non-zero (the binary reads `*(node + 0x10)`,
     * i.e. the key byte inside the node payload at +0x0C).
     */
    [[nodiscard]] bool MeshBatchEntryIsSkinned(const MeshBatchBucket& bucket) noexcept
    {
      return bucket.first.mIsStaticPose != 0;
    }

    /**
     * FAF divergence from the shipped binary - not a recovered function.
     *
     * What it does:
     * Empties every bucket's instance list for the next `MeshRenderer::Batch`
     * while keeping the buckets themselves, and periodically drops the ones
     * that went unused.
     *
     * The binary starts every Batch with `meshes.clear()`, and Batch runs two or
     * three times a frame (main view, shadow camera, cartographic). That frees
     * every map node and every instance vector, and the same buckets are then
     * reallocated as they refill - thousands of allocations a frame in a busy
     * scene. Clearing a vector keeps its capacity, so a bucket that is visible
     * frame after frame stops allocating at all.
     *
     * Buckets left empty since the previous Batch are erased every
     * `kPruneEveryNthBatch` calls, so the map follows the recently visible set
     * instead of growing. Pruning only occasionally matters: main view and
     * shadow camera alternate over the same map, so a bucket one of them sees
     * is always momentarily empty from the other's point of view.
     *
     * An empty bucket's key may name a MeshLOD the mesh cache has since
     * released. The key compare only reads that pointer's value, and every
     * consumer of the map skips empty buckets before touching the LOD.
     */
    void RecycleBatchBuckets(MeshBatchBucketTree& buckets)
    {
      constexpr unsigned kPruneEveryNthBatch = 64u;
      static unsigned sBatchesSincePrune = 0u;

      const bool prune = (++sBatchesSincePrune >= kPruneEveryNthBatch);
      if (prune) {
        sBatchesSincePrune = 0u;
      }

      for (auto it = buckets.begin(); it != buckets.end();) {
        if (prune && it->second.empty()) {
          it = buckets.erase(it);
          continue;
        }
        it->second.clear();
        ++it;
      }
    }

    /**
     * Resolves a material's cached render-stage index, resolving it from the
     * effect's `renderStage` integer annotation on first use and caching the
     * result back into `mShaderIndex` (binary: the `mMat.mVal < 0` block).
     */
    [[nodiscard]] std::int32_t ResolveMaterialRenderStage(CD3DEffect* const effect, MeshMaterial& material)
    {
      if (material.mShaderIndex < 0) {
        material.mShaderIndex =
          effect->GetIntegerAnnotation(material.mShaderAnnotation, fa::string("renderStage"), 0);
      }
      return material.mShaderIndex;
    }
}


  /**
   * Address: 0x007DFF30 (FUN_007DFF30, ?RenderCartographic@MeshRenderer@Moho@@QAEXMMMABVGeomCamera3@2@AAV?$map@...@Z)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::RenderCartographic(
   *   MeshRenderer* this, std::map<MeshBatchKey, vector<MeshInstance*>>* map,
   *   float surfaceElevation, float minimumElevation, float maximumElevation,
   *   const GeomCamera3& camera);
   *
   * What it does:
   * Draws one mesh batch tree in cartographic (minimap) mode. Binds the seven
   * cartographic mesh shader-vars for this pass (time / lodBasis / the three
   * elevation floats / view / proj), then walks the batch-bucket RB-tree in key
   * order. Unlike Render it does NOT call ConfigureShader and does NOT select an
   * effect — the caller has already made a cartographic effect the device's
   * current effect, so it reads `device->GetCurEffect()` to resolve the per-
   * material cartographic technique. There is no renderStage gate: each material
   * lazily resolves + caches its "cartographicTechnique" string annotation
   * (`MeshMaterial::mCartographicTechnique`, guarded by `mCartographicTechniqueResolved`) and is drawn only when
   * that technique is non-empty. Per material it binds the albedo/specular/
   * normals samplers (this bind order), then draws the bucket's instances through
   * the LOD's lazily-built skinned/static hardware batch, always un-mirrored
   * (binary pushes 0 as the last Render arg, 0x007E030C).
   *
   * The three float params are the elevation lane: the binary binds
   * `shaderVarMeshSurfaceElevation = a3`, `shaderVarMeshMinimumElevation = a4`,
   * `shaderVarMeshMaximumElevation = a5` (0x007E0000..0x007E006C), which is why
   * they are named surface/minimum/maximum here rather than the decompiler's
   * mislabelled projection-scale trio.
   */
  void MeshRenderer::RenderCartographic(
    const float surfaceElevation,
    const float minimumElevation,
    const float maximumElevation,
    const GeomCamera3& camera,
    MeshBatchBucketTree& meshMap
  )
  {
    // Nothing to draw when the batch tree is empty (binary: `if (*(arg4+8))`).
    if (meshMap.empty()) {
      return;
    }

    // The current effect is whatever cartographic effect the caller selected;
    // GetResources() is still pinged at the head of the pass exactly as the
    // binary does (D3D_GetDevice()->GetResources(), 0x007DFF69..0x007DFF79).
    MeshShaderVarSet& sv = GetMeshShaderVars();

    CD3DDevice* const device = D3D_GetDevice();
    device->GetResources();

    // Frame time: fold the frame counter into a float (with the unsigned int
    // fixup the binary applies to negative counters), add the accumulated delta
    // frame, then wrap into the shader time window (fmod by 36000). Identical to
    // RenderDepth's / ConfigureShader's shaderTime lane.
    const auto frameCounter = static_cast<std::int32_t>(instanceListSize);
    double frameSeconds = static_cast<double>(frameCounter);
    if (frameCounter < 0) {
      frameSeconds += 4294967296.0; // 2^32 unsigned fixup (dbl_E4F710)
    }
    frameSeconds += deltaFrame;
    // `fmod(float, float)` (0x00422920 -> _CIfmod): the time is stored to a
    // float argument before the call.
    const float shaderTime = static_cast<float>(fa::fmod(static_cast<float>(frameSeconds), 36000.0f)); // flt_F57F08
    if (sv.time.Exists()) {
      sv.time.SetFloat(shaderTime);
    }

    // Bind the cartographic shader-constant lane in binary order: LOD basis
    // (viewport matrix row 1, camera.viewport.r[1], 4 floats = arg5+660), then
    // the three elevation floats, then the view/projection matrices (arg5+92 /
    // arg5+28). (Transcribed from FUN_007DFF30 @0x007DFFD6..0x007E00A8.)
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    if (sv.minimumElevation.Exists()) {
      sv.minimumElevation.SetFloat(minimumElevation);
    }
    if (sv.maximumElevation.Exists()) {
      sv.maximumElevation.SetFloat(maximumElevation);
    }
    if (sv.surfaceElevation.Exists()) {
      sv.surfaceElevation.SetFloat(surfaceElevation);
    }
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    // Cartographic mode does NOT select an effect: it consumes the effect the
    // caller already made current (binary: `effect = device->GetCurEffect()`,
    // vtbl+0x58 @0x007E00AA..0x007E00B3). This effect resolves each material's
    // cartographic technique string annotation.
    CD3DEffect* const effect = device->GetCurEffect();

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // Walk the batch-bucket map in key order. The binary's `begin()` is
    // `head->left` and its `end()` is the header itself, stepped by `_Inc`
    // (0x007E42F0) - which is what `fa::map`'s iterator does.
    for (const MeshBatchBucket& bucket : meshMap) {
      // A recycled bucket can sit empty over a released mesh; see
      // RecycleBatchBuckets. Skip it before touching its LOD.
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = MeshBatchEntryLod(bucket);
      MeshMaterial& material = lod->mat;

      // Lazily resolve + cache this material's cartographic technique the first
      // time the cartographic pass reaches it (binary: `if (!mMat.byte8C) {
      // mMat.byte8C = 1; mMat.mStr2 = GetStringAnnotation(mAnnot,
      // "cartographicTechnique", ""); }`). Unlike Render/RenderDepth there is no
      // renderStage gate — the only per-material gate is a non-empty technique.
      if (!material.mCartographicTechniqueResolved) {
        material.mCartographicTechniqueResolved = true;
        const fa::string cartographicTechnique =
          effect->GetStringAnnotation(material.mShaderAnnotation, fa::string("cartographicTechnique"), fa::string(""));
        material.mCartographicTechnique.assign_owned(cartographicTechnique.view());
      }

      // Only draw when a cartographic technique is defined for the material
      // (binary: `if (mMat.mStr2._Mysize)`).
      if (material.mCartographicTechnique.size() != 0) {
        device->SelectTechnique(material.mCartographicTechnique.c_str());

        // Cartographic pass binds three samplers, in binary bind order:
        // albedo, specular, normals (0x007E01FD / 0x007E020B / 0x007E0219).
        tv.albedoTexture.GetTexture(material.mAlbedoSheet);
        tv.specularTexture.GetTexture(material.mSpecularSheet);
        tv.normalsTexture.GetTexture(material.mNormalsSheet);

        // Draw the bucket's instances through the LOD's lazily-built hardware
        // mesh batch (skinned for static-pose buckets, static otherwise). The
        // shared_ptr handle keeps the batch retained for the draw call; the
        // cartographic pass always draws un-mirrored (binary pushes 0,
        // 0x007E030C).
        boost::shared_ptr<MeshBatch> batchHandle;
        if (MeshBatchEntryIsSkinned(bucket)) {
          lod->GetSkinnedBatch(batchHandle);
        } else {
          lod->GetStaticBatch(batchHandle);
        }
        if (batchHandle) {
          batchHandle->Render(bucket.second, false);
        }
      }
    }
  }

  /**
   * Address: 0x007E0830 (FUN_007E0830, ?RenderSilhouette@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::RenderSilhouette(
   *     Moho::MeshRenderer *this, const struct Moho::GeomCamera3 *a2);
   *
   * What it does:
   * Draws the silhouette overlay in two passes over the same batch tree: the
   * `Occlude` technique writes the occluders that hide silhouettes, then the
   * `Silhouette` technique draws the outlines themselves. Each pass has its
   * own per-LOD opt-in flag and binds only the albedo sampler.
   *
   * Note IDA prints `this` and `a2` swapped here, as it does in
   * Silhouette::Render: the body reads camera fields off `this`
   * (`(int)this + 660` is GeomCamera3::viewport.r[1] at 0x294) and the batch
   * tree off `a2`.
   */
  void MeshRenderer::RenderSilhouette(const GeomCamera3& camera)
  {
    CD3DDevice* const device = D3D_GetDevice();

    // Same pass head as RenderCartographic/RenderDepth, minus the time and
    // elevation lanes: LOD basis from the viewport matrix row 1, then the two
    // camera matrices.
    MeshShaderVarSet& sv = GetMeshShaderVars();
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    device->SelectFxFile("mesh");

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // The two passes walk the same tree but gate on different per-LOD bytes
    // (0x007E0913 reads MeshLOD+0xAD, 0x007E0A93 reads +0xAE), so a mesh can
    // occlude without being outlined and vice versa.
    const auto drawPass =
      [&](const char* const technique, std::uint8_t MeshLOD::* const gate) {
        device->SelectTechnique(technique);
        for (const MeshBatchBucket& bucket : meshes) {
          // See RecycleBatchBuckets: an empty bucket's LOD may be released.
          if (bucket.second.empty()) {
            continue;
          }
          MeshLOD* const lod = MeshBatchEntryLod(bucket);
          if (!(lod->*gate)) {
            continue;
          }

          tv.albedoTexture.GetTexture(lod->mat.mAlbedoSheet);

          boost::shared_ptr<MeshBatch> batchHandle;
          if (MeshBatchEntryIsSkinned(bucket)) {
            lod->GetSkinnedBatch(batchHandle);
          } else {
            lod->GetStaticBatch(batchHandle);
          }
          if (batchHandle) {
            batchHandle->Render(bucket.second, false);
          }
        }
      };

    drawPass("Occlude", &MeshLOD::occlude);
    drawPass("Silhouette", &MeshLOD::silhouette);
  }

  /**
   * Address: 0x007E03B0 (FUN_007E03B0, ?RenderDepth@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@AAV?$map@...@Z)
   *
   * What it does:
   * Draws one mesh batch tree into the active depth surface. Structurally this
   * is the same RB-tree walk as Render but: the pass head binds only the
   * time / lodBasis / view / proj mesh shader-vars (no ConfigureShader,
   * textures or lighting); the per-node gate is the depth stage bit
   * (`mShaderIndex & 1`); the material technique is a lazily-cached
   * `depthTechnique` string annotation; only the albedo sampler is bound; and
   * the batch is always drawn un-mirrored.
   *
   * The depth-technique string is `MeshMaterial::mDepthTechnique` (a fa::string at
   * mMat+0x70). The binary's reads at mMat+0x74 / +0x84 / +0x88 (`_Bx`,
   * `_Mysize`, `_Myres`) are that same string's internal members at
   * string+0x04 / +0x14 / +0x18 — normal fa::string access, not a separate
   * field. Cross-checked from FUN_007E03B0.asm via mAlbedoSheet at esi+0x2C =
   * mMat+0x20, mShaderIndex at esi+0x5C = mMat+0x50, mDepthTechniqueResolved at esi+0x99
   * = mMat+0x8D.
   */
  void MeshRenderer::RenderDepth(const GeomCamera3& camera, MeshBatchBucketTree& meshMap)
  {
    // Nothing to draw when the batch tree is empty (binary: `if (*(arg4+8))`).
    if (meshMap.empty()) {
      return;
    }

    // Bind only the depth-pass shader-constant lane: frame time, LOD basis, and
    // the view/projection matrices. RenderDepth does NOT call ConfigureShader
    // and never mirrors (no water-plane reflection of the view matrix).
    // (Transcribed from FUN_007E03B0 @0x007E03D0..0x007E04B0.)
    MeshShaderVarSet& sv = GetMeshShaderVars();

    CD3DDevice* const device = D3D_GetDevice();

    // Frame time: fold the frame counter into a float (with the unsigned int
    // fixup the binary applies to negative counters), add the accumulated delta
    // frame, then wrap into the shader time window (fmod by 36000). Identical to
    // ConfigureShader's shaderTime lane.
    const auto frameCounter = static_cast<std::int32_t>(instanceListSize);
    double frameSeconds = static_cast<double>(frameCounter);
    if (frameCounter < 0) {
      frameSeconds += 4294967296.0; // 2^32 unsigned fixup
    }
    frameSeconds += deltaFrame;
    // `fmod(float, float)` (0x00422920 -> _CIfmod): the time is stored to a
    // float argument before the call.
    const float shaderTime = static_cast<float>(fa::fmod(static_cast<float>(frameSeconds), 36000.0f)); // flt_F57F08
    if (sv.time.Exists()) {
      sv.time.SetFloat(shaderTime);
    }

    // LOD basis = viewport matrix row 1 (camera.viewport.r[1], 4 floats; the
    // binary's arg0+660).
    if (sv.lodBasis.Exists()) {
      SetShaderVarMem(sv.lodBasis, 4, &camera.viewport.r[1].x);
    }
    // View / projection matrices bound directly (un-mirrored). arg0+92 / arg0+28.
    if (sv.viewMatrix.Exists()) {
      sv.viewMatrix.SetMatrix4x4(&camera.view);
    }
    if (sv.projMatrix.Exists()) {
      sv.projMatrix.SetMatrix4x4(&camera.projection);
    }

    // Select the "mesh" effect as the device's current effect.
    CD3DEffect* const meshEffect = device->GetResources()->FindEffect("mesh");
    device->SetCurEffect(meshEffect);

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // Walk the batch-bucket map in key order (binary: begin = head->left,
    // end = header, stepped by `_Inc` at 0x007E42F0).
    for (const MeshBatchBucket& bucket : meshMap) {
      // A recycled bucket can sit empty over a released mesh; see
      // RecycleBatchBuckets. Skip it before touching its LOD.
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = MeshBatchEntryLod(bucket);
      MeshMaterial& material = lod->mat;

      // Resolve + cache the material render stage on first use.
      const std::int32_t renderStage = ResolveMaterialRenderStage(meshEffect, material);

      // Depth gate: only draw materials whose render stage participates in the
      // depth pass (binary: `if (mMat.mVal & 1)`).
      if ((renderStage & 1) == 0) {
        continue;
      }

      // Lazily resolve + cache this material's depth technique the first time
      // the depth pass reaches it (binary: `if (!mMat.byte8D) { mMat.byte8D=1;
      // mMat.mStr3 = GetStringAnnotation(mAnnot,"depthTechnique",""); }`).
      if (!material.mDepthTechniqueResolved) {
        material.mDepthTechniqueResolved = true;
        const fa::string depthTechnique =
          meshEffect->GetStringAnnotation(material.mShaderAnnotation, fa::string("depthTechnique"), fa::string(""));
        material.mDepthTechnique.assign_owned(depthTechnique.view());
      }

      // Only draw when a depth technique is defined for the material
      // (binary: `if (mMat.mStr3._Mysize)`).
      if (material.mDepthTechnique.size() != 0) {
        device->SelectTechnique(material.mDepthTechnique.c_str());

        // Depth pass binds only the albedo sampler.
        tv.albedoTexture.GetTexture(material.mAlbedoSheet);

        // Draw the bucket's instances through the LOD's lazily-built hardware
        // mesh batch (skinned for static-pose buckets, static otherwise). The
        // shared_ptr handle keeps the batch retained for the draw call; the
        // depth pass always draws un-mirrored (binary passes 0).
        boost::shared_ptr<MeshBatch> batchHandle;
        if (MeshBatchEntryIsSkinned(bucket)) {
          lod->GetSkinnedBatch(batchHandle);
        } else {
          lod->GetStaticBatch(batchHandle);
        }
        if (batchHandle) {
          batchHandle->Render(bucket.second, false);
        }
      }
    }
  }

  /**
   * Address: 0x007E0C30 (FUN_007E0C30, Moho::MeshRenderer::Render)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::Render(
   *   std::map<MeshBatchKey, vector<MeshInstance*>>* map, MeshRenderer* this,
   *   int meshFlags, Moho::GeomCamera3* camera, Moho::Shadow* shadow);
   *
   * What it does:
   * Draws one mesh batch tree with optional shadow state. Selects the "mesh"
   * effect, binds the whole per-pass shader-constant lane (ConfigureShader),
   * then walks the batch-bucket RB-tree in key order. For each bucket it
   * resolves the material render stage, applies the pass stage filter, selects
   * the material technique, lazily resolves the environment texture sheet,
   * binds the six per-material texture samplers, then draws the bucket's
   * instance vector through the LOD's lazily-built skinned/static hardware mesh
   * batch. `mirrored` (the batch draw flag) is `meshFlags == 2`.
   *
   * The recovered entry is invoked by name from the main render lane at
   * `src/moho/app/WxRuntimeTypes.cpp`
   * (`renderer->Render(meshFlags, *cam, shadowRenderer, instance->meshes)`).
   */
  void MeshRenderer::Render(
    const std::int32_t meshFlags,
    const GeomCamera3& camera,
    Shadow* const shadow,
    MeshBatchBucketTree& meshMap
  )
  {
    if (meshMap.empty()) {
      return;
    }

    // Active render-time terrain resource (nullptr when no map/terrain). Read at
    // the head of the pass exactly like the binary's `sWldMap ? mTerrainRes : 0`.
    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();

    // Select the mesh effect as the device's current effect, then bind the whole
    // mesh shader-constant lane for this pass. `mirrored` is `meshFlags == 2`.
    // (Transcribed from FUN_007E0C30 @0x007E0C64..0x007E0CD7.)
    CD3DDevice* const device = D3D_GetDevice();
    CD3DEffect* const meshEffect = device->GetResources()->FindEffect("mesh");
    device->SetCurEffect(meshEffect);
    const bool mirrored = (meshFlags == 2);
    ConfigureShader(camera, shadow, mirrored);

    // Per-pass stage filter selectors (binary: v44 = a3 & 0x30, v42 = a3 & 0xC).
    const std::int32_t stageMaskHigh = meshFlags & 0x30;
    const std::int32_t stageMaskLow = meshFlags & 0x0C;

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();

    // Walk the batch-bucket map in key order (binary: begin = head->left,
    // end = header, stepped by `_Inc` at 0x007E42F0).
    for (const MeshBatchBucket& bucket : meshMap) {
      // A recycled bucket can sit empty over a released mesh; see
      // RecycleBatchBuckets. Skip it before touching its LOD.
      if (bucket.second.empty()) {
        continue;
      }
      MeshLOD* const lod = MeshBatchEntryLod(bucket);
      MeshMaterial& material = lod->mat;

      // Resolve + cache the material render stage on first use.
      const std::int32_t renderStage = ResolveMaterialRenderStage(meshEffect, material);

      // Pass stage filter (binary: `!v13 || v13==2 ||
      // ((val & (a3&0x30)) && (val & (a3&0xC)))`).
      const bool passesStageFilter =
        meshFlags == 0 || meshFlags == 2 ||
        (((renderStage & stageMaskHigh) != 0) && ((renderStage & stageMaskLow) != 0));
      if (!passesStageFilter) {
        continue;
      }

      // Select this material's technique for the pass (FUN_007E0C30
      // @0x007E0DAD..0x007E0DB7: virtual slot 21 `SelectTechnique` with the
      // material's shader-annotation technique name, before the environment
      // lane and every draw of the bucket).
      device->SelectTechnique(material.mShaderAnnotation.c_str());

      // Lazily resolve the environment texture sheet the first time this
      // material is drawn. When a terrain resource is present the sheet is the
      // terrain's per-environment lookup (keyed by the material's "environment"
      // string annotation); otherwise it is the renderer's shared mesh
      // environment texture. Both are ID3DTextureSheet-rooted, which is why the
      // lane is held at that base -- no cast is needed in either direction, and
      // the stored word is the one the binary stores.
      if (!material.mEnvironmentSheet) {
        if (terrainRes != nullptr) {
          const fa::string environmentKey =
            meshEffect->GetStringAnnotation(material.mShaderAnnotation, fa::string("environment"), fa::string("<default>"));
          material.mEnvironmentSheet = terrainRes->GetEnvLookup(environmentKey);
        } else {
          material.mEnvironmentSheet = meshEnvironmentTex;
        }
      }

      // Bind the six per-material texture samplers, in binary bind order.
      tv.environmentTexture.GetTexture(material.mEnvironmentSheet);
      tv.albedoTexture.GetTexture(material.mAlbedoSheet);
      tv.specularTexture.GetTexture(material.mSpecularSheet);
      tv.lookupTexture.GetTexture(material.mLookupSheet);
      tv.secondaryTexture.GetTexture(material.mSecondarySheet);
      tv.normalsTexture.GetTexture(material.mNormalsSheet);

      // Draw the bucket's instances through the LOD's lazily-built hardware mesh
      // batch (skinned for static-pose buckets, static otherwise). The
      // shared_ptr handle keeps the batch retained for the draw call.
      boost::shared_ptr<MeshBatch> batchHandle;
      if (MeshBatchEntryIsSkinned(bucket)) {
        lod->GetSkinnedBatch(batchHandle);
      } else {
        lod->GetStaticBatch(batchHandle);
      }
      if (batchHandle) {
        batchHandle->Render(bucket.second, mirrored);
      }
    }
  }

  /**
   * Address: 0x007DFDB0 (FUN_007DFDB0, Moho::MeshRenderer::RenderSkeletons)
   *
   * What it does:
   * Draws skeleton-debug overlays for visible mesh instances.
   */
  void MeshRenderer::RenderSkeletons(
    CD3DPrimBatcher* const debugBatcher,
    CDebugCanvas* const debugCanvas,
    const GeomCamera3& camera,
    const bool showBoneNames
  )
  {
    (void)debugBatcher;
    (void)debugCanvas;
    (void)camera;
    (void)showBoneNames;
  }

  /**
   * Address: 0x007E2290 (FUN_007E2290, Moho::MeshRenderer::RenderSkeleton)
   *
   * What it does:
   * Draws one mesh instance skeleton-debug overlay. The recovered entry
   * calls `MeshInstance::ComputeDebugPose` at the head of the function
   * (address 0x007DE7A0) to refresh the interpolated pose used for the
   * bone-debug pass; remaining CD3D-prim-batcher draw-call mechanics are
   * still under recovery, so this TU keeps the typed pose-refresh step
   * and drops the draw-call emission until its typed dependencies are
   * wired.
   */
  void MeshRenderer::RenderSkeleton(
    CD3DPrimBatcher* const debugBatcher,
    CDebugCanvas* const debugCanvas,
    MeshInstance* const meshInstance,
    const bool showBoneNames
  )
  {
    (void)debugBatcher;
    (void)debugCanvas;
    (void)showBoneNames;

    if (meshInstance == nullptr) {
      return;
    }

    const boost::shared_ptr<CAniPose> activePose = meshInstance->ComputeDebugPose();
    if (!activePose) {
      return;
    }

    // Draw-call emission (CD3DPrimBatcher bind + bone-line quad batch)
    // stays blocked on typed CD3DPrimBatcher surface recovery; the pose
    // refresh above produces the same observable side effect as the
    // binary's skeleton-overlay entry before it enters draw-call code.
  }

  /**
   * Address: 0x007E0380 (FUN_007E0380, ?RenderCartographic@MeshRenderer@Moho@@QAEXMMMABVGeomCamera3@2@@Z)
   *
   * What it does:
   * Forwards cartographic rendering to the batch-map overload using this
   * renderer's persistent `meshes` tree.
   */
  void MeshRenderer::RenderCartographic(
    const float surfaceElevation,
    const float minimumElevation,
    const float maximumElevation,
    const GeomCamera3& camera
  )
  {
    RenderCartographic(surfaceElevation, minimumElevation, maximumElevation, camera, meshes);
  }

  /**
   * Address: 0x007E0820 (FUN_007E0820, ?RenderDepth@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@@Z)
   *
   * What it does:
   * Forwards depth rendering to the batch-map overload using this renderer's
   * persistent `meshes` tree.
   */
  void MeshRenderer::RenderDepth(const GeomCamera3& camera)
  {
    RenderDepth(camera, meshes);
  }

  /**
   * Address: 0x007E11A0 (FUN_007E11A0, ?Render@MeshRenderer@Moho@@QAEXIABVGeomCamera3@2@PAVShadow@2@@Z)
   *
   * What it does:
   * Forwards one standard render call to the batch-map overload using this
   * renderer's persistent `meshes` tree.
   */
  void MeshRenderer::Render(const std::int32_t meshFlags, const GeomCamera3& camera, Shadow* const shadow)
  {
    Render(meshFlags, camera, shadow, meshes);
  }

  /**
   * Address: 0x007E11C0 (FUN_007E11C0,
   * ?RenderThumbnail@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@PAVMeshInstance@2@PAVID3DRenderTarget@2@PAVID3DDepthStencil@2@@Z)
   *
   * What it does:
   * Renders one mesh instance with one thumbnail camera into the caller-provided
   * color/depth targets. Binds the caller's render/depth targets with a full
   * clear, selects the mesh effect + top-LOD technique, binds the three material
   * texture sheets (albedo/normals/specular), then draws the single instance
   * through the LOD's static hardware batch (un-mirrored).
   */
  void MeshRenderer::RenderThumbnail(
    const GeomCamera3& camera,
    MeshInstance* const meshInstance,
    ID3DRenderTarget* const renderTarget,
    ID3DDepthStencil* const depthStencil
  )
  {
    if (!meshInstance || !renderTarget || !depthStencil) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();

    // Retain the instance's mesh for the whole pass and select its top LOD. The
    // binary reads `*mesh->lods._Myfirst` (the first LOD) after taking a live
    // shared_ptr copy via GetMesh(); the handle keeps the mesh alive across the
    // draw. (FUN_007E11C0 @0x007E11EA..0x007E11FE.)
    const boost::shared_ptr<Mesh> mesh = meshInstance->GetMesh();
    MeshLOD* const lod = mesh->lods.front();

    // Bind the caller's color + depth targets with a full clear (color
    // 0xFF000000, z=1.0, stencil=0). The decompiler mislabels the two pointer
    // args, but the frame slots resolve to renderTarget (arg_C, first SetRender-
    // Target1 param) then depthStencil (arg_10, second) — matching the caller
    // MeshThumbnailRenderer::RenderThumbnail which passes (mColorTarget,
    // mDepthStencil). (FUN_007E11C0 @0x007E11FF..0x007E1220.)
    device->SetRenderTarget1(renderTarget, depthStencil, true, 0xFF000000, 1.0f, 0);

    // Select the mesh effect file, then bind the mesh shader-constant lane for
    // this thumbnail pass (no shadow, not mirrored).
    device->SelectFxFile("mesh");
    ConfigureShader(camera, nullptr, false);

    // Select the top LOD material's technique, then bind its three texture
    // sheets in binary bind order: albedo, normals, specular. These are the same
    // shared shader-var handles the batch-map render path binds
    // (GetMeshTextureShaderVars()). (FUN_007E11C0 @0x007E124E..0x007E127D.)
    MeshMaterial& material = lod->mat;
    device->SelectTechnique(material.mShaderAnnotation.c_str());

    MeshTextureShaderVarSet& tv = GetMeshTextureShaderVars();
    tv.albedoTexture.GetTexture(material.mAlbedoSheet);
    tv.normalsTexture.GetTexture(material.mNormalsSheet);
    tv.specularTexture.GetTexture(material.mSpecularSheet);

    // Draw the single instance through the LOD's lazily-built static hardware
    // batch (thumbnails are never skinned, so GetStaticBatch only). The batch is
    // fed a one-element instance vector and drawn un-mirrored; the shared_ptr
    // handle retains the batch for the draw and the vector releases after.
    // (FUN_007E11C0 @0x007E1282..0x007E12DB.)
    boost::shared_ptr<MeshBatch> batchHandle;
    lod->GetStaticBatch(batchHandle);
    if (batchHandle) {
      fa::vector<MeshInstance*> singleInstance;
      singleInstance.push_back(meshInstance);
      batchHandle->Render(singleInstance, false);
    }
  }

  /**
   * Address: 0x007DFA00 (FUN_007DFA00, ?Batch@MeshRenderer@Moho@@QAEXHMABVGeomCamera3@2@ABVVector4f@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::MeshRenderer::Batch(
   *   MeshRenderer* this, int gameTick, float deltaFrame,
   *   const GeomCamera3& camera, const Vector4f& fadePlane);
   *
   * What it does:
   * Rebuilds this renderer's per-key render-batch map (`meshes`) for one frame.
   * Clears the bucket tree, snapshots the frame tick/delta, collects every mesh
   * instance intersecting the camera frustum from the mesh spatial DB, then for
   * each visible instance: selects a LOD by view-depth distance, applies the
   * dissolve fade, frustum-culls the instance sphere, and appends it into the
   * bucket keyed by `(isStaticPose, blueprint sort order)`.
   */
  void MeshRenderer::Batch(
    const std::int32_t gameTick,
    const float deltaFrameArg,
    const GeomCamera3& camera,
    const Vector4f& fadePlane
  )
  {
    // Clear last frame's buckets and reset the renderer frame lanes.
    RecycleBatchBuckets(meshes);
    // Binary stores `gameTick` (param0) into +0x94 and clears the batched-count
    // lane at +0x9C; both are reused by this pass as frame-scoped scratch.
    instanceListSize = gameTick;
    instanceListStateFlags = 0u;
    deltaFrame = deltaFrameArg;

    // Camera forward direction = negated third row of the inverse-view matrix.
    // Used as the spatial-DB support/selector axis for the collect volume.
    const Wm3::Vec3f cameraForward(
      -camera.inverseView.r[2].x,
      -camera.inverseView.r[2].y,
      -camera.inverseView.r[2].z
    );

    // Collect every renderable instance whose bounds intersect the camera
    // frustum solid. SpatialDB<MeshInstance> yields its own payload type, so
    // these slots no longer have to be laundered through UserEntity*.
    gpg::fastvector<MeshInstance*> collected;
    meshSpatialDb.CollectAllInVolume(
      collected, &const_cast<GeomCamera3&>(camera).solid2, cameraForward, fadePlane
    );

    // Engine change (ren_MeshParallelInterp): the instances the walk below would place, placed first on
    // the worker pool. The gates are the walk's own, so the same instances are updated either way.
    if (ren_MeshParallelInterp && CUserWorkerPool::ConfiguredWorkerCount() != 0U) {
      static std::vector<MeshInstance*> sStale;
      sStale.clear();
      for (MeshInstance* const instance : collected) {
        const bool isStatic = instance->isStaticPose != 0u;
        if ((!ren_MeshSkinned && isStatic) || (!ren_MeshStatic && !isStatic) || instance->isHidden != 0u) {
          continue;
        }
        if (instance->visibilityCamera != nullptr && instance->visibilityCamera != &camera) {
          continue;
        }
        if (instance->InterpolatedFieldsStale()) {
          sStale.push_back(instance);
        }
      }
      constexpr std::size_t kParallelInterpMin = 64U;
      constexpr std::size_t kParallelInterpGrain = 32U;
      if (sStale.size() >= kParallelInterpMin) {
        CUserWorkerPool::Get().ParallelFor(sStale.size(), kParallelInterpGrain, [&](const std::size_t begin, const std::size_t end) {
          for (std::size_t index = begin; index < end; ++index) {
            sStale[index]->UpdateInterpolatedFields();
          }
        });
      }
    }


    for (MeshInstance* const instance : collected) {

      // Skinned/static inclusion gates plus the hidden flag.
      const bool isStatic = instance->isStaticPose != 0u;
      if ((!ren_MeshSkinned && isStatic) || (!ren_MeshStatic && !isStatic) || instance->isHidden != 0u) {
        continue;
      }

      // Clutter belongs to the camera that generated its region.
      if (instance->visibilityCamera != nullptr && instance->visibilityCamera != &camera) {
        continue;
      }

      instance->UpdateInterpolatedFields();

      // View-depth distance: the interpolated world position dotted with
      // `fadePlane` (a,b,c,d). 0x007DFB78 loads the plane pointer from
      // [esp+1FCh] right after FUN_007DEC80 (`ret 4`, so esp is restored):
      // that is the argument after `camera` ([esp+1F8h]), i.e. `fadePlane`,
      // not the camera. 0x007DFB7F..0x007DFBB9 then computes
      // (pos.z*c + pos.y*b) + a*pos.x + d in that order. Reading the plane out
      // of the camera transform's orientation quaternion instead gave a depth
      // that only looked right for an untilted camera, so tilting or turning
      // the camera pushed units and props to low LODs or past their cutoff.
      const Wm3::Vec3f& worldPos = instance->interpolatedPosition;
      const float distance =
        worldPos.z * fadePlane.z
        + worldPos.y * fadePlane.y
        + fadePlane.x * worldPos.x
        + fadePlane.w;

      // Engine change: the instance holds its mesh, so this walk needs no counted copy per instance.
      Mesh* const mesh = instance->mesh.get();
      const MeshLOD* const lod = mesh->ComputeLOD(distance);

      if (lod == nullptr || distance > (mesh->GetMaxCutoff() + ren_MeshDissolve)) {
        continue;
      }

      // Dissolve fade for LODs that fade out past their cutoff.
      if (lod->useDissolve != 0u && lod->cutoff > 0.0f && distance > lod->cutoff) {
        instance->SetDissolve(1.0f - ((distance - lod->cutoff) / ren_MeshDissolve));
      } else {
        instance->dissolve = 1.0f;
      }

      // Fully dissolved instances are skipped entirely.
      if (instance->dissolve < ren_MeshDissolveCutoff) {
        continue;
      }

      instance->UpdateInterpolatedFields();

      // Second frustum cull against the camera solid using the refreshed
      // bounding sphere. The binary reads this camera pointer from the arg0
      // stack slot, which the demangled `int` parameter cannot address; the
      // only live view camera in this pass is `camera`, so both the collect
      // volume and this cull share it.
      if (!camera.solid2.Intersects(instance->sphere)) {
        continue;
      }

      // Engine addition (ren_ShadowCasterCull): in the shadow pass, a mesh whose shadow can't reach the view.
      if (gShadowCasterRegion.active && !gShadowCasterRegion.MayShadow(instance->sphere)) {
        continue;
      }

      // Append into the bucket keyed by (isStaticPose, selected LOD, sort
      // order). The LOD lane carries the `ComputeLOD` result: the binary
      // stores it at 0x007DFBED and the key load at 0x007DFCDC reads that same
      // slot back (see `MeshBatchKey::mLod` for why IDA splits the one slot
      // into `var_1D0`/`var_1D4`). Keying on it is what keeps one bucket to one
      // LOD, so each bucket draws with its own material and hardware batch.
      MeshBatchKey key;
      key.mIsStaticPose = instance->isStaticPose;
      key.mLod = const_cast<MeshLOD*>(lod);
      key.mSortKey = mesh->GetSortOrder();

      MeshBatchInstanceVector* const bucket = MeshBatchBucketTreeFindOrCreateInstances(key, meshes);
      if (bucket != nullptr) {
        // `std::vector<MeshInstance*>::push_back` (0x007D9FC0, growing through
        // `_Insert_n` at 0x007DA270) - the container's own append.
        bucket->push_back(instance);
        ++instanceListStateFlags;
      }
    }

    // FAF: the bones of this map's skinned instances, written once for every
    // pass that is about to draw it.
    PrepareBonePalettes();
  }

  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Writes the bones of every posed instance of every skinned bucket in
   * `meshes` into the bone palette texture and uploads it, when the mesh
   * effect reads its skinning palette from there. Each Batch call starts the
   * texture over: the draws of the previous map have all been issued by then.
   */
  void MeshRenderer::SaveBatch(std::vector<SavedBucket>& out) const
  {
    std::size_t used = 0U;
    for (const MeshBatchBucket& bucket : meshes) {
      if (bucket.second.empty()) {
        continue;
      }
      if (used == out.size()) {
        out.emplace_back();
      }
      SavedBucket& saved = out[used++];
      saved.key = bucket.first;
      saved.instances.assign(bucket.second.begin(), bucket.second.end());
    }
    out.resize(used);
  }

  void MeshRenderer::BatchFromSaved(
    const std::int32_t gameTick, const float deltaFrameArg, const GeomCamera3& camera, const std::vector<SavedBucket>& saved
  )
  {
    RecycleBatchBuckets(meshes);
    instanceListSize = gameTick;
    instanceListStateFlags = 0u;
    deltaFrame = deltaFrameArg;
    for (const SavedBucket& source : saved) {
      MeshBatchInstanceVector* bucket = nullptr;
      for (MeshInstance* const instance : source.instances) {
        if (instance->visibilityCamera != nullptr && instance->visibilityCamera != &camera) {
          continue;
        }
        if (!camera.solid2.Intersects(instance->sphere)) {
          continue;
        }
        if (bucket == nullptr) {
          MeshBatchKey key = source.key;
          bucket = MeshBatchBucketTreeFindOrCreateInstances(key, meshes);
          if (bucket == nullptr) {
            break;
          }
        }
        bucket->push_back(instance);
        ++instanceListStateFlags;
      }
    }
    PrepareBonePalettes();
  }

  void MeshRenderer::PrepareBonePalettes()
  {
    if (!HardwareMeshBatch::UsesBoneTexture()) {
      return;
    }

    HardwareMeshBatch::BeginBonePalettes();
    for (const MeshBatchBucket& bucket : meshes) {
      // See RecycleBatchBuckets: an empty bucket's LOD may be released.
      if (bucket.second.empty() || !MeshBatchEntryIsSkinned(bucket)) {
        continue;
      }

      // Every LOD batch is a HardwareMeshBatch (BuildHardwareMeshBatchForLod).
      boost::shared_ptr<MeshBatch> batchHandle;
      MeshBatchEntryLod(bucket)->GetSkinnedBatch(batchHandle);
      if (batchHandle) {
        static_cast<HardwareMeshBatch*>(batchHandle.get())->PrepareBonePalettes(bucket.second);
      }
    }
    HardwareMeshBatch::UploadBonePalettes();
  }
namespace
{
    /**
     * The distance fog parameters of a mesh effect compiled with
     * FAF_BONE_TEXTURE (see MeshRenderer::SetDistanceFog).
     */
    struct DistanceFogShaderVars
    {
      ShaderVar params{};
      ShaderVar color{};

      DistanceFogShaderVars()
      {
        RegisterShaderVar("fogParams", &params, "mesh");
        RegisterShaderVar("fogColor", &color, "mesh");
      }
    };

    [[nodiscard]] DistanceFogShaderVars& GetDistanceFogShaderVars()
    {
      // Never destroyed: the effect unlinks its shader-vars when it goes,
      // which may happen after static destruction would have run.
      static DistanceFogShaderVars* const vars = new DistanceFogShaderVars();
      return *vars;
    }
}


  /**
   * FAF addition, not in the shipped binary.
   *
   * What it does:
   * Sets the mesh effect's fog parameters to what the fixed-function linear
   * table fog computes per pixel from the same values: the fraction of the
   * pixel's own colour kept is saturate((end - d) / (end - start)), stored
   * as `end / (end - start)` and `1 / (end - start)` so the shader does one
   * multiply-add. d is the eye distance when the projection is w-based
   * (Direct3D's "w-friendly" check, a non-zero _34) and the depth otherwise.
   * With fog off the parameters keep every pixel's colour.
   */
  void MeshRenderer::SetDistanceFog(
    const bool enabled,
    const gpg::gal::Matrix* const projection,
    const float fogStart,
    const float fogEnd,
    const std::uint32_t fogColor
  )
  {
    DistanceFogShaderVars& vars = GetDistanceFogShaderVars();
    if (!vars.params.Exists()) {
      return;
    }

    float params[4] = {1.0f, 0.0f, 1.0f, 0.0f};
    if (enabled) {
      // A start at or past the end would divide by zero; this turns it into
      // the step the fog would converge on.
      constexpr float kMinimumFogRange = 1.0e-4f;
      const float range = std::max(fogEnd - fogStart, kMinimumFogRange);
      params[0] = fogEnd / range;
      params[1] = 1.0f / range;
      params[2] = (projection == nullptr || projection->r[2].w != 0.0f) ? 1.0f : 0.0f;
    }
    SetShaderVarMem(vars.params, 4u, params);

    constexpr float kChannelScale = 1.0f / 255.0f;
    const float color[3] = {
      static_cast<float>((fogColor >> 16u) & 0xFFu) * kChannelScale,
      static_cast<float>((fogColor >> 8u) & 0xFFu) * kChannelScale,
      static_cast<float>(fogColor & 0xFFu) * kChannelScale,
    };
    SetShaderVarMem(vars.color, 3u, color);
  }
}

