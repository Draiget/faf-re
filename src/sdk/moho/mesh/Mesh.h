#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <vector>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/mesh/MeshBatchKey.h"
#include "moho/mesh/MeshEnvironment.h"
#include "moho/containers/TDatList.h"
#include "moho/resource/CResourceWatcher.h"
#include "moho/render/camera/VTransform.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Box3.h"
#include "Wm3Sphere3.h"
#include "Wm3Vector2.h"

namespace moho
{
  class CAniPose;
  class CD3DPrimBatcher;
  class CDebugCanvas;
  class MeshBatch;
  class Mesh;
  class MeshMaterial;
  class CD3DDynamicTextureSheet;
  class ID3DRenderTarget;
  class ID3DDepthStencil;
  class Shadow;
  struct RMeshBlueprint;
  struct RMeshBlueprintLOD;
  class RScmResource;
  struct GeomCamera3;

  struct SpatialDB_MeshInstance
  {
    void* db;           // +0x00
    std::int32_t entry; // +0x04

    /**
     * Address: 0x00501A80 (FUN_00501A80, sub_501A80)
     *
     * What it does:
     * Registers one mesh-instance owner in the spatial-db storage and seeds entry state.
     */
    void Register(void* spatialDbStorage, void* owner, std::int32_t routingMask);

    /**
     * Address: 0x00501B00 (FUN_00501B00, sub_501B00)
     *
     * What it does:
     * Updates dissolve-cutoff payload in the current spatial-db entry.
     */
    void UpdateDissolveCutoff(float cutoff);

    /**
     * Address: 0x00501C10 (FUN_00501C10, sub_501C10)
     *
     * What it does:
     * Updates cached entry AABB payload lanes for this mesh-instance in spatial DB.
     */
    void UpdateBounds(const Wm3::AxisAlignedBox3f& bounds);

    /**
     * What it does:
     * Clears local registration state; detached-tree internals are reconstructed incrementally.
     */
    void ClearRegistration() noexcept;

    /**
     * Address: 0x00501BC0 (FUN_00501BC0, ??1SpatialDB_MeshInstance@Moho@@QAE@XZ)
     *
     * What it does:
     * Clears mesh-instance spatial-db registration state.
     */
    ~SpatialDB_MeshInstance();
  };

  class MeshMaterial
  {
  public:
    /**
     * Address: 0x007DBFC0 (FUN_007DBFC0, ??1MeshMaterial@Moho@@UAE@XZ)
     * Deleting thunk: 0x007DBFA0 (FUN_007DBFA0)
     */
    virtual ~MeshMaterial();

    /**
     * Address: 0x007DBEE0 (FUN_007DBEE0, ??0MeshMaterial@Moho@@QAE@XZ)
     */
    MeshMaterial();

    MeshMaterial(const MeshMaterial&) = default;

    /**
     * Address: 0x007DCBF0 (FUN_007DCBF0, ??4MeshMaterial@Moho@@QAEAAV01@ABV01@@Z)
     *
     * What it does:
     * Copies annotation/texture-sheet handles and runtime tags from one material.
     */
    MeshMaterial& operator=(const MeshMaterial& rhs);

    /**
     * Address: 0x007DC760 (FUN_007DC760,
     * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABVRMeshBlueprintLOD@2@PAVCResourceWatcher@2@@Z)
     *
     * What it does:
     * Builds one material from one mesh LOD blueprint descriptor.
     */
    static boost::shared_ptr<MeshMaterial> Create(const RMeshBlueprintLOD& blueprintLod, CResourceWatcher* resourceWatcher);

    /**
     * Address: 0x007DC1B0 (FUN_007DC1B0,
     * ?Create@MeshMaterial@Moho@@SA?AV?$shared_ptr@VMeshMaterial@Moho@@@boost@@ABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@00000PAVCResourceWatcher@2@@Z)
     *
     * What it does:
     * Creates one mesh material and resolves per-texture sheet handles from paths.
     */
    static boost::shared_ptr<MeshMaterial> Create(
      const msvc8::string& shaderName,
      const msvc8::string& albedoName,
      const msvc8::string& normalsName,
      const msvc8::string& specularName,
      const msvc8::string& lookupName,
      const msvc8::string& secondaryName,
      CResourceWatcher* resourceWatcher
    );

  public:
    msvc8::string mShaderAnnotation;                              // +0x04
    boost::shared_ptr<CD3DDynamicTextureSheet> mAlbedoSheet;      // +0x20
    boost::shared_ptr<CD3DDynamicTextureSheet> mNormalsSheet;     // +0x28
    boost::shared_ptr<CD3DDynamicTextureSheet> mSpecularSheet;    // +0x30
    boost::shared_ptr<CD3DDynamicTextureSheet> mLookupSheet;      // +0x38
    boost::shared_ptr<CD3DDynamicTextureSheet> mSecondarySheet;   // +0x40
    boost::shared_ptr<CD3DDynamicTextureSheet> mEnvironmentSheet; // +0x48
    std::int32_t mShaderIndex;                                    // +0x50
    msvc8::string mAuxTag0;                                       // +0x54
    msvc8::string mAuxTag1;                                       // +0x70
    std::uint8_t mRuntimeFlag0;                                   // +0x8C
    std::uint8_t mRuntimeFlag1;                                   // +0x8D
    std::uint8_t mPad8E_8F[0x02]{};
  };

  class MeshLOD
  {
  public:
    /**
     * Address: 0x007DC8C0 (FUN_007DC8C0,
     * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@ABVRMeshBlueprintLOD@1@V?$shared_ptr@VMeshMaterial@Moho@@@3@PAVCResourceWatcher@1@@Z)
     *
     * What it does:
     * Initializes one runtime LOD from blueprint/material/resource fallback state.
     */
    MeshLOD(
      const RMeshBlueprintLOD& blueprintLod,
      boost::shared_ptr<RScmResource> previousResource,
      boost::shared_ptr<MeshMaterial> material,
      CResourceWatcher* ownerWatcher
    );

    /**
     * Address: 0x007DCA40 (FUN_007DCA40,
     * ??0MeshLOD@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
     *
     * What it does:
     * Initializes one runtime LOD from pre-resolved resource/material shared
     * pointers without blueprint-load side effects.
     */
    MeshLOD(boost::shared_ptr<RScmResource> resource, boost::shared_ptr<MeshMaterial> material);

    /**
     * Address: 0x007DCD60 (FUN_007DCD60, ??1MeshLOD@Moho@@UAE@XZ)
     */
    virtual ~MeshLOD();

    /**
     * Address: 0x007DCED0 (FUN_007DCED0)
     *
     * What it does:
     * Reloads model/material resources from one blueprint LOD entry.
     */
    void Load(
      const RMeshBlueprintLOD& blueprintLod,
      boost::shared_ptr<RScmResource> previousResource,
      boost::shared_ptr<MeshMaterial> material,
      CResourceWatcher* ownerWatcher
    );

    /**
     * Address: 0x007DD4D0 (FUN_007DD4D0)
     *
     * What it does:
     * Releases loaded resource/material state for this LOD.
     */
    void Clear();

    /**
     * Address: 0x007DD190 (FUN_007DD190)
     *
     * What it does:
     * Clears cached batch handles for this LOD.
     */
    void ResetBatches();

  public:
    std::uint8_t useDissolve; // +0x04
    std::uint8_t pad_05_07[0x03]{};
    float cutoff;                                     // +0x08
    MeshMaterial mat;                                 // +0x0C
    boost::shared_ptr<RScmResource> previousResource; // +0x9C
    boost::shared_ptr<RScmResource> res;              // +0xA4
    std::uint8_t scrolling;                           // +0xAC
    std::uint8_t occlude;                             // +0xAD
    std::uint8_t silhouette;                          // +0xAE
    std::uint8_t pad_AF{};
    boost::shared_ptr<RMeshBlueprintLOD> lodBlueprintCopy; // +0xB0
    boost::shared_ptr<MeshBatch> staticBatch;              // +0xB8
    boost::shared_ptr<MeshBatch> dynamicBatch;             // +0xC0
  };

  class Mesh : public CResourceWatcher
  {
  public:
    /**
     * Address: 0x007DD680 (FUN_007DD680,
     * ??0Mesh@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
     */
    Mesh(const RMeshBlueprint* blueprint, boost::shared_ptr<MeshMaterial> material);

    /**
     * Address: 0x007DD750 (FUN_007DD750,
     * ??0Mesh@Moho@@QAE@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@3@@Z)
     *
     * What it does:
     * Initializes a mesh with one pre-resolved resource/material LOD lane.
     */
    Mesh(boost::shared_ptr<RScmResource> resource, boost::shared_ptr<MeshMaterial> material);

    /**
     * Address: 0x007DD880 (FUN_007DD880, ??1Mesh@Moho@@UAE@XZ)
     */
    virtual ~Mesh();

    /**
     * Address: 0x007DDFC0 (FUN_007DDFC0, ?OnResourceChanged@Mesh@Moho@@EAEXVStrArg@gpg@@@Z)
     */
    virtual void OnResourceChanged(gpg::StrArg resourcePath);

    /**
     * Address: 0x007DDB50 (FUN_007DDB50,
     * ?Load@Mesh@Moho@@AAEXPBVRMeshBlueprint@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
     */
    void Load(const RMeshBlueprint* blueprint, boost::shared_ptr<MeshMaterial> material);

    /**
     * Address: 0x007DDAC0 (FUN_007DDAC0)
     */
    void Clear();

    /**
     * Address: 0x007DE030 (FUN_007DE030)
     *
     * What it does:
     * Resets cached batch handles for every loaded LOD.
     */
    void ResetBatches();

    /**
     * Address: 0x007DDC50 (FUN_007DDC50,
     * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@ABVRMeshBlueprintLOD@2@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
     */
    MeshLOD* CreateLOD(const RMeshBlueprintLOD& blueprintLod, boost::shared_ptr<MeshMaterial> material);

    /**
     * Address: 0x007DDE50 (FUN_007DDE50,
     * ?CreateLOD@Mesh@Moho@@AAEPAVMeshLOD@2@V?$shared_ptr@VRScmResource@Moho@@@boost@@V?$shared_ptr@VMeshMaterial@Moho@@@5@@Z)
     *
     * What it does:
     * Adds one direct resource/material-backed mesh LOD entry.
     */
    MeshLOD* CreateLOD(boost::shared_ptr<RScmResource> resource, boost::shared_ptr<MeshMaterial> material);

    /**
     * Address: 0x007DD950 (FUN_007DD950, ?GetResource@Mesh@Moho@@QBE?AV?$shared_ptr@VRScmResource@Moho@@@boost@@H@Z)
     */
    [[nodiscard]] boost::shared_ptr<RScmResource> GetResource(std::int32_t lodIndex) const;

  public:
    const RMeshBlueprint* bp;                  // +0x20
    boost::shared_ptr<MeshMaterial> material;  // +0x24
    std::uint32_t unk2C;                       // +0x2C
    msvc8::vector<MeshLOD*> lods;              // +0x30
    std::uint32_t unk3C;                       // +0x3C
  };

  class MeshKey
  {
  public:
    /**
     * Address: 0x007DAF00 (FUN_007DAF00,
     * ??0MeshKey@Moho@@QAE@PBVRMeshBlueprint@1@V?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
     */
    MeshKey(const RMeshBlueprint* blueprint, boost::shared_ptr<MeshMaterial> meshMaterial);

    /**
     * Address: 0x007DF6E0 (FUN_007DF6E0, copy ctor)
     */
    MeshKey(const MeshKey& rhs);

    /**
     * Address: 0x007DAF60 (FUN_007DAF60, ??1MeshKey@Moho@@QAE@XZ)
     * Deleting thunk: 0x007DAFC0 (FUN_007DAFC0, sub_7DAFC0)
     */
    virtual ~MeshKey();

    [[nodiscard]] bool Equals(const MeshKey& rhs) const noexcept;

    /**
     * Address chain: 0x007E5B20 / 0x007E5C00 comparator logic
     *
     * What it does:
     * Orders keys lexicographically by (blueprint pointer, material object pointer).
     */
    [[nodiscard]] bool LessThan(const MeshKey& rhs) const noexcept;

  public:
    const RMeshBlueprint* blueprint;              // +0x04
    boost::shared_ptr<MeshMaterial> meshMaterial; // +0x08
  };

  class MeshInstance
  {
  public:
    /**
     * Address: 0x007DE060 (FUN_007DE060,
     * ??0MeshInstance@Moho@@QAE@PAV?$SpatialDB@VMeshInstance@Moho@@@1@HIV?$shared_ptr@VMesh@Moho@@@boost@@ABV?$Vector3@M@Wm3@@_N@Z)
     */
    MeshInstance(
      const Wm3::Vec3f& scale,
      void* spatialDbStorage,
      std::int32_t gameTick,
      std::int32_t color,
      bool isStaticPose,
      boost::shared_ptr<Mesh> mesh
    );

    /**
     * Address: 0x007DE550 (FUN_007DE550, ??1MeshInstance@Moho@@QAE@XZ)
     */
    ~MeshInstance();

    /**
     * Address: 0x007DE510 (FUN_007DE510, deleting thunk)
     *
     * What it does:
     * Runs destructor and conditionally frees memory when low flag bit is set.
     */
    virtual void Release(std::int32_t destroyNow);

    /**
     * Address: 0x007DADD0 (FUN_007DADD0, ?GetMesh@MeshInstance@Moho@@QBE?AV?$shared_ptr@VMesh@Moho@@@boost@@XZ)
     */
    [[nodiscard]] boost::shared_ptr<Mesh> GetMesh() const;

    /**
     * Address: 0x007DE930 (FUN_007DE930, ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0@Z)
     *
     * What it does:
     * Applies start/end stance transforms, flags interpolation refresh, and
     * marks stance/bounds state dirty when transform data changed.
     */
    void SetStance(const VTransform& startTransform, const VTransform& endTransform);

    /**
     * Address: 0x007DEA30 (FUN_007DEA30,
     * ?SetStance@MeshInstance@Moho@@QAEXABVVTransform@2@0V?$shared_ptr@VCAniPose@Moho@@@boost@@1@Z)
     *
     * What it does:
     * Applies one pose-aware stance update lane for static-pose meshes:
     * updates pose handles, refreshes interpolation markers, and conditionally
     * updates transform/bounds state.
     */
    void SetStance(
      const VTransform& startTransform,
      const VTransform& endTransform,
      bool forceRefresh,
      boost::shared_ptr<CAniPose> startPoseArg,
      boost::shared_ptr<CAniPose> endPoseArg
    );

    /**
     * Address: 0x007DEC80 (FUN_007DEC80, ?UpdateInterpolatedFields@MeshInstance@Moho@@ABEXXZ)
     *
     * What it does:
     * Recomputes interpolated transform fields for the current global
     * interpolant and refreshes fallback runtime bounds.
     */
    void UpdateInterpolatedFields();

  public:
    using ListLink = TDatListItem<void, void>;

    ListLink* linkPrev;           // +0x04
    ListLink* linkNext;           // +0x08
    SpatialDB_MeshInstance db;    // +0x0C
    boost::shared_ptr<Mesh> mesh; // +0x14
    std::int32_t color;           // +0x1C
    float meshColor;              // +0x20
    std::int32_t unk24;           // +0x24
    std::uint8_t isHidden;        // +0x28
    std::uint8_t isReflected;     // +0x29
    std::uint8_t pad_2A_2B[0x02]{};
    std::int32_t gameTick;               // +0x2C
    float uniformScale;                  // +0x30
    Wm3::Vec3f scale;                    // +0x34
    VTransform endTransform;             // +0x40
    VTransform startTransform;           // +0x5C
    Wm3::Quatf curOrientation;           // +0x78
    Wm3::Vec3f interpolatedPosition;     // +0x88
    Wm3::Vec2f scroll1;                  // +0x94
    Wm3::Vec2f scroll2;                  // +0x9C
    std::uint8_t hasStanceUpdatePending; // +0xA4
    std::uint8_t isStaticPose;           // +0xA5
    std::uint8_t isLocked;               // +0xA6
    std::uint8_t pad_A7{};
    boost::shared_ptr<CAniPose> startPose; // +0xA8
    boost::shared_ptr<CAniPose> endPose;   // +0xB0
    boost::shared_ptr<CAniPose> curPose;   // +0xB8
    float dissolve;                        // +0xC0
    float parameters;                      // +0xC4
    float fractionCompleteParameter;       // +0xC8
    float fractionHealthParameter;         // +0xCC
    float lifetimeParameter;               // +0xD0
    float auxiliaryParameter;              // +0xD4
    std::int8_t frameCounter;              // +0xD8
    std::uint8_t interpolationStateFresh;  // +0xD9
    std::uint8_t pad_DA_DB[0x02]{};
    float currInterpolant;    // +0xDC
    Wm3::Sphere3f sphere;     // +0xE0
    float xMin;               // +0xF0
    float yMin;               // +0xF4
    float zMin;               // +0xF8
    float xMax;               // +0xFC
    float yMax;               // +0x100
    float zMax;               // +0x104
    Wm3::Box3f box;           // +0x108
    float renderMinX;         // +0x144
    float renderMinY;         // +0x148
    float renderMinZ;         // +0x14C
    float renderMaxX;         // +0x150
    float renderMaxY;         // +0x154
    float renderMaxZ;         // +0x158
    std::uint8_t boundsValid; // +0x15C
    std::uint8_t pad_15D_15F[0x03]{};

  public:
    static std::uint8_t sFrameCounter;
    static float sCurrentInterpolant;
  };

  struct MeshRendererMeshCacheEntry
  {
    MeshKey key;                  // +0x00
    boost::shared_ptr<Mesh> mesh; // +0x10
  };

  struct MeshRendererMeshCacheNode
  {
    MeshRendererMeshCacheNode* left;   // +0x00
    MeshRendererMeshCacheNode* parent; // +0x04
    MeshRendererMeshCacheNode* right;  // +0x08
    MeshRendererMeshCacheEntry entry;  // +0x0C
    std::uint8_t color;                // +0x24
    std::uint8_t isSentinel;           // +0x25
    std::uint8_t pad_26_27[0x02]{};
  };

  struct MeshRendererMeshCacheTree
  {
    void* proxy;                     // +0x00
    MeshRendererMeshCacheNode* head; // +0x04
    std::uint32_t size;              // +0x08
  };

  class MeshRenderer
  {
  public:
    /**
     * Address: 0x007DF150 (FUN_007DF150, ??0MeshRenderer@Moho@@QAE@XZ)
     */
    MeshRenderer();

    /**
     * Address: 0x007DF330 (FUN_007DF330, ??1MeshRenderer@Moho@@QAE@XZ)
     */
    virtual ~MeshRenderer();

    /**
     * Address: 0x007E16C0 (FUN_007E16C0, ?GetInstance@MeshRenderer@Moho@@SAPAV12@XZ)
     */
    static MeshRenderer* GetInstance();

    /**
     * Address: 0x007E1370 (FUN_007E1370, ?Reset@MeshRenderer@Moho@@QAEXXZ)
     *
     * What it does:
     * Releases global sheet handles, clears per-instance LOD batches, and resets batch-bucket state.
     */
    void Reset();

    /**
     * Address: 0x007E1510 (FUN_007E1510, ?Shutdown@MeshRenderer@Moho@@QAEXXZ)
     *
     * What it does:
     * Performs reset-time cleanup and detaches the intrusive instance-list sentinel.
     */
    void Shutdown();

    /**
     * Address: 0x007DF530 (FUN_007DF530,
     * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIPBVRMeshBlueprint@2@ABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMeshMaterial@Moho@@@boost@@@Z)
     */
    MeshInstance* CreateMeshInstance(
      std::int32_t gameTick,
      std::int32_t color,
      const RMeshBlueprint* blueprint,
      const Wm3::Vec3f& scale,
      bool isStaticPose,
      boost::shared_ptr<MeshMaterial> material
    );

    /**
     * Address: 0x007DF8E0 (FUN_007DF8E0,
     * ?CreateMeshInstance@MeshRenderer@Moho@@QAEPAVMeshInstance@2@HIABV?$Vector3@M@Wm3@@_NV?$shared_ptr@VMesh@Moho@@@boost@@@Z)
     */
    MeshInstance* CreateMeshInstance(
      std::int32_t gameTick,
      std::int32_t color,
      const Wm3::Vec3f& scale,
      bool isStaticPose,
      boost::shared_ptr<Mesh> mesh
    );

    /**
     * Address: 0x007E11C0 (FUN_007E11C0,
     * ?RenderThumbnail@MeshRenderer@Moho@@QAEXABVGeomCamera3@2@PAVMeshInstance@2@PAVID3DRenderTarget@2@PAVID3DDepthStencil@2@@Z)
     *
     * What it does:
     * Renders one mesh instance with one thumbnail camera into caller-provided
     * color/depth targets.
     */
    void RenderThumbnail(
      const GeomCamera3& camera,
      MeshInstance* meshInstance,
      ID3DRenderTarget* renderTarget,
      ID3DDepthStencil* depthStencil
    );

    /**
     * Address: 0x007E19D0 (FUN_007E19D0, Moho::MeshRenderer::ConfigureShader)
     *
     * What it does:
     * Binds the terrain/sun/shadow shader-constant lane for one mesh render
     * pass before batch iteration begins.
     */
    void ConfigureShader(const GeomCamera3& camera, Shadow* shadow, bool mirrored);

    /**
     * Address: 0x007DFDB0 (FUN_007DFDB0, Moho::MeshRenderer::RenderSkeletons)
     *
     * What it does:
     * Renders every mesh instance in the cache with skeleton-debug overlays
     * and a shared prim batcher state.
     */
    void RenderSkeletons(CD3DPrimBatcher* debugBatcher, CDebugCanvas* debugCanvas, const GeomCamera3& camera, bool showBoneNames);

    /**
     * Address: 0x007E2290 (FUN_007E2290, Moho::MeshRenderer::RenderSkeleton)
     *
     * What it does:
     * Draws one mesh instance's skeleton debug pose, optional bone names, and
     * wireframe bounds.
     */
    void RenderSkeleton(CD3DPrimBatcher* debugBatcher, CDebugCanvas* debugCanvas, MeshInstance* meshInstance, bool showBoneNames);

    /**
     * Address: 0x007E0C30 (FUN_007E0C30, Moho::MeshRenderer::Render)
     *
     * What it does:
     * Draws one batch map of mesh instances with the active material shader
     * state and optional shadow lane.
     */
    void Render(
      std::int32_t meshFlags,
      const GeomCamera3& camera,
      Shadow* shadow,
      MeshBatchBucketTree& meshMap
    );

  public:
    [[nodiscard]] boost::shared_ptr<Mesh>
    FindOrCreateMesh(const RMeshBlueprint* blueprint, boost::shared_ptr<MeshMaterial> material);

    MeshEnvironment meshEnvironment;                                 // +0x04
    MeshRendererMeshCacheTree meshCacheTree;                         // +0x60
    boost::shared_ptr<CD3DDynamicTextureSheet> dissolveTex;          // +0x6C
    boost::shared_ptr<CD3DDynamicTextureSheet> meshEnvironmentTex;   // +0x74
    boost::shared_ptr<CD3DDynamicTextureSheet> anisotropiclookupTex; // +0x7C
    boost::shared_ptr<CD3DDynamicTextureSheet> insectlookupTex;      // +0x84
    MeshInstance::ListLink instanceListHead;                         // +0x8C
    std::int32_t instanceListSize;                                   // +0x94
    float deltaFrame;                                                // +0x98
    std::uint32_t instanceListStateFlags;                            // +0x9C
    MeshBatchBucketTree meshes;                                      // +0xA0
    SpatialDB_MeshInstance meshSpatialDb;                            // +0xAC
  };

  static_assert(sizeof(SpatialDB_MeshInstance) == 0x08, "SpatialDB_MeshInstance size must be 0x08");
  static_assert(
    offsetof(MeshMaterial, mShaderAnnotation) == 0x04, "MeshMaterial::mShaderAnnotation offset must be 0x04"
  );
  static_assert(offsetof(MeshMaterial, mAlbedoSheet) == 0x20, "MeshMaterial::mAlbedoSheet offset must be 0x20");
  static_assert(offsetof(MeshMaterial, mNormalsSheet) == 0x28, "MeshMaterial::mNormalsSheet offset must be 0x28");
  static_assert(offsetof(MeshMaterial, mSpecularSheet) == 0x30, "MeshMaterial::mSpecularSheet offset must be 0x30");
  static_assert(offsetof(MeshMaterial, mLookupSheet) == 0x38, "MeshMaterial::mLookupSheet offset must be 0x38");
  static_assert(offsetof(MeshMaterial, mSecondarySheet) == 0x40, "MeshMaterial::mSecondarySheet offset must be 0x40");
  static_assert(
    offsetof(MeshMaterial, mEnvironmentSheet) == 0x48, "MeshMaterial::mEnvironmentSheet offset must be 0x48"
  );
  static_assert(offsetof(MeshMaterial, mShaderIndex) == 0x50, "MeshMaterial::mShaderIndex offset must be 0x50");
  static_assert(offsetof(MeshMaterial, mAuxTag0) == 0x54, "MeshMaterial::mAuxTag0 offset must be 0x54");
  static_assert(offsetof(MeshMaterial, mAuxTag1) == 0x70, "MeshMaterial::mAuxTag1 offset must be 0x70");
  static_assert(offsetof(MeshMaterial, mRuntimeFlag0) == 0x8C, "MeshMaterial::mRuntimeFlag0 offset must be 0x8C");
  static_assert(offsetof(MeshMaterial, mRuntimeFlag1) == 0x8D, "MeshMaterial::mRuntimeFlag1 offset must be 0x8D");
  static_assert(sizeof(MeshMaterial) == 0x90, "MeshMaterial size must be 0x90");

  static_assert(offsetof(MeshLOD, useDissolve) == 0x04, "MeshLOD::useDissolve offset must be 0x04");
  static_assert(offsetof(MeshLOD, cutoff) == 0x08, "MeshLOD::cutoff offset must be 0x08");
  static_assert(offsetof(MeshLOD, previousResource) == 0x9C, "MeshLOD::previousResource offset must be 0x9C");
  static_assert(offsetof(MeshLOD, res) == 0xA4, "MeshLOD::res offset must be 0xA4");
  static_assert(offsetof(MeshLOD, lodBlueprintCopy) == 0xB0, "MeshLOD::lodBlueprintCopy offset must be 0xB0");
  static_assert(offsetof(MeshLOD, staticBatch) == 0xB8, "MeshLOD::staticBatch offset must be 0xB8");
  static_assert(offsetof(MeshLOD, dynamicBatch) == 0xC0, "MeshLOD::dynamicBatch offset must be 0xC0");
  static_assert(sizeof(MeshLOD) == 0xC8, "MeshLOD size must be 0xC8");

  static_assert(offsetof(Mesh, bp) == 0x20, "Mesh::bp offset must be 0x20");
  static_assert(offsetof(Mesh, material) == 0x24, "Mesh::material offset must be 0x24");
  static_assert(offsetof(Mesh, lods) == 0x30, "Mesh::lods offset must be 0x30");
#if defined(MOHO_STRICT_LAYOUT_ASSERTS)
  static_assert(sizeof(Mesh) == 0x40, "Mesh size must be 0x40");
#endif

  static_assert(offsetof(MeshKey, blueprint) == 0x04, "MeshKey::blueprint offset must be 0x04");
  static_assert(offsetof(MeshKey, meshMaterial) == 0x08, "MeshKey::meshMaterial offset must be 0x08");
  static_assert(sizeof(MeshKey) == 0x10, "MeshKey size must be 0x10");

  static_assert(offsetof(MeshInstance, db) == 0x0C, "MeshInstance::db offset must be 0x0C");
  static_assert(offsetof(MeshInstance, mesh) == 0x14, "MeshInstance::mesh offset must be 0x14");
  static_assert(offsetof(MeshInstance, isHidden) == 0x28, "MeshInstance::isHidden offset must be 0x28");
  static_assert(offsetof(MeshInstance, isReflected) == 0x29, "MeshInstance::isReflected offset must be 0x29");
  static_assert(
    offsetof(MeshInstance, hasStanceUpdatePending) == 0xA4, "MeshInstance::hasStanceUpdatePending offset must be 0xA4"
  );
  static_assert(offsetof(MeshInstance, startPose) == 0xA8, "MeshInstance::startPose offset must be 0xA8");
  static_assert(offsetof(MeshInstance, curPose) == 0xB8, "MeshInstance::curPose offset must be 0xB8");
  static_assert(
    offsetof(MeshInstance, interpolationStateFresh) == 0xD9, "MeshInstance::interpolationStateFresh offset must be 0xD9"
  );
  static_assert(offsetof(MeshInstance, sphere) == 0xE0, "MeshInstance::sphere offset must be 0xE0");
  static_assert(offsetof(MeshInstance, box) == 0x108, "MeshInstance::box offset must be 0x108");
  static_assert(sizeof(MeshInstance) == 0x160, "MeshInstance size must be 0x160");
  static_assert(sizeof(MeshInstance::ListLink) == 0x08, "MeshInstance::ListLink size must be 0x08");

  static_assert(
    offsetof(MeshRendererMeshCacheEntry, key) == 0x00, "MeshRendererMeshCacheEntry::key offset must be 0x00"
  );
  static_assert(
    offsetof(MeshRendererMeshCacheEntry, mesh) == 0x10, "MeshRendererMeshCacheEntry::mesh offset must be 0x10"
  );
  static_assert(sizeof(MeshRendererMeshCacheEntry) == 0x18, "MeshRendererMeshCacheEntry size must be 0x18");

  static_assert(
    offsetof(MeshRendererMeshCacheNode, left) == 0x00, "MeshRendererMeshCacheNode::left offset must be 0x00"
  );
  static_assert(
    offsetof(MeshRendererMeshCacheNode, entry) == 0x0C, "MeshRendererMeshCacheNode::entry offset must be 0x0C"
  );
  static_assert(
    offsetof(MeshRendererMeshCacheNode, color) == 0x24, "MeshRendererMeshCacheNode::color offset must be 0x24"
  );
  static_assert(
    offsetof(MeshRendererMeshCacheNode, isSentinel) == 0x25, "MeshRendererMeshCacheNode::isSentinel offset must be 0x25"
  );
  static_assert(sizeof(MeshRendererMeshCacheNode) == 0x28, "MeshRendererMeshCacheNode size must be 0x28");

  static_assert(
    offsetof(MeshRendererMeshCacheTree, proxy) == 0x00, "MeshRendererMeshCacheTree::proxy offset must be 0x00"
  );
  static_assert(
    offsetof(MeshRendererMeshCacheTree, head) == 0x04, "MeshRendererMeshCacheTree::head offset must be 0x04"
  );
  static_assert(
    offsetof(MeshRendererMeshCacheTree, size) == 0x08, "MeshRendererMeshCacheTree::size offset must be 0x08"
  );
  static_assert(sizeof(MeshRendererMeshCacheTree) == 0x0C, "MeshRendererMeshCacheTree size must be 0x0C");

  static_assert(offsetof(MeshRenderer, meshEnvironment) == 0x04, "MeshRenderer::meshEnvironment offset must be 0x04");
  static_assert(offsetof(MeshRenderer, meshCacheTree) == 0x60, "MeshRenderer::meshCacheTree offset must be 0x60");
  static_assert(offsetof(MeshRenderer, dissolveTex) == 0x6C, "MeshRenderer::dissolveTex offset must be 0x6C");
  static_assert(
    offsetof(MeshRenderer, meshEnvironmentTex) == 0x74, "MeshRenderer::meshEnvironmentTex offset must be 0x74"
  );
  static_assert(
    offsetof(MeshRenderer, anisotropiclookupTex) == 0x7C, "MeshRenderer::anisotropiclookupTex offset must be 0x7C"
  );
  static_assert(offsetof(MeshRenderer, insectlookupTex) == 0x84, "MeshRenderer::insectlookupTex offset must be 0x84");
  static_assert(offsetof(MeshRenderer, instanceListHead) == 0x8C, "MeshRenderer::instanceListHead offset must be 0x8C");
  static_assert(offsetof(MeshRenderer, instanceListSize) == 0x94, "MeshRenderer::instanceListSize offset must be 0x94");
  static_assert(offsetof(MeshRenderer, deltaFrame) == 0x98, "MeshRenderer::deltaFrame offset must be 0x98");
  static_assert(
    offsetof(MeshRenderer, instanceListStateFlags) == 0x9C, "MeshRenderer::instanceListStateFlags offset must be 0x9C"
  );
  static_assert(offsetof(MeshRenderer, meshes) == 0xA0, "MeshRenderer::meshes offset must be 0xA0");
  static_assert(offsetof(MeshRenderer, meshSpatialDb) == 0xAC, "MeshRenderer::meshSpatialDb offset must be 0xAC");
  static_assert(sizeof(MeshRenderer) == 0xB4, "MeshRenderer size must be 0xB4");
} // namespace moho
