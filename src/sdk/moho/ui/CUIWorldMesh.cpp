#include "moho/ui/CUIWorldMesh.h"

#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/lua/SCR_Color.h"
#include "moho/mesh/Mesh.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/resource/ResourceManager.h"
#include "moho/resource/RScmResource.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/RRuleGameRules.h"

namespace moho
{
  namespace
  {
    /**
     * Address: 0x0086D790 (FUN_0086D790)
     *
     * What it does:
     * Returns the lazily cached reflection descriptor for `CUIWorldMesh`.
     */
    [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCUIWorldMeshTypeBridge()
    {
      if (CUIWorldMesh::sType == nullptr) {
        CUIWorldMesh::sType = gpg::LookupRType(typeid(CUIWorldMesh));
      }
      return CUIWorldMesh::sType;
    }

    /**
     * Alias of FUN_00539BA0 (model-resource lookup lane).
     *
     * What it does:
     * Resolves one SCM model resource from path into a retained shared handle.
     */
    [[nodiscard]] boost::shared_ptr<RScmResource> ResolveModelResourceByPath(const char* const modelPath)
    {
      if (RScmResource::sType == nullptr) {
        RScmResource::sType = gpg::LookupRType(typeid(RScmResource));
      }

      boost::weak_ptr<RScmResource> weakResource{};
      (void)RES_GetResource(&weakResource, modelPath != nullptr ? modelPath : "", nullptr, RScmResource::sType);
      return weakResource.lock();
    }

    [[nodiscard]] const char* LuaStringOrEmpty(const LuaPlus::LuaObject& object) noexcept
    {
      const char* const value = object.GetString();
      return value != nullptr ? value : "";
    }
  } // namespace

  gpg::RType* CUIWorldMesh::sType = nullptr;

  /**
   * Address: 0x0086ADC0 (FUN_0086ADC0, Moho::CUIWorldMesh::GetClass)
   *
   * What it does:
   * Returns cached reflection descriptor for `CUIWorldMesh`.
   */
  gpg::RType* CUIWorldMesh::GetClass() const
  {
    return CachedCUIWorldMeshTypeBridge();
  }

  /**
   * Address: 0x0086ADE0 (FUN_0086ADE0, Moho::CUIWorldMesh::GetDerivedObjectRef)
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef CUIWorldMesh::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x0086B1E0 (FUN_0086B1E0, ??0CUIWorldMesh@Moho@@QAE@@Z)
   * Mangled: ??0CUIWorldMesh@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes one script-visible world-mesh owner and binds the provided
   * Lua object.
   */
  CUIWorldMesh::CUIWorldMesh(const LuaPlus::LuaObject& luaObject)
    : CScriptObject()
    , mMeshInstance(nullptr)
  {
    SetLuaObject(luaObject);
  }

  /**
   * Address: 0x0086B250 (FUN_0086B250, ??1CUIWorldMesh@Moho@@QAE@@Z)
   * Deleting thunk: 0x0086B230 (FUN_0086B230, Moho::CUIWorldMesh::dtr)
   *
   * What it does:
   * Releases the owned mesh-instance lane when the mesh renderer runtime is
   * still available, then tears down base script-object storage.
   */
  CUIWorldMesh::~CUIWorldMesh()
  {
    if (mMeshInstance != nullptr && MeshRenderer::GetInstance() != nullptr) {
      delete mMeshInstance;
      mMeshInstance = nullptr;
    }
  }

  /**
   * Address: 0x0086AE00 (FUN_0086AE00)
   *
   * What it does:
   * Builds one stance transform from position/orientation components and
   * applies it to the owned mesh instance as both start and end stance.
   */
  void CUIWorldMesh::SetStanceFromComponents(
    const float positionX,
    const float positionY,
    const float positionZ,
    const float orientationX,
    const float orientationY,
    const float orientationZ,
    const float orientationW
  )
  {
    if (mMeshInstance == nullptr) {
      return;
    }

    VTransform transform{};
    transform.orient_.x = orientationX;
    transform.orient_.y = orientationY;
    transform.orient_.z = orientationZ;
    transform.orient_.w = orientationW;
    transform.pos_.x = positionX;
    transform.pos_.y = positionY;
    transform.pos_.z = positionZ;
    mMeshInstance->SetStance(transform, transform);
  }

  /**
   * Address: 0x0086B2C0 (FUN_0086B2C0, Moho::CUIWorldMesh::SetMesh)
   *
   * What it does:
   * Resolves one world-mesh descriptor table and updates the owned mesh
   * instance from either direct model/material lanes or unit blueprint data.
   */
  void CUIWorldMesh::SetMesh(const LuaPlus::LuaObject& meshDescriptor)
  {
    float uniformScale = 1.0f;
    int color = -1;
    float lodCutoff = 1000.0f;

    if (const LuaPlus::LuaObject uniformScaleObject = meshDescriptor["UniformScale"]; !uniformScaleObject.IsNil()) {
      uniformScale = uniformScaleObject.GetNumber();
    }

    if (const LuaPlus::LuaObject colorObject = meshDescriptor["Color"]; !colorObject.IsNil()) {
      msvc8::string encodedColor(LuaStringOrEmpty(colorObject));
      color = static_cast<int>(SCR_DecodeColor(encodedColor));
    }

    if (const LuaPlus::LuaObject lodCutoffObject = meshDescriptor["LODCutoff"]; !lodCutoffObject.IsNil()) {
      lodCutoff = lodCutoffObject.GetNumber();
    }

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    if (const LuaPlus::LuaObject meshNameObject = meshDescriptor["MeshName"]; !meshNameObject.IsNil()) {
      const LuaPlus::LuaObject shaderNameObject = meshDescriptor["ShaderName"];
      const LuaPlus::LuaObject textureNameObject = meshDescriptor["TextureName"];
      if (shaderNameObject.IsNil() || textureNameObject.IsNil()) {
        gpg::Warnf("WorldMesh:SetMesh - MeshName specified, but ShaderName or TextureName were not specified");
        return;
      }

      const boost::shared_ptr<RScmResource> modelResource = ResolveModelResourceByPath(LuaStringOrEmpty(meshNameObject));
      const msvc8::string textureName(LuaStringOrEmpty(textureNameObject));
      const msvc8::string shaderName(LuaStringOrEmpty(shaderNameObject));
      const msvc8::string emptyTextureName{};
      const boost::shared_ptr<MeshMaterial> material =
        MeshMaterial::Create(shaderName, textureName, emptyTextureName, emptyTextureName, emptyTextureName, emptyTextureName, nullptr);

      boost::shared_ptr<Mesh> mesh(new Mesh(modelResource, material));
      if (!mesh->lods.empty()) {
        MeshLOD* const primaryLod = mesh->lods.front();
        if (primaryLod != nullptr) {
          primaryLod->SetCutoff(lodCutoff);
        }
      }

      CWldSession* const worldSession = WLD_GetActiveSession();
      const int gameTick = worldSession != nullptr ? worldSession->mGameTick : 0;
      const Wm3::Vec3f scale{uniformScale, uniformScale, uniformScale};
      mMeshInstance = meshRenderer != nullptr ? meshRenderer->CreateMeshInstance(gameTick, color, scale, false, mesh) : nullptr;
    } else {
      const LuaPlus::LuaObject blueprintIdObject = meshDescriptor["BlueprintID"];
      if (blueprintIdObject.IsNil()) {
        gpg::Warnf("WorldMesh:SetMesh - no mesh specified");
        return;
      }

      CWldSession* const worldSession = WLD_GetActiveSession();
      RMeshBlueprint* meshBlueprint = nullptr;
      float blueprintUniformScale = uniformScale;
      int gameTick = 0;
      if (worldSession != nullptr && worldSession->mRules != nullptr) {
        msvc8::string blueprintId(LuaStringOrEmpty(blueprintIdObject));
        RResId normalizedBlueprintId{};
        gpg::STR_CopyFilename(&normalizedBlueprintId.name, &blueprintId);

        if (RUnitBlueprint* const unitBlueprint = worldSession->mRules->GetUnitBlueprint(normalizedBlueprintId);
            unitBlueprint != nullptr) {
          meshBlueprint = worldSession->mRules->GetMeshBlueprint(unitBlueprint->Display.MeshBlueprint);
          blueprintUniformScale = unitBlueprint->Display.UniformScale;
        }
        gameTick = worldSession->mGameTick;
      }

      const Wm3::Vec3f scale{blueprintUniformScale, blueprintUniformScale, blueprintUniformScale};
      mMeshInstance = meshRenderer != nullptr
        ? meshRenderer->CreateMeshInstance(gameTick, color, meshBlueprint, scale, false, boost::shared_ptr<MeshMaterial>())
        : nullptr;
    }

    if (mMeshInstance != nullptr) {
      mMeshInstance->isHidden = 1;
    } else {
      gpg::Warnf("WorldMesh:SetMesh - unable to create MeshInsance");
    }
  }
} // namespace moho
