#include "RDebugCollision.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/Sim.h"

namespace
{
  using TypeInfo = moho::RDebugCollisionTypeInfo;

  alignas(TypeInfo) unsigned char gRDebugCollisionTypeInfoStorage[sizeof(TypeInfo)] = {};
  bool gRDebugCollisionTypeInfoConstructed = false;

  [[nodiscard]] gpg::RType* CachedRDebugCollisionType()
  {
    if (!moho::RDebugCollision::sType) {
      moho::RDebugCollision::sType = gpg::LookupRType(typeid(moho::RDebugCollision));
    }
    return moho::RDebugCollision::sType;
  }

  [[nodiscard]] gpg::RType* CachedRDebugOverlayType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(moho::RDebugOverlay));
    }
    return sType;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = staticType;
    return out;
  }

  /**
   * Address: 0x0064C790 (LAB_0064C790, RDebugCollisionTypeInfo::newRefFunc_)
   */
  [[nodiscard]] gpg::RRef CreateRDebugCollisionRefOwned()
  {
    return MakeTypedRef(new moho::RDebugCollision(), CachedRDebugCollisionType());
  }

  /**
   * Address: 0x0064C7E0 (LAB_0064C7E0, RDebugCollisionTypeInfo::deleteFunc_)
   */
  void DeleteRDebugCollisionOwned(void* object)
  {
    delete static_cast<moho::RDebugCollision*>(object);
  }

  /**
   * Address: 0x0064C800 (LAB_0064C800, RDebugCollisionTypeInfo::ctorRefFunc_)
   */
  [[nodiscard]] gpg::RRef ConstructRDebugCollisionRefInPlace(void* objectStorage)
  {
    auto* const object = static_cast<moho::RDebugCollision*>(objectStorage);
    if (object) {
      new (object) moho::RDebugCollision();
    }
    return MakeTypedRef(object, CachedRDebugCollisionType());
  }

  /**
   * Address: 0x0064C840 (LAB_0064C840, RDebugCollisionTypeInfo::dtrFunc_)
   */
  void DestroyRDebugCollisionInPlace(void* object)
  {
    auto* const overlay = static_cast<moho::RDebugCollision*>(object);
    if (overlay) {
      overlay->~RDebugCollision();
    }
  }

  void AddRDebugOverlayBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedRDebugOverlayType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] TypeInfo& GetRDebugCollisionTypeInfo() noexcept
  {
    if (!gRDebugCollisionTypeInfoConstructed) {
      (void)new (gRDebugCollisionTypeInfoStorage) TypeInfo();
      gRDebugCollisionTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRDebugCollisionTypeInfoStorage);
  }

  void cleanup_RDebugCollisionTypeInfo_00BFB670_Impl()
  {
    if (!gRDebugCollisionTypeInfoConstructed) {
      return;
    }

    GetRDebugCollisionTypeInfo().~RDebugCollisionTypeInfo();
    gRDebugCollisionTypeInfoConstructed = false;
  }

  void CleanupRDebugCollisionTypeInfoAtexit()
  {
    cleanup_RDebugCollisionTypeInfo_00BFB670_Impl();
  }
} // namespace

namespace moho
{
  gpg::RType* RDebugCollision::sType = nullptr;

  /**
   * Address: 0x0064C270 (FUN_0064C270, ?GetClass@RDebugCollision@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* RDebugCollision::GetClass() const
  {
    return CachedRDebugCollisionType();
  }

  /**
   * Address: 0x0064C290 (FUN_0064C290, ?GetDerivedObjectRef@RDebugCollision@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef RDebugCollision::GetDerivedObjectRef()
  {
    return MakeTypedRef(this, GetClass());
  }

  /**
   * Address: 0x0064C860 (FUN_0064C860, scalar deleting body)
   */
  RDebugCollision::~RDebugCollision() = default;

  /**
   * Address: 0x0064C500 (FUN_0064C500)
   */
  void RDebugCollision::Tick(Sim* const sim)
  {
    if (!sim || !sim->mEntityDB) {
      return;
    }

    // Draw-API lift (FUN_00450110 / FUN_00450520) is still pending.
    // Keep the typed collision-primitive scan path in place.
    for (Entity* const entity : sim->mEntityDB->Entities()) {
      if (!entity || !entity->CollisionExtents) {
        continue;
      }

      (void)entity->CollisionExtents->GetBox();
      (void)entity->CollisionExtents->GetSphere();
    }
  }

  /**
   * Address: 0x0064C2B0 (FUN_0064C2B0, Moho::RDebugCollisionTypeInfo::RDebugCollisionTypeInfo)
   */
  RDebugCollisionTypeInfo::RDebugCollisionTypeInfo()
    : RDebugOverlayClass()
  {
    gpg::PreRegisterRType(typeid(RDebugCollision), this);
  }

  /**
   * Address: 0x0064C3A0 (FUN_0064C3A0, scalar deleting destructor thunk)
   */
  RDebugCollisionTypeInfo::~RDebugCollisionTypeInfo() = default;

  /**
   * Address: 0x0064C390 (FUN_0064C390)
   */
  const char* RDebugCollisionTypeInfo::GetName() const
  {
    return "RDebugCollision";
  }

  /**
   * Address: 0x0064C340 (FUN_0064C340)
   */
  void RDebugCollisionTypeInfo::Init()
  {
    size_ = sizeof(RDebugCollision);
    newRefFunc_ = &CreateRDebugCollisionRefOwned;
    deleteFunc_ = &DeleteRDebugCollisionOwned;
    ctorRefFunc_ = &ConstructRDebugCollisionRefInPlace;
    dtrFunc_ = &DestroyRDebugCollisionInPlace;
    AddRDebugOverlayBase(this);
    gpg::RType::Init();
    RegisterOverlayClass("Display collision boxes for all units", "Collision");
    Finish();
  }

  /**
   * Address: 0x00BFB670 (FUN_00BFB670, sub_BFB670)
   *
   * What it does:
   * Releases startup-owned `RDebugCollisionTypeInfo` reflection storage.
   */
  void cleanup_RDebugCollisionTypeInfo()
  {
    cleanup_RDebugCollisionTypeInfo_00BFB670_Impl();
  }

  /**
   * Address: 0x00BD3B30 (FUN_00BD3B30, register_RDebugCollisionTypeInfo)
   *
   * What it does:
   * Forces startup construction/preregistration for `RDebugCollision` RTTI and installs exit cleanup.
   */
  void register_RDebugCollisionTypeInfo()
  {
    (void)GetRDebugCollisionTypeInfo();
    (void)std::atexit(&CleanupRDebugCollisionTypeInfoAtexit);
  }
} // namespace moho

namespace
{
  struct RDebugCollisionStartupBootstrap
  {
    RDebugCollisionStartupBootstrap()
    {
      moho::register_RDebugCollisionTypeInfo();
    }
  };

  [[maybe_unused]] RDebugCollisionStartupBootstrap gRDebugCollisionStartupBootstrap;
} // namespace
