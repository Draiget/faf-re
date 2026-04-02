#include "Prop.h"

#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityDb.h"
#include "moho/path/PathTables.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/Sim.h"

namespace
{
  constexpr std::uint8_t kPropEntityIdSourceIndex = moho::kEntityIdSourceIndexInvalid;
  constexpr std::uint32_t kPropEntityIdFamilySourceBits =
    moho::MakeEntityIdFamilySourceBits(moho::EEntityIdFamily::Prop, kPropEntityIdSourceIndex);
  constexpr std::uint32_t kPropEntityIdFallback =
    moho::MakeEntityId(moho::EEntityIdFamily::Prop, kPropEntityIdSourceIndex, 1u);
  constexpr std::uint32_t kPropCollisionBucketFlags = 0x200u;

  gpg::RType* gEntitySerializationType = nullptr;

  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializedType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }

  struct DestroyQueueNodeView
  {
    DestroyQueueNodeView* next;
    DestroyQueueNodeView* prev;
    moho::Entity* entity;
  };

  struct CommandDbDestroyQueueView
  {
    std::uint8_t pad_00[0x20];
    std::int32_t count;         // +0x20
    DestroyQueueNodeView* head; // +0x24
  };

  void QueueEntityForDestroyNoCallback(moho::Entity* entity)
  {
    if (!entity || !entity->SimulationRef || !entity->SimulationRef->mCommandDB) {
      return;
    }

    auto* const queue = reinterpret_cast<CommandDbDestroyQueueView*>(entity->SimulationRef->mCommandDB);
    DestroyQueueNodeView* const head = queue->head;
    if (!head) {
      return;
    }

    auto* const node = static_cast<DestroyQueueNodeView*>(::operator new(sizeof(DestroyQueueNodeView)));
    node->next = head;
    node->prev = head->prev;
    node->entity = entity;

    ++queue->count;
    head->prev = node;
    node->prev->next = node;
  }

  void QueuePropReclaimDelete(moho::Prop& prop)
  {
    if (prop.DestroyQueuedFlag != 0u) {
      return;
    }

    prop.DestroyQueuedFlag = 1u;
    QueueEntityForDestroyNoCallback(&prop);

    if (prop.SimulationRef) {
      prop.mCoordNode.ListLinkBefore(&prop.SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00721A90 (FUN_00721A90)
   *
   * What it does:
   * Marks terrain/water occupancy masks for the reclaim area rectangle.
   */
  void LoadOccupancy(const std::uint8_t occupancyCaps, moho::COGrid* grid, const gpg::Rect2i& rect)
  {
    if (!grid) {
      return;
    }

    const int width = rect.x1 - rect.x0;
    const int height = rect.z1 - rect.z0;
    if (width <= 0 || height <= 0) {
      return;
    }

    if ((occupancyCaps & 0x07u) != 0u) {
      grid->terrainOccupation.FillRect(rect.x0, rect.z0, width, height, true);
    }
    if ((occupancyCaps & 0x08u) != 0u) {
      grid->waterOccupation.FillRect(rect.x0, rect.z0, width, height, true);
    }

    if (grid->sim && grid->sim->mPathTables) {
      grid->sim->mPathTables->DirtyClusters(rect);
    }
  }
} // namespace

namespace moho
{
  gpg::RType* SPropPriorityInfo::sType = nullptr;
  gpg::RType* Prop::sType = nullptr;
  CScrLuaMetatableFactory<Prop> CScrLuaMetatableFactory<Prop>::sInstance{};

  CScrLuaMetatableFactory<Prop>& CScrLuaMetatableFactory<Prop>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00680010 (FUN_00680010, Moho::CScrLuaMetatableFactory<Moho::Prop>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<Prop>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00BD50F0 (FUN_00BD50F0, register_CScrLuaMetatableFactory_Prop_Index)
   *
   * What it does:
   * Allocates one factory-object index and assigns it to prop metatable factory singleton.
   */
  int register_CScrLuaMetatableFactory_Prop_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<Prop>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x006F9CD0 (FUN_006F9CD0)
   *
   * What it does:
   * Initializes Prop for serializer construction lanes by using Entity's
   * non-blueprint constructor and applying Prop reclaim defaults.
   */
  Prop::Prop(Sim* sim)
    : Entity(sim, kPropCollisionBucketFlags)
    , mReclaimMass(0.0f)
    , mReclaimEnergy(0.0f)
    , mTracksReclaimArea(false)
    , mReclaimTerminated(false)
    , pad_027A{0u, 0u}
    , mPriorityInfo{0, 0}
    , mHandleIndex(-1)
  {}

  /**
   * Address: 0x006F9D90 (FUN_006F9D90)
   *
   * What it does:
   * Constructs Prop from blueprint/transform, initializes layer+mesh+reclaim
   * state, and registers reclaim occupancy area when needed.
   */
  Prop::Prop(Sim* sim, const RPropBlueprint* blueprint, const VTransform& transform)
    : Entity(
        static_cast<REntityBlueprint*>(const_cast<RPropBlueprint*>(blueprint)),
        sim,
        static_cast<EntId>(
          sim && sim->mEntityDB ? sim->mEntityDB->DoReserveId(kPropEntityIdFamilySourceBits) : kPropEntityIdFallback
        ),
        kPropCollisionBucketFlags
      )
    , mReclaimMass(0.0f)
    , mReclaimEnergy(0.0f)
    , mTracksReclaimArea(false)
    , mReclaimTerminated(false)
    , pad_027A{0u, 0u}
    , mPriorityInfo{0, 0}
    , mHandleIndex(-1)
  {
    if (!blueprint) {
      return;
    }

    const float uniformScale = blueprint->Display.UniformScale;
    mDrawScaleX = uniformScale;
    mDrawScaleY = uniformScale;
    mDrawScaleZ = uniformScale;

    // Entity orientation lanes are stored as (w,x,y,z) in Vector4f::x/y/z/w slots.
    PendingOrientation.x = transform.orient_.w;
    PendingOrientation.y = transform.orient_.x;
    PendingOrientation.z = transform.orient_.y;
    PendingOrientation.w = transform.orient_.z;
    PendingPosition.x = transform.pos_.x;
    PendingPosition.y = transform.pos_.y;
    PendingPosition.z = transform.pos_.z;

    const ELayer startingLayer = GetStartingLayer(transform.pos_, LAYER_Land);
    SetCurrentLayer(startingLayer);
    AdvanceCoords();
    AdvanceCoords();

    MaxHealth = blueprint->Defense.Health;
    mReclaimMass = blueprint->Economy.ReclaimMassMax;
    mReclaimEnergy = blueprint->Economy.ReclaimEnergyMax;

    mVisibilityLayerDefault = 2;
    mFootprintLayer = static_cast<int>(LAYER_Seabed);
    mVisibilityState = 1u;

    SetMesh(blueprint->Display.MeshBlueprint, nullptr, true);
    RunScript("OnCreate");

    if (mReclaimMass > 0.0f || mReclaimEnergy > 0.0f) {
      mTracksReclaimArea = true;

      if (sim && sim->mOGrid) {
        gpg::Rect2i rect{};
        rect.x0 = static_cast<int>(transform.pos_.x - static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);
        rect.z0 = static_cast<int>(transform.pos_.z - static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);
        rect.x1 = rect.x0 + static_cast<int>(blueprint->mFootprint.mSizeX);
        rect.z1 = rect.z0 + static_cast<int>(blueprint->mFootprint.mSizeZ);

        LoadOccupancy(static_cast<std::uint8_t>(blueprint->mFootprint.mOccupancyCaps), sim->mOGrid, rect);
      }
    }
  }

  /**
   * Address: 0x006FB3B0 (FUN_006FB3B0)
   *
   * IDA signature:
   * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, Moho::RPropBlueprint const *);
   *
   * What it does:
   * Allocates Prop and dispatches to Prop ctor path.
   */
  Prop* Prop::CreateFromBlueprintResolved(Sim* sim, const RPropBlueprint* blueprint, const VTransform& transform)
  {
    if (!sim || !blueprint) {
      return nullptr;
    }

    return new (std::nothrow) Prop(sim, blueprint, transform);
  }

  /**
   * Address: 0x006F9A30 (FUN_006F9A30, Moho::Prop::GetClass)
   */
  gpg::RType* Prop::GetClass() const
  {
    gpg::RType* type = sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Prop));
      sType = type;
    }
    return type;
  }

  /**
   * Address: 0x006F9A50 (FUN_006F9A50, Moho::Prop::GetDerivedObjectRef)
   */
  gpg::RRef Prop::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x006F9A70 (FUN_006F9A70)
   */
  Prop* Prop::IsProp()
  {
    return this;
  }

  /**
   * Address: 0x006FA2A0 (FUN_006FA2A0)
   */
  void Prop::Sync(SSyncData* syncData)
  {
    if (mOnDestroyDispatched != 0u) {
      if (mInterfaceCreated != 0u) {
        DestroyInterface(syncData);
      }
    } else {
      if (mInterfaceCreated == 0u) {
        CreateInterface(syncData);
      }
      SyncInterface(syncData);
    }

    const bool samePosition =
      Position.x == PrevPosition.x && Position.y == PrevPosition.y && Position.z == PrevPosition.z;
    const bool sameOrientation = Orientation.x == PrevOrientation.x && Orientation.y == PrevOrientation.y &&
      Orientation.z == PrevOrientation.z && Orientation.w == PrevOrientation.w;
    if (samePosition && sameOrientation) {
      mCoordNode.ListUnlink();
    }
  }

  /**
   * Address: 0x006F9A80 (FUN_006F9A80)
   */
  float Prop::GetUniformScale() const
  {
    if (!BluePrint) {
      return 1.0f;
    }

    const auto* const blueprint = reinterpret_cast<const RPropBlueprint*>(BluePrint);
    return blueprint->Display.UniformScale;
  }

  /**
   * Address: 0x006F9A90 (FUN_006F9A90)
   */
  bool Prop::IsMobile() const
  {
    return false;
  }

  /**
   * Address: 0x006FA180 (FUN_006FA180)
   */
  float Prop::Materialize(const float reclaimDelta)
  {
    if (reclaimDelta == 0.0f) {
      return 0.0f;
    }

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }

    const float previous = FractionCompleted;
    if (reclaimDelta <= 0.0f) {
      float next = previous + reclaimDelta;
      if (next > 1.0f) {
        next = 1.0f;
      }
      if (next < 0.0f) {
        next = 0.0f;
      }
      FractionCompleted = next;
    } else {
      float next = previous + reclaimDelta;
      if (next > 1.0f) {
        next = 1.0f;
      }
      if (next < 0.0f) {
        next = 0.0f;
      }

      if (MaxHealth > 0.0f) {
        const float minFractionFromHealth = Health / MaxHealth;
        if (next < minFractionFromHealth) {
          next = minFractionFromHealth;
        }
      }
      FractionCompleted = next;
    }

    const float applied = FractionCompleted - previous;
    CallbackStr("BeingReclaimed");

    if (FractionCompleted == 0.0f && reclaimDelta < 0.0f) {
      CallbackStr("OnReclaimed");
      mReclaimTerminated = true;
      QueuePropReclaimDelete(*this);
    }

    return applied;
  }

  /**
   * Address: 0x006FA150 (FUN_006FA150)
   */
  void Prop::Kill(Entity* killer, gpg::StrArg reason, const float overkillRatio)
  {
    Entity::Kill(killer, reason, overkillRatio);
    mReclaimTerminated = true;
  }

  /**
   * Address: 0x006FB0F0 (FUN_006FB0F0, Moho::Prop::MemberDeserialize)
   *
   * What it does:
   * Loads Prop reclaim and priority state after deserializing Entity base lanes.
   */
  void Prop::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};
    const gpg::RType* const entityType = ResolveSerializedType<Entity>(gEntitySerializationType);
    archive->Read(entityType, this, ownerRef);

    archive->ReadFloat(&mReclaimMass);
    archive->ReadFloat(&mReclaimEnergy);
    archive->ReadBool(&mTracksReclaimArea);
    archive->ReadBool(&mReclaimTerminated);

    if (version >= 1) {
      ownerRef = {};
      const gpg::RType* const priorityType = ResolveSerializedType<SPropPriorityInfo>(SPropPriorityInfo::sType);
      archive->Read(priorityType, &mPriorityInfo, ownerRef);
      archive->ReadInt(&mHandleIndex);
    }
  }

  /**
   * Address: 0x006FB1D0 (FUN_006FB1D0, Moho::Prop::MemberSerialize)
   *
   * What it does:
   * Saves Prop reclaim and priority state after serializing Entity base lanes.
   */
  void Prop::MemberSerialize(gpg::WriteArchive* const archive, const int version) const
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};
    const gpg::RType* const entityType = ResolveSerializedType<Entity>(gEntitySerializationType);
    archive->Write(entityType, this, ownerRef);

    archive->WriteFloat(mReclaimMass);
    archive->WriteFloat(mReclaimEnergy);
    archive->WriteBool(mTracksReclaimArea);
    archive->WriteBool(mReclaimTerminated);

    if (version >= 1) {
      ownerRef = {};
      const gpg::RType* const priorityType = ResolveSerializedType<SPropPriorityInfo>(SPropPriorityInfo::sType);
      archive->Write(priorityType, &mPriorityInfo, ownerRef);
      archive->WriteInt(mHandleIndex);
    }
  }
} // namespace moho

namespace
{
  struct PropLuaFactoryBootstrap
  {
    PropLuaFactoryBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_Prop_Index();
    }
  };

  [[maybe_unused]] PropLuaFactoryBootstrap gPropLuaFactoryBootstrap;
} // namespace
