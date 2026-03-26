#include "Entity.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <string>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityMotor.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"

namespace
{
  enum class BlueprintKind : std::uint8_t
  {
    Unknown = 0,
    Unit,
    Projectile,
    Prop
  };

  [[nodiscard]] BlueprintKind GuessBlueprintKind(const moho::REntityBlueprint* blueprint)
  {
    if (!blueprint) {
      return BlueprintKind::Unknown;
    }

    const std::string scriptModule = blueprint->mScriptModule.to_std();
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "projectile")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "unit")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "prop")) {
      return BlueprintKind::Prop;
    }

    const std::string scriptClass = blueprint->mScriptClass.to_std();
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Projectile")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Unit")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Prop")) {
      return BlueprintKind::Prop;
    }

    const std::string id = blueprint->mBlueprintId.to_std();
    if (gpg::STR_ContainsNoCase(id.c_str(), "/projectiles/")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_ContainsNoCase(id.c_str(), "/units/")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_ContainsNoCase(id.c_str(), "/props/")) {
      return BlueprintKind::Prop;
    }

    return BlueprintKind::Unknown;
  }

  struct ScriptFallbackSpec
  {
    const char* module;
    const char* className;
  };

  [[nodiscard]] ScriptFallbackSpec GetScriptFallbackSpec(const BlueprintKind kind)
  {
    switch (kind) {
    case BlueprintKind::Unit:
      return {"/lua/sim/unit.lua", "Unit"};
    case BlueprintKind::Projectile:
      return {"/lua/sim/projectile.lua", "Projectile"};
    case BlueprintKind::Prop:
      return {"/lua/sim/prop.lua", "Prop"};
    default:
      return {nullptr, nullptr};
    }
  }

  [[nodiscard]] std::string BuildBlueprintScriptModuleFromId(const moho::REntityBlueprint* blueprint)
  {
    if (!blueprint) {
      return {};
    }

    std::string id = blueprint->mBlueprintId.to_std();
    if (id.empty()) {
      return {};
    }

    gpg::STR_NormalizeFilenameLowerSlash(id);

    std::size_t start = 0;
    if (!id.empty() && id.front() == '/') {
      start = 1;
    }
    const std::size_t underscorePos = id.find('_', start);
    if (underscorePos == std::string::npos || underscorePos <= start) {
      return {};
    }

    return "/" + id.substr(start, underscorePos - start) + "_script.lua";
  }

  [[nodiscard]] LuaPlus::LuaObject
  ResolveBlueprintScriptFactory(moho::Sim* sim, const moho::REntityBlueprint* blueprint)
  {
    if (!sim || !sim->mLuaState) {
      return {};
    }

    const BlueprintKind kind = GuessBlueprintKind(blueprint);
    const ScriptFallbackSpec fallback = GetScriptFallbackSpec(kind);
    if (!fallback.module || !fallback.className) {
      const char* id = (blueprint && !blueprint->mBlueprintId.empty()) ? blueprint->mBlueprintId.c_str() : "<unknown>";
      gpg::Warnf("Can't tell the type of blueprint id '%s'.  No scripts for you -- one year.", id);
      return {};
    }

    const char* requestedClass = "TypeClass";
    if (blueprint && !blueprint->mScriptClass.empty()) {
      requestedClass = blueprint->mScriptClass.c_str();
    }

    std::string requestedModuleStorage;
    const char* requestedModule = nullptr;
    if (blueprint && !blueprint->mScriptModule.empty()) {
      requestedModule = blueprint->mScriptModule.c_str();
    } else {
      requestedModuleStorage = BuildBlueprintScriptModuleFromId(blueprint);
      if (!requestedModuleStorage.empty()) {
        requestedModule = requestedModuleStorage.c_str();
      }
    }

    if (requestedModule && *requestedModule) {
      LuaPlus::LuaObject requestedModuleObj = moho::SCR_ImportLuaModule(sim->mLuaState, requestedModule);
      if (requestedModuleObj) {
        LuaPlus::LuaObject factoryObj =
          moho::SCR_GetLuaTableField(sim->mLuaState, requestedModuleObj, requestedClass);
        if (factoryObj) {
          return factoryObj;
        }

        gpg::Warnf(
          "Script module '%s' exists but doesn't define '%s'.\nFalling back to '%s' in module '%s'.",
          requestedModule,
          requestedClass,
          fallback.className,
          fallback.module
        );
      } else {
        gpg::Warnf(
          "Problems loading module '%s'.  Falling back to '%s' in '%s'.",
          requestedModule,
          fallback.className,
          fallback.module
        );
      }
    }

    LuaPlus::LuaObject fallbackModuleObj = moho::SCR_ImportLuaModule(sim->mLuaState, fallback.module);
    if (fallbackModuleObj) {
      LuaPlus::LuaObject fallbackFactory =
        moho::SCR_GetLuaTableField(sim->mLuaState, fallbackModuleObj, fallback.className);
      if (fallbackFactory) {
        return fallbackFactory;
      }

      gpg::Warnf(
        "Script module '%s' exists but doesn't define '%s'.\nNo scripts for you -- one year.",
        fallback.module,
        fallback.className
      );
    } else {
      gpg::Warnf("Can't find module '%s'.  No scripts for you -- one year.", fallback.module);
    }

    return {};
  }

  [[nodiscard]] moho::CArmyImpl* ResolveEntityArmyFromEntityId(moho::Sim* sim, const moho::EntId entityId) noexcept
  {
    if (!sim) {
      return nullptr;
    }

    const std::uint8_t sourceIndex = moho::ExtractEntityIdSourceIndex(static_cast<std::uint32_t>(entityId));
    if (sourceIndex == moho::kEntityIdSourceIndexInvalid) {
      return nullptr;
    }

    if (sourceIndex >= sim->mArmiesList.size()) {
      return nullptr;
    }

    return sim->mArmiesList[sourceIndex];
  }

  void RegisterEntityInDbIfMissing(moho::Sim* sim, moho::Entity* entity)
  {
    if (!sim || !entity || !sim->mEntityDB) {
      return;
    }

    auto& entities = sim->mEntityDB->Entities();
    for (auto it = entities.begin(); it != entities.end(); ++it) {
      if (*it == entity) {
        return;
      }
    }
    entities.push_back(entity);
  }

  [[nodiscard]] std::uint8_t ComputeFootprintOccupancyMask(
    const moho::Entity* entity, const moho::SFootprint& footprint, const Wm3::Vec3f&
  ) noexcept
  {
    (void)entity;
    // 0x007209E0 (`Moho::OCCUPY_FootprintFits`) also considers dynamic map blockers;
    // current typed recovery keeps the capability mask for layer bootstrap.
    return static_cast<std::uint8_t>(footprint.mOccupancyCaps);
  }

  [[nodiscard]] float SampleHeightFieldBilinear(const moho::CHeightField* field, const float x, const float z) noexcept
  {
    if (!field || !field->data || field->width <= 0 || field->height <= 0) {
      return 0.0f;
    }

    const int width = field->width;
    const int height = field->height;

    const int baseX = static_cast<int>(std::floor(static_cast<double>(x)));
    const int baseZ = static_cast<int>(std::floor(static_cast<double>(z)));
    const float fracX = x - static_cast<float>(baseX);
    const float fracZ = z - static_cast<float>(baseZ);

    auto sample = [&](int sx, int sz) -> float {
      if (sx < 0) {
        sx = 0;
      } else if (sx >= width) {
        sx = width - 1;
      }
      if (sz < 0) {
        sz = 0;
      } else if (sz >= height) {
        sz = height - 1;
      }

      const std::uint16_t packed = field->data[sz * width + sx];
      return static_cast<float>(packed) * 0.0078125f;
    };

    const float h00 = sample(baseX, baseZ);
    const float h10 = sample(baseX + 1, baseZ);
    const float h01 = sample(baseX, baseZ + 1);
    const float h11 = sample(baseX + 1, baseZ + 1);

    const float h0 = h00 + (h10 - h00) * fracX;
    const float h1 = h01 + (h11 - h01) * fracX;
    return h0 + (h1 - h0) * fracZ;
  }

  [[nodiscard]] Wm3::Vector3f RotateVectorByQuaternion(const moho::Vector4f& q, const Wm3::Vector3f& v) noexcept
  {
    // Entity orientation is packed as (w,x,y,z) in Vector4f::x/y/z/w slots.
    const Wm3::Quatf quaternion{q.x, q.y, q.z, q.w};
    Wm3::Vector3f out{};
    Wm3::MultiplyQuaternionVector(&out, v, quaternion);
    return out;
  }

  [[nodiscard]] std::uint8_t LayerToOccupancyBit(const moho::ELayer layer) noexcept
  {
    switch (layer) {
    case moho::LAYER_Land:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_LAND);
    case moho::LAYER_Seabed:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SEABED);
    case moho::LAYER_Sub:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SUB);
    case moho::LAYER_Water:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_WATER);
    case moho::LAYER_Air:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_AIR);
    case moho::LAYER_Orbit:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_ORBIT);
    default:
      return 0u;
    }
  }

  [[nodiscard]] bool HasOccupancyBit(const moho::EOccupancyCaps caps, const std::uint8_t bit) noexcept
  {
    return (static_cast<std::uint8_t>(caps) & bit) != 0u;
  }

  struct CollisionCellRect
  {
    std::uint16_t startX;
    std::uint16_t startZ;
    std::uint16_t width;
    std::uint16_t height;
  };

  [[nodiscard]] int FloorToInt(const float value) noexcept
  {
    return static_cast<int>(std::floor(static_cast<double>(value)));
  }

  [[nodiscard]] int CeilToInt(const float value) noexcept
  {
    return static_cast<int>(std::ceil(static_cast<double>(value)));
  }

  [[nodiscard]] std::uint16_t ClampCellStartToU16(const int value) noexcept
  {
    if (value <= 0) {
      return 0;
    }
    if (value >= 0xFFFF) {
      return 0xFFFFu;
    }
    return static_cast<std::uint16_t>(value);
  }

  [[nodiscard]] std::uint16_t ClampCellExtentToU16(const int extentCandidate, const std::uint16_t startCell) noexcept
  {
    const int maxExtent = 0xFFFF - static_cast<int>(startCell);
    int extent = extentCandidate;
    if (extent >= maxExtent) {
      extent = maxExtent;
    }
    if (extent < 0) {
      extent = 0;
    }
    return static_cast<std::uint16_t>(extent);
  }

  /**
   * Address: 0x004FCBE0 (FUN_004FCBE0)
   *
   * What it does:
   * Converts world-space AABB bounds into quantized collision-cell rectangle:
   * {startX,startZ,width,height}.
   */
  [[nodiscard]] CollisionCellRect
  BuildCollisionCellRectFromBounds(const moho::EntityCollisionBoundsView& bounds) noexcept
  {
    const int minCellX = FloorToInt(bounds.minX) >> 2;
    const int minCellZ = FloorToInt(bounds.minZ) >> 2;
    const int maxCellX = (CeilToInt(bounds.maxX) + 3) >> 2;
    const int maxCellZ = (CeilToInt(bounds.maxZ) + 3) >> 2;

    CollisionCellRect rect{};
    rect.startX = ClampCellStartToU16(minCellX);
    rect.startZ = ClampCellStartToU16(minCellZ);
    rect.width = ClampCellExtentToU16(maxCellX - static_cast<int>(rect.startX), rect.startX);
    rect.height = ClampCellExtentToU16(maxCellZ - static_cast<int>(rect.startZ), rect.startZ);
    return rect;
  }

  /**
   * Address: 0x004FD9B0 (FUN_004FD9B0, append-path subset)
   *
   * What it does:
   * Pushes one chunk-base pointer into the grid chunk-pointer vector
   * (layout at +0x28/+0x2C/+0x30).
   */
  void AppendCollisionChunkPointer(moho::EntityCollisionSpatialGrid& grid, moho::EntityCollisionCellNode* chunkBase)
  {
    auto** begin = grid.mChunkBlocksBegin;
    auto** end = grid.mChunkBlocksEnd;
    auto** capacityEnd = grid.mChunkBlocksCapacityEnd;

    if (begin && end < capacityEnd) {
      *end = chunkBase;
      grid.mChunkBlocksEnd = end + 1;
      return;
    }

    const std::size_t size = begin ? static_cast<std::size_t>(end - begin) : 0u;
    const std::size_t capacity = begin ? static_cast<std::size_t>(capacityEnd - begin) : 0u;

    if (capacity >= 0x3FFFFFFFu) {
      throw std::length_error("vector<T> too long");
    }

    std::size_t newCapacity = capacity + (capacity >> 1);
    const std::size_t minCapacity = size + 1u;
    if (newCapacity < minCapacity) {
      newCapacity = minCapacity;
    }
    if (newCapacity > 0x3FFFFFFFu) {
      newCapacity = minCapacity;
    }

    auto** newBegin = static_cast<moho::EntityCollisionCellNode**>(
      ::operator new(newCapacity * sizeof(moho::EntityCollisionCellNode*))
    );
    if (size != 0u && begin) {
      std::memmove(newBegin, begin, size * sizeof(*begin));
    }
    newBegin[size] = chunkBase;

    if (begin) {
      ::operator delete(begin);
    }

    grid.mChunkBlocksBegin = newBegin;
    grid.mChunkBlocksEnd = newBegin + size + 1u;
    grid.mChunkBlocksCapacityEnd = newBegin + newCapacity;
  }

  /**
   * Address: 0x004FCE90 (FUN_004FCE90)
   *
   * What it does:
   * Ensures free-node list contains at least `requiredFreeNodes` entries by
   * allocating 0x2000-node chunks (0x10000 bytes each) and linking them.
   */
  void EnsureCollisionFreeNodes(moho::EntityCollisionSpatialGrid& grid, const int requiredFreeNodes)
  {
    while (grid.mFreeNodeCount < requiredFreeNodes) {
      auto* chunk = static_cast<moho::EntityCollisionCellNode*>(::operator new(0x10000u));
      for (int i = 0; i < 0x1FFF; ++i) {
        chunk[i].next = &chunk[i + 1];
      }

      chunk[0x1FFF].next = grid.mFreeNodeHead;
      grid.mFreeNodeHead = chunk;

      AppendCollisionChunkPointer(grid, chunk);
      grid.mFreeNodeCount += 0x2000;
    }
  }

  [[nodiscard]] moho::EntityCollisionCellNode**
  SelectCollisionBucketHeadArray(moho::EntityCollisionSpatialGrid& grid, const std::uint32_t bucketFlags) noexcept
  {
    if ((bucketFlags & 0x100u) != 0u) {
      return grid.mBucketHeads100;
    }
    if ((bucketFlags & 0x200u) != 0u) {
      return grid.mBucketHeads200;
    }
    if ((bucketFlags & 0x0C00u) != 0u) {
      return grid.mBucketHeadsC00;
    }
    return nullptr;
  }

  /**
   * Address: 0x004FCF20 (FUN_004FCF20)
   *
   * What it does:
   * Pops one node from the grid free-list, tags ownership to `span`, then
   * prepends it to the selected collision bucket chain.
   */
  void InsertSpanNodeIntoBucket(moho::EntityCollisionCellSpan& span, const int bucketIndex)
  {
    if ((span.mBucketFlags & 0x0F00u) == 0u) {
      return;
    }

    moho::EntityCollisionSpatialGrid& grid = *span.mSpatialGrid;
    moho::EntityCollisionCellNode* const node = grid.mFreeNodeHead;
    grid.mFreeNodeHead = node->next;
    node->owner = &span;

    moho::EntityCollisionCellNode** const bucketHeads = SelectCollisionBucketHeadArray(grid, span.mBucketFlags);
    node->next = bucketHeads[bucketIndex];
    bucketHeads[bucketIndex] = node;

    --grid.mFreeNodeCount;
  }

  /**
   * Address: 0x004FCF90 (FUN_004FCF90)
   *
   * What it does:
   * Removes `span` node from the selected bucket chain and returns the node
   * to the grid free-list.
   */
  void RemoveSpanNodeFromBucket(
    const int bucketIndex, moho::EntityCollisionSpatialGrid& grid, moho::EntityCollisionCellSpan& span
  )
  {
    if ((span.mBucketFlags & 0x0F00u) == 0u) {
      return;
    }

    moho::EntityCollisionCellNode** const bucketHeads = SelectCollisionBucketHeadArray(grid, span.mBucketFlags);
    moho::EntityCollisionCellNode** link = &bucketHeads[bucketIndex];
    moho::EntityCollisionCellNode* node = *link;
    while (node->owner != &span) {
      link = &node->next;
      node = node->next;
    }

    *link = node->next;
    node->owner = nullptr;
    node->next = grid.mFreeNodeHead;
    ++grid.mFreeNodeCount;
    grid.mFreeNodeHead = node;
  }

  /**
   * Address: 0x004FD420 (FUN_004FD420)
   *
   * What it does:
   * Adds current span membership into collision buckets for all covered cells.
   */
  void AddSpanMembership(moho::EntityCollisionCellSpan& span)
  {
    moho::EntityCollisionSpatialGrid& grid = *span.mSpatialGrid;
    const std::int32_t requiredNodes = static_cast<std::int32_t>(
      static_cast<std::uint32_t>(span.mCellWidth) * static_cast<std::uint32_t>(span.mCellHeight)
    );
    EnsureCollisionFreeNodes(grid, requiredNodes);

    int rowBase = static_cast<int>(span.mCellStartX) + (static_cast<int>(span.mCellStartZ) << grid.mRowShift);
    for (int row = 0; row < static_cast<int>(span.mCellHeight); ++row) {
      for (int col = 0; col < static_cast<int>(span.mCellWidth); ++col) {
        const int bucketIndex = (rowBase + col) & static_cast<int>(grid.mBucketMask);
        InsertSpanNodeIntoBucket(span, bucketIndex);
      }
      rowBase += grid.mRowStride;
    }
  }

  /**
   * Address: 0x004FD490 (FUN_004FD490)
   *
   * What it does:
   * Removes current span membership from collision buckets for all covered cells.
   */
  void RemoveSpanMembership(moho::EntityCollisionCellSpan& span)
  {
    moho::EntityCollisionSpatialGrid& grid = *span.mSpatialGrid;
    int rowBase = static_cast<int>(span.mCellStartX) + (static_cast<int>(span.mCellStartZ) << grid.mRowShift);
    for (int row = 0; row < static_cast<int>(span.mCellHeight); ++row) {
      for (int col = 0; col < static_cast<int>(span.mCellWidth); ++col) {
        const int bucketIndex = (rowBase + col) & static_cast<int>(grid.mBucketMask);
        RemoveSpanNodeFromBucket(bucketIndex, grid, span);
      }
      rowBase += grid.mRowStride;
    }
  }

  [[nodiscard]] bool
  CollisionCellRectEqualsSpan(const CollisionCellRect& rect, const moho::EntityCollisionCellSpan& span) noexcept
  {
    return rect.startX == span.mCellStartX && rect.startZ == span.mCellStartZ && rect.width == span.mCellWidth &&
      rect.height == span.mCellHeight;
  }

  void RelinkSpanToRectIfChanged(moho::EntityCollisionCellSpan& span, const CollisionCellRect& nextRect)
  {
    if (CollisionCellRectEqualsSpan(nextRect, span)) {
      return;
    }

    RemoveSpanMembership(span);
    span.mCellStartX = nextRect.startX;
    span.mCellStartZ = nextRect.startZ;
    span.mCellWidth = nextRect.width;
    span.mCellHeight = nextRect.height;
    AddSpanMembership(span);
  }

  /**
   * Address: 0x004FD590 (FUN_004FD590)
   *
   * What it does:
   * Rebuilds quantized collision-cell rectangle directly from bounds and
   * relinks bucket membership only when span changed.
   */
  void RelinkSpanFromBoundsIfChanged(moho::EntityCollisionCellSpan& span, const moho::EntityCollisionBoundsView& bounds)
  {
    const CollisionCellRect nextRect = BuildCollisionCellRectFromBounds(bounds);
    RelinkSpanToRectIfChanged(span, nextRect);
  }

  /**
   * Address: 0x004FD4F0 (FUN_004FD4F0)
   *
   * What it does:
   * Reads primitive AABB, rebuilds quantized span rectangle, and if changed:
   * removes old bucket membership, writes new rectangle, then re-adds membership.
   */
  void RelinkSpanFromCollisionPrimitive(
    moho::EntityCollisionCellSpan& span, const moho::EntityCollisionUpdater* collisionPrimitive
  )
  {
    if (collisionPrimitive) {
      moho::EntityCollisionBoundsScratch scratchBounds{};
      const moho::EntityCollisionBoundsView* const bounds = collisionPrimitive->GetBoundingBox(&scratchBounds);
      RelinkSpanFromBoundsIfChanged(span, *bounds);
      return;
    }

    RelinkSpanToRectIfChanged(span, CollisionCellRect{});
  }

  void RefreshCollisionBoundsSnapshot(moho::Entity& entity)
  {
    if (!entity.CollisionExtents) {
      return;
    }

    moho::EntityCollisionBoundsScratch scratchBounds{};
    const moho::EntityCollisionBoundsView* const bounds = entity.CollisionExtents->GetBoundingBox(&scratchBounds);
    entity.mCollisionBoundsMin.x = bounds->minX;
    entity.mCollisionBoundsMin.y = bounds->minY;
    entity.mCollisionBoundsMin.z = bounds->minZ;
    entity.mCollisionBoundsMax.x = bounds->maxX;
    entity.mCollisionBoundsMax.y = bounds->maxY;
    entity.mCollisionBoundsMax.z = bounds->maxZ;
  }

  /**
   * Address: 0x0067AE00 (shared body used by FUN_0067AC40/FUN_0067AD30/FUN_0067AE00)
   *
   * What it does:
   * Replaces collision primitive pointer, relinks span as needed, and keeps
   * cached collision bounds in sync.
   */
  void InstallCollisionPrimitiveAndRefresh(moho::Entity& entity, moho::EntityCollisionUpdater* replacement)
  {
    moho::EntityCollisionUpdater* const old = entity.CollisionExtents;
    entity.CollisionExtents = replacement;
    ::operator delete(old);

    if (!entity.CollisionExtents) {
      RelinkSpanToRectIfChanged(entity.mCollisionCellSpan, CollisionCellRect{});
      return;
    }

    const moho::EntityTransformPayload current = moho::ReadEntityTransformPayload(entity.Orientation, entity.Position);
    entity.CollisionExtents->SetTransform(current);
    RelinkSpanFromCollisionPrimitive(entity.mCollisionCellSpan, entity.CollisionExtents);
    RefreshCollisionBoundsSnapshot(entity);
  }

  [[nodiscard]] Wm3::Box3f BuildBlueprintCollisionBox(const moho::REntityBlueprint& blueprint)
  {
    Wm3::Box3f localBox{};
    localBox.Center[0] = blueprint.mCollisionOffsetX;
    localBox.Center[1] = blueprint.mCollisionOffsetY + blueprint.mSizeY * 0.5f;
    localBox.Center[2] = blueprint.mCollisionOffsetZ;

    localBox.Axis[0][0] = 1.0f;
    localBox.Axis[0][1] = 0.0f;
    localBox.Axis[0][2] = 0.0f;
    localBox.Axis[1][0] = 0.0f;
    localBox.Axis[1][1] = 1.0f;
    localBox.Axis[1][2] = 0.0f;
    localBox.Axis[2][0] = 0.0f;
    localBox.Axis[2][1] = 0.0f;
    localBox.Axis[2][2] = 1.0f;

    localBox.Extent[0] = blueprint.mSizeX * 0.5f;
    localBox.Extent[1] = blueprint.mSizeY * 0.5f;
    localBox.Extent[2] = blueprint.mSizeZ * 0.5f;
    return localBox;
  }

  [[nodiscard]] Wm3::Vec3f BuildBlueprintCollisionCenter(const moho::REntityBlueprint& blueprint)
  {
    Wm3::Vec3f center{};
    center.x = blueprint.mCollisionOffsetX;
    center.y = blueprint.mCollisionOffsetY + blueprint.mSizeY * 0.5f;
    center.z = blueprint.mCollisionOffsetZ;
    return center;
  }

  /**
   * Address: 0x00678E90 (FUN_00678E90)
   *
   * What it does:
   * Stores pending transform/scalar and links the coord-node into Sim list
   * when it is currently detached.
   */
  void SetPendingTransformAndEnsureCoordLink(
    moho::Entity& entity, const moho::EntityTransformPayload& pending, const float pendingAux
  )
  {
    moho::WriteEntityTransformPayload(entity.PendingOrientation, entity.PendingPosition, pending);
    entity.mPendingVelocityScale = pendingAux;

    if (entity.SimulationRef && entity.mCoordNode.ListIsSingleton()) {
      entity.mCoordNode.ListLinkBefore(&entity.SimulationRef->mCoordEntities);
    }
  }

  [[nodiscard]] std::uint32_t ReadBlueprintCategoryBitIndex(const moho::REntityBlueprint* blueprint) noexcept
  {
    return blueprint ? blueprint->mCategoryBitIndex : 0u;
  }

  struct MeshBoneEntryView
  {
    std::uint8_t bytes[0x58];
  };

  static_assert(sizeof(MeshBoneEntryView) == 0x58, "MeshBoneEntryView size must be 0x58");

  struct MeshObjectBoneSpanView
  {
    std::uint8_t pad_00_10[0x10];
    const MeshBoneEntryView* boneBegin; // +0x10
    const MeshBoneEntryView* boneEnd;   // +0x14
  };

  static_assert(
    offsetof(MeshObjectBoneSpanView, boneBegin) == 0x10, "MeshObjectBoneSpanView::boneBegin offset must be 0x10"
  );
  static_assert(
    offsetof(MeshObjectBoneSpanView, boneEnd) == 0x14, "MeshObjectBoneSpanView::boneEnd offset must be 0x14"
  );

  struct AttachRuntimeNodeView
  {
    AttachRuntimeNodeView* next;
    AttachRuntimeNodeView* prev;
    std::uint8_t pad_08[0x04];
    AttachRuntimeNodeView** owner;
    std::uint8_t pad_10[0x04];
    std::int32_t pendingValue;
    std::uint8_t queuedFlag;
    std::uint8_t pad_19[0x03];
  };

  static_assert(offsetof(AttachRuntimeNodeView, owner) == 0x0C, "AttachRuntimeNodeView::owner offset must be 0x0C");
  static_assert(
    offsetof(AttachRuntimeNodeView, pendingValue) == 0x14, "AttachRuntimeNodeView::pendingValue offset must be 0x14"
  );
  static_assert(
    offsetof(AttachRuntimeNodeView, queuedFlag) == 0x18, "AttachRuntimeNodeView::queuedFlag offset must be 0x18"
  );

  /**
   * Address: 0x00679550 (inlined block)
   *
   * What it does:
   * Relinks an attached runtime node back to its owner list when it is marked queued.
   */
  void ResetAttachRuntimeNodeIfQueued(moho::Entity* entity)
  {
    if (!entity) {
      return;
    }

    auto* node = reinterpret_cast<AttachRuntimeNodeView*>(entity->mSubtask);
    if (!node || node->queuedFlag == 0u) {
      return;
    }

    node->pendingValue = 0;

    AttachRuntimeNodeView* const next = node->next;
    AttachRuntimeNodeView* const prev = node->prev;
    if (next && prev) {
      next->prev = prev;
      prev->next = next;
    }

    node->next = node;
    node->prev = node;

    AttachRuntimeNodeView** const owner = node->owner;
    if (owner) {
      node->next = *owner;
      node->prev = reinterpret_cast<AttachRuntimeNodeView*>(owner);
      *owner = node;
      if (node->next) {
        node->next->prev = node;
      }
    }

    node->queuedFlag = 0u;
  }

  /**
   * Address: 0x00679680 (FUN_00679680)
   *
   * What it does:
   * Applies attach-link/local transform from `src` into `dst`, including
   * intrusive weak-chain rewire when attach owner changes.
   */
  void ApplyAttachInfo(moho::SEntAttachInfo& dst, const moho::SEntAttachInfo& src)
  {
    moho::WeakPtr<moho::Entity>& dstWeak = dst.TargetWeakLink();
    const moho::WeakPtr<moho::Entity>& srcWeak = src.TargetWeakLink();

    if (dstWeak.ownerLinkSlot != srcWeak.ownerLinkSlot) {
      dstWeak.ResetFromOwnerLinkSlot(srcWeak.ownerLinkSlot);
    }

    dst.mParentBoneIndex = src.mParentBoneIndex;
    dst.mChildBoneIndex = src.mChildBoneIndex;
    dst.mRelativeOrientX = src.mRelativeOrientX;
    dst.mRelativeOrientY = src.mRelativeOrientY;
    dst.mRelativeOrientZ = src.mRelativeOrientZ;
    dst.mRelativeOrientW = src.mRelativeOrientW;
    dst.mRelativePosX = src.mRelativePosX;
    dst.mRelativePosY = src.mRelativePosY;
    dst.mRelativePosZ = src.mRelativePosZ;
  }

  struct DestroyQueueNodeView
  {
    DestroyQueueNodeView* next;
    DestroyQueueNodeView* prev;
    moho::Entity* entity;
  };

  static_assert(sizeof(DestroyQueueNodeView) == 0x0C, "DestroyQueueNodeView size must be 0x0C");

  struct CommandDbDestroyQueueView
  {
    std::uint8_t pad_00[0x20];
    std::int32_t count;         // +0x20
    DestroyQueueNodeView* head; // +0x24
  };

  static_assert(
    offsetof(CommandDbDestroyQueueView, count) == 0x20, "CommandDbDestroyQueueView::count offset must be 0x20"
  );
  static_assert(
    offsetof(CommandDbDestroyQueueView, head) == 0x24, "CommandDbDestroyQueueView::head offset must be 0x24"
  );

  /**
   * Address: 0x00679B80 (inlined with FUN_0067DE00/FUN_0067DE40)
   *
   * What it does:
   * Inserts entity into command-db destroy queue linked-list and increments queue size.
   */
  void QueueEntityForDestroy(moho::Entity* entity)
  {
    if (!entity || !entity->SimulationRef || !entity->SimulationRef->mCommandDB) {
      return;
    }

    auto* queue = reinterpret_cast<CommandDbDestroyQueueView*>(entity->SimulationRef->mCommandDB);
    DestroyQueueNodeView* const head = queue->head;
    if (!head) {
      return;
    }

    if (queue->count == 0x3FFFFFFF) {
      throw std::length_error("list<T> too long");
    }

    auto* node = reinterpret_cast<DestroyQueueNodeView*>(::operator new(sizeof(DestroyQueueNodeView)));
    node->next = head;
    node->prev = head->prev;
    node->entity = entity;

    ++queue->count;
    head->prev = node;
    node->prev->next = node;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00676C40
   *
   * What it does:
   * Returns cached reflection descriptor for Entity.
   */
  gpg::RType* Entity::GetClass() const
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(Entity));
    }
    return sEntityType;
  }

  /**
   * Address: 0x00676C60
   *
   * What it does:
   * Packs {this, GetClass()} as a reflection reference handle.
   */
  gpg::RRef Entity::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x00677C90 (FUN_00677C90)
   *
   * What it does:
   * Initializes Entity base state blocks, binds script object from blueprint module,
   * seeds collision/grid metadata, and dispatches `StandardInit`.
   */
  Entity::Entity(REntityBlueprint* blueprint, Sim* sim, const EntId entityId, const std::uint32_t collisionBucketFlags)
    : CTask(nullptr, false)
  {
    std::memset(pad_011E, 0, sizeof(pad_011E));
    std::memset(pad_0120, 0, sizeof(pad_0120));
    std::memset(pad_0174, 0, sizeof(pad_0174));
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    std::memset(pad_01F8_01FC, 0, sizeof(pad_01F8_01FC));
    std::memset(pad_0258, 0, sizeof(pad_0258));

    LuaPlus::LuaObject arg1{};
    LuaPlus::LuaObject arg2{};
    LuaPlus::LuaObject arg3{};
    LuaPlus::LuaObject scriptFactory = ResolveBlueprintScriptFactory(sim, blueprint);
    CreateLuaObject(scriptFactory, arg1, arg2, arg3);

    mCollisionCellSpan.mCellStartX = 0u;
    mCollisionCellSpan.mCellStartZ = 0u;
    mCollisionCellSpan.mCellWidth = 0u;
    mCollisionCellSpan.mCellHeight = 0u;
    mCollisionCellSpan.mSpatialGrid =
      (sim && sim->mOGrid) ? reinterpret_cast<EntityCollisionSpatialGrid*>(&sim->mOGrid->entityGrid) : nullptr;
    mCollisionCellSpan.mReserved0C = 0u;
    mCollisionCellSpan.mBucketFlags = collisionBucketFlags;

    mCoordNode.ListUnlink();

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    mMeshRef = {};
    mMeshTypeClassId = 0;

    mDrawScaleX = 1.0f;
    mDrawScaleY = 1.0f;
    mDrawScaleZ = 1.0f;

    Health = 0.0f;
    MaxHealth = 0.0f;
    BeingBuilt = 0u;
    Dead = 0u;
    DirtySyncState = 0u;
    mDestroyedByKill = 0u;

    Orientation = {1.0f, 0.0f, 0.0f, 0.0f};
    Position = {0.0f, 0.0f, 0.0f};
    PrevOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PrevPosition = {0.0f, 0.0f, 0.0f};
    mVelocityScale = 0.0f;
    FractionCompleted = 0.0f;

    mVisibilityState = 0u;
    mFootprintLayer = 0;
    mCurrentLayer = LAYER_None;
    mUseAltFootprint = 0u;
    mUseAltFootprintSecondary = 0u;

    SimulationRef = nullptr;
    ArmyRef = nullptr;

    PendingOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    PendingPosition = {0.0f, 0.0f, 0.0f};
    mPositionHistory = nullptr;
    mPendingVelocityScale = 1.0f;
    CollisionExtents = nullptr;

    mAttachInfo = SEntAttachInfo::MakeDetached();

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVisibilityLayerFriendly = 2;
    mVisibilityLayerEnemy = 2;
    mVisibilityLayerNeutral = 4;
    mVisibilityLayerDefault = 2;
    mInterfaceCreated = 0u;
    readinessFlags = 0;
    mCollisionBoundsMin = {0.0f, 0.0f, 0.0f};
    mCollisionBoundsMax = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    BluePrint = blueprint;
    StandardInit(sim, entityId);
  }

  /**
   * Address: 0x00678370 (FUN_00678370)
   *
   * What it does:
   * Applies runtime identity ownership (sim/army/id), initializes interface/visibility
   * defaults, registers entity in sim db/lists, and initializes collision shape.
   */
  void Entity::StandardInit(Sim* sim, const EntId entityId)
  {
    SimulationRef = sim;
    ArmyRef = ResolveEntityArmyFromEntityId(sim, entityId);
    id_ = entityId;
    mTickCreated = sim ? sim->mCurTick : 0u;
    mReserved74 = 0u;

    Dead = 0u;
    mCurrentLayer = LAYER_None;
    mPendingVelocityScale = 1.0f;
    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    readinessFlags = 0;
    mInterfaceCreated = 0u;

    mVisibilityLayerFriendly = 2;
    mVisibilityLayerEnemy = 2;
    mVisibilityLayerNeutral = 4;
    mVisibilityLayerDefault = 2;

    RegisterEntityInDbIfMissing(sim, this);
    RefreshCollisionShapeFromBlueprint();

    if (SimulationRef) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x0062AD30 / 0x00678880 (FUN_0062AD30/FUN_00678880)
   *
   * What it does:
   * Chooses initial simulation layer from footprint occupancy, category hints,
   * map water elevation and terrain elevation at spawn coordinates.
   */
  ELayer Entity::GetStartingLayer(const Wm3::Vec3f& worldPos, const ELayer desiredLayer) const
  {
    const SFootprint& footprint = GetFootprint();
    const std::uint8_t occupancyMask = ComputeFootprintOccupancyMask(this, footprint, worldPos);

    const bool isExperimental = IsInCategory("EXPERIMENTAL");
    const bool isBeacon = IsInCategory("FERRYBEACON");

    const std::uint8_t desiredMaskBit = LayerToOccupancyBit(desiredLayer);
    if ((occupancyMask & desiredMaskBit) != 0u) {
      return desiredLayer;
    }

    if ((occupancyMask & static_cast<std::uint8_t>(EOccupancyCaps::OC_AIR)) != 0u) {
      return isExperimental ? LAYER_Land : LAYER_Air;
    }

    const STIMap* const mapData = (SimulationRef ? SimulationRef->mMapData : nullptr);
    const float waterElevation = (mapData && mapData->IsWaterEnabled()) ? mapData->GetWaterElevation() : -10000.0f;
    const float terrainElevation =
      SampleHeightFieldBilinear((mapData ? mapData->GetHeightField() : nullptr), worldPos.x, worldPos.z);

    if (waterElevation <= terrainElevation) {
      return LAYER_Land;
    }

    if (HasOccupancyBit(footprint.mOccupancyCaps, static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)) &&
        !isExperimental) {
      return LAYER_Sub;
    }

    if (HasOccupancyBit(footprint.mOccupancyCaps, static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) || isBeacon) {
      return LAYER_Water;
    }

    return LAYER_Seabed;
  }

  /**
   * Address: 0x00678D40
   *
   * What it does:
   * Base error text provider for script/runtime diagnostics.
   */
  msvc8::string Entity::GetErrorDescription()
  {
    return {};
  }

  /**
   * Address: 0x005BDB10
   */
  Unit* Entity::IsUnit()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB20
   */
  Prop* Entity::IsProp()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB30
   */
  Projectile* Entity::IsProjectile()
  {
    return nullptr;
  }

  /**
   * Address: 0x00672BB0
   */
  ReconBlip* Entity::IsReconBlip()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB40
   */
  CollisionBeamEntity* Entity::IsCollisionBeam()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB50
   */
  Shield* Entity::IsShield()
  {
    return nullptr;
  }

  /**
   * Address: 0x00678BB0
   *
   * What it does:
   * Returns mesh bone count from the loaded mesh skeleton block.
   */
  int Entity::GetBoneCount() const
  {
    if (!mMeshRef.mObj) {
      return 0;
    }

    const auto* const meshObject = static_cast<const MeshObjectBoneSpanView*>(mMeshRef.mObj);
    const MeshBoneEntryView* const begin = meshObject->boneBegin;
    const MeshBoneEntryView* const end = meshObject->boneEnd;
    if (!begin || !end || end < begin) {
      return 0;
    }

    return static_cast<int>(end - begin);
  }

  /**
   * Address: 0x005BDB60
   */
  bool Entity::IsBeingBuilt() const
  {
    return BeingBuilt != 0u;
  }

  /**
   * Address: 0x0067A0A0
   *
   * What it does:
   * Updates visibility + interface sync state and clears dirty-sync marker.
   */
  void Entity::Sync(SSyncData* syncData)
  {
    UpdateVisibility();

    if (mOnDestroyDispatched != 0u || mVisibilityState == 0u) {
      if (mInterfaceCreated != 0u) {
        DestroyInterface(syncData);
      }
    } else {
      if (mInterfaceCreated == 0u) {
        CreateInterface(syncData);
      }
      SyncInterface(syncData);
    }

    DirtySyncState = 0u;

    if (mQueueRelinkBlocked == 0u) {
      mCoordNode.ListUnlink();
    }
  }

  /**
   * Address: 0x0067A720 (FUN_0067A720)
   *
   * What it does:
   * Resolves mesh resource id (or explicit placeholder) and updates mesh binding.
   */
  void
  Entity::SetMesh(const RResId& meshResId, RMeshBlueprint* explicitPlaceholder, const bool allowExplicitPlaceholder)
  {
    RMeshBlueprint* meshBlueprint = nullptr;

    if (SimulationRef && SimulationRef->mRules && !meshResId.name.empty()) {
      meshBlueprint = SimulationRef->mRules->GetMeshBlueprint(meshResId);
    }

    if (!meshBlueprint && allowExplicitPlaceholder) {
      meshBlueprint = explicitPlaceholder;
    }

    mMeshRef.mObj = meshBlueprint;
    mMeshRef.mType = nullptr;
    mMeshTypeClassId = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(meshBlueprint));

    if (!meshBlueprint && !meshResId.name.empty()) {
      gpg::Warnf("Failed to load mesh for blueprint %s", meshResId.name.raw_data_unsafe());
    }
  }

  /**
   * Address: 0x005BDBD0
   */
  float Entity::GetUniformScale() const
  {
    return 1.0f;
  }

  /**
   * Address: 0x00678DC0
   *
   * What it does:
   * Returns frame velocity from current/previous positions scaled by mVelocityScale.
   */
  Wm3::Vec3f Entity::GetVelocity() const
  {
    Wm3::Vec3f velocity{};
    velocity.x = (Position.x - PrevPosition.x) * mVelocityScale;
    velocity.y = (Position.y - PrevPosition.y) * mVelocityScale;
    velocity.z = (Position.z - PrevPosition.z) * mVelocityScale;
    return velocity;
  }

  /**
   * Address: 0x005BDBF0
   */
  bool Entity::IsMobile() const
  {
    return true;
  }

  /**
   * Address: 0x00679F70
   *
   * What it does:
   * CTask execution entry point, forwarding to motion tick logic.
   */
  int Entity::Execute()
  {
    return MotionTick();
  }

  /**
   * Address: 0x00679CE0
   *
   * What it does:
   * Returns world transform for the requested bone (or entity/world-anchor fallback).
   */
  VTransform Entity::GetBoneWorldTransform(const int boneIndex) const
  {
    VTransform result = BuildVTransformFromEntityTransformPayload(ReadEntityTransformPayload(Orientation, Position));

    if (boneIndex != -1 || !BluePrint) {
      return result;
    }

    const Wm3::Vector3f localAnchor{
      BluePrint->mCollisionOffsetX,
      BluePrint->mCollisionOffsetY + BluePrint->mSizeY * 0.5f,
      BluePrint->mCollisionOffsetZ,
    };
    const Wm3::Vector3f rotatedOffset = RotateVectorByQuaternion(Orientation, localAnchor);
    result.pos_.x += rotatedOffset.x;
    result.pos_.y += rotatedOffset.y;
    result.pos_.z += rotatedOffset.z;
    return result;
  }

  /**
   * Address: 0x00679E20
   *
   * What it does:
   * Returns local-space transform for a bone index, with `-1` fallback to blueprint anchor.
   */
  VTransform Entity::GetBoneLocalTransform(const int boneIndex) const
  {
    VTransform result{};
    result.orient_.w = 1.0f;
    result.orient_.x = 0.0f;
    result.orient_.y = 0.0f;
    result.orient_.z = 0.0f;
    result.pos_.x = 0.0f;
    result.pos_.y = 0.0f;
    result.pos_.z = 0.0f;

    if (boneIndex == -1 && BluePrint) {
      result.pos_.x = BluePrint->mCollisionOffsetX;
      result.pos_.y = BluePrint->mCollisionOffsetY + BluePrint->mSizeY * 0.5f;
      result.pos_.z = BluePrint->mCollisionOffsetZ;
    }

    return result;
  }

  /**
   * Address: 0x00679210 (FUN_00679210)
   *
   * What it does:
   * Writes pending transform, advances twice, then updates entity intel manager.
   */
  void Entity::Warp(const VTransform& transform)
  {
    const EntityTransformPayload pending = ReadEntityTransformPayload(transform);
    SetPendingTransformAndEnsureCoordLink(*this, pending, 1.0f);
    AdvanceCoords();
    AdvanceCoords();

    if (mIntelManager && SimulationRef) {
      const EntityTransformPayload current = ReadEntityTransformPayload(Orientation, Position);
      const Wm3::Vec3f probePosition{
        current.posX,
        current.posY + 1.0f,
        current.posZ,
      };
      mIntelManager->Update(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }
  }

  /**
   * Address: 0x00679F70
   *
   * What it does:
   * Advances the active motor when not attached; returns engine task status code.
   */
  int Entity::MotionTick()
  {
    if (!mAttachInfo.HasAttachTarget()) {
      if (!mMotor) {
        return -2;
      }

      mMotor->Update(this);
    }

    return 1;
  }

  /**
   * Address: 0x00679FA0 (FUN_00679FA0)
   *
   * What it does:
   * Replaces entity motor from auto_ptr handoff storage.
   */
  void Entity::SetMotor(msvc8::auto_ptr<EntityMotor>& motor)
  {
    EntityMotor* const newMotor = motor.release();
    EntityMotor* oldMotor = mMotor;
    mMotor = newMotor;

    if (oldMotor) {
      delete oldMotor;
    }

    if (mMotor) {
      mMotor->BindEntity(this);
    }
  }

  /**
   * Address: 0x005BDC10
   */
  msvc8::vector<Entity*>& Entity::GetAttachedEntities()
  {
    return mAttachedEntities;
  }

  /**
   * Address: 0x0067A220
   */
  void Entity::CreateInterface(SSyncData*)
  {
    mInterfaceCreated = 1u;
  }

  /**
   * Address: 0x0067A260
   */
  void Entity::DestroyInterface(SSyncData*)
  {
    mInterfaceCreated = 0u;
  }

  /**
   * Address: 0x0067A290
   */
  void Entity::SyncInterface(SSyncData*)
  {
    // 0x0067A290 serializes interface visibility channels into sync payload.
  }

  /**
   * Address: 0x00679550 (FUN_00679550)
   *
   * What it does:
   * Validates parent attach chain, appends this entity to parent attached-list,
   * repairs queued runtime-link state, then applies attach payload into `mAttachInfo`.
   */
  bool Entity::AttachTo(const SEntAttachInfo& attachInfo)
  {
    if (mAttachInfo.HasAttachTarget()) {
      return false;
    }

    Entity* const parent = attachInfo.GetAttachTargetEntity();
    if (!parent) {
      return false;
    }

    for (Entity* ancestor = parent; ancestor != nullptr; ancestor = ancestor->mAttachInfo.GetAttachTargetEntity()) {
      if (ancestor == this) {
        return false;
      }
      if (!ancestor->mAttachInfo.HasAttachTarget()) {
        break;
      }
    }

    msvc8::vector<Entity*>& parentChildren = parent->GetAttachedEntities();
    if (std::find(parentChildren.begin(), parentChildren.end(), this) != parentChildren.end()) {
      return false;
    }

    parentChildren.push_back(this);
    ResetAttachRuntimeNodeIfQueued(this);
    ApplyAttachInfo(mAttachInfo, attachInfo);
    return true;
  }

  /**
   * Address: 0x006796F0 (FUN_006796F0)
   *
   * What it does:
   * Removes this entity from parent attached-list and applies detached defaults
   * to the local attach-info block.
   */
  bool Entity::DetachFrom(Entity* parent, bool)
  {
    if (!parent) {
      return false;
    }

    msvc8::vector<Entity*>& parentChildren = parent->GetAttachedEntities();
    for (Entity** it = parentChildren.begin(); it != parentChildren.end(); ++it) {
      if (*it != this) {
        continue;
      }

      parentChildren.erase(it);

      SEntAttachInfo detached = SEntAttachInfo::MakeDetached();
      ApplyAttachInfo(mAttachInfo, detached);

      return true;
    }

    return false;
  }

  /**
   * Address: 0x006797E0
   */
  void Entity::AttachedEntityDestroyed(Entity*)
  {
    CallbackStr("OnAttachedDestroyed");
  }

  /**
   * Address: 0x00679800
   */
  void Entity::AttachedEntityKilled(Entity*)
  {
    CallbackStr("OnAttachedKilled");
  }

  /**
   * Address: 0x00679820
   */
  void Entity::ParentEntityDestroyed(Entity*)
  {
    CallbackStr("OnParentDestroyed");
  }

  /**
   * Address: 0x00679840
   */
  void Entity::ParentEntityKilled(Entity*)
  {
    CallbackStr("OnParentKilled");
  }

  /**
   * Address: 0x005BDC20
   */
  float Entity::Materialize(float)
  {
    return 0.0f;
  }

  /**
   * Address: 0x00679940
   *
   * What it does:
   * Sets absolute health, triggers OnHealthChanged on 0.25-step bucket changes,
   * and ensures the coord-node is queued into Sim coord list.
   */
  void Entity::SetHealth(const float newHealth)
  {
    if (MaxHealth <= 0.0f) {
      Health = newHealth;
      return;
    }

    const float invMaxHealth = 1.0f / MaxHealth;
    const float prevBucket = std::floor(invMaxHealth * Health * 4.0f) * 0.25f;
    const float nextBucket = std::floor(invMaxHealth * newHealth * 4.0f) * 0.25f;

    Health = newHealth;

    if (nextBucket != prevBucket) {
      CallbackStr("OnHealthChanged");
    }

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00679860
   *
   * What it does:
   * Applies delta health with dead/heal guard and clamp to [0, MaxHealth].
   */
  void Entity::AdjustHealth(Entity*, const float delta)
  {
    if (std::isnan(delta) || delta == 0.0f) {
      return;
    }

    if (Dead && delta > 0.0f) {
      return;
    }

    float next = Health + delta;
    if (next > MaxHealth) {
      next = MaxHealth;
    }
    if (next < 0.0f) {
      next = 0.0f;
    }

    if (next != Health) {
      SetHealth(next);
    }
  }

  /**
   * Address: 0x00679A80
   *
   * What it does:
   * Dispatches attached/parent killed notifications and marks entity dead/dirty.
   */
  void Entity::Kill(Entity*, gpg::StrArg, float)
  {
    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    if (parent) {
      parent->AttachedEntityKilled(this);
    }

    for (Entity* child : mAttachedEntities) {
      if (child) {
        child->ParentEntityKilled(this);
      }
    }

    DirtySyncState = 1;
    Dead = 1;
  }

  /**
   * Address: 0x00679B80 (FUN_00679B80)
   *
   * What it does:
   * Marks destroy dispatch, queues this entity in Sim destroy queue, emits script
   * callback, detaches from parent, and notifies attached children.
   */
  void Entity::OnDestroy()
  {
    mOnDestroyDispatched = 1;
    QueueEntityForDestroy(this);
    CallbackStr("OnDestroy");

    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    if (parent) {
      parent->AttachedEntityDestroyed(this);
      (void)DetachFrom(parent, false);
    }

    for (Entity* child : mAttachedEntities) {
      if (child) {
        child->ParentEntityDestroyed(this);
      }
    }
  }

  void Entity::Destroy()
  {
    OnDestroy();
  }

  /**
   * Address: 0x006791D0 (FUN_006791D0)
   *
   * What it does:
   * Pushes current transform to collision primitive, relinks collision-cell
   * bucket membership, and refreshes cached world-space bounds at +0x240.
   */
  void Entity::UpdateCollision()
  {
    if (!CollisionExtents) {
      return;
    }

    auto* collision = CollisionExtents;
    const EntityTransformPayload current = ReadEntityTransformPayload(Orientation, Position);
    collision->SetTransform(current);
    RelinkSpanFromCollisionPrimitive(mCollisionCellSpan, collision);
    RefreshCollisionBoundsSnapshot(*this);
  }

  /**
   * Address: 0x0067AC40 (FUN_0067AC40)
   *
   * What it does:
   * Builds a box collision primitive from supplied local box and installs it.
   */
  void Entity::SetCollisionBoxShape(const Wm3::Box3f& localBox)
  {
    InstallCollisionPrimitiveAndRefresh(*this, new BoxCollisionPrimitive(localBox));
  }

  /**
   * Address: 0x0067AD30 (FUN_0067AD30)
   *
   * What it does:
   * Builds a sphere collision primitive from local center/radius and installs it.
   */
  void Entity::SetCollisionSphereShape(const Wm3::Vec3f& localCenter, const float radius)
  {
    InstallCollisionPrimitiveAndRefresh(*this, new SphereCollisionPrimitive(localCenter, radius));
  }

  /**
   * Address: 0x0067AE00 (FUN_0067AE00)
   *
   * What it does:
   * Clears active collision primitive and resets collision-cell span to zero.
   */
  void Entity::RevertCollisionShape()
  {
    InstallCollisionPrimitiveAndRefresh(*this, nullptr);
  }

  /**
   * Address: 0x0067AE70 (FUN_0067AE70)
   *
   * What it does:
   * Recreates collision primitive from blueprint shape descriptor.
   */
  void Entity::RefreshCollisionShapeFromBlueprint()
  {
    if (!BluePrint) {
      RevertCollisionShape();
      return;
    }

    switch (BluePrint->mCollisionShape) {
    case COLSHAPE_None:
      RevertCollisionShape();
      break;
    case COLSHAPE_Box:
      SetCollisionBoxShape(BuildBlueprintCollisionBox(*BluePrint));
      break;
    case COLSHAPE_Sphere:
      SetCollisionSphereShape(BuildBlueprintCollisionCenter(*BluePrint), BluePrint->mSizeX * 0.5f);
      break;
    default:
      break;
    }
  }

  void Entity::MarkNeedsSyncGameData() noexcept
  {
    DirtySyncState = 1;
  }

  /**
   * Address: 0x00689F20 (FUN_00689F20, Moho::Entity::GetUniqueName)
   *
   * What it does:
   * Returns the entity's unique runtime name string.
   */
  msvc8::string Entity::GetUniqueName() const
  {
    return msvc8::string(mUniqueName.data(), mUniqueName.size());
  }

  /**
   * Address: 0x00678880 (FUN_00678880, ?GetFootprint@Entity@Moho@@QBEABUSFootprint@2@XZ)
   *
   * What it does:
   * Returns active footprint (default or alt footprint).
   * Throws when blueprint pointer is missing.
   */
  const SFootprint& Entity::GetFootprint() const
  {
    if (!BluePrint) {
      throw std::runtime_error("Attempt to get footprint on nameless entity");
    }

    const bool useAlt = (mUseAltFootprint != 0u) || (mUseAltFootprintSecondary != 0u);
    return useAlt ? BluePrint->mAltFootprint : BluePrint->mFootprint;
  }

  /**
   * Address: 0x0067AFF0 (FUN_0067AFF0, ?SetCurrentLayer@Entity@Moho@@QAEXW4ELayer@2@@Z)
   *
   * What it does:
   * Updates current layer and issues `OnLayerChange(new, old)` callback.
   */
  void Entity::SetCurrentLayer(const ELayer newLayer)
  {
    const ELayer oldLayer = mCurrentLayer;
    mCurrentLayer = newLayer;
    if (newLayer == oldLayer) {
      return;
    }

    const char* oldName = LayerToString(oldLayer);
    const char* newName = LayerToString(newLayer);
    const char* newNameArg = newName;
    const char* oldNameArg = oldName;
    CallbackStr("OnLayerChange", &newNameArg, &oldNameArg);
  }

  /**
   * Address: 0x0067B050 (FUN_0067B050)
   *
   * What it does:
   * Resolves category text through Sim rules and tests the blueprint category bit.
   */
  bool Entity::IsInCategory(const char* categoryName) const noexcept
  {
    if (!categoryName || !BluePrint || !SimulationRef || !SimulationRef->mRules) {
      return false;
    }

    const CategoryWordRangeView* const range = SimulationRef->mRules->GetEntityCategory(categoryName);
    if (!range) {
      return false;
    }

    const std::uint32_t bitIndex = ReadBlueprintCategoryBitIndex(BluePrint);
    const auto wordIt = range->FindWord(bitIndex >> 5u);
    if (wordIt == range->cend()) {
      return false;
    }

    return (((*wordIt) >> (bitIndex & 0x1Fu)) & 1u) != 0u;
  }

  Wm3::Vec3f const& Entity::GetPositionWm3() const noexcept
  {
    return *reinterpret_cast<Wm3::Vec3f const*>(&Position);
  }

  VTransform const& Entity::GetTransformWm3() const noexcept
  {
    return *reinterpret_cast<VTransform const*>(&Orientation);
  }

  /**
   * Address: 0x00678800 (FUN_00678800, ?InitPositionHistory@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the rolling position-history ring with identity/default samples.
   */
  void Entity::InitPositionHistory()
  {
    PositionHistory* const rebuiltHistory = new (std::nothrow) PositionHistory;
    if (rebuiltHistory) {
      InitializePositionHistory(*rebuiltHistory);
    }

    delete mPositionHistory;
    mPositionHistory = rebuiltHistory;
  }

  /**
   * Address: 0x00678F10 (FUN_00678F10, ?AdvanceCoords@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Commits pending transform to current, archives previous/current snapshots,
   * updates collision when movement changed, runs intel force-update pass,
   * then relinks coord node into Sim's coord-entities list when needed.
   */
  void Entity::AdvanceCoords()
  {
    const EntityTransformPayload previous = ReadEntityTransformPayload(Orientation, Position);
    const EntityTransformPayload current = ReadEntityTransformPayload(PendingOrientation, PendingPosition);

    WriteEntityTransformPayload(PrevOrientation, PrevPosition, previous);
    WriteEntityTransformPayload(Orientation, Position, current);
    mVelocityScale = mPendingVelocityScale;

    if (mPositionHistory) {
      RecordEntityPositionHistory(*mPositionHistory, previous, current);
    }

    if (CollisionExtents &&
        (EntityTransformPositionDiffers(current, previous) || EntityTransformOrientationDiffers(current, previous))) {
      UpdateCollision();
    }

    if (mIntelManager && SimulationRef) {
      const Wm3::Vec3f probePosition{
        current.posX,
        current.posY + 1.0f,
        current.posZ,
      };
      mIntelManager->ForceUpdate(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678A70
   *
   * What it does:
   * Resolves entity visibility channel for current sync context.
   */
  void Entity::UpdateVisibility()
  {
    int resolvedLayer = mVisibilityLayerDefault;
    if (ArmyRef) {
      if (SimulationRef && SimulationRef->mSyncArmy == -1) {
        resolvedLayer = mVisibilityLayerFriendly;
      }
    }

    mFootprintLayer = resolvedLayer;
    mVisibilityState = static_cast<std::uint8_t>(resolvedLayer != static_cast<int>(LAYER_Land));
  }

  const char* Entity::LayerToString(const ELayer layer) noexcept
  {
    switch (layer) {
    case LAYER_Land:
      return "Land";
    case LAYER_Seabed:
      return "Seabed";
    case LAYER_Sub:
      return "Sub";
    case LAYER_Water:
      return "Water";
    case LAYER_Air:
      return "Air";
    case LAYER_Orbit:
      return "Orbit";
    default:
      return "";
    }
  }
} // namespace moho
