#include "moho/ai/CAiBuilderImpl.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>

#include "moho/command/SSTICommandIssueData.h"
#include "moho/containers/BVSet.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/render/camera/VTransform.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  [[nodiscard]] std::uint32_t EncodeRebuildKey(const SOCellPos& cellPos) noexcept
  {
    const int x = static_cast<int>(cellPos.x);
    const int z = static_cast<int>(cellPos.z);
    return static_cast<std::uint32_t>(x * 10000 + z);
  }

  [[nodiscard]] SOCellPos DecodeRebuildKey(const std::uint32_t key) noexcept
  {
    const int signedKey = static_cast<std::int32_t>(key);
    SOCellPos cellPos{};
    cellPos.x = static_cast<std::int16_t>(signedKey / 10000);
    cellPos.z = static_cast<std::int16_t>(signedKey % 10000);
    return cellPos;
  }

  [[nodiscard]] SBuilderRebuildNode* AllocateRebuildNode() noexcept
  {
    auto* const node = static_cast<SBuilderRebuildNode*>(::operator new(sizeof(SBuilderRebuildNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->key = 0;
    node->blueprint = nullptr;
    node->color = 1;
    node->isNil = 0;
    node->pad16[0] = 0;
    node->pad16[1] = 0;
    return node;
  }

  void InitializeRebuildMap(SBuilderRebuildMap& map)
  {
    map.mMeta00 = 0;
    map.mHead = AllocateRebuildNode();
    map.mHead->isNil = 1;
    map.mHead->parent = map.mHead;
    map.mHead->left = map.mHead;
    map.mHead->right = map.mHead;
    map.mSize = 0;
  }

  void DestroyRebuildTree(SBuilderRebuildNode* node, SBuilderRebuildNode* head)
  {
    if (!node || node == head || node->isNil != 0) {
      return;
    }

    DestroyRebuildTree(node->left, head);
    DestroyRebuildTree(node->right, head);
    ::operator delete(node);
  }

  void ClearRebuildMapNodes(SBuilderRebuildMap& map)
  {
    if (!map.mHead) {
      map.mSize = 0;
      return;
    }

    DestroyRebuildTree(map.mHead->parent, map.mHead);
    map.mHead->parent = map.mHead;
    map.mHead->left = map.mHead;
    map.mHead->right = map.mHead;
    map.mSize = 0;
  }

  void DestroyRebuildMap(SBuilderRebuildMap& map)
  {
    if (!map.mHead) {
      map.mSize = 0;
      return;
    }

    ClearRebuildMapNodes(map);
    ::operator delete(map.mHead);
    map.mHead = nullptr;
    map.mSize = 0;
    map.mMeta00 = 0;
  }

  [[nodiscard]] SBuilderRebuildNode* FindRebuildNode(const SBuilderRebuildMap& map, const std::uint32_t key)
  {
    SBuilderRebuildNode* node = map.mHead ? map.mHead->parent : nullptr;
    while (node && node != map.mHead && node->isNil == 0) {
      if (key < node->key) {
        node = node->left;
      } else if (key > node->key) {
        node = node->right;
      } else {
        return node;
      }
    }

    return nullptr;
  }

  void RefreshRebuildMapExtremes(SBuilderRebuildMap& map)
  {
    if (!map.mHead) {
      return;
    }

    SBuilderRebuildNode* const head = map.mHead;
    SBuilderRebuildNode* root = head->parent;
    if (!root || root == head || root->isNil != 0 || map.mSize == 0) {
      head->parent = head;
      head->left = head;
      head->right = head;
      map.mSize = 0;
      return;
    }

    SBuilderRebuildNode* minNode = root;
    while (minNode->left != head && minNode->left && minNode->left->isNil == 0) {
      minNode = minNode->left;
    }

    SBuilderRebuildNode* maxNode = root;
    while (maxNode->right != head && maxNode->right && maxNode->right->isNil == 0) {
      maxNode = maxNode->right;
    }

    head->left = minNode;
    head->right = maxNode;
  }

  [[nodiscard]] SBuilderRebuildNode* MinimumNode(SBuilderRebuildNode* node, SBuilderRebuildNode* head)
  {
    SBuilderRebuildNode* current = node;
    while (current && current->left != head && current->left && current->left->isNil == 0) {
      current = current->left;
    }
    return current;
  }

  void TransplantNode(SBuilderRebuildMap& map, SBuilderRebuildNode* oldNode, SBuilderRebuildNode* newNode)
  {
    SBuilderRebuildNode* const head = map.mHead;
    if (!oldNode || !head) {
      return;
    }

    if (oldNode->parent == head) {
      head->parent = newNode;
    } else if (oldNode == oldNode->parent->left) {
      oldNode->parent->left = newNode;
    } else {
      oldNode->parent->right = newNode;
    }

    if (newNode && newNode != head) {
      newNode->parent = oldNode->parent;
    }
  }

  void RemoveRebuildNode(SBuilderRebuildMap& map, SBuilderRebuildNode* node)
  {
    if (!map.mHead || !node || node == map.mHead || node->isNil != 0) {
      return;
    }

    SBuilderRebuildNode* const head = map.mHead;

    if (node->left == head) {
      TransplantNode(map, node, node->right);
    } else if (node->right == head) {
      TransplantNode(map, node, node->left);
    } else {
      SBuilderRebuildNode* successor = MinimumNode(node->right, head);
      if (successor && successor->parent != node) {
        TransplantNode(map, successor, successor->right);
        successor->right = node->right;
        if (successor->right && successor->right != head) {
          successor->right->parent = successor;
        }
      }

      TransplantNode(map, node, successor);
      if (successor) {
        successor->left = node->left;
        if (successor->left && successor->left != head) {
          successor->left->parent = successor;
        }
      }
    }

    ::operator delete(node);
    if (map.mSize > 0) {
      --map.mSize;
    }
    RefreshRebuildMapExtremes(map);
  }

  void AddOrUpdateRebuildNode(SBuilderRebuildMap& map, const std::uint32_t key, const RUnitBlueprint* blueprint)
  {
    if (!map.mHead) {
      InitializeRebuildMap(map);
    }

    SBuilderRebuildNode* const existing = FindRebuildNode(map, key);
    if (existing) {
      existing->blueprint = blueprint;
      return;
    }

    SBuilderRebuildNode* const head = map.mHead;
    SBuilderRebuildNode* parent = head;
    SBuilderRebuildNode* node = head->parent;
    bool placeLeft = true;

    while (node && node != head && node->isNil == 0) {
      parent = node;
      if (key < node->key) {
        node = node->left;
        placeLeft = true;
      } else {
        node = node->right;
        placeLeft = false;
      }
    }

    SBuilderRebuildNode* const inserted = AllocateRebuildNode();
    inserted->key = key;
    inserted->blueprint = blueprint;
    inserted->left = head;
    inserted->right = head;
    inserted->parent = parent;

    if (parent == head) {
      head->parent = inserted;
      head->left = inserted;
      head->right = inserted;
    } else if (placeLeft) {
      parent->left = inserted;
      if (head->left == head || key < head->left->key) {
        head->left = inserted;
      }
    } else {
      parent->right = inserted;
      if (head->right == head || key > head->right->key) {
        head->right = inserted;
      }
    }

    ++map.mSize;
  }

  template <typename Fn>
  void ForEachRebuildNode(SBuilderRebuildNode* node, SBuilderRebuildNode* head, Fn&& fn)
  {
    if (!node || node == head || node->isNil != 0) {
      return;
    }

    ForEachRebuildNode(node->left, head, fn);
    fn(*node);
    ForEachRebuildNode(node->right, head, fn);
  }

  [[nodiscard]] bool HasSeabedOccupancy(const SFootprint& footprint) noexcept
  {
    const auto mask = static_cast<std::uint8_t>(footprint.mOccupancyCaps);
    return (mask & static_cast<std::uint8_t>(EOccupancyCaps::OC_SEABED)) != 0u;
  }

  [[nodiscard]] Entity* FindEntityById(CEntityDb* entityDb, const EntId id)
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      Entity* const entity = *it;
      if (entity && entity->id_ == id) {
        return entity;
      }
    }

    return nullptr;
  }

  [[nodiscard]] bool IsTransportTargetEntityAllowed(const Entity* entity)
  {
    if (!entity) {
      return false;
    }

    return entity->IsInCategory("FERRYBEACON") || entity->IsInCategory("TRANSPORTATION") ||
           entity->IsInCategory("AIRSTAGINGPLATFORM");
  }

} // namespace

gpg::RType* CAiBuilderImpl::sType = nullptr;

/**
 * Address: 0x0059FAB0 (FUN_0059FAB0, default ctor)
 */
CAiBuilderImpl::CAiBuilderImpl()
  : mOwnerUnit(nullptr)
  , mIsFactory(0)
  , mIsOnTarget(1)
  , mFactoryQueueDirty(1)
  , mPad0B(0)
  , mAimTarget(Wm3::Vector3f::Zero())
  , mRebuildStructures{}
  , mFactoryCommands()
{
  InitializeRebuildMap(mRebuildStructures);
}

/**
 * Address: 0x0059F920 (FUN_0059F920, unit ctor)
 */
CAiBuilderImpl::CAiBuilderImpl(Unit* const unit)
  : mOwnerUnit(unit)
  , mIsFactory(0)
  , mIsOnTarget(1)
  , mFactoryQueueDirty(0)
  , mPad0B(0)
  , mAimTarget(Wm3::Vector3f::Zero())
  , mRebuildStructures{}
  , mFactoryCommands()
{
  InitializeRebuildMap(mRebuildStructures);
}

/**
 * Address: 0x0059FB50 (FUN_0059FB50, scalar deleting thunk)
 * Address: 0x0059F9C0 (FUN_0059F9C0, core dtor)
 */
CAiBuilderImpl::~CAiBuilderImpl()
{
  BuilderClearFactoryCommandQueue();
  DestroyRebuildMap(mRebuildStructures);
}

/**
 * Address: 0x0059FAA0 (FUN_0059FAA0)
 */
bool CAiBuilderImpl::BuilderIsFactory() const
{
  return mIsFactory != 0;
}

/**
 * Address: 0x0059FA90 (FUN_0059FA90)
 */
void CAiBuilderImpl::BuilderSetIsFactory(const bool isFactory)
{
  mIsFactory = static_cast<std::uint8_t>(isFactory);
}

/**
 * Address: 0x0059EEF0 (FUN_0059EEF0)
 */
void CAiBuilderImpl::BuilderSetUpInitialRally()
{
  if (!mOwnerUnit || !mOwnerUnit->SimulationRef) {
    return;
  }

  const RUnitBlueprint* const blueprint = mOwnerUnit->GetBlueprint();
  if (!blueprint) {
    return;
  }

  const VTransform& transform = mOwnerUnit->GetTransform();
  const Wm3::Vector3f localRally{blueprint->Economy.InitialRallyX, 0.0f, blueprint->Economy.InitialRallyZ};
  const Wm3::Vector3f rallyWorldPos = transform.pos_ + transform.orient_.Rotate(localRally);

  BVSet<EntId, EntIdUniverse> factorySet{};
  (void)factorySet.mBits.Add(static_cast<unsigned int>(mOwnerUnit->id_));

  SSTICommandIssueData issueData{};
  issueData.mCommandType = EUnitCommandType::UNITCOMMAND_Move;
  issueData.mTarget.mType = EAiTargetType::AITARGET_Ground;
  issueData.mTarget.mEntityId = 0xF0000000u;
  issueData.mTarget.mPos = rallyWorldPos;

  mOwnerUnit->SimulationRef->IssueFactoryCommand(factorySet, issueData, true);
  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F220 (FUN_0059F220)
 */
void CAiBuilderImpl::BuilderValidateFactoryCommandQueue()
{
  if (mIsFactory == 0) {
    return;
  }

  std::size_t index = 0;
  while (index < mFactoryCommands.size()) {
    CUnitCommand* const command = mFactoryCommands[index].GetObjectPtr();
    if (!command) {
      EraseWeakVectorEntry(mFactoryCommands, index);
      mFactoryQueueDirty = 1;
      continue;
    }

    if (command->mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_TransportLoadUnits) {
      ++index;
      continue;
    }

    bool shouldRemove = true;
    if (mOwnerUnit && mOwnerUnit->SimulationRef && command->mVarDat.mTarget1.mType == EAiTargetType::AITARGET_Entity) {
      const EntId targetId = static_cast<EntId>(command->mVarDat.mTarget1.mEntityId);
      Entity* const entity = FindEntityById(mOwnerUnit->SimulationRef->mEntityDB, targetId);
      shouldRemove = !IsTransportTargetEntityAllowed(entity);
    }

    if (!shouldRemove) {
      ++index;
      continue;
    }

    command->RemoveUnit(mOwnerUnit);
    EraseWeakVectorEntry(mFactoryCommands, index);
    mFactoryQueueDirty = 1;
  }

  if (BuilderIsFactoryQueueEmpty()) {
    BuilderSetUpInitialRally();
  }
}

/**
 * Address: 0x0059F440 (FUN_0059F440)
 */
bool CAiBuilderImpl::BuilderIsFactoryQueueEmpty() const
{
  return mFactoryCommands.empty();
}

/**
 * Address: 0x0059EED0 (FUN_0059EED0)
 */
bool CAiBuilderImpl::BuilderIsFactoryQueueDirty() const
{
  return mFactoryQueueDirty != 0;
}

/**
 * Address: 0x0059EEE0 (FUN_0059EEE0)
 */
void CAiBuilderImpl::BuilderSetFactoryQueueDirty(const bool dirty)
{
  mFactoryQueueDirty = static_cast<std::uint8_t>(dirty);
}

/**
 * Address: 0x0059F470 (FUN_0059F470)
 */
msvc8::vector<WeakPtr<CUnitCommand>>& CAiBuilderImpl::BuilderGetFactoryCommandQueue()
{
  return mFactoryCommands;
}

/**
 * Address: 0x0059F480 (FUN_0059F480)
 */
bool CAiBuilderImpl::BuilderIsBusy() const
{
  if (!mOwnerUnit || !mOwnerUnit->CommandQueue) {
    return false;
  }

  const CUnitCommandQueue* const queue = mOwnerUnit->CommandQueue;
  if (!queue || queue->mCommandVec.empty()) {
    return false;
  }

  const CUnitCommand* const command = queue->mCommandVec.front().GetObjectPtr();
  if (!command) {
    return false;
  }

  switch (command->mVarDat.mCmdType) {
  case EUnitCommandType::UNITCOMMAND_BuildFactory:
  case EUnitCommandType::UNITCOMMAND_BuildMobile:
  case EUnitCommandType::UNITCOMMAND_Script:
  case EUnitCommandType::UNITCOMMAND_Upgrade:
    return true;
  default:
    return false;
  }
}

/**
 * Address: 0x0059F4D0 (FUN_0059F4D0)
 */
void CAiBuilderImpl::BuilderAddFactoryCommand(CUnitCommand* const command, const int index)
{
  if (!command) {
    return;
  }

  command->AddUnit(mOwnerUnit, mFactoryCommands, index);
  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F500 (FUN_0059F500)
 */
bool CAiBuilderImpl::BuilderContainsCommand(CUnitCommand* const command)
{
  if (!command) {
    return false;
  }

  for (std::size_t i = 0; i < mFactoryCommands.size(); ++i) {
    if (mFactoryCommands[i].GetObjectPtr() == command) {
      return true;
    }
  }
  return false;
}

/**
 * Address: 0x0059F540 (FUN_0059F540)
 */
CUnitCommand* CAiBuilderImpl::BuilderGetFactoryCommand(const int index)
{
  if (index < 0) {
    return nullptr;
  }

  const std::size_t idx = static_cast<std::size_t>(index);
  if (idx >= mFactoryCommands.size()) {
    return nullptr;
  }

  return mFactoryCommands[idx].GetObjectPtr();
}

/**
 * Address: 0x0059F580 (FUN_0059F580)
 */
void CAiBuilderImpl::BuilderRemoveFactoryCommand(CUnitCommand* const command)
{
  if (!command) {
    return;
  }

  command->RemoveUnit(mOwnerUnit, mFactoryCommands);
  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F5A0 (FUN_0059F5A0)
 */
void CAiBuilderImpl::BuilderClearFactoryCommandQueue()
{
  while (!mFactoryCommands.empty()) {
    CUnitCommand* const command = mFactoryCommands.back().GetObjectPtr();
    if (!command) {
      mFactoryCommands.pop_back();
      continue;
    }

    command->RemoveUnit(mOwnerUnit, mFactoryCommands);
  }

  mFactoryQueueDirty = 1;
}

/**
 * Address: 0x0059F600 (FUN_0059F600)
 */
void CAiBuilderImpl::BuilderSetAimTarget(const Wm3::Vector3f target)
{
  mAimTarget = target;
  if (mOwnerUnit && Wm3::Vector3f::LengthSq(target) > 0.0f) {
    mOwnerUnit->RunScript("OnPrepareArmToBuild");
  }
}

/**
 * Address: 0x0059F650 (FUN_0059F650)
 */
Wm3::Vector3f CAiBuilderImpl::BuilderGetAimTarget() const
{
  return mAimTarget;
}

/**
 * Address: 0x0059F670 (FUN_0059F670)
 */
void CAiBuilderImpl::BuilderSetOnTarget(const bool onTarget)
{
  mIsOnTarget = static_cast<std::uint8_t>(onTarget);
}

/**
 * Address: 0x0059F680 (FUN_0059F680)
 */
bool CAiBuilderImpl::BuilderGetOnTarget() const
{
  return mIsOnTarget != 0;
}

/**
 * Address: 0x0059F690 (FUN_0059F690)
 */
void CAiBuilderImpl::BuilderAddRebuildStructure(const SOCellPos& cellPos, const RUnitBlueprint* const blueprint)
{
  AddOrUpdateRebuildNode(mRebuildStructures, EncodeRebuildKey(cellPos), blueprint);
}

/**
 * Address: 0x0059F6C0 (FUN_0059F6C0)
 */
void CAiBuilderImpl::BuilderRemoveRebuildStructure(const SOCellPos& cellPos)
{
  const std::uint32_t key = EncodeRebuildKey(cellPos);
  SBuilderRebuildNode* const node = FindRebuildNode(mRebuildStructures, key);
  RemoveRebuildNode(mRebuildStructures, node);
}

/**
 * Address: 0x0059F710 (FUN_0059F710)
 */
void CAiBuilderImpl::BuilderClearRebuildStructure()
{
  ClearRebuildMapNodes(mRebuildStructures);
}

/**
 * Address: 0x0059F740 (FUN_0059F740)
 */
const RUnitBlueprint* CAiBuilderImpl::BuilderGetNextRebuildStructure(SOCellPos& outCellPos)
{
  outCellPos = {0, 0};

  if (!mOwnerUnit || !mRebuildStructures.mHead || mRebuildStructures.mSize == 0) {
    return nullptr;
  }

  const Sim* const sim = mOwnerUnit->SimulationRef;
  const STIMap* const mapData = sim ? sim->mMapData : nullptr;
  const CHeightField* const heightField = (mapData && mapData->mHeightField) ? mapData->mHeightField.get() : nullptr;
  const Wm3::Vector3f unitPos = mOwnerUnit->GetPosition();

  const RUnitBlueprint* bestBlueprint = nullptr;
  SOCellPos bestCell{0, 0};
  float bestDist = std::numeric_limits<float>::infinity();

  ForEachRebuildNode(mRebuildStructures.mHead->parent, mRebuildStructures.mHead, [&](SBuilderRebuildNode& node) {
    const RUnitBlueprint* const blueprint = node.blueprint;
    if (!blueprint) {
      return;
    }

    const SOCellPos cellPos = DecodeRebuildKey(node.key);
    const float centerX = static_cast<float>(cellPos.x) + static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f;
    const float centerZ = static_cast<float>(cellPos.z) + static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f;

    float centerY = 0.0f;
    if (heightField) {
      centerY = heightField->GetElevation(centerX, centerZ);
      if (!HasSeabedOccupancy(blueprint->mFootprint) && mapData && mapData->mWaterEnabled != 0 &&
          mapData->mWaterElevation > centerY) {
        centerY = mapData->mWaterElevation;
      }
    }

    const float dx = centerX - unitPos.x;
    const float dy = centerY - unitPos.y;
    const float dz = centerZ - unitPos.z;
    const float distSq = (dx * dx) + (dy * dy) + (dz * dz);

    if (distSq >= bestDist) {
      return;
    }

    if (!sim || !sim->mOGrid) {
      return;
    }

    if (OCCUPY_FootprintFits(*sim->mOGrid, cellPos, blueprint->mFootprint, EOccupancyCaps::OC_ANY) ==
        static_cast<EOccupancyCaps>(0u)) {
      return;
    }

    bestDist = distSq;
    bestBlueprint = blueprint;
    bestCell = cellPos;
  });

  outCellPos = bestCell;
  return bestBlueprint;
}
