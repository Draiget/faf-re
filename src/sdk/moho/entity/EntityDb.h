#pragma once
#include <cstddef>
#include <cstdint>

#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"

namespace moho
{
  class Entity;

  struct CEntityDbListHead
  {
    void* next; // +0x00
    void* prev; // +0x04
  };
  static_assert(sizeof(CEntityDbListHead) == 0x08, "CEntityDbListHead size must be 0x08");

  struct CEntityDbAllUnitsNode : msvc8::Tree<CEntityDbAllUnitsNode>
  {
    std::uint32_t key;      // +0x0C
    void* unitListNode;     // +0x10 (points to intrusive unit list node)
    std::uint8_t color;     // +0x14
    std::uint8_t isNil;     // +0x15
    std::uint8_t pad_16[2]; // +0x16
  };

  static_assert(offsetof(CEntityDbAllUnitsNode, key) == 0x0C, "CEntityDbAllUnitsNode::key offset must be 0x0C");
  static_assert(
    offsetof(CEntityDbAllUnitsNode, unitListNode) == 0x10, "CEntityDbAllUnitsNode::unitListNode offset must be 0x10"
  );
  static_assert(sizeof(CEntityDbAllUnitsNode) == 0x18, "CEntityDbAllUnitsNode size must be 0x18");

  class CEntityDb
  {
  public:
    /**
     * Address: 0x00684480 (FUN_00684480, ?DoReserveId@EntityDB@Moho@@AAE?AVEntId@2@I@Z)
     *
     * What it does:
     * Reserves a new entity id in the requested packed-id family/source key
     * (`[31..28]=family`, `[27..20]=source`).
     */
    [[nodiscard]] std::uint32_t DoReserveId(std::uint32_t requestedFamilySourceBits);

    /**
     * Address: 0x00683C90 (FUN_00683C90,
     * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ)
     *
     * What it does:
     * Returns the lower-bound tree iterator node for `sourceIndex << 20`.
     */
    [[nodiscard]] CEntityDbAllUnitsNode* AllUnitsEnd(std::uint32_t sourceIndex) const;

    /**
     * Address: 0x00683D10 (FUN_00683D10,
     * ?AllUnitsEnd@EntityDB@Moho@@QAE?AV?$Iterator@VUnit@Moho@@@EntityDBIterators@2@XZ_0)
     *
     * What it does:
     * Returns the lower-bound tree iterator node for the first non-unit family key
     * (`EEntityIdSentinel::FirstNonUnitFamily`, value `0x10000000`).
     */
    [[nodiscard]] CEntityDbAllUnitsNode* AllUnitsEnd() const;

    [[nodiscard]] msvc8::list<Entity*>& Entities() noexcept;
    [[nodiscard]] const msvc8::list<Entity*>& Entities() const noexcept;

  private:
    CEntityDbAllUnitsNode* mAllUnits;          // +0x00
    std::uint8_t mIdFamilyPoolsOpaque[0x14]{}; // +0x04 (two map-like trees used by id alloc/find/release paths)
    CEntityDbListHead mRegisteredEntitySets;   // +0x18 (used by Sim::RegisterEntitySet)
    std::uint8_t mOpaqueTail[0x30]{};          // +0x20 (remaining unrecovered members)
  };

  static_assert(sizeof(CEntityDb) == 0x50, "CEntityDb size must be 0x50");
} // namespace moho
