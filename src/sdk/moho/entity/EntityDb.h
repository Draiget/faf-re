#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Tree.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Entity;
  struct SEntitySetTemplateUnit;
  class Unit;

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

    /**
     * Address: 0x005C87A0 (FUN_005C87A0, Moho::CUnitIterAllArmies::Next)
     *
     * What it does:
     * Advances one all-units tree iterator node to its in-order successor.
     */
    [[nodiscard]]
    static CEntityDbAllUnitsNode* NextAllUnitsNode(CEntityDbAllUnitsNode* node) noexcept;

    /**
     * Address: 0x005C87A0 callsite shape (Moho::CUnitIterAllArmies payload)
     *
     * What it does:
     * Converts one all-units tree node payload into the owning `Unit*`.
     */
    [[nodiscard]]
    static Unit* UnitFromAllUnitsNode(const CEntityDbAllUnitsNode* node) noexcept;

    [[nodiscard]] msvc8::list<Entity*>& Entities() noexcept;
    [[nodiscard]] const msvc8::list<Entity*>& Entities() const noexcept;

    /**
     * What it does:
     * Registers one intrusive entity-set node in the DB-owned set registry.
     */
    void RegisterEntitySet(SEntitySetTemplateUnit& set) noexcept;

    /**
     * Address: 0x00689760 (FUN_00689760, Moho::EntityDB::MemberSerialize)
     *
     * What it does:
     * Loads EntityDB-owned entity/id-pool/set payload lanes from a read archive.
     */
    void MemberSerialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x006897F0 (FUN_006897F0, Moho::EntityDB::MemberDeserialize)
     *
     * What it does:
     * Saves EntityDB-owned entity/id-pool/set payload lanes into a write archive.
     */
    void MemberDeserialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00684AA0 (FUN_00684AA0, Moho::EntityDB::SerEntities read lane)
     *
     * What it does:
     * Reads the entity-id + owned-entity pointer stream until sentinel id `0xF0000000`.
     */
    void SerEntities(gpg::ReadArchive* archive);

    /**
     * Address: 0x006849C0 (FUN_006849C0, Moho::EntityDB::SerEntities write lane)
     *
     * What it does:
     * Writes the entity-id + owned-entity pointer stream and appends sentinel id
     * `0xF0000000`.
     */
    void SerEntities(gpg::WriteArchive* archive);

    /**
     * Address: 0x00684B40 (FUN_00684B40, Moho::EntityDB::SerSets read lane)
     *
     * What it does:
     * Reads unowned `EntitySetBase` pointers and links them into the registered
     * intrusive set list.
     */
    void SerSets(gpg::ReadArchive* archive);

    /**
     * Address: 0x00684BC0 (FUN_00684BC0, Moho::EntityDB::SerSets write lane)
     *
     * What it does:
     * Writes registered intrusive `EntitySetBase` pointers as an unowned pointer
     * stream terminated by `nullptr`.
     */
    void SerSets(gpg::WriteArchive* archive);

  private:
    CEntityDbAllUnitsNode* mAllUnits;          // +0x00
    std::uint8_t mIdFamilyPoolsOpaque[0x14]{}; // +0x04 (two map-like trees used by id alloc/find/release paths)
    CEntityDbListHead mRegisteredEntitySets;   // +0x18 (used by Sim::RegisterEntitySet)
    std::uint8_t mOpaqueTail[0x30]{};          // +0x20 (remaining unrecovered members)
  };

  static_assert(sizeof(CEntityDb) == 0x50, "CEntityDb size must be 0x50");

  /**
   * VFTABLE: 0x00E27980
   * COL: 0x00E8D0F0
   */
  class EntityDBSerializer
  {
  public:
    /**
     * Address: 0x00684910 (FUN_00684910, Moho::EntityDBSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive-load flow into `CEntityDb::MemberSerialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00684920 (FUN_00684920, Moho::EntityDBSerializer::Serialize)
     *
     * What it does:
     * Forwards archive-save flow into `CEntityDb::MemberDeserialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00688A90 (FUN_00688A90, Moho::EntityDBSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `EntityDB` RTTI serializer callbacks.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };
  static_assert(
    offsetof(EntityDBSerializer, mHelperNext) == 0x04, "EntityDBSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(EntityDBSerializer, mHelperPrev) == 0x08, "EntityDBSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(EntityDBSerializer, mDeserialize) == 0x0C, "EntityDBSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(EntityDBSerializer, mSerialize) == 0x10, "EntityDBSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(EntityDBSerializer) == 0x14, "EntityDBSerializer size must be 0x14");

  /**
   * Address: 0x00BFCAD0 (FUN_00BFCAD0, Moho::EntityDBSerializer::~EntityDBSerializer)
   *
   * What it does:
   * Unlinks `EntityDBSerializer` from the intrusive helper list and rewires
   * self-links.
   */
  gpg::SerHelperBase* cleanup_EntityDBSerializer();

  /**
   * Address: 0x00BD51A0 (FUN_00BD51A0, register_EntityDBSerializer)
   *
   * What it does:
   * Initializes the `EntityDBSerializer` helper callback lanes and installs
   * process-exit cleanup.
   */
  int register_EntityDBSerializer();
} // namespace moho
