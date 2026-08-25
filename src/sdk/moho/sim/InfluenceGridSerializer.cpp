#include "moho/sim/InfluenceGridSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/CInfluenceMap.h"

namespace
{
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gInfluenceEntrySetType = nullptr;
  gpg::RType* gSThreatVectorType = nullptr;
  gpg::RType* gSThreatType = nullptr;

  // Alias of FUN_00717CF0 behavior from CInfluenceMap.cpp.
  void DeserializeInfluenceGridSerializerBridge(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const grid = reinterpret_cast<moho::InfluenceGrid*>(objectPtr);
    if (!archive || !grid) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(
      CachedType<msvc8::set<moho::InfluenceMapEntry, moho::InfluenceMapEntryLess>>(gInfluenceEntrySetType),
      &grid->entries,
      owner
    );
    archive->Read(CachedType<msvc8::vector<moho::SThreat>>(gSThreatVectorType), &grid->threats, owner);

    gpg::RType* const threatType = CachedType<moho::SThreat>(gSThreatType);
    archive->Read(threatType, &grid->threat, owner);
    archive->Read(threatType, &grid->decay, owner);
  }

  // Alias of FUN_00717D00 behavior from CInfluenceMap.cpp.
  void SerializeInfluenceGridSerializerBridge(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const grid = reinterpret_cast<const moho::InfluenceGrid*>(objectPtr);
    if (!archive || !grid) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(
      CachedType<msvc8::set<moho::InfluenceMapEntry, moho::InfluenceMapEntryLess>>(gInfluenceEntrySetType),
      const_cast<msvc8::set<moho::InfluenceMapEntry, moho::InfluenceMapEntryLess>*>(&grid->entries),
      owner
    );
    archive->Write(
      CachedType<msvc8::vector<moho::SThreat>>(gSThreatVectorType),
      const_cast<msvc8::vector<moho::SThreat>*>(&grid->threats),
      owner
    );

    gpg::RType* const threatType = CachedType<moho::SThreat>(gSThreatType);
    archive->Write(threatType, const_cast<moho::SThreat*>(&grid->threat), owner);
    archive->Write(threatType, const_cast<moho::SThreat*>(&grid->decay), owner);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDA7E0 (FUN_00BDA7E0, dynamic initializer for the global
   * `InfluenceGridSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  InfluenceGridSerializer::InfluenceGridSerializer()
    : mLoadCallback(&DeserializeInfluenceGridSerializerBridge)
    , mSaveCallback(&SerializeInfluenceGridSerializerBridge)
  {}

  InfluenceGridSerializer::~InfluenceGridSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00719410 (FUN_00719410, gpg::SerSaveLoadHelper_InfluenceGrid::Init)
   *
   * IDA signature:
   * void __thiscall sub_719410(_DWORD *this);
   */
  void InfluenceGridSerializer::Init()
  {
    gpg::RType* const type = InfluenceGrid::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B9204 -- process-global `InfluenceGridSerializer` singleton.
  moho::InfluenceGridSerializer gInfluenceGridSerializer;
} // namespace
