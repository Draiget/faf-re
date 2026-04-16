#include "moho/sim/InfluenceGridSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/CInfluenceMap.h"

namespace
{
  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

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
  moho::InfluenceGridSerializer gInfluenceGridSerializer;

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

  /**
   * Address: 0x007193E0 (FUN_007193E0)
   *
   * What it does:
   * Initializes startup `InfluenceGrid` helper links and callback slots.
   */
  [[maybe_unused]] [[nodiscard]] moho::InfluenceGridSerializer* InitializeInfluenceGridSerializerHelperStorage() noexcept
  {
    InitializeHelperNode(gInfluenceGridSerializer);
    gInfluenceGridSerializer.mLoadCallback = &DeserializeInfluenceGridSerializerBridge;
    gInfluenceGridSerializer.mSaveCallback = &SerializeInfluenceGridSerializerBridge;
    return &gInfluenceGridSerializer;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00719410 (FUN_00719410, gpg::SerSaveLoadHelper_InfluenceGrid::Init)
   *
   * IDA signature:
   * void __thiscall sub_719410(_DWORD *this);
   */
  void InfluenceGridSerializer::RegisterSerializeFunctions()
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
  struct InfluenceGridSerializerBootstrap
  {
    InfluenceGridSerializerBootstrap()
    {
      (void)InitializeInfluenceGridSerializerHelperStorage();
    }
  };

  [[maybe_unused]] InfluenceGridSerializerBootstrap gInfluenceGridSerializerBootstrap;
} // namespace
