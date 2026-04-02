#include "moho/sim/CInfluenceMapSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CArmyImpl.h"

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

  gpg::RType* gCArmyImplType = nullptr;
  gpg::RType* gBlipCellSetType = nullptr;
  gpg::RType* gInfluenceGridVectorType = nullptr;
  moho::CInfluenceMapSerializer gCInfluenceMapSerializer;

  /**
   * Address: 0x0071F330 (FUN_0071F330, sub_71F330)
   */
  void Deserialize_CInfluenceMap(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<moho::CInfluenceMap*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    object->mArmy = nullptr;
    if (tracked.object) {
      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedType<moho::CArmyImpl>(gCArmyImplType));
      object->mArmy = static_cast<moho::CArmyImpl*>(upcast.mObj);
    }

    archive->ReadInt(&object->mTotal);
    archive->ReadInt(&object->mWidth);
    archive->ReadInt(&object->mHeight);
    archive->ReadInt(&object->mGridSize);
    archive->Read(
      CachedType<msvc8::set<moho::InfluenceMapCellIndex, moho::InfluenceMapCellIndexLess>>(gBlipCellSetType),
      &object->mBlipCells,
      owner
    );
    archive->Read(CachedType<msvc8::vector<moho::InfluenceGrid>>(gInfluenceGridVectorType), &object->mMapEntries, owner);
  }

  /**
   * Address: 0x0071F400 (FUN_0071F400, sub_71F400)
   */
  void Serialize_CInfluenceMap(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<moho::CInfluenceMap*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    gpg::RRef armyRef{};
    armyRef.mObj = object->mArmy;
    armyRef.mType = object->mArmy ? CachedType<moho::CArmyImpl>(gCArmyImplType) : nullptr;
    gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Unowned, owner);

    archive->WriteInt(object->mTotal);
    archive->WriteInt(object->mWidth);
    archive->WriteInt(object->mHeight);
    archive->WriteInt(object->mGridSize);
    archive->Write(
      CachedType<msvc8::set<moho::InfluenceMapCellIndex, moho::InfluenceMapCellIndexLess>>(gBlipCellSetType),
      &object->mBlipCells,
      owner
    );
    archive->Write(CachedType<msvc8::vector<moho::InfluenceGrid>>(gInfluenceGridVectorType), &object->mMapEntries, owner);
  }

  /**
   * Address: 0x00717700 (FUN_00717700, sub_717700)
   */
  int Deserialize_CInfluenceMapThunk(const int archivePtr, const int objectPtr)
  {
    Deserialize_CInfluenceMap(reinterpret_cast<gpg::ReadArchive*>(archivePtr), objectPtr, 0, nullptr);
    return 0;
  }

  /**
   * Address: 0x00717710 (FUN_00717710, sub_717710)
   */
  int Serialize_CInfluenceMapThunk(const int objectPtr, const int archivePtr)
  {
    Serialize_CInfluenceMap(reinterpret_cast<gpg::WriteArchive*>(archivePtr), objectPtr, 0, nullptr);
    return 0;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDA6C0 (FUN_00BDA6C0, sub_BDA6C0)
   *
   * What it does:
   * Initializes CInfluenceMap serializer helper callbacks and binds them into
   * CInfluenceMap RTTI.
   */
  void register_CInfluenceMapSerializer()
  {
    gCInfluenceMapSerializer.mHelperNext = nullptr;
    gCInfluenceMapSerializer.mHelperPrev = nullptr;
    gCInfluenceMapSerializer.mLoadCallback =
      reinterpret_cast<gpg::RType::load_func_t>(&Deserialize_CInfluenceMapThunk);
    gCInfluenceMapSerializer.mSaveCallback =
      reinterpret_cast<gpg::RType::save_func_t>(&Serialize_CInfluenceMapThunk);
    gCInfluenceMapSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x00718B60 (FUN_00718B60, gpg::SerSaveLoadHelper_CInfluenceMap::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_718B60(void (__cdecl **this)(...)))(...);
   */
  void CInfluenceMapSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CInfluenceMap::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  struct CInfluenceMapSerializerBootstrap
  {
    CInfluenceMapSerializerBootstrap()
    {
      moho::register_CInfluenceMapSerializer();
    }
  };

  CInfluenceMapSerializerBootstrap gCInfluenceMapSerializerBootstrap;
} // namespace
