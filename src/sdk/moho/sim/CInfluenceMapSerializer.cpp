
#include <cstddef>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CArmyImpl.h"
#include "gpg/core/reflection/Reflection.h"

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

} // namespace

namespace moho
{
} // namespace moho

namespace
{
} // namespace

namespace moho
{
  /**
   * Address: 0x0071F330 (FUN_0071F330, sub_71F330)
   * Address: 0x0071E2F0 (FUN_0071E2F0)
   */
  void CInfluenceMap::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef owner = ownerRef;

    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, owner);
    mArmy = nullptr;
    if (tracked.object) {
      gpg::RRef source{};
      source.mObj = tracked.object;
      source.mType = tracked.type;
      const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedType<moho::CArmyImpl>(gCArmyImplType));
      mArmy = static_cast<moho::CArmyImpl*>(upcast.mObj);
    }

    archive->ReadInt(&mTotal);
    archive->ReadInt(&mWidth);
    archive->ReadInt(&mHeight);
    archive->ReadInt(&mGridSize);
    archive->Read(
      CachedType<msvc8::set<moho::InfluenceMapCellIndex, moho::InfluenceMapCellIndexLess>>(gBlipCellSetType),
      &mBlipCells,
      owner
    );
    archive->Read(CachedType<msvc8::vector<moho::InfluenceGrid>>(gInfluenceGridVectorType), &mMapEntries, owner);
  }

  /**
   * Address: 0x0071F400 (FUN_0071F400, sub_71F400)
   * Address: 0x0071E300 (FUN_0071E300)
   */
  void CInfluenceMap::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef owner = ownerRef;
    gpg::RRef armyRef{};
    armyRef.mObj = mArmy;
    armyRef.mType = mArmy ? CachedType<moho::CArmyImpl>(gCArmyImplType) : nullptr;
    gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Unowned, owner);

    archive->WriteInt(mTotal);
    archive->WriteInt(mWidth);
    archive->WriteInt(mHeight);
    archive->WriteInt(mGridSize);
    archive->Write(
      CachedType<msvc8::set<moho::InfluenceMapCellIndex, moho::InfluenceMapCellIndexLess>>(gBlipCellSetType),
      &mBlipCells,
      owner
    );
    archive->Write(CachedType<msvc8::vector<moho::InfluenceGrid>>(gInfluenceGridVectorType), &mMapEntries, owner);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CInfluenceMap>`, vtable 0x00E3176C.
   *
   * Address: 0x00BDA6C0 (FUN_00BDA6C0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFFF40 (FUN_00BFFF40 -- the global's destructor.)
   * Address: 0x00718B60 (FUN_00718B60 -- `Init`.)
   * Address: 0x00717700 (FUN_00717700 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00717710 (FUN_00717710 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CInfluenceMapSerializer : gpg::SerSaveLoadHelper<CInfluenceMap>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B9434 -- process-global `CInfluenceMapSerializer` singleton.
  moho::CInfluenceMapSerializer gCInfluenceMapSerializer;
} // namespace
