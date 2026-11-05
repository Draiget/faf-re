
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/ReconBlip.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeakPtrReflection.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  gpg::RType* gReconBlipType = nullptr;
  gpg::RType* gWeakPtrUnitType = nullptr;

  /**
   * Address: 0x005C90A0 (FUN_005C90A0)
   *
   * What it does:
   * Fills one reflected object reference from a `ReconBlip*` lane.
   */
  [[maybe_unused]] gpg::RRef* FillReconBlipObjectRef(gpg::RRef* const outRef, moho::ReconBlip* const object)
  {
    if (!outRef) {
      return nullptr;
    }

    outRef->mObj = object;
    outRef->mType = object ? gpg::CachedLookup<moho::ReconBlip>(gReconBlipType) : nullptr;
    return outRef;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    if (!gWeakPtrUnitType) {
      gWeakPtrUnitType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      if (!gWeakPtrUnitType) {
        gWeakPtrUnitType = moho::register_WeakPtr_Unit_Type_00();
      }
    }
    return gWeakPtrUnitType;
  }

  // Addresses 0x005C90D0/0x005CAF90 (deserialize "ThunkA"/"ThunkB" pair) and
  // 0x005C90E0/0x005CAFA0 (serialize "ThunkA"/"ThunkB" pair) formerly modeled
  // here are dead: zero data_refs and zero call_edges in the callgraph index
  // for all four, and no source-level caller anywhere in src/**.
  // `ReconBlipSerializer::Deserialize`/`Serialize` below already call
  // `DeserializeReconBlipMembers`/`SerializeReconBlipMembers` above directly.
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
   * Address: 0x005CC880 (FUN_005CC880)
   *
   * What it does:
   * Deserializes `ReconBlip` reflected member lanes in binary order.
   */
  void ReconBlip::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef ownerRef{};

    archive->Read(gpg::RTypeOf<moho::Entity>(), static_cast<moho::Entity*>(this), ownerRef);
    archive->Read(ResolveWeakPtrUnitType(), &mCreator, ownerRef);
    archive->ReadBool(reinterpret_cast<bool*>(&mDeleteWhenStale));
    archive->Read(gpg::RTypeOf<Wm3::Vector3f>(), &mJamOffset, ownerRef);
    archive->Read(gpg::RTypeOf<moho::SSTIUnitConstantData>(), &mUnitConstDat, ownerRef);
    archive->Read(gpg::RTypeOf<moho::SSTIUnitVariableData>(), &mUnitVarDat, ownerRef);
    archive->Read(gpg::RTypeOf<fa::vector<moho::SPerArmyReconInfo>>(), &mReconDat, ownerRef);
  }

  /**
   * Address: 0x005CC9F0 (FUN_005CC9F0)
   *
   * What it does:
   * Serializes `ReconBlip` reflected member lanes in binary order.
   */
  void ReconBlip::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef ownerRef{};

    archive->Write(gpg::RTypeOf<moho::Entity>(), static_cast<const moho::Entity*>(this), ownerRef);
    archive->Write(ResolveWeakPtrUnitType(), &mCreator, ownerRef);
    archive->WriteBool(mDeleteWhenStale != 0u);
    archive->Write(gpg::RTypeOf<Wm3::Vector3f>(), &mJamOffset, ownerRef);
    archive->Write(gpg::RTypeOf<moho::SSTIUnitConstantData>(), &mUnitConstDat, ownerRef);
    archive->Write(gpg::RTypeOf<moho::SSTIUnitVariableData>(), &mUnitVarDat, ownerRef);
    archive->Write(gpg::RTypeOf<fa::vector<moho::SPerArmyReconInfo>>(), &mReconDat, ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<ReconBlip>`, vtable 0x00E1DA64.
   *
   * Address: 0x00BCDCE0 (FUN_00BCDCE0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF7930 (FUN_00BF7930 -- the global's destructor.)
   * Address: 0x005C43B0 (FUN_005C43B0 -- `Init`.)
   * Address: 0x005BFC90 (FUN_005BFC90 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005BFCA0 (FUN_005BFCA0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct ReconBlipSerializer : gpg::SerSaveLoadHelper<ReconBlip>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AF810 -- process-global `ReconBlipSerializer` singleton.
  moho::ReconBlipSerializer gReconBlipSerializer;
} // namespace
