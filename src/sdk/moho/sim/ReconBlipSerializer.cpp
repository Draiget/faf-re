
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
  gpg::RType* gEntityType = nullptr;
  gpg::RType* gReconBlipType = nullptr;
  gpg::RType* gWeakPtrUnitType = nullptr;
  gpg::RType* gVector3fType = nullptr;
  gpg::RType* gUnitConstDataType = nullptr;
  gpg::RType* gUnitVarDataType = nullptr;
  gpg::RType* gPerArmyReconInfoVectorType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveEntityType()
  {
    if (!gEntityType) {
      gEntityType = gpg::LookupRType(typeid(moho::Entity));
    }
    return gEntityType;
  }

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
    outRef->mType = object ? CachedType<moho::ReconBlip>(gReconBlipType) : nullptr;
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

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    return CachedType<Wm3::Vector3f>(gVector3fType);
  }

  [[nodiscard]] gpg::RType* ResolveUnitConstDataType()
  {
    return CachedType<moho::SSTIUnitConstantData>(gUnitConstDataType);
  }

  [[nodiscard]] gpg::RType* ResolveUnitVarDataType()
  {
    return CachedType<moho::SSTIUnitVariableData>(gUnitVarDataType);
  }

  [[nodiscard]] gpg::RType* ResolvePerArmyReconInfoVectorType()
  {
    return CachedType<msvc8::vector<moho::SPerArmyReconInfo>>(gPerArmyReconInfoVectorType);
  }

  [[nodiscard]] gpg::RType* ResolvePerArmyReconInfoType()
  {
    if (!moho::SPerArmyReconInfo::sType) {
      moho::SPerArmyReconInfo::sType = gpg::LookupRType(typeid(moho::SPerArmyReconInfo));
    }
    return moho::SPerArmyReconInfo::sType;
  }

  // Addresses 0x005C90D0/0x005CAF90 (deserialize "ThunkA"/"ThunkB" pair) and
  // 0x005C90E0/0x005CAFA0 (serialize "ThunkA"/"ThunkB" pair) formerly modeled
  // here are dead: zero data_refs and zero call_edges in the callgraph index
  // for all four, and no source-level caller anywhere in src/sdk/**.
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

    archive->Read(ResolveEntityType(), static_cast<moho::Entity*>(this), ownerRef);
    archive->Read(ResolveWeakPtrUnitType(), &mCreator, ownerRef);
    archive->ReadBool(reinterpret_cast<bool*>(&mDeleteWhenStale));
    archive->Read(ResolveVector3fType(), &mJamOffset, ownerRef);
    archive->Read(ResolveUnitConstDataType(), &mUnitConstDat, ownerRef);
    archive->Read(ResolveUnitVarDataType(), &mUnitVarDat, ownerRef);
    archive->Read(ResolvePerArmyReconInfoVectorType(), &mReconDat, ownerRef);
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

    archive->Write(ResolveEntityType(), static_cast<const moho::Entity*>(this), ownerRef);
    archive->Write(ResolveWeakPtrUnitType(), &mCreator, ownerRef);
    archive->WriteBool(mDeleteWhenStale != 0u);
    archive->Write(ResolveVector3fType(), &mJamOffset, ownerRef);
    archive->Write(ResolveUnitConstDataType(), &mUnitConstDat, ownerRef);
    archive->Write(ResolveUnitVarDataType(), &mUnitVarDat, ownerRef);
    archive->Write(ResolvePerArmyReconInfoVectorType(), &mReconDat, ownerRef);
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
