#include "SSTIArmyConstantData.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "moho/sim/CIntelGrid.h"

namespace
{
  // The real ctor's cache slot (Moho__EntId__sType) resolves via
  // typeid(??_R0?AVEntId@Moho@@@8) -- a *class*-mangled ('V' prefix) RTTI
  // descriptor, meaning the 2007 source declared `EntId` as its own
  // distinct class, not a bare integer alias. The current codebase-wide
  // recovery models EntId as `using EntId = std::int32_t;` in five separate
  // headers (Entity.h, Sim.h, IUnit.h, CWldSession.h,
  // SSTICommandVariableData.h), under which typeid(EntId) resolves to
  // typeid(std::int32_t) by alias transparency. Reconciling that whole-
  // codebase typedef-vs-class divergence is out of scope for this pass;
  // this cache intentionally matches the current alias definition so
  // behavior is consistent with every other EntId call site today.
  [[nodiscard]] gpg::RType* CachedEntIdType()
  {
    static gpg::RType* sCachedType = nullptr;
    if (!sCachedType) {
      sCachedType = gpg::LookupRType(typeid(std::int32_t));
    }
    return sCachedType;
  }

} // namespace

namespace moho
{
  gpg::RType* SSTIArmyConstantData::sType = nullptr;

  /**
   * Address: 0x006FD330 (FUN_006FD330, Moho::SSTIArmyConstantData::SSTIArmyConstantData)
   *
   * What it does:
   * Initializes fixed army identity lanes, clears civilian flag padding, and
   * nulls all tracked intel-grid shared pointers.
   */
  SSTIArmyConstantData::SSTIArmyConstantData()
    : mArmyIndex(0)
    , mArmyName()
    , mPlayerName()
    , mIsCivilian(0)
    , mPad3D{0, 0, 0}
    , mVisionReconGrid()
    , mWaterReconGrid()
    , mRadarReconGrid()
    , mSonarReconGrid()
    , mOmniReconGrid()
    , mRciReconGrid()
    , mSciReconGrid()
    , mVciReconGrid()
  {}

  /**
   * Address: 0x00742FA0 (FUN_00742FA0, Moho::SSTIArmyConstantData::SSTIArmyConstantData copy-ctor)
   *
   * What it does:
   * Clones fixed identity/string lanes and all eight tracked shared
   * `CIntelGrid` pointer lanes from one source payload.
   * Address: 0x00754B00 (FUN_00754B00 -- a second emission of this copy constructor, guarded on a null source; zero callers, unreachable; formerly `CopyConstructSSTIArmyConstantDataIfPresentPrimary`, removed 2026-09-11.)
   * Address: 0x00755E30 (FUN_00755E30 -- a third emission of it; zero callers, unreachable; formerly `CopyConstructSSTIArmyConstantDataIfPresentSecondary`, removed 2026-09-11.)
   */
  SSTIArmyConstantData::SSTIArmyConstantData(const SSTIArmyConstantData& other)
    : mArmyIndex(other.mArmyIndex)
    , mArmyName(other.mArmyName)
    , mPlayerName(other.mPlayerName)
    , mIsCivilian(other.mIsCivilian)
    , mPad3D{other.mPad3D[0], other.mPad3D[1], other.mPad3D[2]}
    , mVisionReconGrid(other.mVisionReconGrid)
    , mWaterReconGrid(other.mWaterReconGrid)
    , mRadarReconGrid(other.mRadarReconGrid)
    , mSonarReconGrid(other.mSonarReconGrid)
    , mOmniReconGrid(other.mOmniReconGrid)
    , mRciReconGrid(other.mRciReconGrid)
    , mSciReconGrid(other.mSciReconGrid)
    , mVciReconGrid(other.mVciReconGrid)
  {}

  /**
   * Address: 0x006FD570 (FUN_006FD570, Moho::SSTIArmyConstantData::~SSTIArmyConstantData)
   *
   * What it does:
   * Runs reverse-order member teardown for intel-grid shared pointers and army
   * identity strings.
   */
  SSTIArmyConstantData::~SSTIArmyConstantData() = default;

  /**
   * Address: 0x005510C0 (FUN_005510C0, Moho::SSTIArmyConstantData::MemberSerialize)
   *
   * What it does:
   * Serializes fixed army identity lanes and all eight tracked shared
   * `CIntelGrid` pointer lanes to a write archive.
   */
  void SSTIArmyConstantData::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef ownerRef{};
    archive->WriteUInt(static_cast<std::uint32_t>(mArmyIndex));
    archive->WriteString(const_cast<msvc8::string*>(&mArmyName));
    archive->WriteString(const_cast<msvc8::string*>(&mPlayerName));
    archive->WriteBool(mIsCivilian != 0u);

    const auto writeSharedGridPointer = [archive, &ownerRef](const boost::shared_ptr<CIntelGrid>& gridPointer) {
      gpg::RRef gridRef{};
      (void)gpg::RRef_CIntelGrid(&gridRef, const_cast<CIntelGrid*>(gridPointer.get()));
      gpg::WriteRawPointer(archive, gridRef, gpg::TrackedPointerState::Shared, ownerRef);
    };

    writeSharedGridPointer(mVisionReconGrid);
    writeSharedGridPointer(mWaterReconGrid);
    writeSharedGridPointer(mRadarReconGrid);
    writeSharedGridPointer(mSonarReconGrid);
    writeSharedGridPointer(mOmniReconGrid);
    writeSharedGridPointer(mRciReconGrid);
    writeSharedGridPointer(mSciReconGrid);
    writeSharedGridPointer(mVciReconGrid);
  }

  /**
   * Address: 0x00550FC0 (FUN_00550FC0, Moho::SSTIArmyConstantData::MemberDeserialize)
   *
   * What it does:
   * Reads army identity lanes (`mArmyIndex` as uint, `mArmyName`, `mPlayerName`,
   * `mIsCivilian` as bool) followed by eight tracked-shared `CIntelGrid`
   * pointers in declaration order via `ReadPointerShared_CIntelGrid`.
   */
  void SSTIArmyConstantData::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    archive->ReadUInt(reinterpret_cast<std::uint32_t*>(&mArmyIndex));
    archive->ReadString(&mArmyName);
    archive->ReadString(&mPlayerName);
    bool isCivilian = false;
    archive->ReadBool(&isCivilian);
    mIsCivilian = static_cast<std::uint8_t>(isCivilian ? 1 : 0);

    // Eight tracked-shared grid pointers, in the same order MemberSerialize
    // writes them. The binary gives each read its own zeroed owner ref rather
    // than sharing one.
    //
    // `ReadPointerShared_CIntelGrid` takes a `boost::SharedPtrRaw<CIntelGrid>&`
    // and the lanes are declared as `boost::shared_ptr<CIntelGrid>`; the two
    // are the same (px, pi) pair, which `SharedPtrRaw::reset_from_owner`
    // already static_asserts, so the view is taken here rather than at each of
    // the eight call sites.
    const auto readSharedGridPointer = [archive](boost::shared_ptr<CIntelGrid>& gridPointer) {
      static_assert(
        sizeof(boost::shared_ptr<CIntelGrid>) == sizeof(boost::SharedPtrRaw<CIntelGrid>),
        "boost::shared_ptr<CIntelGrid> must have the same (px, pi) layout as SharedPtrRaw<CIntelGrid>"
      );

      const gpg::RRef ownerRef{};
      gpg::ReadPointerShared_CIntelGrid(
        reinterpret_cast<boost::SharedPtrRaw<CIntelGrid>&>(gridPointer), archive, ownerRef
      );
    };

    readSharedGridPointer(mVisionReconGrid);
    readSharedGridPointer(mWaterReconGrid);
    readSharedGridPointer(mRadarReconGrid);
    readSharedGridPointer(mSonarReconGrid);
    readSharedGridPointer(mOmniReconGrid);
    readSharedGridPointer(mRciReconGrid);
    readSharedGridPointer(mSciReconGrid);
    readSharedGridPointer(mVciReconGrid);
  }

  /**
   * Address: 0x007000A0 (FUN_007000A0)
   *
   * IDA signature:
   * Moho::SSTIArmyConstantData *callcnv_F3 sub_7000A0@<eax>(
   *     Moho::SSTIArmyConstantData *a1@<eax>, Moho::SSTIArmyConstantData *a2@<esi>);
   *
   * What it does:
   * Assigns one `SSTIArmyConstantData` payload from `source` into
   * `destination` — index, both names, the civilian flag and all eight tracked
   * intel-grid shared lanes — and returns the destination pointer.
   */
  SSTIArmyConstantData* AssignArmyConstantData(
    const SSTIArmyConstantData& source, SSTIArmyConstantData* const destination
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    *destination = source;
    return destination;
  }

  /**
   * Address: 0x00BC9AB0 (FUN_00BC9AB0, dynamic initializer for the global
   * `SSTIArmyConstantDataSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SSTIArmyConstantDataSerializer::SSTIArmyConstantDataSerializer()
    : mLoadCallback(&SSTIArmyConstantDataSerializer::Deserialize)
    , mSaveCallback(&SSTIArmyConstantDataSerializer::Serialize)
  {}

  SSTIArmyConstantDataSerializer::~SSTIArmyConstantDataSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x005507F0 (FUN_005507F0, Moho::SSTIArmyConstantDataSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `SSTIArmyConstantData`. Forwards
   * the reflected object pointer to
   * `SSTIArmyConstantData::MemberDeserialize` (FUN_00550FC0 body); `version`
   * and the owner-ref lane are unused by the member (mirrors the binary
   * tail call).
   */
  void SSTIArmyConstantDataSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    auto* const data = reinterpret_cast<SSTIArmyConstantData*>(static_cast<std::intptr_t>(objectPtr));
    if (data == nullptr) {
      return;
    }
    data->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00550810 (FUN_00550810, Moho::SSTIArmyConstantDataSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `SSTIArmyConstantData`. Forwards
   * the reflected object pointer to
   * `SSTIArmyConstantData::MemberSerialize` (FUN_005510C0 body); `version`
   * and the owner-ref lane are unused by the member (mirrors the binary
   * tail call).
   */
  void SSTIArmyConstantDataSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
  {
    const auto* const data = reinterpret_cast<const SSTIArmyConstantData*>(static_cast<std::intptr_t>(objectPtr));
    if (data == nullptr) {
      return;
    }
    data->MemberSerialize(archive);
  }

  /**
   * Address: 0x00550CF0 (FUN_00550CF0, shared Init() body)
   */
  void SSTIArmyConstantDataSerializer::Init()
  {
    if (SSTIArmyConstantData::sType == nullptr) {
      SSTIArmyConstantData::sType = gpg::LookupRType(typeid(SSTIArmyConstantData));
    }

    gpg::RType* const type = SSTIArmyConstantData::sType;
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BC9F80 (FUN_00BC9F80, dynamic initializer for the global
   * `EntIdSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  EntIdSerializer::EntIdSerializer()
    : mLoadCallback(&EntIdSerializer::Deserialize)
    , mSaveCallback(&EntIdSerializer::Serialize)
  {}

  EntIdSerializer::~EntIdSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00557EF0 (FUN_00557EF0, Moho::EntIdSerializer::Deserialize)
   *
   * What it does:
   * Reflection load-callback facade for `EntId`. Reads the raw id value
   * directly through the archive (matches the binary's `ReadUInt` call on
   * the raw 4-byte id storage).
   */
  void EntIdSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<std::int32_t*>(static_cast<std::intptr_t>(objectPtr));
    archive->ReadInt(object);
  }

  /**
   * Address: 0x00557F10 (FUN_00557F10, Moho::EntIdSerializer::Serialize)
   *
   * What it does:
   * Reflection save-callback facade for `EntId`. Writes the raw id value
   * directly through the archive (matches the binary's `WriteUInt` call on
   * the raw 4-byte id storage).
   */
  void EntIdSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const object = reinterpret_cast<const std::int32_t*>(static_cast<std::intptr_t>(objectPtr));
    archive->WriteInt(*object);
  }

  /**
   * Address: 0x005589E0 (FUN_005589E0, shared Init() body)
   */
  void EntIdSerializer::Init()
  {
    gpg::RType* const type = CachedEntIdType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010AC3DC -- process-global `SSTIArmyConstantDataSerializer` singleton.
  moho::SSTIArmyConstantDataSerializer gSSTIArmyConstantDataSerializer;

  // Address: 0x010AC890 -- process-global `EntIdSerializer` singleton.
  moho::EntIdSerializer gEntIdSerializer;
} // namespace
