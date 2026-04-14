#include "moho/unit/core/SSTIUnitConstantDataSerializer.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "moho/misc/Stats.h"
#include "moho/unit/core/Unit.h"

namespace
{
  moho::SSTIUnitConstantDataSerializer gSSTIUnitConstantDataSerializer;

  [[nodiscard]] gpg::RRef NullOwnerRef() noexcept
  {
    return gpg::RRef{};
  }

  [[nodiscard]] gpg::RType* CachedStatsStatItemType()
  {
    gpg::RType* type = moho::Stats<moho::StatItem>::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::Stats<moho::StatItem>));
      moho::Stats<moho::StatItem>::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeStatsStatItemRef(moho::Stats<moho::StatItem>* const value)
  {
    return gpg::RRef(value, CachedStatsStatItemType());
  }

  /**
   * Address: 0x005CAD60 (FUN_005CAD60, func_InitStatItemParent)
   *
   * What it does:
   * Initializes one boost shared-control lane for `Stats<StatItem>` ownership.
   */
  void InitializeStatsRootSharedControl(
    boost::detail::sp_counted_base*& outControl,
    moho::Stats<moho::StatItem>* const statsRoot
  )
  {
    outControl = nullptr;
    if (statsRoot != nullptr) {
      outControl = new boost::detail::sp_counted_impl_p<moho::Stats<moho::StatItem>>(statsRoot);
    }
  }

  void ReadStatsRootShared(
    boost::shared_ptr<moho::Stats<moho::StatItem>>& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef
  )
  {
    boost::SharedPtrRaw<moho::Stats<moho::StatItem>> rawPointer = boost::SharedPtrRawFromSharedRetained(outPointer);
    gpg::ReadPointerShared_Stats_StatItem(rawPointer, archive, ownerRef);
    outPointer = boost::SharedPtrFromRawRetained(rawPointer);
    rawPointer.release();
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode() noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&gSSTIUnitConstantDataSerializer.mHelperNext);
  }

  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode() noexcept
  {
    if (
      gSSTIUnitConstantDataSerializer.mHelperNext != nullptr &&
      gSSTIUnitConstantDataSerializer.mHelperPrev != nullptr
    ) {
      gSSTIUnitConstantDataSerializer.mHelperNext->mPrev = gSSTIUnitConstantDataSerializer.mHelperPrev;
      gSSTIUnitConstantDataSerializer.mHelperPrev->mNext = gSSTIUnitConstantDataSerializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = SerializerSelfNode();
    gSSTIUnitConstantDataSerializer.mHelperPrev = self;
    gSSTIUnitConstantDataSerializer.mHelperNext = self;
    return self;
  }

  void ResetSerializerNode() noexcept
  {
    if (
      gSSTIUnitConstantDataSerializer.mHelperNext == nullptr ||
      gSSTIUnitConstantDataSerializer.mHelperPrev == nullptr
    ) {
      gpg::SerHelperBase* const self = SerializerSelfNode();
      gSSTIUnitConstantDataSerializer.mHelperPrev = self;
      gSSTIUnitConstantDataSerializer.mHelperNext = self;
      return;
    }

    (void)UnlinkSerializerNode();
  }

  /**
   * Address: 0x0055C590 (FUN_0055C590, serializer singleton init lane)
   *
   * What it does:
   * Re-initializes helper-list links and callback pointers on the global
   * `SSTIUnitConstantDataSerializer` instance and returns that singleton.
   */
  [[nodiscard]] moho::SSTIUnitConstantDataSerializer* InitializeSSTIUnitConstantDataSerializerSingleton()
  {
    ResetSerializerNode();
    gSSTIUnitConstantDataSerializer.mDeserialize = &moho::SSTIUnitConstantDataSerializer::Deserialize;
    gSSTIUnitConstantDataSerializer.mSerialize = &moho::SSTIUnitConstantDataSerializer::Serialize;
    return &gSSTIUnitConstantDataSerializer;
  }

  void cleanup_SSTIUnitConstantDataSerializer_atexit()
  {
    moho::cleanup_SSTIUnitConstantDataSerializer();
  }
} // namespace

namespace moho
{
  gpg::RType* SSTIUnitConstantData::sType = nullptr;

  /**
   * Address: 0x005BD720 (FUN_005BD720, ??0SSTIUnitConstantData@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes one unit constant-data payload and seeds a default
   * `Stats<StatItem>` shared root.
   */
  SSTIUnitConstantData::SSTIUnitConstantData()
    : mBuildStateTag(0u)
    , pad_01{0u, 0u, 0u}
    , mStatsRoot()
    , mFake(0u)
    , pad_0D{0u, 0u, 0u}
  {
    auto* const allocation = static_cast<moho::Stats<moho::StatItem>*>(
      ::operator new(sizeof(moho::Stats<moho::StatItem>), std::nothrow)
    );
    moho::Stats<moho::StatItem>* statsRoot = nullptr;
    if (allocation != nullptr) {
      statsRoot = new (allocation) moho::Stats<moho::StatItem>();
    }

    boost::SharedPtrRaw<moho::Stats<moho::StatItem>> statsRootRaw{};
    statsRootRaw.px = statsRoot;
    try {
      InitializeStatsRootSharedControl(statsRootRaw.pi, statsRoot);
    } catch (...) {
      delete statsRoot;
      throw;
    }

    mStatsRoot = boost::SharedPtrFromRawRetained(statsRootRaw);
    statsRootRaw.release();
  }

  /**
   * Address: 0x0055DF40 (FUN_0055DF40, Moho::SSTIUnitConstantData::MemberDeserialize)
   *
   * What it does:
   * Loads build-state tag, stats root shared-pointer lane, and fake flag from
   * archive payload.
   */
  void SSTIUnitConstantData::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
  {
    if (version < 1) {
      throw gpg::SerializationError("unsupported version.");
    }

    bool buildStateTag = false;
    archive->ReadBool(&buildStateTag);
    mBuildStateTag = static_cast<std::uint8_t>(buildStateTag ? 1u : 0u);

    ReadStatsRootShared(mStatsRoot, archive, NullOwnerRef());

    bool fake = false;
    archive->ReadBool(&fake);
    mFake = static_cast<std::uint8_t>(fake ? 1u : 0u);
  }

  /**
   * Address: 0x0055DFB0 (FUN_0055DFB0, Moho::SSTIUnitConstantData::MemberSerialize)
   *
   * What it does:
   * Saves build-state tag, stats root shared-pointer lane, and fake flag to
   * archive payload.
   */
  void SSTIUnitConstantData::MemberSerialize(gpg::WriteArchive* const archive, const int version) const
  {
    if (version < 1) {
      throw gpg::SerializationError("unsupported version.");
    }

    archive->WriteBool(mBuildStateTag != 0u);
    gpg::WriteRawPointer(
      archive,
      MakeStatsStatItemRef(mStatsRoot.get()),
      gpg::TrackedPointerState::Shared,
      NullOwnerRef()
    );
    archive->WriteBool(mFake != 0u);
  }

  /**
   * Address: 0x0055C550 (FUN_0055C550, Moho::SSTIUnitConstantDataSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive load flow into `SSTIUnitConstantData::MemberDeserialize`.
   */
  void SSTIUnitConstantDataSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<SSTIUnitConstantData*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberDeserialize(archive, version);
  }

  /**
   * Address: 0x0055C570 (FUN_0055C570, Moho::SSTIUnitConstantDataSerializer::Serialize)
   *
   * What it does:
   * Forwards archive save flow into `SSTIUnitConstantData::MemberSerialize`.
   */
  void SSTIUnitConstantDataSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::RRef* const /*ownerRef*/
  )
  {
    const auto* const object = reinterpret_cast<const SSTIUnitConstantData*>(static_cast<std::uintptr_t>(objectPtr));
    object->MemberSerialize(archive, version);
  }

  /**
   * Address: 0x0055CB80 (FUN_0055CB80, gpg::SerSaveLoadHelper<Moho::SSTIUnitConstantData>::Init lane)
   *
   * What it does:
   * Binds serializer load/save callbacks into `SSTIUnitConstantData` RTTI.
   */
  void SSTIUnitConstantDataSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* type = SSTIUnitConstantData::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(SSTIUnitConstantData));
      SSTIUnitConstantData::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BF5420 (FUN_00BF5420, Moho::SSTIUnitConstantDataSerializer::~SSTIUnitConstantDataSerializer)
   *
   * What it does:
   * Unlinks the serializer helper node from the intrusive helper list and
   * restores self-links.
   */
  void cleanup_SSTIUnitConstantDataSerializer()
  {
    (void)UnlinkSerializerNode();
  }

  /**
   * Address: 0x00BCA640 (FUN_00BCA640, register_SSTIUnitConstantDataSerializer)
   *
   * What it does:
   * Initializes serializer callback pointers, vftable lane, and atexit cleanup.
   */
  void register_SSTIUnitConstantDataSerializer()
  {
    (void)InitializeSSTIUnitConstantDataSerializerSingleton();
    (void)std::atexit(&cleanup_SSTIUnitConstantDataSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SSTIUnitConstantDataSerializerBootstrap
  {
    SSTIUnitConstantDataSerializerBootstrap()
    {
      moho::register_SSTIUnitConstantDataSerializer();
    }
  };

  [[maybe_unused]] SSTIUnitConstantDataSerializerBootstrap gSSTIUnitConstantDataSerializerBootstrap;
} // namespace
