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
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

namespace
{
  class SSTIUnitConstantDataTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "SSTIUnitConstantData";
    }

    void Init() override
    {
      size_ = sizeof(moho::SSTIUnitConstantData);
      gpg::RType::Init();
      Finish();
    }
  };

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

  /**
   * Address: 0x005CC860 (FUN_005CC860, destroy_Stats_StatItem_if_present)
   *
   * What it does:
   * Runs one `Stats_StatItem` destructor and frees storage when the incoming
   * pointer lane is non-null.
   */
  void DestroyStatsStatItemIfPresent(moho::Stats_StatItem* const statItem) noexcept
  {
    if (statItem == nullptr) {
      return;
    }

    delete statItem;
  }

} // namespace

namespace moho
{
  gpg::RType* SSTIUnitConstantData::sType = nullptr;

  /**
   * Address: 0x0055C410 (FUN_0055C410, preregister_SSTIUnitConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIUnitConstantData`.
   */
  gpg::RType* preregister_SSTIUnitConstantDataTypeInfo()
  {
    static SSTIUnitConstantDataTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(SSTIUnitConstantData), &typeInfo);
    SSTIUnitConstantData::sType = &typeInfo;
    return &typeInfo;
  }

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

    const gpg::RRef ownerRef = NullOwnerRef();
    archive->ReadPointerShared(&mStatsRoot, &ownerRef);

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

} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SSTIUnitConstantDataTypeInfo_f5d847, moho::preregister_SSTIUnitConstantDataTypeInfo)

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SSTIUnitConstantData>`, vtable 0x00E1881C.
   *
   * Address: 0x00BCA640 (FUN_00BCA640 -- constructs the global and registers its destructor.)
   * Address: 0x00BF5420 (FUN_00BF5420 -- the global's destructor.)
   * Address: 0x0055C590 (FUN_0055C590 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x0055CB80 (FUN_0055CB80 -- `Init`.)
   * Address: 0x0055C550 (FUN_0055C550 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x0055C570 (FUN_0055C570 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct SSTIUnitConstantDataSerializer : gpg::SerSaveLoadHelper<SSTIUnitConstantData>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ACBE0 -- process-global `SSTIUnitConstantDataSerializer` singleton.
  moho::SSTIUnitConstantDataSerializer gSSTIUnitConstantDataSerializer;
} // namespace
