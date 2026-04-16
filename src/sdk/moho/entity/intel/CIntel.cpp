#include "CIntel.h"

#include <new>
#include <stdexcept>
#include <typeinfo>

#include "CIntelCounterHandle.h"
#include "CIntelPosHandle.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"

namespace
{
  struct CIntelSerializerHelperRuntime
  {
    void* mVtable;
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(CIntelSerializerHelperRuntime, mHelperNext) == 0x04,
    "CIntelSerializerHelperRuntime::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CIntelSerializerHelperRuntime, mHelperPrev) == 0x08,
    "CIntelSerializerHelperRuntime::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CIntelSerializerHelperRuntime, mLoadCallback) == 0x0C,
    "CIntelSerializerHelperRuntime::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CIntelSerializerHelperRuntime, mSaveCallback) == 0x10,
    "CIntelSerializerHelperRuntime::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CIntelSerializerHelperRuntime) == 0x14, "CIntelSerializerHelperRuntime size must be 0x14");

  CIntelSerializerHelperRuntime gCIntelSerializerHelper{};

  [[nodiscard]] gpg::RType* CachedCIntelPosHandleType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CIntelPosHandle));
    }
    return cached;
  }

  [[nodiscard]] gpg::RRef MakePosHandleRef(moho::CIntelPosHandle* const handle)
  {
    gpg::RRef out{};
    gpg::RType* const baseType = CachedCIntelPosHandleType();
    out.mObj = handle;
    out.mType = baseType;
    if (!handle || !baseType) {
      return out;
    }

    try {
      gpg::RType* dynamicType = gpg::LookupRType(typeid(*handle));
      if (!dynamicType) {
        return out;
      }

      std::int32_t baseOffset = 0;
      if (!dynamicType->IsDerivedFrom(baseType, &baseOffset)) {
        out.mType = dynamicType;
        return out;
      }

      out.mObj = reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(handle) - static_cast<std::uintptr_t>(baseOffset)
      );
      out.mType = dynamicType;
      return out;
    } catch (...) {
      return out;
    }
  }

  [[nodiscard]] moho::CIntelPosHandle* ReadPosHandlePointer(gpg::ReadArchive& archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(&archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCIntelPosHandleType());
    if (upcast.mObj) {
      return static_cast<moho::CIntelPosHandle*>(upcast.mObj);
    }

    throw std::runtime_error("CIntel::ReadArchive expected CIntelPosHandle-compatible pointer.");
  }

  [[nodiscard]] bool PositionChanged(const moho::CIntelPosHandle& handle, const Wm3::Vec3f& position) noexcept
  {
    return handle.mLastPos.x != position.x || handle.mLastPos.y != position.y || handle.mLastPos.z != position.z;
  }

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

  int DeserializeCIntelFromArchiveBridge(const int archivePtr, const int objectPtr)
  {
    gpg::ReadArchive* const archive = reinterpret_cast<gpg::ReadArchive*>(archivePtr);
    auto* const intel = reinterpret_cast<moho::CIntel*>(objectPtr);
    if (archive == nullptr || intel == nullptr) {
      return 0;
    }

    const gpg::RRef nullOwner{};
    intel->ReadArchive(*archive, nullOwner);
    return 0;
  }
} // namespace

namespace moho
{
  gpg::RType* CIntel::sType = nullptr;

  /**
   * Address: 0x00683170 (FUN_00683170)
   *
   * What it does:
   * Returns cached reflected type metadata for `CIntel`, resolving it
   * through RTTI lookup on first use.
   */
  gpg::RType* CIntel::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CIntel));
    }
    return sType;
  }

  /**
   * Address: 0x0076DED0 (FUN_0076DED0, Moho::CIntel::CIntel)
   *
   * What it does:
   * Initializes all intel handle slots to null and clears all
   * `{present,enabled}` toggle-state pairs.
   */
  CIntel::CIntel()
    : mVisionGrid(nullptr)
    , mWaterGrid(nullptr)
    , mRadarGrid(nullptr)
    , mSonarGrid(nullptr)
    , mOmniGrid(nullptr)
    , mRCIGrid(nullptr)
    , mSCIGrid(nullptr)
    , mVCIGrid(nullptr)
    , mReservedGrid(nullptr)
  {
    BoolFieldInit(&mJamming);
    BoolFieldInit(&mCloak);
    BoolFieldInit(&mSpoof);
    BoolFieldInit(&mSonarStealth);
    BoolFieldInit(&mRadarStealth);
  }

  /**
   * Address: 0x0076DAE0 (FUN_0076DAE0, Moho::CIntel::CIntel)
   *
   * What it does:
   * Initializes intel handles and toggle presence flags from
   * `RUnitBlueprintIntel` radii/booleans and owning recon/sim pointers.
   */
  CIntel::CIntel(const RUnitBlueprintIntel* const blueprintIntel, Sim* const sim, CAiReconDBImpl* const reconDB)
    : CIntel()
  {
    if (blueprintIntel->VisionRadius != 0u) {
      InitIntel(1, blueprintIntel->VisionRadius, reconDB, sim);
    }
    if (blueprintIntel->WaterVisionRadius != 0u) {
      InitIntel(2, blueprintIntel->WaterVisionRadius, reconDB, sim);
    }
    if (blueprintIntel->RadarRadius != 0u) {
      InitIntel(3, blueprintIntel->RadarRadius, reconDB, sim);
    }
    if (blueprintIntel->SonarRadius != 0u) {
      InitIntel(4, blueprintIntel->SonarRadius, reconDB, sim);
    }
    if (blueprintIntel->OmniRadius != 0u) {
      InitIntel(5, blueprintIntel->OmniRadius, reconDB, sim);
    }
    if (blueprintIntel->RadarStealthFieldRadius != 0u) {
      InitIntel(6, blueprintIntel->RadarStealthFieldRadius, reconDB, sim);
    }
    if (blueprintIntel->SonarStealthFieldRadius != 0u) {
      InitIntel(7, blueprintIntel->SonarStealthFieldRadius, reconDB, sim);
    }
    if (blueprintIntel->CloakFieldRadius != 0u) {
      InitIntel(8, blueprintIntel->CloakFieldRadius, reconDB, sim);
    }

    mJamming.present = static_cast<std::uint8_t>(
      (blueprintIntel->JammerBlips != 0u && blueprintIntel->JamRadius.max != 0u) ? 1u : 0u
    );
    mCloak.present = static_cast<std::uint8_t>(blueprintIntel->Cloak != 0u ? 1u : 0u);
    mSpoof.present = static_cast<std::uint8_t>(blueprintIntel->SpoofRadius.max != 0u ? 1u : 0u);
    mSonarStealth.present = static_cast<std::uint8_t>(blueprintIntel->SonarStealth != 0u ? 1u : 0u);
    mRadarStealth.present = static_cast<std::uint8_t>(blueprintIntel->RadarStealth != 0u ? 1u : 0u);
  }

  /**
   * Address: 0x0076D800 (FUN_0076D800, Moho::CIntel::BoolFieldInit)
   *
   * What it does:
   * Clears one `{present,enabled}` toggle pair.
   */
  void CIntel::BoolFieldInit(CIntelToggleState* const toggleState)
  {
    toggleState->present = 0u;
    toggleState->enabled = 0u;
  }

  /**
   * Address: 0x0076E490 (FUN_0076E490, Moho::CIntel::ForceUpdate)
   *
   * Wm3::Vector3f *,int
   *
   * What it does:
   * Forces position refresh pass across all active intel handles.
   */
  void CIntel::ForceUpdate(const Wm3::Vec3f& position, const std::int32_t tick)
  {
    for (std::size_t i = 0; i < kHandleCount; ++i) {
      CIntelPosHandle* const handle = mIntelHandles[i];
      if (!handle) {
        continue;
      }

      handle->UpdatePos(tick, position);
    }
  }

  /**
   * Address: 0x0076E4C0 (FUN_0076E4C0, Moho::CIntel::Update)
   *
   * Wm3::Vector3f *,int
   *
   * What it does:
   * Updates armed intel handles against new position and updates
   * per-handle tick stamps.
   */
  void CIntel::Update(const Wm3::Vec3f& position, const std::int32_t tick)
  {
    for (std::size_t i = 0; i < kHandleCount; ++i) {
      CIntelPosHandle* const handle = mIntelHandles[i];
      if (!handle) {
        continue;
      }

      if (handle->mEnabled != 0u) {
        const std::uint32_t savedRadius = handle->mRadius;
        if (PositionChanged(*handle, position)) {
          handle->SubViz();
          handle->mLastPos = position;
          handle->mRadius = savedRadius;
          handle->AddViz();
        }
      } else {
        handle->mLastPos = position;
      }

      handle->mLastTickUpdated = tick;
    }
  }

  /**
   * Address: 0x0076EA60 (FUN_0076EA60)
   *
   * What it does:
   * Reads all 9 intel-handle pointers and 5 toggle-state pairs from archive,
   * replacing any existing handle instances.
   */
  void CIntel::ReadArchive(gpg::ReadArchive& archive, const gpg::RRef& ownerRef)
  {
    for (std::size_t i = 0; i < kHandleCount; ++i) {
      CIntelPosHandle* const loaded = ReadPosHandlePointer(archive, ownerRef);
      CIntelPosHandle* const previous = mIntelHandles[i];
      mIntelHandles[i] = loaded;
      if (previous) {
        previous->Destroy(1);
      }
    }

    CIntelToggleState* const toggles[5] = {&mJamming, &mCloak, &mSpoof, &mSonarStealth, &mRadarStealth};
    for (CIntelToggleState* const toggle : toggles) {
      bool present = false;
      bool enabled = false;
      archive.ReadBool(&present);
      archive.ReadBool(&enabled);
      toggle->present = static_cast<std::uint8_t>(present ? 1u : 0u);
      toggle->enabled = static_cast<std::uint8_t>(enabled ? 1u : 0u);
    }
  }

  /**
   * Address: 0x0076EAE0 (FUN_0076EAE0, Moho::CIntel::WriteArchive)
   *
   * What it does:
   * Writes all 9 intel-handle pointers as owned tracked pointers and then
   * serializes 5 toggle-state `{present,enabled}` pairs.
   */
  void CIntel::WriteArchive(gpg::WriteArchive& archive, const gpg::RRef& ownerRef) const
  {
    for (std::size_t i = 0; i < kHandleCount; ++i) {
      const gpg::RRef handleRef = MakePosHandleRef(mIntelHandles[i]);
      gpg::WriteRawPointer(&archive, handleRef, gpg::TrackedPointerState::Owned, ownerRef);
    }

    const CIntelToggleState* const toggles[5] = {&mJamming, &mCloak, &mSpoof, &mSonarStealth, &mRadarStealth};
    for (const CIntelToggleState* const toggle : toggles) {
      archive.WriteBool(toggle->present != 0u);
      archive.WriteBool(toggle->enabled != 0u);
    }
  }

  /**
   * Address: 0x0076E6B0 (FUN_0076E6B0)
   *
   * What it does:
   * Serializer-load thunk lane that forwards directly into
   * `CIntel::ReadArchive` using a null-owner reflection reference.
   */
  [[maybe_unused]] void DeserializeCIntelFromArchiveThunk(gpg::ReadArchive* const archive, CIntel* const intel)
  {
    if (archive == nullptr || intel == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    intel->ReadArchive(*archive, nullOwner);
  }

  /**
   * Address: 0x0076E9E0 (FUN_0076E9E0, thunk to 0x0076EA60)
   *
   * What it does:
   * Reflection serializer load callback wrapper for `ReadArchive`.
   */
  void CIntel::SerializeLoad(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || !ownerRef || objectPtr == 0) {
      return;
    }

    auto* const intel = reinterpret_cast<CIntel*>(static_cast<std::uintptr_t>(objectPtr));
    intel->ReadArchive(*archive, *ownerRef);
  }

  /**
   * Address: 0x0076E6C0 (FUN_0076E6C0, Moho::CIntelSerializer::Serialize)
   *
   * What it does:
   * Reflection serializer save callback wrapper for `WriteArchive`.
   */
  void CIntel::SerializeSave(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    if (!archive || !ownerRef || objectPtr == 0) {
      return;
    }

    auto* const intel = reinterpret_cast<CIntel*>(static_cast<std::uintptr_t>(objectPtr));
    intel->WriteArchive(*archive, *ownerRef);
  }

  /**
   * Address: 0x0076E6D0 (FUN_0076E6D0)
   *
   * What it does:
   * Initializes startup CIntel serializer-helper links and binds recovered
   * load/save callback lanes.
   */
  [[nodiscard]] gpg::SerHelperBase* InitializeCIntelSerializerHelper()
  {
    InitializeHelperNode(gCIntelSerializerHelper);
    gCIntelSerializerHelper.mLoadCallback = reinterpret_cast<gpg::RType::load_func_t>(
      &DeserializeCIntelFromArchiveBridge
    );
    gCIntelSerializerHelper.mSaveCallback = reinterpret_cast<gpg::RType::save_func_t>(&CIntel::SerializeSave);
    return HelperSelfNode(gCIntelSerializerHelper);
  }

  /**
   * Address: 0x0076E010 (FUN_0076E010, Moho::CIntel::InitIntel)
   *
   * What it does:
   * Initializes or replaces one intel lane (vision/radar/sonar/omni/counter
   * fields/toggle lanes) against recon grids.
   */
  void CIntel::InitIntel(
    const std::int32_t intelType, const std::uint32_t radius, CAiReconDBImpl* const reconDB, Sim* const sim
  )
  {
    auto replacePosHandle = [](CIntelPosHandle*& slot, CIntelPosHandle* const replacement) {
      CIntelPosHandle* const previous = slot;
      slot = replacement;
      if (previous) {
        previous->Destroy(1);
      }
    };

    auto replaceCounterHandle = [](CIntelCounterHandle*& slot, CIntelCounterHandle* const replacement) {
      CIntelCounterHandle* const previous = slot;
      slot = replacement;
      if (previous) {
        previous->Destroy(1);
      }
    };

    switch (intelType) {
    case 1: {
      boost::SharedPtrRaw<CIntelGrid> grid = reconDB ? reconDB->ReconGetVisionGrid() : boost::SharedPtrRaw<CIntelGrid>{};
      replacePosHandle(mVisionGrid, new (std::nothrow) CIntelPosHandle(radius, grid));
      grid.release();
      return;
    }
    case 2: {
      boost::SharedPtrRaw<CIntelGrid> grid = reconDB ? reconDB->ReconGetWaterGrid() : boost::SharedPtrRaw<CIntelGrid>{};
      replacePosHandle(mWaterGrid, new (std::nothrow) CIntelPosHandle(radius, grid));
      grid.release();
      return;
    }
    case 3: {
      boost::SharedPtrRaw<CIntelGrid> grid = reconDB ? reconDB->ReconGetRadarGrid() : boost::SharedPtrRaw<CIntelGrid>{};
      replacePosHandle(mRadarGrid, new (std::nothrow) CIntelPosHandle(radius, grid));
      grid.release();
      return;
    }
    case 4: {
      boost::SharedPtrRaw<CIntelGrid> grid = reconDB ? reconDB->ReconGetSonarGrid() : boost::SharedPtrRaw<CIntelGrid>{};
      replacePosHandle(mSonarGrid, new (std::nothrow) CIntelPosHandle(radius, grid));
      grid.release();
      return;
    }
    case 5: {
      boost::SharedPtrRaw<CIntelGrid> grid = reconDB ? reconDB->ReconGetOmniGrid() : boost::SharedPtrRaw<CIntelGrid>{};
      replacePosHandle(mOmniGrid, new (std::nothrow) CIntelPosHandle(radius, grid));
      grid.release();
      return;
    }
    case 6:
      replaceCounterHandle(
        mRCIGrid,
        new (std::nothrow) CIntelCounterHandle(radius, sim, INTELCOUNTER_RadarStealthField, reconDB)
      );
      return;
    case 7:
      replaceCounterHandle(
        mSCIGrid,
        new (std::nothrow) CIntelCounterHandle(radius, sim, INTELCOUNTER_SonarStealthField, reconDB)
      );
      return;
    case 8:
      replaceCounterHandle(mVCIGrid, new (std::nothrow) CIntelCounterHandle(radius, sim, INTELCOUNTER_CloakField, reconDB));
      return;
    case 9:
      mJamming.present = 1u;
      return;
    case 11:
      mSpoof.present = 1u;
      return;
    case 12:
      mSonarStealth.present = 1u;
      return;
    case 13:
      mRadarStealth.present = 1u;
      return;
    default:
      gpg::Warnf("Unknown intel type %i", intelType);
      return;
    }
  }

  bool CIntel::HasActiveJamming() const noexcept
  {
    return mJamming.present != 0u && mJamming.enabled != 0u;
  }
} // namespace moho

namespace
{
  struct CIntelSerializerHelperBootstrap
  {
    CIntelSerializerHelperBootstrap()
    {
      (void)moho::InitializeCIntelSerializerHelper();
    }
  };

  [[maybe_unused]] CIntelSerializerHelperBootstrap gCIntelSerializerHelperBootstrap;
} // namespace
