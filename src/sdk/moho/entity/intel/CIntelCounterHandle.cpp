#include "CIntelCounterHandle.h"

#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/Sim.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedSimType()
  {
    if (!moho::Sim::sType) {
      moho::Sim::sType = gpg::LookupRType(typeid(moho::Sim));
    }
    return moho::Sim::sType;
  }

  [[nodiscard]] gpg::RType* CachedIAiReconDBType()
  {
    if (!moho::IAiReconDB::sType) {
      moho::IAiReconDB::sType = gpg::LookupRType(typeid(moho::IAiReconDB));
    }
    return moho::IAiReconDB::sType;
  }

  [[noreturn]] void ThrowPointerTypeMismatch(gpg::RType* const expectedType, const gpg::RRef& source)
  {
    const char* const expected = expectedType ? expectedType->GetName() : "null";
    const char* const actual = source.mType ? source.mType->GetName() : "null";
    const msvc8::string message = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected,
      actual
    );
    throw std::runtime_error(message.c_str());
  }

  template <class TPointer> [[nodiscard]] gpg::RRef MakeDerivedRef(TPointer* const object, gpg::RType* expectedType)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = expectedType;
    if (!object || !expectedType) {
      return out;
    }

    try {
      gpg::RType* dynamicType = gpg::LookupRType(typeid(*object));
      if (!dynamicType) {
        return out;
      }

      std::int32_t baseOffset = 0;
      if (!dynamicType->IsDerivedFrom(expectedType, &baseOffset)) {
        out.mType = dynamicType;
        return out;
      }

      out.mObj = reinterpret_cast<void*>(
        reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset)
      );
      out.mType = dynamicType;
      return out;
    } catch (...) {
      return out;
    }
  }

  template <class TPointer>
  [[nodiscard]]
  TPointer* ReadTypedPointer(gpg::ReadArchive* const archive, gpg::RType* const expectedType, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, expectedType);
    if (!upcast.mObj) {
      ThrowPointerTypeMismatch(expectedType, source);
    }

    return static_cast<TPointer*>(upcast.mObj);
  }

  void ApplyCounterIntelToReconGrid(moho::CIntelCounterHandle& handle, moho::IAiReconDB* reconDB, const bool doAdd)
  {
    if (reconDB == nullptr) {
      return;
    }

    boost::SharedPtrRaw<moho::CIntelGrid> grid{};
    switch (handle.mType) {
    case moho::INTELCOUNTER_RadarStealthField:
      grid = reconDB->ReconGetRCIGrid();
      break;
    case moho::INTELCOUNTER_SonarStealthField:
      grid = reconDB->ReconGetSCIGrid();
      break;
    case moho::INTELCOUNTER_CloakField:
      grid = reconDB->ReconGetVCIGrid();
      break;
    default:
      gpg::Warnf(
        "Moho::CIntelCounterHandle::%s: unsupported counter intel type %i",
        doAdd ? "AddViz" : "SubViz",
        static_cast<int>(handle.mType)
      );
      return;
    }

    if (grid.px != nullptr) {
      if (doAdd) {
        grid.px->AddCircle(handle.mLastPos, handle.mRadius);
      } else {
        grid.px->SubtractCircle(handle.mLastPos, handle.mRadius);
      }
    }

    grid.release();
  }

  void ApplyCounterIntelToForeignArmies(moho::CIntelCounterHandle& handle, const bool doAdd)
  {
    if (handle.mSim == nullptr) {
      return;
    }

    for (moho::CArmyImpl* const army : handle.mSim->mArmiesList) {
      if (army == nullptr) {
        continue;
      }

      moho::IAiReconDB* const reconDB = army->GetReconDB();
      if (reconDB == handle.mReconDB) {
        continue;
      }

      ApplyCounterIntelToReconGrid(handle, reconDB, doAdd);
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CIntelCounterHandle::sType = nullptr;

  gpg::RType* CIntelCounterHandle::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CIntelCounterHandle));
    }
    return sType;
  }

  /**
   * Address: 0x0076D9F0 (FUN_0076D9F0, Moho::CIntelCounterHandle::CIntelCounterHandle)
   *
   * What it does:
   * Initializes counter-intel handle state, owner pointers, and type selector.
   */
CIntelCounterHandle::CIntelCounterHandle(
  const std::uint32_t radius, Sim* const sim, const EIntelCounter type, CAiReconDBImpl* const reconDB
)
    : CIntelPosHandle(radius, boost::SharedPtrRaw<CIntelGrid>{})
    , mSim(sim)
    , mReconDB(reconDB)
    , mType(type)
  {
    mLastPos = {};
    mRadius = radius;
    mLastTickUpdated = 0;
    mEnabled = 0;
    mGrid = {};
  }

  /**
   * Address: 0x0076DA60 (FUN_0076DA60, Moho::CIntelCounterHandle::~CIntelCounterHandle)
   *
   * What it does:
   * Removes currently applied counter-intel coverage and then tears down base
   * intel-handle ownership.
   */
  CIntelCounterHandle::~CIntelCounterHandle()
  {
    SubViz();
    mEnabled = 0;
  }

  /**
   * Address: 0x00770120 (FUN_00770120, Moho::CIntelCounterHandle::MemberDeserialize)
   *
   * gpg::ReadArchive *
   *
   * IDA signature:
   * void __usercall Moho::CIntelCounterHandle::MemberDeserialize(
   *   gpg::ReadArchive *archive@<eax>, Moho::CIntelCounterHandle *this@<esi>);
   *
   * What it does:
   * Loads `mSim`, `mReconDB`, `mType`, then deserializes the
   * `CIntelPosHandle` base payload.
   */
  void CIntelCounterHandle::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};
    mSim = ReadTypedPointer<Sim>(archive, CachedSimType(), ownerRef);
    mReconDB = ReadTypedPointer<IAiReconDB>(archive, CachedIAiReconDBType(), ownerRef);

    int counterType = static_cast<int>(INTELCOUNTER_None);
    archive->ReadInt(&counterType);
    mType = static_cast<EIntelCounter>(counterType);

    archive->Read(CIntelPosHandle::StaticGetClass(), static_cast<CIntelPosHandle*>(this), ownerRef);
  }

  /**
   * Address: 0x0076FDF0 (FUN_0076FDF0)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelCounterHandle::MemberDeserialize`.
   */
  [[maybe_unused]] void CIntelCounterHandleMemberDeserializeBridgeA(
    gpg::ReadArchive* const archive,
    CIntelCounterHandle* const handle
  )
  {
    if (handle != nullptr) {
      handle->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x007701A0 (FUN_007701A0, Moho::CIntelCounterHandle::MemberSerialize)
   *
   * gpg::WriteArchive *
   *
   * IDA signature:
   * void __usercall Moho::CIntelCounterHandle::MemberSerialize(
   *   Moho::CIntelCounterHandle *this@<edi>, gpg::WriteArchive *archive@<esi>);
   *
   * What it does:
   * Saves `mSim` and `mReconDB` as unowned pointers, writes `mType`,
   * then serializes the `CIntelPosHandle` base payload.
   */
  void CIntelCounterHandle::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef ownerRef{};

    const gpg::RRef simRef = MakeDerivedRef(mSim, CachedSimType());
    gpg::WriteRawPointer(archive, simRef, gpg::TrackedPointerState::Unowned, ownerRef);

    const gpg::RRef reconDbRef = MakeDerivedRef(mReconDB, CachedIAiReconDBType());
    gpg::WriteRawPointer(archive, reconDbRef, gpg::TrackedPointerState::Unowned, ownerRef);

    archive->WriteInt(static_cast<int>(mType));
    archive->Write(CIntelPosHandle::StaticGetClass(), static_cast<const CIntelPosHandle*>(this), ownerRef);
  }

  /**
   * Address: 0x0076FE00 (FUN_0076FE00)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelCounterHandle::MemberSerialize`.
   */
  [[maybe_unused]] void CIntelCounterHandleMemberSerializeBridgeA(
    const CIntelCounterHandle* const handle,
    gpg::WriteArchive* const archive
  )
  {
    if (handle != nullptr) {
      handle->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0076FFE0 (FUN_0076FFE0)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelCounterHandle::MemberDeserialize`.
   */
  [[maybe_unused]] void CIntelCounterHandleMemberDeserializeBridgeB(
    gpg::ReadArchive* const archive,
    CIntelCounterHandle* const handle
  )
  {
    if (handle != nullptr) {
      handle->MemberDeserialize(archive);
    }
  }

  /**
   * Address: 0x0076FFF0 (FUN_0076FFF0)
   *
   * What it does:
   * Serializer bridge thunk that forwards to `CIntelCounterHandle::MemberSerialize`.
   */
  [[maybe_unused]] void CIntelCounterHandleMemberSerializeBridgeB(
    const CIntelCounterHandle* const handle,
    gpg::WriteArchive* const archive
  )
  {
    if (handle != nullptr) {
      handle->MemberSerialize(archive);
    }
  }

  /**
   * Address: 0x0076F5D0 (FUN_0076F5D0, Moho::CIntelCounterHandle::AddViz)
   *
   * What it does:
   * Applies this counter-intel radius to matching foreign-army recon grids.
   */
  void CIntelCounterHandle::AddViz()
  {
    if (mEnabled == 0u || mRadius == 0u) {
      return;
    }

    ApplyCounterIntelToForeignArmies(*this, true);
  }

  /**
   * Address: 0x0076F720 (FUN_0076F720, Moho::CIntelCounterHandle::SubViz)
   *
   * What it does:
   * Removes this counter-intel radius from matching foreign-army recon grids.
   */
  void CIntelCounterHandle::SubViz()
  {
    if (mEnabled == 0u || mRadius == 0u) {
      return;
    }

    ApplyCounterIntelToForeignArmies(*this, false);
  }

  /**
   * Address: 0x0076DAC0 (FUN_0076DAC0, Moho::CIntelCounterHandle::dtr)
   *
   * What it does:
   * Runs non-virtual destructor body and conditionally frees the object
   * allocation when `shouldDelete & 1` is set.
   */
  void CIntelCounterHandle::Destroy(const int shouldDelete)
  {
    this->~CIntelCounterHandle();
    if ((shouldDelete & 1) != 0) {
      ::operator delete(this);
    }
  }
} // namespace moho
