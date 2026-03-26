#pragma once

#include <cstddef>
#include <cstdint>

#include "CIntelPosHandle.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CAiReconDBImpl;
  class IAiReconDB;
  class Sim;

  enum EIntelCounter : std::int32_t
  {
    INTELCOUNTER_None = 0x00,
    INTELCOUNTER_RadarStealthField = 0x01,
    INTELCOUNTER_SonarStealthField = 0x02,
    INTELCOUNTER_CloakField = 0x08,
  };

  /**
   * Recovered counter-intel handle used for radar/sonar stealth and cloak fields.
   *
   * Layout evidence:
   * - FUN_0076D9F0 constructor writes mSim(+0x24), mReconDB(+0x28), mType(+0x2C)
   * - CIntelCounterHandleTypeInfo::Init (0x0076F4F0) sets sizeof to 0x30.
   */
  class CIntelCounterHandle : public CIntelPosHandle
  {
  public:
    [[nodiscard]] static gpg::RType* StaticGetClass();

    static gpg::RType* sType;

    /**
     * Address: 0x0076D9F0 (FUN_0076D9F0, Moho::CIntelCounterHandle::CIntelCounterHandle)
     *
     * What it does:
     * Initializes counter-intel handle state, owner pointers, and type selector.
     */
    CIntelCounterHandle(std::uint32_t radius, Sim* sim, EIntelCounter type, CAiReconDBImpl* reconDB);

    /**
     * Address: 0x0076DA60 (FUN_0076DA60, Moho::CIntelCounterHandle::~CIntelCounterHandle)
     *
     * What it does:
     * Removes currently applied counter-intel coverage and then tears down base
     * intel-handle ownership.
     */
    ~CIntelCounterHandle();

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
    void MemberDeserialize(gpg::ReadArchive* archive);

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
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x0076F5D0 (FUN_0076F5D0, Moho::CIntelCounterHandle::AddViz)
     *
     * What it does:
     * Applies this counter-intel radius to matching foreign-army recon grids.
     */
    void AddViz() override;

    /**
     * Address: 0x0076F720 (FUN_0076F720, Moho::CIntelCounterHandle::SubViz)
     *
     * What it does:
     * Removes this counter-intel radius from matching foreign-army recon grids.
     */
    void SubViz() override;

    /**
     * Address: 0x0076DAC0 (FUN_0076DAC0, Moho::CIntelCounterHandle::dtr)
     *
     * What it does:
     * Runs non-virtual destructor body and conditionally frees the object
     * allocation when `shouldDelete & 1` is set.
     */
    void Destroy(int shouldDelete) override;

    Sim* mSim;                 // +0x24
    IAiReconDB* mReconDB;      // +0x28
    EIntelCounter mType;       // +0x2C
  };

#if defined(_M_IX86)
  static_assert(sizeof(CIntelCounterHandle) == 0x30, "CIntelCounterHandle size must be 0x30");
  static_assert(offsetof(CIntelCounterHandle, mSim) == 0x24, "CIntelCounterHandle::mSim offset must be 0x24");
  static_assert(offsetof(CIntelCounterHandle, mReconDB) == 0x28, "CIntelCounterHandle::mReconDB offset must be 0x28");
  static_assert(offsetof(CIntelCounterHandle, mType) == 0x2C, "CIntelCounterHandle::mType offset must be 0x2C");
#endif
} // namespace moho
