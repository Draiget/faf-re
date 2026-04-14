#pragma once

#include <cstddef>

#include "gpg/core/containers/FastVector.h"
#include "moho/ai/IAiFormationDB.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Sim;

  /**
   * VFTABLE: 0x00E1B52C
   * COL:  0x00E70A38
   */
  class CAiFormationDBImpl : public IAiFormationDB
  {
  public:
    /**
     * Address: 0x0059BFE0 (FUN_0059BFE0, non-deleting dtor body)
     * Address: 0x0059C340 (FUN_0059C340)
     *
     * What it does:
     * Tears down formation-instance vector storage, then (for deleting lane)
     * releases the concrete formation DB instance.
     */
    ~CAiFormationDBImpl() override;

    /**
     * Address: 0x0059C0C0 (FUN_0059C0C0)
     */
    const char* GetScriptName(int scriptIndex, EFormationType formationType) override;

    /**
     * Address: 0x0059C0F0 (FUN_0059C0F0)
     */
    int GetScriptIndex(gpg::StrArg scriptName, EFormationType formationType) override;

    /**
     * Address: 0x0059C060 (FUN_0059C060)
     */
    void RemoveFormation(CAiFormationInstance* formation) override;

    /**
     * Address: 0x0059C030 (FUN_0059C030)
     */
    void Update() override;

    /**
     * Address: 0x0059C120 (FUN_0059C120)
     */
    CAiFormationInstance* NewFormation(
      const SFormationUnitWeakRefSet* unitWeakSet,
      const char* scriptName,
      const SCoordsVec2* formationCenter,
      float orientX,
      float orientY,
      float orientZ,
      float orientW,
      int commandType
    ) override;

    /**
     * Address: 0x0059EA20 (FUN_0059EA20, Moho::CAiFormationDBImpl::MemberDeserialize)
     *
     * What it does:
     * Reads serialized formation-DB members from archive lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x0059EA90 (FUN_0059EA90, Moho::CAiFormationDBImpl::MemberSerialize)
     *
     * What it does:
     * Writes serialized formation-DB members to archive lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    Sim* mSim;                                                   // +0x04
    gpg::fastvector_n<CAiFormationInstance*, 10> mFormInstances; // +0x08
  };

  static_assert(offsetof(CAiFormationDBImpl, mSim) == 0x04, "CAiFormationDBImpl::mSim offset must be 0x04");
  static_assert(
    offsetof(CAiFormationDBImpl, mFormInstances) == 0x08, "CAiFormationDBImpl::mFormInstances offset must be 0x08"
  );
  static_assert(sizeof(CAiFormationDBImpl) == 0x40, "CAiFormationDBImpl size must be 0x40");
} // namespace moho
