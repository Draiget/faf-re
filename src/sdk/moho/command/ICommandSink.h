#pragma once
#include <cstdint>

#include "CmdDefs.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/containers/BVSet.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/Entity.h"
#include "moho/resource/RResId.h"
#include "SSTICommandIssueData.h"

namespace gpg
{
  struct MD5Digest;
}

namespace moho
{
  struct SOCellPos;
  using CommandSourceId = uint32_t;
  using CSeqNo = int32_t;

  struct CommandList; // container of target entities/units (a2)
  struct CommandSpec; // command descriptor (a3)

  /**
   * Abstract class, pure virtual functions (all are __purecall <-> sub_A82547)
   */
  class ICommandSink
  {
    // Primary vftable (24 entries)
  public:
    /**
     * Address: 0x00748650
     *
     * VFTable SLOT: 0
     */
    virtual void SetCommandSource(CommandSourceId sourceId) = 0;

    /**
     * Address:0x007486B0
     *
     * VFTable SLOT: 1
     */
    virtual void OnCommandSourceTerminated() = 0;

    /**
     * Address: 0x007487C0
     *
     * VFTable SLOT: 2
     */
    virtual void VerifyChecksum(gpg::MD5Digest const&, CSeqNo) = 0;

    /**
     * Address: 0x00748960
     *
     * VFTable SLOT: 3
     */
    virtual void RequestPause() = 0;

    /**
     * Address: 0x007489A0
     *
     * VFTable SLOT: 4
     */
    virtual void Resume() = 0;

    /**
     * Address: 0x007489C0
     *
     * VFTable SLOT: 5
     */
    virtual void SingleStep() = 0;

    /**
     * Address: 0x00748AA0
     *
     * VFTable SLOT: 6
     */
    virtual void CreateUnit(uint32_t, RResId const&, SCoordsVec2 const&, float) = 0;

    /**
     * Address: 0x00748C00
     *
     * VFTable SLOT: 7
     */
    virtual void CreateProp(const char*, Wm3::Vec3f const&) = 0;

    /**
     * Address: 0x00748C80
     *
     * VFTable SLOT: 8
     */
    virtual void DestroyEntity(EntId) = 0;

    /**
     * Address: 0x00748CD0
     *
     * VFTable SLOT: 9
     */
    virtual void WarpEntity(EntId, VTransform const&) = 0;

    /**
     * Address: 0x00748D50
     * #STRs:
     *  "SetFireState", "SetAutoMode", "CustomName",
     *  "SetAutoSurfaceMode", "SetRepeatQueue", "SetPaused",
     *  "SiloBuildTactical", "SiloBuildNuke", "ToggleScriptBit",
     *  "false"
     *
     * VFTable SLOT: 10
     */
    virtual void ProcessInfoPair(void* id, const char* key, const char* val) = 0;

    /**
     * Address: 0x00749290
     *
     * Moho::BVSet<Moho::EntId,Moho::EntIdUniverse> const &,Moho::SSTICommandIssueData const &,bool
     *
     * IDA signature:
     * char __userpurge Moho__Sim__IssueCommand@<al>(Moho::Sim *this@<ecx>, int esi0@<esi>, int *a3,
     * Moho::SSTICommandIssueData *commandIssueData, BOOL flag);
     *
     * VFTable SLOT: 11
     */
    virtual void
    IssueCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const& commandIssueData, bool flag) = 0;

    /**
     * Address: 0x007494B0
     *
     * VFTable SLOT: 12
     */
    virtual void
    IssueFactoryCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const& commandIssueData, bool) = 0;

    /**
     * Address: 0x00749680
     *
     * VFTable SLOT: 13
     */
    virtual void IncreaseCommandCount(CmdId, int) = 0;

    /**
     * Address: 0x007496E0
     *
     * VFTable SLOT: 14
     */
    virtual void DecreaseCommandCount(CmdId, int) = 0;

    /**
     * Address: 0x00749740
     *
     * VFTable SLOT: 15
     */
    virtual void SetCommandTarget(CmdId, SSTITarget const&) = 0;

    /**
     * Address: 0x00749800
     *
     * VFTable SLOT: 16
     */
    virtual void SetCommandType(CmdId, EUnitCommandType) = 0;

    /**
     * Address: 0x00749860
     *
     * VFTable SLOT: 17
     */
    virtual void SetCommandCells(CmdId, gpg::core::FastVector<SOCellPos> const&, Wm3::Vector3<float> const&) = 0;

    /**
     * Address: 0x00749970
     *
     * VFTable SLOT: 18
     */
    virtual void RemoveCommandFromUnitQueue(CmdId, EntId) = 0;

    /**
     * Address: 0x00749A70
     *
     * VFTable SLOT: 19
     */
    virtual void ExecuteLuaInSim(const char*, LuaPlus::LuaObject const&) = 0;

    /**
     * Address: 0x00749B60
     *
     * VFTable SLOT: 20
     */
    virtual void LuaSimCallback(const char*, LuaPlus::LuaObject const&, BVSet<EntId, EntIdUniverse> const&) = 0;

    /**
     * Address: 0x00749DA0
     *
     * VFTable SLOT: 21
     */
    virtual void
    ExecuteDebugCommand(const char*, Wm3::Vector3<float> const&, uint32_t, BVSet<EntId, EntIdUniverse> const&) = 0;

    /**
     * Address: 0x00749F40
     *
     * VFTable SLOT: 22
     */
    virtual void AdvanceBeat(int);

    /**
     * Address: 0x0074B100
     *
     * VFTable SLOT: 23
     */
    virtual void EndGame();
  };
} // namespace moho
