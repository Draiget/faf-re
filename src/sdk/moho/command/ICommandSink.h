#pragma once
#include <cstdint>

#include "CmdDefs.h"
#include "gpg/core/containers/String.h"
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
   * VFTABLE: 0x00E2E794 (24 slots, every one `_purecall` at 0x00A82547)
   * RTTI:    .?AVICommandSink@Moho@@
   *
   * The command-stream vocabulary: one virtual per `ECmdStreamOp`. The
   * interface itself has no bodies. Its two implementors each own their
   * slot addresses:
   *   - `Sim`         (vftable 0x00E34714) applies the command to the world;
   *   - `CMarshaller` (vftable 0x00E2E7FC) serialises it onto the wire.
   * `CDecoder` is the reverse of `CMarshaller`: it reads the wire and calls
   * back into an `ICommandSink` (the `Sim`).
   *
   * There is no virtual destructor slot. Nothing deletes through an
   * `ICommandSink*`; each owner holds its concrete type.
   */
  class ICommandSink
  {
  public:
    /**
     * Address: 0x006E59F0 (FUN_006E59F0)
     * Address: 0x006E5A70 (FUN_006E5A70)
     * Address: 0x006E5A80 (FUN_006E5A80)
     *
     * What it does:
     * Re-installs the interface vftable (`mov [this], 0x00E2E794; ret`) as the
     * last step of destroying an implementor.
     *
     * 0x006E59F0 is reached only from EH unwind funclets: 0x00BB94F3 and
     * 0x00BC1A13 destroy `Sim`'s `ICommandSink` base when `Sim::Sim` /
     * `Sim::~Sim` unwind. It was formerly cited as `ICommandSink()`, but no
     * constructor path ever calls it. The destructor is user-declared
     * because a trivial one would never be called from a funclet.
     *
     * 0x006E5A70 and 0x006E5A80 are byte-identical copies emitted in
     * `CMarshaller`'s translation unit, beside `CMarshaller::CMarshaller`
     * (0x006E5A60). Nothing in the binary references them. The implicit
     * `ICommandSink()` and `CMarshaller`'s implicit destructor both reduce
     * to this same single store, so they are the compiler's out-of-line
     * copies of this family, not source of their own. They were formerly
     * `ResetICommandSinkBaseVtableLaneA/B` over an `ICommandSinkRuntimeView`,
     * which stored the address of a one-byte static where the vftable
     * belongs.
     */
    ~ICommandSink() {}

    // Slot 0
    virtual void SetCommandSource(CommandSourceId sourceId) = 0;

    // Slot 1
    virtual void OnCommandSourceTerminated() = 0;

    // Slot 2
    virtual void VerifyChecksum(gpg::MD5Digest const&, CSeqNo) = 0;

    // Slot 3
    virtual void RequestPause() = 0;

    // Slot 4
    virtual void Resume() = 0;

    // Slot 5
    virtual void SingleStep() = 0;

    // Slot 6
    virtual void CreateUnit(uint32_t, RResId const&, SCoordsVec2 const&, float) = 0;

    // Slot 7
    virtual void CreateProp(const char*, Wm3::Vec3f const&) = 0;

    // Slot 8
    virtual void DestroyEntity(EntId) = 0;

    // Slot 9
    virtual void WarpEntity(EntId, VTransform const&) = 0;

    /**
     * Slot 10
     *
     * `Sim`'s override is mangled
     * `?ProcessInfoPair@Sim@Moho@@UAEXVEntId@2@VStrArg@gpg@@1@Z`, i.e.
     * `(EntId, gpg::StrArg, gpg::StrArg)`. The id is an entity id, not a
     * pointer.
     */
    virtual void ProcessInfoPair(EntId entityId, gpg::StrArg key, gpg::StrArg value) = 0;

    // Slot 11
    virtual void
    IssueCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const& commandIssueData, bool flag) = 0;

    // Slot 12
    virtual void
    IssueFactoryCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const& commandIssueData, bool) = 0;

    // Slot 13
    virtual void IncreaseCommandCount(CmdId, int) = 0;

    // Slot 14
    virtual void DecreaseCommandCount(CmdId, int) = 0;

    // Slot 15
    virtual void SetCommandTarget(CmdId, SSTITarget const&) = 0;

    // Slot 16
    virtual void SetCommandType(CmdId, EUnitCommandType) = 0;

    // Slot 17
    virtual void SetCommandCells(CmdId, gpg::core::FastVector<SOCellPos> const&, Wm3::Vector3<float> const&) = 0;

    // Slot 18
    virtual void RemoveCommandFromUnitQueue(CmdId, EntId) = 0;

    // Slot 19
    virtual void ExecuteLuaInSim(const char*, LuaPlus::LuaObject const&) = 0;

    // Slot 20
    virtual void LuaSimCallback(const char*, LuaPlus::LuaObject const&, BVSet<EntId, EntIdUniverse> const&) = 0;

    // Slot 21
    virtual void
    ExecuteDebugCommand(const char*, Wm3::Vector3<float> const&, uint32_t, BVSet<EntId, EntIdUniverse> const&) = 0;

    // Slot 22
    virtual void AdvanceBeat(int) = 0;

    // Slot 23
    virtual void EndGame() = 0;
  };
} // namespace moho
