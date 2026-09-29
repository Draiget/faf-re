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
  using CSeqNo = int32_t;

  /**
   * VFTABLE: 0x00E2E794 (24 slots, every one `_purecall` at 0x00A82547)
   * RTTI:    .?AVICommandSink@Moho@@
   *
   * The simulation command stream, as an interface: one virtual per
   * `ECmdStreamOp`, in opcode order apart from `Advance` (opcode 0), which is
   * slot 22. Every change a player makes to the game world is one of these
   * calls. The same call sequence reaches every machine's sim, so the game
   * stays in lockstep.
   *
   * How a command travels:
   *
   *   UI / Lua / console
   *     -> `ISTIDriver` (`CSimDriver`), which takes the driver lock and
   *        returns the beat the command will land on as its "cookie"
   *     -> `CMarshaller`   : this interface, serialising each call as one
   *                          `CMDST_*` message
   *     -> `CClientManagerImpl` / `CClientBase` : per-client queues. Each
   *        beat `CClientBase::UpdateState` merges them into one stream,
   *        emitting `SetCommandSource` whenever the sender changes.
   *     -> `CDecoder`      : reads the merged stream (live or from a replay)
   *                          and calls the same slot on ...
   *     -> `Sim`           : this interface again, applying the command.
   *
   * `Sim` checks every world-changing command against the current command
   * source (`OkayToMessWith`). A command from a source that does not control
   * the army or unit is dropped silently. `CreateUnit`, `CreateProp`,
   * `WarpEntity` and `ExecuteLuaInSim` are cheat commands and are ignored
   * unless cheats are on.
   *
   * There is no virtual destructor slot. Nothing deletes through an
   * `ICommandSink*`; each owner holds its concrete type
   * (`CSimDriver::mMarshaller`, `CSimDriver::mSim`).
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

    /**
     * Slot 0 - `CMDST_SetCommandSource` (1): `uint8` source id.
     *
     * Says which player (command source) the commands that follow come from.
     * It is not issued by gameplay code. `CSimDriver`'s constructor sends it
     * once for the local source. `CClientBase::UpdateState` inserts one
     * whenever the merged stream switches between clients, deduplicated
     * against `CClientManagerImpl::mLastEmittedCommandSource`.
     *
     * `Sim`: makes it the current source for every later check. An
     * out-of-range id sets the invalid source (0xFF), so the commands after
     * it are ignored until the next valid one.
     */
    virtual void SetCommandSource(CommandSourceId sourceId) = 0;

    /**
     * Slot 1 - `CMDST_CommandSourceTerminated` (2): no payload.
     *
     * The current source has left the game. `CClientBase::UpdateState`
     * writes it for each of an ejected client's sources once the eject
     * beat is reached. It also passes one through from a client's own
     * stream, and then drops that source from the client's valid set.
     *
     * `Sim`: logs the departure and folds source and tick into the checksum
     * context. It lifts a pause that source holds, and tells every army the
     * source could control (`CArmyImpl::OnCommandSourceTerminated`).
     */
    virtual void OnCommandSourceTerminated() = 0;

    /**
     * Slot 2 - `CMDST_VerifyChecksum` (3): `MD5Digest` + `CSeqNo` beat.
     *
     * One player's hash of its sim state at a past beat. `CSimDriver`
     * publishes it from the sync path for beats its own sim has hashed.
     *
     * `Sim`: compares it with its own hash ring for that beat and records a
     * desync when they differ.
     */
    virtual void VerifyChecksum(gpg::MD5Digest const&, CSeqNo) = 0;

    /**
     * Slot 3 - `CMDST_RequestPause` (4): no payload.
     *
     * Issued via `ISTIDriver::RequestPause` by `CWldSession::RequestPause`,
     * `SessionRequestPause` (Lua) and the session loader.
     *
     * `Sim`: pauses on behalf of the current source, unless the game is
     * already paused or that source has no pause allowance left (each pause
     * spends one of its `mTimeouts`).
     */
    virtual void RequestPause() = 0;

    /**
     * Slot 4 - `CMDST_Resume` (5): no payload.
     *
     * Issued via `ISTIDriver::Resume` by `CWldSession::Resume`,
     * `SessionResume` (Lua) and the Lua debugger's step/resume hooks.
     *
     * `Sim`: clears the pause, if the command has a valid source.
     */
    virtual void Resume() = 0;

    /**
     * Slot 5 - `CMDST_SingleStep` (6): no payload.
     *
     * Issued via `ISTIDriver::SingleStep` by the `WLD_SingleStep` console
     * command.
     *
     * `Sim`: while paused, lets exactly one beat run.
     */
    virtual void SingleStep() = 0;

    /**
     * Slot 6 - `CMDST_CreateUnit` (7): `uint8` army, blueprint id,
     * `SCoordsVec2` position, heading.
     *
     * Cheat. Issued via `ISTIDriver::CreateUnit` by the `CreateUnit`
     * console command and `CreateUnitAtMouse` (Lua).
     *
     * `Sim`: spawns a finished unit for that army at the position, facing
     * `heading`.
     */
    virtual void CreateUnit(uint32_t, RResId const&, SCoordsVec2 const&, float) = 0;

    /**
     * Slot 7 - `CMDST_CreateProp` (8): blueprint id + world position.
     *
     * Cheat. Issued via `ISTIDriver::CreateProp` by the `CreateProp` and
     * `LotsOfProps` console commands.
     *
     * `Sim`: creates the prop, unrotated, at the position.
     */
    virtual void CreateProp(const char*, Wm3::Vec3f const&) = 0;

    /**
     * Slot 8 - `CMDST_DestroyEntity` (9): entity id.
     *
     * Nothing in this binary issues it: no caller goes through
     * `ISTIDriver::DestroyEntity` (driver slot +0x58). It is only ever
     * decoded, e.g. from another build's stream.
     *
     * `Sim`: destroys the entity if the current source may control it.
     */
    virtual void DestroyEntity(EntId) = 0;

    /**
     * Slot 9 - `CMDST_WarpEntity` (10): entity id + `VTransform`.
     *
     * Cheat. Issued via `ISTIDriver::WarpEntity` by the
     * `TeleportSelectedUnits` console command.
     *
     * `Sim`: moves the entity to the transform.
     */
    virtual void WarpEntity(EntId, VTransform const&) = 0;

    /**
     * Slot 10 - `CMDST_ProcessInfoPair` (11): entity id + key + value.
     *
     * A named per-unit setting. The keys `Sim` understands are
     * `SetFireState`, `SetAutoMode`, `SetAutoSurfaceMode`, `SetRepeatQueue`,
     * `SetPaused`, `CustomName`, `SiloBuildTactical`, `SiloBuildNuke`,
     * `ToggleScriptBit`, and `PlayNoStagingPlatformsVO` /
     * `PlayBusyStagingPlatformsVO` (value `"play"`; they run the army
     * brain's voice-over hook). Other keys are ignored. Issued via
     * `ISTIDriver::ProcessInfoPair` by the matching UI Lua
     * functions (`SetFireState`, `ToggleFireState`, `SetAutoMode`,
     * `SetAutoSurfaceMode`, `SetPaused`, `ToggleScriptBit`,
     * `UserUnit:ProcessInfo`, `UserUnit:SetCustomName`), by `IssueCommand` /
     * `IssueBlueprintCommand` / `IssueDockCommand`, and by the
     * `ProcessInfoPair` / `RenameUnit` console commands.
     *
     * `Sim`: applies the setting to the unit if it is alive and the
     * current source may control it.
     *
     * `Sim`'s override is mangled
     * `?ProcessInfoPair@Sim@Moho@@UAEXVEntId@2@VStrArg@gpg@@1@Z`, i.e.
     * `(EntId, gpg::StrArg, gpg::StrArg)`. The id is an entity id, not a
     * pointer.
     */
    virtual void ProcessInfoPair(EntId entityId, gpg::StrArg key, gpg::StrArg value) = 0;

    /**
     * Slot 11 - `CMDST_IssueCommand` (12): unit id set + command data +
     * clear-queue flag.
     *
     * The ordinary order: move, attack, build, patrol and the rest. Issued
     * via `ISTIDriver::IssueCommand` by `ISSUE_Command`, the path for every
     * order given in the UI.
     *
     * `Sim`: builds one shared `CUnitCommand` and queues it on each unit the
     * source controls, replacing their queues when `clear` is set.
     */
    virtual void
    IssueCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const& commandIssueData, bool flag) = 0;

    /**
     * Slot 12 - `CMDST_IssueFactoryCommand` (13): factory id set + command
     * data + clear-queue flag.
     *
     * An order for a factory's build queue. Issued via
     * `ISTIDriver::IssueFactoryCommand` by `ISSUE_FactoryCommand`.
     *
     * `Sim`: gives the command to every controllable factory in the set.
     */
    virtual void
    IssueFactoryCommand(BVSet<EntId, EntIdUniverse> const&, SSTICommandIssueData const& commandIssueData, bool) = 0;

    /**
     * Slot 13 - `CMDST_IncreaseCommandCount` (14): command id + count.
     *
     * Nothing in this binary issues it through `ISTIDriver::
     * IncreaseCommandCount` (driver slot +0x6C). `ISSUE_IncreaseCommandCount`
     * re-issues the factory build `count` times through `ISSUE_Command`
     * instead.
     *
     * `Sim`: adds to a queued command's repeat count.
     */
    virtual void IncreaseCommandCount(CmdId, int) = 0;

    /**
     * Slot 14 - `CMDST_DecreaseCommandCount` (15): command id + count.
     *
     * Issued via `ISTIDriver::DecreaseCommandCount` by
     * `ISSUE_DecreaseCommandCount`, `DeleteCommand` and
     * `DecreaseBuildCountInQueue` (Lua).
     *
     * `Sim`: lowers a queued command's repeat count. At zero the command is
     * removed from every unit's queue.
     */
    virtual void DecreaseCommandCount(CmdId, int) = 0;

    /**
     * Slot 15 - `CMDST_SetCommandTarget` (16): command id + `SSTITarget`.
     *
     * Re-targets an order already in a queue (dragging a waypoint). Issued
     * via `ISTIDriver::SetCommandTarget` by `ISSUE_SetCommandTarget`.
     *
     * `Sim`: resolves the target and sets it on the command.
     */
    virtual void SetCommandTarget(CmdId, SSTITarget const&) = 0;

    /**
     * Slot 16 - `CMDST_SetCommandType` (17): command id + `EUnitCommandType`.
     *
     * Changes what a queued order does. Issued via
     * `ISTIDriver::SetCommandType` when a queue is restarted from one of its
     * commands (0x0081DEF0, which inlines the out-of-line
     * `ISSUE_SetCommandType` copy at 0x008B11C0).
     *
     * `Sim`: sets the type and marks the command for an update.
     */
    virtual void SetCommandType(CmdId, EUnitCommandType) = 0;

    /**
     * Slot 17 - `CMDST_SetCommandCells` (18): command id + cell list +
     * target position.
     *
     * The footprint of a formation or area order. The only issuing path is
     * `ISSUE_SetCommandCells` (0x008B11F0, driver slot +0x7C), and nothing in
     * the binary calls it, so it is only ever decoded.
     *
     * `Sim`: replaces the command's cells and re-targets it at the position.
     */
    virtual void SetCommandCells(CmdId, gpg::core::FastVector<SOCellPos> const&, Wm3::Vector3<float> const&) = 0;

    /**
     * Slot 18 - `CMDST_RemoveCommandFromQueue` (19): command id + unit id.
     *
     * Takes one unit out of a shared order. Issued via
     * `ISTIDriver::RemoveCommandFromUnitQueue` by
     * `ISSUE_RemoveCommandFromUnitQueue` and `ISSUE_RemoveLastCommand`.
     *
     * `Sim`: removes the command from that unit's queue, or from its builder
     * queue.
     */
    virtual void RemoveCommandFromUnitQueue(CmdId, EntId) = 0;

    /**
     * Slot 19 - `CMDST_ExecuteLuaInSim` (21): function name + `LuaObject`
     * argument.
     *
     * Cheat. Issued via `ISTIDriver::ExecuteLuaInSim` by `ExecLuaInSim`
     * (Lua).
     *
     * `Sim`: calls the named global Lua function with the argument.
     */
    virtual void ExecuteLuaInSim(const char*, LuaPlus::LuaObject const&) = 0;

    /**
     * Slot 20 - `CMDST_LuaSimCallback` (22): callback name + `LuaObject`
     * arguments + unit id set.
     *
     * The legal way for UI Lua to ask the sim for something. Issued via
     * `ISTIDriver::LuaSimCallback` by `SimCallback` (Lua).
     *
     * `Sim`: calls `DoCallback(name, args, units)` from
     * `/lua/SimCallbacks.lua`. `units` holds every listed id that is still a
     * unit. Ownership is not checked here; the Lua callbacks check it.
     */
    virtual void LuaSimCallback(const char*, LuaPlus::LuaObject const&, BVSet<EntId, EntIdUniverse> const&) = 0;

    /**
     * Slot 21 - `CMDST_DebugCommand` (20): command text + mouse world
     * position + focus army + selected entity set.
     *
     * A console command that must run inside the sim. Issued via
     * `ISTIDriver::ExecuteDebugCommand` by `DoSimCommand`.
     *
     * `Sim`: runs the text through the sim console parser, with the position
     * and selection as context.
     */
    virtual void
    ExecuteDebugCommand(const char*, Wm3::Vector3<float> const&, uint32_t, BVSet<EntId, EntIdUniverse> const&) = 0;

    /**
     * Slot 22 - `CMDST_Advance` (0): beat count.
     *
     * Ends a beat: every command before it in the stream belongs to that
     * beat. `CSimDriver`'s issue thread sends it through the marshaller.
     * `CClientManagerImpl::UpdateStates` also appends one per dispatched
     * beat, and `CReplayClient` sends a final one when the replay runs out.
     *
     * `Sim`: runs one simulation beat. The count is not read. `CDecoder`
     * first flushes the recording stream, so a replay holds whole beats.
     */
    virtual void AdvanceBeat(int) = 0;

    /**
     * Slot 23 - `CMDST_EndGame` (23): no payload.
     *
     * Issued by `CClientManagerImpl::Disconnect`, and by `CReplayClient` at
     * the end of a replay.
     *
     * `Sim`: marks the game as ended. `CDecoder` also closes the recording
     * stream.
     */
    virtual void EndGame() = 0;
  };
} // namespace moho
