#pragma once

#include <cstdint>

#include "legacy/containers/Vector.h"
#include "moho/command/ICommandSink.h"
#include "moho/render/camera/GeomCamera3.h"
#include "platform/Platform.h"
#include "SSyncFilter.h"

namespace moho
{
  class CClientManagerImpl;
  class Sim;
  class CD3DPrimBatcher;
  class CSaveGameRequestImpl;
  struct SSyncData;

  /**
   * Base simulation-thread interface.
   *
   * Recovered from CSimDriver vtable (0x00E3350C).
   */
  class ISTIDriver
  {
  public:
    /**
     * Address: 0x0073B0C0 (FUN_0073B0C0, ??0ISTIDriver@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes one simulation-driver base interface object.
     */
    ISTIDriver();

    // Slot 0. Base: 0x0073B0D0 (FUN_0073B0D0); CSimDriver deleting thunk: 0x0073B910 (FUN_0073B910)
    // Base scalar-deleting destructor for ISTIDriver.
    virtual ~ISTIDriver();

    // Slot 1. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073BBF0 (FUN_0073BBF0)
    // Forces all clients to disconnect from the driver transport.
    virtual void DisconnectClients() = 0;

    // Slot 2. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073BC80 (FUN_0073BC80)
    // Stops worker threads and tears down simulation-side state.
    virtual void ShutDown() = 0;

    // Slot 3. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B190 (FUN_0073B190)
    // Returns the owning client manager.
    virtual CClientManagerImpl* GetClientManager() = 0;

    // Slot 4. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073BDE0 (FUN_0073BDE0)
    // Placeholder virtual in the original vtable (ret-only nullsub/no-op).
    virtual void NoOp() = 0;

    // Slot 5. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C250 (FUN_0073C250)
    // Main dispatch tick: save handling, mode transitions, and sim stepping.
    virtual void Dispatch() = 0;

    // Slot 6. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C410 (FUN_0073C410)
    // Increments the outstanding driver activity counter.
    virtual void IncrementOutstandingRequests() = 0;

    // Slot 7. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C440 (FUN_0073C440)
    // Decrements the activity counter and timestamps completion boundaries.
    virtual void DecrementOutstandingRequestsAndSignal() = 0;

    // Slot 8. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C4F0 (FUN_0073C4F0)
    // True when at least one sync packet is queued.
    virtual bool HasSyncData() = 0;

    // Slot 9. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C520 (FUN_0073C520)
    // Pops the next sync packet, blocking via event pumping while empty.
    virtual void GetSyncData(SSyncData*& outSyncData) = 0;

    // Slot 10. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B1A0 (FUN_0073B1A0)
    // Event signaled when new sync data becomes available.
    virtual HANDLE GetSyncDataAvailableEvent() = 0;

    // Slot 11. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C630 (FUN_0073C630)
    // Returns current sim speed metric (stubbed as 0.0 in retail driver).
    virtual double GetSimSpeed() = 0;

    // Slot 12. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B1B0 (FUN_0073B1B0)
    // Updates focus army used by sync filtering.
    virtual void SetArmyIndex(int armyIndex) = 0;

    // Slot 13. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B270 (FUN_0073B270)
    // Replaces camera list used when preparing sync snapshots.
    virtual void SetGeomCams(const msvc8::vector<GeomCamera3>& geoCams) = 0;

    // Slot 14. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B3F0 (FUN_0073B3F0)
    // Retail binary performs compare-only logic for mask block A (no state mutation in this build).
    virtual void SetSyncFilterMaskA(const SSyncFilterMaskBlock& block) = 0;

    // Slot 15. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B4B0 (FUN_0073B4B0)
    // Replaces pending sync-filter mask block B.
    virtual void SetSyncFilterMaskB(const SSyncFilterMaskBlock& block) = 0;

    // Slot 16. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073B240 (FUN_0073B240)
    // Toggles sync-filter option bit used during Sim::Sync.
    virtual void SetSyncFilterOptionFlag(bool value) = 0;

    // Slot 17. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C660 (FUN_0073C660),
    // ECmdStreamOp::CMDST_RequestPause (4)
    // Returns command cookie via optional out lane when provided.
    virtual void RequestPause(std::int32_t* outCommandCookie = nullptr) = 0;

    // Slot 18. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C700 (FUN_0073C700), ECmdStreamOp::CMDST_Resume
    // (5)
    // Returns command cookie via optional out lane when provided.
    virtual void Resume(std::int32_t* outCommandCookie = nullptr) = 0;

    // Slot 19. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C7A0 (FUN_0073C7A0),
    // ECmdStreamOp::CMDST_SingleStep (6)
    virtual void SingleStep() = 0;

    // Slot 20. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C840 (FUN_0073C840),
    // ECmdStreamOp::CMDST_CreateUnit (7)
    virtual void CreateUnit(uint32_t armyIndex, const RResId& id, const SCoordsVec2& pos, float heading) = 0;

    // Slot 21. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C8F0 (FUN_0073C8F0),
    // ECmdStreamOp::CMDST_CreateProp (8)
    virtual void CreateProp(const char* id, const Wm3::Vec3f& loc) = 0;

    // Slot 22. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073C990 (FUN_0073C990),
    // ECmdStreamOp::CMDST_DestroyEntity (9)
    virtual void DestroyEntity(EntId entityId) = 0;

    // Slot 23. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CA30 (FUN_0073CA30),
    // ECmdStreamOp::CMDST_WarpEntity (10)
    virtual void WarpEntity(EntId entityId, const VTransform& transform) = 0;

    // Slot 24. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CAD0 (FUN_0073CAD0),
    // ECmdStreamOp::CMDST_ProcessInfoPair (11)
    virtual void ProcessInfoPair(void* id, const char* key, const char* val) = 0;

    // Slot 25. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CB70 (FUN_0073CB70),
    // ECmdStreamOp::CMDST_IssueCommand (12)
    virtual void
    IssueCommand(const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& data, bool clear) = 0;

    // Slot 26. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CC10 (FUN_0073CC10),
    // ECmdStreamOp::CMDST_IssueFactoryCommand (13)
    virtual void
    IssueFactoryCommand(const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& data, bool clear) = 0;

    // Slot 27. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CCB0 (FUN_0073CCB0),
    // ECmdStreamOp::CMDST_IncreaseCommandCount (14)
    virtual void IncreaseCommandCount(CmdId id, int count) = 0;

    // Slot 28. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CD50 (FUN_0073CD50),
    // ECmdStreamOp::CMDST_DecreaseCommandCount (15)
    virtual void DecreaseCommandCount(CmdId id, int count) = 0;

    // Slot 29. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CDF0 (FUN_0073CDF0),
    // ECmdStreamOp::CMDST_SetCommandTarget (16)
    virtual void SetCommandTarget(CmdId id, const SSTITarget& target) = 0;

    // Slot 30. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CE90 (FUN_0073CE90),
    // ECmdStreamOp::CMDST_SetCommandType (17)
    virtual void SetCommandType(CmdId id, EUnitCommandType type) = 0;

    // Slot 31. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CF30 (FUN_0073CF30),
    // ECmdStreamOp::CMDST_SetCommandCells (18)
    virtual void
    SetCommandCells(CmdId id, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& target) = 0;

    // Slot 32. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073CFD0 (FUN_0073CFD0),
    // ECmdStreamOp::CMDST_RemoveCommandFromQueue (19)
    virtual void RemoveCommandFromUnitQueue(CmdId id, EntId unitId) = 0;

    // Slot 33. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073D070 (FUN_0073D070),
    // ECmdStreamOp::CMDST_ExecuteLuaInSim (21)
    virtual void ExecuteLuaInSim(const char* lua, const LuaPlus::LuaObject& args) = 0;

    // Slot 34. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073D110 (FUN_0073D110),
    // ECmdStreamOp::CMDST_LuaSimCallback (22)
    virtual void
    LuaSimCallback(const char* fnName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities) = 0;

    // Slot 35. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073D1B0 (FUN_0073D1B0),
    // ECmdStreamOp::CMDST_DebugCommand (20)
    virtual void ExecuteDebugCommand(
      const char* command,
      const Wm3::Vector3<float>& worldPos,
      uint32_t focusArmy,
      const BVSet<EntId, EntIdUniverse>& entities
    ) = 0;

    // Slot 36. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073DEA0 (FUN_0073DEA0)
    // Processes pending events while interlocked mode is active.
    virtual Sim* ProcessEvents() = 0;

    // Slot 37. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073DF50 (FUN_0073DF50)
    // Decrements interlocked-mode reference counter.
    virtual void ReleaseInterlockRef() = 0;

    // Slot 38. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073DF60 (FUN_0073DF60)
    // Enqueues a save-game request to be executed on Dispatch().
    virtual void RequestSaveGame(CSaveGameRequestImpl* request) = 0;

    // Slot 39. Base: 0x00A82547 (_purecall); CSimDriver override: 0x0073DFE0 (FUN_0073DFE0)
    // Renders network/sync diagnostics overlay.
    virtual void
    DrawNetworkStats(CD3DPrimBatcher* batcher, float anchorX, float anchorY, float scaleX, float scaleY) = 0;
  };

  static_assert(sizeof(ISTIDriver) == 0x4, "ISTIDriver size must be 0x4");
} // namespace moho
