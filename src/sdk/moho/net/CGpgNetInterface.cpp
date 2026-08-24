#include "CGpgNetInterface.h"

#include <boost/bind.hpp>

#include <cstring>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Logging.h"
#include "IClient.h"
#include "CClientManagerImpl.h"
#include "INetTCPServer.h"
#include "INetTCPSocket.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/EngineVectorHelpers.h"
#include "moho/net/INetNATTraversalProviderWeakPtrReflection.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/SimDriver.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "platform/Platform.h"
#include <array>
#include <float.h>
#include <shellapi.h>
#include <wchar.h>
#include <windows.h>

using namespace moho;

namespace moho
{
  class IEditorDispatchHook
  {
  public:
    virtual ~IEditorDispatchHook() = default;
    virtual int Dispatch() = 0;
  };

  IEditorDispatchHook* ed_Hook = nullptr;
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedAtLeastArgsWarning = "%s\n  expected at least %d args, but got %d";
  constexpr const char* kGpgNetActiveHelpText = "bool GpgNetActive()";
  constexpr const char* kGpgNetSendHelpText = "GpgNetSend(cmd,args...)";

  boost::shared_ptr<CGpgNetInterface> sGPGNet;

  /**
   * Address: 0x007B6450 (FUN_007B6450)
   *
   * What it does:
   * Dispatches one optional editor hook lane when present and returns its
   * integer result; returns `0` when no hook is installed.
   */
  [[maybe_unused]] int DispatchEditorHookIfPresent()
  {
    return moho::ed_Hook != nullptr ? moho::ed_Hook->Dispatch() : 0;
  }

  /**
   * Address: 0x007BDB70 (FUN_007BDB70, register_WeakPtr_INetNATTraversalProvider_Type_00)
   *
   * What it does:
   * Forces the `boost::weak_ptr<INetNATTraversalProvider>` reflection lane to
   * materialize during startup.
   */
  [[nodiscard]] gpg::RType* RegisterWeakPtrINetNATTraversalProviderType()
  {
    return gpg::ResolveWeakPtrINetNATTraversalProviderType();
  }

  namespace
  {
    struct GpgNetReflectionBootstrap
    {
      GpgNetReflectionBootstrap()
      {
        (void)RegisterWeakPtrINetNATTraversalProviderType();
      }
    };

    GpgNetReflectionBootstrap gGpgNetReflectionBootstrap;
  } // namespace

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    return moho::SCR_FindLuaInitFormSet("User");
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  int32_t ExpectIntArg(
    CGpgNetInterface& owner,
    const SNetCommandArg* arg
  )
  {
    if (!arg || arg->mType != SNetCommandArg::NETARG_Num) {
      owner.ExpectedInt();
    }
    return arg->mNum;
  }

  void ReadExactFromSocket(
    INetTCPSocket* socket,
    char* out,
    const size_t size,
    const char* eofMessage
  )
  {
    size_t total = 0;
    while (total < size) {
      const size_t got = socket->Read(out + total, size - total);
      if (got == 0) {
        throw std::runtime_error(eofMessage);
      }
      total += got;
    }
  }

  /**
   * Address: 0x007B9040 (FUN_007B9040, func_UnknownCommand)
   *
   * What it does:
   * Emits a `gpg::Warnf` warning naming the unrecognized GPGNET command and
   * returns; the original engine quietly drops unknown commands rather than
   * propagating an exception.
   */
  void LogUnknownCommand(
    const msvc8::string& commandName
  )
  {
    gpg::Warnf("GPGNET: Ignoring unknown gpg.net command \"%s\".", commandName.c_str());
  }

  /**
   * Address: 0x007B6500 (FUN_007B6500)
   *
   * What it does:
   * Returns whether one `LuaStackObject` currently points at a Lua boolean
   * stack slot (`lua_type == LUA_TBOOLEAN`).
   */
  [[maybe_unused]] bool IsLuaStackObjectBooleanType(
    const LuaPlus::LuaStackObject& stackObject
  ) noexcept
  {
    if (stackObject.m_state == nullptr || stackObject.m_state->GetCState() == nullptr) {
      return false;
    }

    return lua_type(stackObject.m_state->GetCState(), stackObject.m_stackIndex) == LUA_TBOOLEAN;
  }

  /**
   * Address: 0x007BB0E0 (FUN_007BB0E0)
   *
   * What it does:
   * Returns the live element count for one legacy vector lane.
   */
  [[nodiscard]] std::size_t GetCommandArgCount(
    const msvc8::vector<SNetCommandArg>& args
  ) noexcept
  {
    return args.size();
  }

  /**
   * Address: 0x007BB0A0 (FUN_007BB0A0)
   *
   * What it does:
   * Clears one command-argument vector lane before the owning command object
   * finishes destruction.
   */
  void DestroyCommandArgStorage(
    msvc8::vector<SNetCommandArg>& args
  ) noexcept
  {
    args = msvc8::vector<SNetCommandArg>{};
  }

  /**
   * Address: 0x007BBA90 (FUN_007BBA90)
   *
   * What it does:
   * Clears the queued command deque and releases its element payload lanes.
   */
  void ClearCommandQueue(
    msvc8::deque<SNetCommand>& commands
  ) noexcept
  {
    commands.clear();
  }

  /**
   * Address: 0x007BB3C0 (FUN_007BB3C0, queue-clear thunk)
   * Address: 0x007BB4D0 (FUN_007BB4D0, queue-clear thunk)
   *
   * What it does:
   * Tail-forwards one queued-command deque clear lane into
   * `ClearCommandQueue`.
   */
  [[maybe_unused]] void ClearCommandQueueThunk(
    msvc8::deque<SNetCommand>& commands
  ) noexcept
  {
    ClearCommandQueue(commands);
  }

  /**
   * Address: 0x007BB440 (FUN_007BB440, deque push-back lane)
   *
   * What it does:
   * Appends one `SNetCommand` to the back of the legacy deque command queue.
   */
  void PushBackQueuedCommand(
    msvc8::deque<SNetCommand>& commandQueue,
    const SNetCommand& command
  )
  {
    commandQueue.push_back(command);
  }

  /**
   * Address: 0x007BE750 (FUN_007BE750, deque push-front lane)
   *
   * What it does:
   * Prepends one `SNetCommand` to the front of the legacy deque command queue
   * and returns the stored front element address.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommand* PushFrontQueuedCommand(
    msvc8::deque<SNetCommand>& commandQueue,
    const SNetCommand& command
  )
  {
    commandQueue.push_front(command);
    return commandQueue.empty() ? nullptr : &commandQueue.front();
  }

  /**
   * Address: 0x007BD950 (FUN_007BD950)
   *
   * What it does:
   * Fills one half-open command-arg range with a single prototype argument by
   * copying scalar lanes and cloning the legacy string payload.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* FillCommandArgRangeFromPrototype(
    SNetCommandArg* destinationBegin,
    SNetCommandArg* destinationEnd,
    const SNetCommandArg& prototype
  )
  {
    while (destinationBegin != destinationEnd) {
      destinationBegin->mType = prototype.mType;
      destinationBegin->mNum = prototype.mNum;
      destinationBegin->mStr.assign(prototype.mStr, 0, msvc8::string::npos);
      ++destinationBegin;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x007BD810 (FUN_007BD810)
   *
   * What it does:
   * Writes `count` copies of one command-argument prototype into contiguous
   * destination lanes, and on exception destroys already-written lanes before
   * rethrowing.
   */
  void CopyAssignCommandArgRangeWithRollback(
    const SNetCommandArg& prototype,
    std::uint32_t count,
    SNetCommandArg* const destination
  )
  {
    if (destination == nullptr || count == 0U) {
      return;
    }

    SNetCommandArg* const begin = destination;
    SNetCommandArg* cursor = destination;
    try {
      for (std::uint32_t i = 0; i < count; ++i, ++cursor) {
        *cursor = prototype;
      }
    } catch (...) {
      for (SNetCommandArg* rollback = begin; rollback != cursor; ++rollback) {
        rollback->ResetPayload();
      }
      throw;
    }
  }

  /**
   * Address: 0x007BEE10 (FUN_007BEE10, command-arg range copy-assign)
   *
   * What it does:
   * Copy-assigns one half-open contiguous `SNetCommandArg` range into
   * destination lanes and returns one-past-last written pointer.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* CopyAssignCommandArgRange(
    SNetCommandArg* destination,
    const SNetCommandArg* sourceBegin,
    const SNetCommandArg* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      destination->mType = sourceBegin->mType;
      destination->mNum = sourceBegin->mNum;
      destination->mStr.assign(sourceBegin->mStr, 0, msvc8::string::npos);
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x007BDE40 (FUN_007BDE40)
   *
   * What it does:
   * Copy-assigns one half-open command-argument source range into destination
   * lanes and rolls back already-written destination entries on exception.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* CopyAssignCommandArgRangeWithRollbackFromSourceLaneA(
    const SNetCommandArg* sourceBegin,
    const SNetCommandArg* sourceEnd,
    SNetCommandArg* destination
  )
  {
    SNetCommandArg* const writtenBegin = destination;
    SNetCommandArg* cursor = destination;
    try {
      while (sourceBegin != sourceEnd) {
        *cursor = *sourceBegin;
        ++cursor;
        ++sourceBegin;
      }
    } catch (...) {
      for (SNetCommandArg* rollback = writtenBegin; rollback != cursor; ++rollback) {
        rollback->ResetPayload();
      }
      throw;
    }
    return cursor;
  }


  /**
   * Address: 0x007BD1B0 (FUN_007BD1B0)
   *
   * What it does:
   * Assigns one command-argument vector lane from source into destination,
   * preserving self-assignment and empty-source clear semantics.
   */
  [[maybe_unused]] msvc8::vector<SNetCommandArg>* AssignCommandArgVectorStorage(
    msvc8::vector<SNetCommandArg>* const destination,
    const int /*destroyContext*/,
    const msvc8::vector<SNetCommandArg>* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    if (destination == source) {
      return destination;
    }

    if (source->empty()) {
      destination->clear();
      return destination;
    }

    *destination = *source;
    return destination;
  }

  /**
   * Address: 0x007BD8F0 (FUN_007BD8F0)
   *
   * What it does:
   * Destroys one half-open `SNetCommandArg` range by releasing each string
   * payload lane in turn.
   */
  void DestroyCommandArgRange(
    SNetCommandArg* first,
    SNetCommandArg* last
  ) noexcept
  {
    for (; first != last; ++first) {
      first->ResetPayload();
    }
  }

  /**
   * Address: 0x007BBD40 (FUN_007BBD40)
   *
   * What it does:
   * Adapts one thiscall range-destroy lane into
   * `DestroyCommandArgRange(begin, end)`.
   */
  [[maybe_unused]] void DestroyCommandArgRangeThiscallAdapter(
    SNetCommandArg* const rangeEnd,
    SNetCommandArg* const rangeBegin
  ) noexcept
  {
    DestroyCommandArgRange(rangeBegin, rangeEnd);
  }

} // namespace

/**
 * Address: 0x007BB840 (FUN_007BB840, msvc8::vector<Moho::SNetCommandArg>::_Tidy)
 *
 * IDA signature:
 * void __usercall sub_7BB840(int a1@<esi>);
 *
 * What it does:
 * Destroys the live element range through the per-`T` range-destroy emission,
 * releases the storage block, and clears the `{first_, last_, end_}` triplet.
 * The VC8 debug-iterator proxy lane at +0x00 is deliberately left alone, which
 * is what the binary does.
 */
/**
 * Address: 0x007BB7F0 (FUN_007BB7F0, msvc8::vector<Moho::SNetCommandArg>::_Buy)
 *
 * IDA signature:
 * char callcnv_F3 sub_7BB7F0@<al>(_DWORD *a1@<edi>, unsigned int a2@<esi>);
 *
 * What it does:
 * Allocates raw storage for `count` elements and arms the triplet: `first` and
 * `last` both point at the block start (nothing constructed yet), `end` at the
 * capacity limit. A count of zero leaves the triplet null and reports success.
 *
 * The guard constant 0x71C71C7 is max_size for this element: 0xFFFFFFFF / 36,
 * and sizeof(SNetCommandArg) is 0x24. Exceeding it raises length_error rather
 * than overflowing the byte count.
 */
bool moho::BuyVectorOfSNetCommandArgStorage(
  msvc8::vector<moho::SNetCommandArg>& storage,
  const std::size_t count
)
{
  constexpr std::size_t kMaxElements = 0x71C71C7u;
  if (count > kMaxElements) {
    throw std::length_error("vector<T> too long");
  }

  if (count == 0u) {
    return true;
  }

  storage.reserve(count);
  return storage.capacity() >= count;
}

/**
 * Address: 0x007BB6A0 (FUN_007BB6A0, msvc8::vector<Moho::SNetCommandArg>::vector(count, value))
 *
 * IDA signature:
 * void __thiscall sub_7BB6A0(unsigned int a1, std::vector_SNetCommandArg *a3, int a4);
 *
 * What it does:
 * Builds a vector holding `count` copies of `prototype`. Storage is bought
 * first, then the elements are copy-constructed into it and `last` is advanced
 * only once the fill has succeeded - so a throw mid-fill leaves `last` at the
 * block start and the rollback funclet has nothing constructed to destroy
 * beyond what the fill lane already unwound.
 */
void moho::ConstructVectorOfSNetCommandArgFilled(
  msvc8::vector<moho::SNetCommandArg>& storage,
  const std::size_t count,
  const moho::SNetCommandArg& prototype
)
{
  storage.clear();
  if (count == 0u) {
    return;
  }

  try {
    storage.insert(storage.begin(), count, prototype);
  } catch (...) {
    moho::TidyVectorOfSNetCommandArg(storage);
    throw;
  }
}

void moho::TidyVectorOfSNetCommandArg(msvc8::vector<moho::SNetCommandArg>& storage) noexcept
{
  if (moho::SNetCommandArg* const first = storage.begin(); first != nullptr) {
    DestroyCommandArgRange(first, storage.end());
    ::operator delete(static_cast<void*>(first));
  }

  storage.reset_range_lanes_preserve_proxy();
}

/**
 * Address: 0x007B9470 (FUN_007B9470, Moho::GPGNET_SetPtr)
 *
 * What it does:
 * Replaces the process-global GPGNet shared-pointer lane (`sGPGNet`).
 */
void moho::GPGNET_SetPtr(
  const boost::shared_ptr<CGpgNetInterface>& ptr
)
{
  sGPGNet = ptr;
}

boost::shared_ptr<moho::CGpgNetInterface> moho::GPGNET_GetPtr()
{
  return sGPGNet;
}

/**
 * Address: 0x007B94C0 (FUN_007B94C0, ?GPGNET_ReportBottleneck@Moho@@YAXABUSClientBottleneckInfo@1@@Z)
 *
 * What it does:
 * Formats one bottleneck report payload and sends `"Bottleneck"` through the
 * active process-global GPGNet interface.
 */
void moho::GPGNET_ReportBottleneck(
  const SClientBottleneckInfo& info
)
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (!active || activeDriver == nullptr) {
    return;
  }

  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();

  const char* bottleneckType = "unknown";
  switch (info.mType) {
    case SClientBottleneckInfo::Nothing:
      bottleneckType = "nothing";
      break;
    case SClientBottleneckInfo::Readiness:
      bottleneckType = "readiness";
      break;
    case SClientBottleneckInfo::Data:
      bottleneckType = "data";
      break;
    case SClientBottleneckInfo::Ack:
      bottleneckType = "ack";
      break;
    default:
      break;
  }

  msvc8::string impactedOwners{};
  const unsigned int endValue = info.mSubobj.Max();
  unsigned int ownerIndex = info.mSubobj.GetNext(std::numeric_limits<unsigned int>::max());
  if (ownerIndex != endValue) {
    if (IClient* const first = clientManager->GetClient(static_cast<int>(ownerIndex)); first != nullptr) {
      impactedOwners = gpg::STR_Printf("%u", static_cast<unsigned int>(first->GetOwnerId()));
    }

    for (ownerIndex = info.mSubobj.GetNext(ownerIndex); ownerIndex != endValue;
         ownerIndex = info.mSubobj.GetNext(ownerIndex)) {
      if (IClient* const next = clientManager->GetClient(static_cast<int>(ownerIndex)); next != nullptr) {
        impactedOwners += gpg::STR_Printf(",%u", static_cast<unsigned int>(next->GetOwnerId()));
      }
    }
  }

  msvc8::string bottleneckTypeText{};
  bottleneckTypeText.assign_owned(bottleneckType);
  const msvc8::string beatText = gpg::STR_Printf("%u", static_cast<unsigned int>(info.mVal));
  const msvc8::string millisText = gpg::STR_Printf("%.1f", static_cast<double>(info.mFloat));

  const SNetCommandArg typeArg(bottleneckTypeText);
  const SNetCommandArg beatArg(beatText);
  const SNetCommandArg ownersArg(impactedOwners);
  const SNetCommandArg millisArg(millisText);
  active->WriteCommandWith4Args("Bottleneck", &typeArg, &beatArg, &ownersArg, &millisArg);
}

/**
 * Address: 0x007B9A20 (FUN_007B9A20, Moho::GPGNET_ReportBottleneckCleared)
 *
 * What it does:
 * Sends one `BottleneckCleared` command through the active process-global
 * GPGNet interface pointer (when available).
 */
void moho::GPGNET_ReportBottleneckCleared()
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  if (!active) {
    return;
  }

  active->SendBottleneckCleared();
}

/**
 * Address: 0x007B9AC0 (FUN_007B9AC0, Moho::GPGNET_ReportDesync)
 *
 * What it does:
 * Sends one GPGNet `"Desync"` command carrying beat/army ids and both hash
 * strings from one desync record.
 */
void moho::GPGNET_ReportDesync(
  const int beat,
  const int army,
  const msvc8::string& hash1,
  const msvc8::string& hash2
)
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  if (!active) {
    return;
  }

  const SNetCommandArg beatArg(beat);
  const SNetCommandArg armyArg(army);
  const SNetCommandArg hash1Arg(hash1);
  const SNetCommandArg hash2Arg(hash2);
  active->WriteCommandWith4Args("Desync", &beatArg, &armyArg, &hash1Arg, &hash2Arg);
}

/**
 * Address: 0x007B9CD0 (FUN_007B9CD0, Moho::GPGNET_SubmitArmyStats)
 *
 * What it does:
 * Sends one GPGNet `"Stats"` command carrying one serialized army-stats
 * payload string.
 */
void moho::GPGNET_SubmitArmyStats(
  const msvc8::string& statsPayload
)
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  if (!active) {
    return;
  }

  const SNetCommandArg payloadArg(statsPayload);
  active->WriteCommandWith1Arg("Stats", &payloadArg);
}

/**
 * Address: 0x007B9360 (FUN_007B9360, ?GPGNET_Attach@Moho@@YAXIG@Z)
 *
 * What it does:
 * Creates and connects the process-global GPGNet interface.
 */
void moho::GPGNET_Attach(
  const u_long addr,
  const u_short port
)
{
  if (GPGNET_GetPtr()) {
    throw std::runtime_error("Can't attach to a gpg.net if we already are.");
  }

  boost::shared_ptr<CGpgNetInterface> created = CGpgNetInterface::CreatePtr(new CGpgNetInterface{});
  created->Connect(addr, port);
  GPGNET_SetPtr(created);
}

/**
 * Address: 0x007B9DD0 (FUN_007B9DD0, ?GPGNET_Shutdown@Moho@@YAXXZ thunk)
 * Address: 0x007BB590 (FUN_007BB590, ?GPGNET_Shutdown@Moho@@YAXXZ body)
 *
 * What it does:
 * Clears the process-global GPGNet interface shared-pointer lane.
 */
void moho::GPGNET_Shutdown()
{
  sGPGNet.reset();
}

/**
 * Address: 0x007B9DE0 (FUN_007B9DE0, cfunc_GpgNetActive)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GpgNetActiveL`.
 */
int moho::cfunc_GpgNetActive(
  lua_State* const luaContext
)
{
  return cfunc_GpgNetActiveL(SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B9E00 (FUN_007B9E00, func_GpgNetActive_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GpgNetActive()` Lua binder in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GpgNetActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(), "GpgNetActive", &moho::cfunc_GpgNetActive, nullptr, "<global>", kGpgNetActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B9E60 (FUN_007B9E60, cfunc_GpgNetActiveL)
 *
 * What it does:
 * Validates no Lua args and pushes whether a process-global GPGNet
 * interface pointer is active.
 */
int moho::cfunc_GpgNetActiveL(
  LuaPlus::LuaState* const state
)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGpgNetActiveHelpText, 0, argumentCount);
  }

  lua_pushboolean(state->m_state, GPGNET_GetPtr() ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007B9EB0 (FUN_007B9EB0, cfunc_GpgNetSend)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GpgNetSendL`.
 */
int moho::cfunc_GpgNetSend(
  lua_State* const luaContext
)
{
  return cfunc_GpgNetSendL(SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B9ED0 (FUN_007B9ED0, func_GpgNetSend_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GpgNetSend(command, args...)` Lua binder in the user init
 * set.
 */
moho::CScrLuaInitForm* moho::func_GpgNetSend_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(), "GpgNetSend", &moho::cfunc_GpgNetSend, nullptr, "<global>", kGpgNetSendHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B9F30 (FUN_007B9F30, cfunc_GpgNetSendL)
 *
 * What it does:
 * Validates and marshals Lua args into `SNetCommandArg` lanes, then sends one
 * command through active process-global GPGNet interface (if present).
 */
int moho::cfunc_GpgNetSendL(
  LuaPlus::LuaState* const state
)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedAtLeastArgsWarning, kGpgNetSendHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject commandArg(state, 1);
  const char* commandName = lua_tostring(rawState, 1);
  if (commandName == nullptr) {
    commandArg.TypeError("string");
    commandName = "";
  }

  msvc8::vector<SNetCommandArg> args;
  for (int index = 2; index <= argumentCount; ++index) {
    const int luaType = lua_type(rawState, index);
    if (luaType == LUA_TNUMBER) {
      LuaPlus::LuaStackObject numberArg(state, index);
      if (lua_type(rawState, index) != LUA_TNUMBER) {
        numberArg.TypeError("integer");
      }

      args.push_back(SNetCommandArg(static_cast<int32_t>(lua_tonumber(rawState, index))));
      continue;
    }

    if (luaType == LUA_TBOOLEAN) {
      LuaPlus::LuaStackObject boolArg(state, index);
      if (lua_type(rawState, index) != LUA_TBOOLEAN && lua_type(rawState, index) != LUA_TNONE) {
        boolArg.TypeError("boolean");
      }

      args.push_back(SNetCommandArg(lua_toboolean(rawState, index) ? 1 : 0));
      continue;
    }

    if (lua_isstring(rawState, index)) {
      LuaPlus::LuaStackObject stringArg(state, index);
      const char* text = lua_tostring(rawState, index);
      if (text == nullptr) {
        stringArg.TypeError("string");
        text = "";
      }

      args.push_back(SNetCommandArg(msvc8::string(text)));
      continue;
    }

    LuaPlus::LuaState::Error(state, "invalid kind of argument to GpgNetSend(): can only deal with ints and strings.");
  }

  if (const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr(); active) {
    active->WriteCommand(commandName, args);
  }

  return 1;
}

/**
 * Address: 0x007B6720 (FUN_007B6720, ??0SNetCommand@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes one queued command entry with copied name, argument vector, and
 * value lanes.
 */
moho::SNetCommand::SNetCommand(
  const char* const name,
  const msvc8::vector<SNetCommandArg>& args,
  const int val
)
  : mName(name)
  , mArgs(args)
  , mVal(val)
{}

/**
 * Address: 0x007BCE70 (FUN_007BCE70)
 *
 * What it does:
 * Copy-constructs one queued command entry by initializing destination name
 * and argument-vector storage from source lanes, then copying queued value.
 *
 * The argument-vector copy is routed through the per-T named helper
 * `CopyConstructVectorOfSNetCommandArg` (FUN_007BAFE0) to preserve the
 * MSVC8 `vector<SNetCommandArg>::vector(const vector&)` symbol shape.
 */
moho::SNetCommand::SNetCommand(
  const SNetCommand& source
)
  : mName()
  , mArgs()
  , mVal(0)
{
  mName.reset_and_assign(source.mName);
  CopyConstructVectorOfSNetCommandArg(mArgs, source.mArgs);
  mVal = source.mVal;
}

/**
 * Address: 0x007BAEF0 (FUN_007BAEF0, ??1SNetCommand@Moho@@QAE@@Z)
 *
 * What it does:
 * Runs member destructors for queued-command name/argument storage.
 */
moho::SNetCommand::~SNetCommand()
{
  DestroyCommandArgStorage(mArgs);
}

/**
 * Address: 0x007BCA70 (FUN_007BCA70, Moho::CGpgNetInterface::CreatePtr)
 *
 * What it does:
 * Creates one owning `boost::shared_ptr<CGpgNetInterface>` from a raw instance
 * pointer and binds `enable_shared_from_this` ownership lanes.
 */
boost::shared_ptr<moho::CGpgNetInterface> moho::CGpgNetInterface::CreatePtr(
  CGpgNetInterface* const inter
)
{
  return boost::shared_ptr<CGpgNetInterface>(inter);
}

/**
 * Address: 0x007B6800 (FUN_007B6800)
 *
 * What it does:
 * Initializes GPGNet task/provider state, creates queue event, and registers
 * the event with the global wait-handle set.
 */
CGpgNetInterface::CGpgNetInterface()
  : enable_shared_from_this()
  , mConnectionState(kNetStatePending)
  , mTcpServer(nullptr)
  , mTcpSocket(nullptr)
  , mCommands()
  , mQueueEvent(nullptr)
  , mConnectThreadWorker(nullptr)
  , mLobbyObject()
  , mNATHandler()
{
  mQueueEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (mQueueEvent) {
    if (auto* const waitHandleSet = WIN_GetWaitHandleSet()) {
      waitHandleSet->AddHandle(mQueueEvent);
    }
  }
}

/**
 * Address: 0x007B6900 (FUN_007B6900 non-deleting body)
 * Address: 0x007B68C0 (FUN_007B68C0 deleting wrapper)
 *
 * What it does:
 * Shuts down transport resources, unregisters the queue event, and releases
 * NAT-traversal callback ownership.
 */
CGpgNetInterface::~CGpgNetInterface()
{
  Shutdown();

  if (mQueueEvent) {
    if (auto* const waitHandleSet = WIN_GetWaitHandleSet()) {
      waitHandleSet->RemoveHandle(mQueueEvent);
    }
    CloseHandle(mQueueEvent);
    mQueueEvent = nullptr;
  }

  mNATHandler.reset();
}

/**
 * Address: 0x007B7680 (FUN_007B7680)
 *
 * What it does:
 * Closes active TCP endpoints, stops the connect worker thread, clears the
 * pending command queue, resets connection state, and resets queue event.
 */
bool CGpgNetInterface::Shutdown()
{
  if (mTcpSocket) {
    mTcpSocket->VirtClose(gpg::Stream::ModeBoth);
  }

  if (mTcpServer) {
    mTcpServer->CloseSocket();
  }

  if (mConnectThreadWorker) {
    mConnectThreadWorker->join();
    delete mConnectThreadWorker;
    mConnectThreadWorker = nullptr;
  }

  ClearCommandQueue(mCommands);

  if (mTcpSocket) {
    delete mTcpSocket;
    mTcpSocket = nullptr;
  }

  if (mTcpServer) {
    delete mTcpServer;
    mTcpServer = nullptr;
  }

  mConnectionState = kNetStatePending;
  return mQueueEvent ? ResetEvent(mQueueEvent) != FALSE : true;
}

/**
 * Address: 0x007B9070 (FUN_007B9070)
 * Address: 0x10381F80 (sub_10381F80)
 *
 * What it does:
 * Updates weak NAT handler pointer used by SendNatPacket command path.
 * The weak/shared interconversion is routed through the generic per-T
 * template `boost::AssignWeakFromShared` (BoostWrappers.h, cited there
 * for this instantiation as FUN_007BB4E0) so the MSVC8 per-T template
 * emission symbol shape is preserved across the assignment.
 */
void CGpgNetInterface::SetTraversalHandler(
  const int port,
  boost::shared_ptr<INetNATTraversalHandler>* handler
)
{
  (void)port;
  boost::mutex::scoped_lock lock(mLock);
  gpg::Logf("GPGNET: setting nat handler to 0x%08x", reinterpret_cast<uintptr_t>(handler->get()));
  boost::AssignWeakFromShared(mNATHandler, *handler);
}

/**
 * Address: 0x007B9160 (FUN_007B9160)
 * Address: 0x10382070 (sub_10382070)
 *
 * What it does:
 * Wraps NAT payload into `ProcessNatPacket` command (`"ip:port"`, binary blob)
 * and forwards it to the GPGNet command stream.
 */
void CGpgNetInterface::ReceivePacket(
  const u_long address,
  u_short port,
  const char* data,
  size_t size
)
{
  const auto ip = NET_GetDottedOctetFromUInt32(address);
  gpg::Logf("GPGNET: received nat packet from %s:%d", ip.c_str(), port);

  const msvc8::string connStr = gpg::STR_Printf("%s:%d", ip.c_str(), static_cast<int>(port));
  SNetCommandArg argFrom(connStr);

  const SNetCommandArg argData(data, size);

  WriteCommandWith2Args("ProcessNatPacket", &argFrom, &argData);
}

/**
 * Address: 0x007BB250 (FUN_007BB250)
 *
 * What it does:
 * Executes one command-queue processing pass and returns task continuation (`1`).
 */
int CGpgNetInterface::Execute()
{
  Process();
  return 1;
}

/**
 * Address: 0x007B65C0 (FUN_007B65C0)
 *
 * What it does:
 * Throws argument-type error for expected integer argument.
 */
void CGpgNetInterface::ExpectedInt() noexcept(
  false
)
{
  throw std::runtime_error("incorrect argument type, expected int");
}

/**
 * Address: 0x007B6630 (FUN_007B6630)
 *
 * What it does:
 * Returns string payload reference or throws type-error if arg is not string.
 */
const msvc8::string& CGpgNetInterface::ExpectedString(const SNetCommandArg* arg) noexcept(false)
{
  if (arg->mType != SNetCommandArg::NETARG_String) {
    throw std::runtime_error("incorrect argument type, expected string");
  }
  return arg->mStr;
}

/**
 * Address: 0x007B66B0 (FUN_007B66B0)
 *
 * What it does:
 * Throws argument-type error for expected binary-data argument.
 */
void CGpgNetInterface::ExpectedData() noexcept(
  false
)
{
  throw std::runtime_error("incorrect argument type, expected data");
}

/**
 * Address: 0x007B67A0 (FUN_007B67A0)
 *
 * What it does:
 * Enqueues a named command with zero arguments and explicit state value.
 */
void CGpgNetInterface::EnqueueCommand0(
  const char* str,
  int val
)
{
  msvc8::vector<SNetCommandArg> args;
  EnqueueCommand(str, args, val);
}

namespace
{
  /**
   * Address: 0x007BC3F0 (FUN_007BC3F0, boost::bind_CGpgNetInterfaceConnect)
   *          0x007BD560 (FUN_007BD560) - basic_vtable<F>::get_vtable(), magic-static
   *                       guarded install of the shared manager/invoker pair
   *          0x007BE9A0 (FUN_007BE9A0) - stores the bound target (ConnectThread
   *                       pointer, `this`, `address`, `port`) into the
   *                       function_buffer
   *          0x007BEE50 (FUN_007BEE50) - basic_vtable<F>::invoker: adjusts
   *                       `this` by the stored offset and dispatches through
   *                       the stored thiscall function pointer with the two
   *                       bound (DWORD, WORD) payload args
   *          0x007BEE70 (FUN_007BEE70) - basic_vtable<F>::manager: publishes
   *                       functor-type RTTI for `check_functor_type_tag`,
   *                       delegates clone/destroy to FUN_007BEFA0
   *
   * What it does:
   * Builds the callable handed to the address/port connect worker thread.
   *
   * `Connect(u_long,u_short)` binds `this`, `address`, and `port` to
   * `ConnectThread` and hands the result to `boost::thread`'s `function0<void>`
   * constructor. This Functor's bound-argument list (two plain DWORD-sized
   * values plus `this`) fits boost::function's small-object buffer, so MSVC8
   * emits the flat this-adjusted-thiscall invoker/manager pair instead of the
   * heap-allocating path the sibling `Connect(const msvc8::string&)` overload
   * needs for its `std::string`-bound Functor (see `MakeConnectThreadLaunchCallback`
   * below). IDA's own analysis names the bind assembler
   * `boost::bind_CGpgNetInterfaceConnect`, confirming the correspondence.
   */
  [[nodiscard]] boost::function0<void> MakeConnectThreadLaunchCallback(
    CGpgNetInterface* const self,
    const u_long address,
    const u_short port
  )
  {
    return boost::function0<void>(
      boost::bind(&CGpgNetInterface::ConnectThread, self, address, port)
    );
  }
} // namespace

/**
 * Address: 0x007B6A30 (FUN_007B6A30)
 *
 * What it does:
 * Starts async TCP connect worker and marks connection state as connecting.
 */
void CGpgNetInterface::Connect(
  const u_long address,
  const u_short port
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStatePending) {
    throw std::runtime_error("Already connected.");
  }

  mConnectionState = kNetStateConnecting;

  boost::thread* const thread = new boost::thread(
    MakeConnectThreadLaunchCallback(this, address, port)
  );

  boost::thread* const oldThread = mConnectThreadWorker;
  mConnectThreadWorker = thread;
  if (oldThread != nullptr) {
    delete oldThread;
  }
}

namespace
{
  /**
   * Address: 0x007BC440 (FUN_007BC440) - bind_t<> assembly (member-pointer half)
   *          0x007BD070 (FUN_007BD070) - bind_t<> assembly (bound-argument-list half)
   *          0x007BD2D0 (FUN_007BD2D0) - list2<value<this>,value<string>> construction
   *          0x007BC520 (FUN_007BC520) - boost::function0<void> converting ctor
   *          0x007BD5E0 (FUN_007BD5E0) - boost::function0<void>::assign_to<Functor>
   *          0x007BDCF0 (FUN_007BDCF0) - magic-statics guard for the local static vtable
   *          0x007BE9F0 (FUN_007BE9F0) - basic_vtable0<>::basic_vtable0 / init(functor_obj_tag)
   *          0x007BDD90 (FUN_007BDD90) - basic_vtable0<>::assign_to dispatcher
   *          0x007BEAA0 (FUN_007BEAA0) - basic_vtable0<>::assign_to(...,function_obj_tag)
   *          0x007BECE0 (FUN_007BECE0) - assign_functor() heap-allocation branch
   *
   * What it does:
   * Builds the callable handed to the launch-template connect worker thread.
   *
   * `Connect(const msvc8::string&)` binds `this` and a copy of
   * `launchCommandTemplate` to `ConnectThread` and hands the result to
   * `boost::thread`'s `function0<void>` constructor. Unlike the simpler
   * `Connect(u_long,u_short)` overload (see `boost::bind_CGpgNetInterfaceConnect`
   * / FUN_007BC3F0), the bound argument here is a full `std::string`, which
   * does not fit boost::function's small-object buffer, so MSVC8 emits the
   * *heap-allocating* path instead of a single flat helper. The functor
   * manager publishes its own RTTI at 0x00F86BE8; the mangled name reads
   *   `.?AV?$bind_t@XV?$mf1@XVCGpgNetInterface@Moho@@VStrArg@gpg@@@_mfi@boost@@
   *     V?$list2@V?$value@PAVCGpgNetInterface@Moho@@@_bi@boost@@
   *       V?$value@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@23@@_bi@3@@_bi@boost@@`
   * i.e. `boost::_bi::bind_t<void,
   *   boost::_mfi::mf1<void, Moho::CGpgNetInterface, gpg::StrArg>,
   *   boost::_bi::list2<boost::_bi::value<Moho::CGpgNetInterface*>,
   *                      boost::_bi::value<std::string>>>` - the bound value is
   * a real (Dinkumware) `std::string` copy, matching `list2`'s second
   * `value<std::string>` slot exactly (payload copied end-to-end through
   * FUN_007BD2D0 -> FUN_007BC440 -> FUN_007BC520 -> FUN_007BD5E0 ->
   * FUN_007BECE0's heap clone).
   *
   * The RTTI shows the bound member-function-pointer target type as
   * `gpg::StrArg`, a *class* type (`V` mangling), not the raw
   * `using StrArg = const char*;` alias this SDK currently models in
   * `gpg/core/containers/String.h`. `gpg/core/utils/Logging.h` documents the
   * same collision independently (its `LogScopeEntry` comment: "the simple
   * API-level alias `gpg::StrArg = const char*` already occupies that
   * identifier"): the *original* `gpg::StrArg` was a real class with its own
   * constructor (`??0StrArg@gpg@@QAE@@Z`), and today's alias is a
   * simplification introduced by an earlier recovery pass. Untangling that
   * is a separate, codebase-wide effort (`gpg::StrArg` / `moho::StrArg` are
   * used as `const char*` at dozens of call sites already). This helper
   * therefore keeps `ConnectThread`'s existing `const msvc8::string&`
   * parameter rather than silently reintroducing a conflicting `StrArg`
   * class here; the mismatch is a known, evidenced gap, not a guess.
   *
   * `FUN_007BEAA0`'s heap-allocation call chain bottoms out in two already
   * -recovered, ICF-shared leaves cited elsewhere and intentionally not
   * re-claimed here: `FUN_007BF120` (checked `operator new` for the 40-byte
   * `bind_t` object, `src/sdk/legacy/containers/Vector.cpp`) and
   * `FUN_007BF180` (raw field-copy construction of the same 40-byte shape,
   * `src/sdk/moho/misc/CrtRuntimeHelpers.cpp`).
   */
  [[nodiscard]] boost::function0<void> MakeConnectThreadLaunchCallback(
    CGpgNetInterface* const self,
    const msvc8::string& launchCommandTemplate
  )
  {
    return boost::function0<void>(
      boost::bind(&CGpgNetInterface::ConnectThread, self, launchCommandTemplate)
    );
  }
} // namespace

/**
 * Address: 0x007B6BA0 (FUN_007B6BA0, func_NET_connect)
 *
 * What it does:
 * Starts async GPGNet-launch connect worker from one command-line template
 * (for example containing `%s` endpoint substitution).
 */
void CGpgNetInterface::Connect(
  const msvc8::string& launchCommandTemplate
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStatePending) {
    throw std::runtime_error("Already connected.");
  }

  mConnectionState = kNetStateConnecting;

  boost::thread* const thread = new boost::thread(
    MakeConnectThreadLaunchCallback(this, launchCommandTemplate)
  );

  boost::thread* const oldThread = mConnectThreadWorker;
  mConnectThreadWorker = thread;
  if (oldThread != nullptr) {
    delete oldThread;
  }
}

/**
 * Address: 0x007B6DB0 (FUN_007B6DB0)
 *
 * What it does:
 * Writes a command name plus argument vector to active GPGNet socket stream.
 */
void CGpgNetInterface::WriteCommand(
  const char* name,
  const msvc8::vector<SNetCommandArg>& args
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  const uint32_t argc = static_cast<uint32_t>(GetCommandArgCount(args));
  mTcpSocket->Write(argc);

  for (const SNetCommandArg& arg : args) {
    WriteArg(&arg);
  }

  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B6F00 (FUN_007B6F00)
 *
 * What it does:
 * Emits `BottleneckCleared` notification over active GPGNet command stream.
 */
void CGpgNetInterface::SendBottleneckCleared()
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName("BottleneckCleared");
  constexpr uint32_t argc = 0;
  mTcpSocket->Write(argc);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B6FF0 (FUN_007B6FF0)
 *
 * What it does:
 * Writes command name with one serialized argument and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith1Arg(
  const char* name,
  const SNetCommandArg* arg
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);
  constexpr uint32_t argc = 1;
  mTcpSocket->Write(argc);
  WriteArg(arg);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B70F0 (FUN_007B70F0)
 *
 * What it does:
 * Writes command name with two serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith2Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 2;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7200 (FUN_007B7200)
 *
 * What it does:
 * Writes command name with three serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith3Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2,
  const SNetCommandArg* arg3
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 3;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  WriteArg(arg3);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7310 (FUN_007B7310)
 *
 * What it does:
 * Writes command name with four serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith4Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2,
  const SNetCommandArg* arg3,
  const SNetCommandArg* arg4
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 4;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  WriteArg(arg3);
  WriteArg(arg4);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7420 (FUN_007B7420)
 *
 * What it does:
 * Writes command name as `uint32 len + raw bytes`.
 */
void CGpgNetInterface::WriteCommandName(
  const char* name
)
{
  if (!mTcpSocket) {
    return;
  }

  const char* const value = name ? name : "";
  const uint32_t len = static_cast<uint32_t>(std::strlen(value));
  mTcpSocket->Write(len);
  if (len != 0) {
    mTcpSocket->Write(value, len);
  }
}

/**
 * Address: 0x007B74A0 (FUN_007B74A0)
 *
 * What it does:
 * Writes `msvc8::string` payload as `uint32 len + raw bytes`.
 */
void CGpgNetInterface::WriteString(
  const msvc8::string& str
)
{
  if (!mTcpSocket) {
    return;
  }

  const uint32_t len = static_cast<uint32_t>(str.size());
  mTcpSocket->Write(len);
  if (len != 0) {
    mTcpSocket->Write(str.data(), len);
  }
}

/**
 * Address: 0x007B7520 (FUN_007B7520)
 *
 * What it does:
 * Serializes one `SNetCommandArg` as tagged payload (`type` + body).
 */
void CGpgNetInterface::WriteArg(
  const SNetCommandArg* arg
)
{
  if (!mTcpSocket || !arg) {
    return;
  }

  const uint8_t type = static_cast<uint8_t>(arg->mType);
  mTcpSocket->Write(type);
  switch (arg->mType) {
  case SNetCommandArg::NETARG_Num:
    mTcpSocket->Write(arg->mNum);
    return;
  case SNetCommandArg::NETARG_String:
    WriteString(ExpectedString(arg));
    return;
  case SNetCommandArg::NETARG_Data:
    WriteString(arg->mStr);
    return;
  default:
    return;
  }
}

/**
 * Address: 0x007B75D0 (FUN_007B75D0)
 *
 * What it does:
 * Validates GPGNet connected state under `mLock` and closes one active TCP
 * socket lane with bidirectional shutdown.
 */
void CGpgNetInterface::EnsureConnectedAndCloseSocket()
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (mTcpSocket != nullptr) {
    mTcpSocket->VirtClose(gpg::Stream::ModeBoth);
  }
}

/**
 * Address: 0x007B7710 (FUN_007B7710 / func_GPGNETProcess)
 *
 * What it does:
 * Drains queued inbound commands, updates state from each command envelope,
 * and dispatches to command-specific handlers.
 */
void CGpgNetInterface::Process()
{
  msvc8::deque<SNetCommand> pending;

  {
    boost::mutex::scoped_lock lock(mLock);
    mCommands.swap(pending);
    if (mQueueEvent) {
      ResetEvent(mQueueEvent);
    }
  }

  while (!pending.empty()) {
    SNetCommand& command = pending.front();
    mConnectionState = static_cast<DWORD>(command.mVal);

    try {
      const auto commandName = command.mName.view();
      if (commandName == "Test") {
        Test(command.mArgs);
      } else if (commandName == "Connected") {
        Connected(command.mArgs);
      } else if (commandName == "CreateLobby") {
        CreateLobby(command.mArgs);
      } else if (commandName == "HasSupcom") {
        HasSupCom(command.mArgs);
      } else if (commandName == "HasForgedAlliance") {
        HasForgedAlliance(command.mArgs);
      } else if (commandName == "HostGame") {
        HostGame(command.mArgs);
      } else if (commandName == "JoinGame") {
        JoinGame(command.mArgs);
      } else if (commandName == "ConnectToPeer") {
        ConnectToPeer(command.mArgs);
      } else if (commandName == "DisconnectFromPeer") {
        DisconnectFromPeer(command.mArgs);
      } else if (commandName == "SendNatPacket") {
        SendNatPacket(command.mArgs);
      } else if (commandName == "EjectPlayer") {
        EjectPlayer(command.mArgs);
      } else {
        LogUnknownCommand(command.mName);
      }
    } catch (const std::exception& ex) {
      gpg::Logf("GPGNET: command processing failed: %s", ex.what());
    }

    pending.pop_front();
  }
}

/**
 * Address: 0x007B7A30 (FUN_007B7A30)
 *
 * What it does:
 * Logs diagnostic dump for Test command arguments.
 */
void CGpgNetInterface::Test(
  msvc8::vector<SNetCommandArg>& args
)
{
  const std::size_t argCount = GetCommandArgCount(args);
  gpg::Logf("GPGNET: test message, %d args", static_cast<int>(argCount));

  for (std::size_t i = 0; i < argCount; ++i) {
    const SNetCommandArg& arg = args[i];
    switch (arg.mType) {
    case SNetCommandArg::NETARG_Num:
      gpg::Logf(" arg[%d]=%d [int]", static_cast<int>(i), arg.mNum);
      break;
    case SNetCommandArg::NETARG_String:
      gpg::Logf(" arg[%d]=\"%s\" [str]", static_cast<int>(i), arg.mStr.c_str());
      break;
    case SNetCommandArg::NETARG_Data: {
      msvc8::string hexDump;
      for (std::size_t b = 0; b < arg.mStr.size(); ++b) {
        if (b != 0) {
          hexDump.append(1, ' ');
        }
        const auto chunk = gpg::STR_Printf("%02x", static_cast<unsigned char>(arg.mStr[b]));
        hexDump.append(chunk.data(), chunk.size());
      }
      gpg::Logf(" arg[%d]={%s}", static_cast<int>(i), hexDump.c_str());
      break;
    }
    default:
      gpg::Logf(" arg[%d]=? [unknown type %d]", static_cast<int>(i), static_cast<int>(arg.mType));
      break;
    }
  }
}

/**
 * Address: 0x007B7C50 (FUN_007B7C50)
 *
 * What it does:
 * Verifies empty argument list and sends `GameState = "Idle"` to GPGNet.
 */
void CGpgNetInterface::Connected(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (!args.empty()) {
    throw std::runtime_error("Wrong number of arguments to Connected command, expected 0");
  }

  gpg::Logf("GPGNET: entering idle state.");
  SNetCommandArg stateArg(msvc8::string("Idle"));
  WriteCommandWith1Arg("GameState", &stateArg);
}

/**
 * Address: 0x007BC5F0 (FUN_007BC5F0, Moho::NET_MakeNATTraversal)
 *
 * What it does:
 * Wraps a `boost::weak_ptr<INetNATTraversalProvider>` into a typed LuaPlus
 * userdata. Mirrors the binary's call sequence exactly:
 *   1. Resolve the per-T metatable via
 *      `CScrLuaMetatableFactory<INetNATTraversalProvider>::Instance().Get(state)`.
 *   2. Default-construct `*out` (LuaObject ctor — empty payload).
 *   3. Build the reflected weak-pointer RRef via
 *      `gpg::RRef_weak_ptr_INetNATTraversalProvider(&ref, provider)`.
 *   4. Bind the userdata payload via `out->AssignNewUserData(state, ref)`.
 *   5. Attach the resolved metatable via `out->SetMetaTable(metatable)`.
 *
 * Returns `out`.
 */
LuaPlus::LuaObject* moho::NET_MakeNATTraversal(
  LuaPlus::LuaState* const state,
  LuaPlus::LuaObject* const out,
  boost::weak_ptr<INetNATTraversalProvider>* const provider)
{
  LuaPlus::LuaObject metatable =
    moho::CScrLuaMetatableFactory<INetNATTraversalProvider>::Instance().Get(state);

  ::new (static_cast<void*>(out)) LuaPlus::LuaObject();

  gpg::RRef providerRef{};
  gpg::RRef_weak_ptr_INetNATTraversalProvider(&providerRef, provider);
  out->AssignNewUserData(state, providerRef);
  out->SetMetaTable(metatable);
  return out;
}

/**
 * Address: 0x007B7DE0 (FUN_007B7DE0)
 *
 * What it does:
 * Calls Lua-side `CreateLobby` factory and stores returned lobby object.
 * Builds the NAT traversal userdata from the live `CGpgNetInterface` (which
 * implements `INetNATTraversalProvider`) via `NET_MakeNATTraversal` and
 * passes it as the 5th `CreateLobby(...)` argument.
 */
void CGpgNetInterface::CreateLobby(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 5) {
    throw std::runtime_error("Wrong number of arguments to CreateLobby command, expected 5");
  }

  if (!mLobbyObject.IsNil()) {
    throw std::runtime_error("Lobby already exists.");
  }

  LuaPlus::LuaState* const state = LuaPlus::g_ConsoleLuaState();
  if (!state) {
    throw std::runtime_error("No active Lua state.");
  }

  LuaPlus::LuaObject createLobby = state->GetGlobal("CreateLobby");
  if (createLobby.IsNil()) {
    throw std::runtime_error("Failed to load \"/lua/multiplayer/onlineprovider.lua\".");
  }

  const bool useUdp = ExpectIntArg(*this, &args[0]) != 0;
  const int localPort = ExpectIntArg(*this, &args[1]);
  const msvc8::string& playerName = ExpectedString(&args[2]);
  const int playerUid = ExpectIntArg(*this, &args[3]);
  const int natPort = ExpectIntArg(*this, &args[4]);
  const msvc8::string playerUidText = gpg::STR_Printf("%d", playerUid);

  // Build the NAT-traversal userdata bound to this GPGNet interface (the
  // engine binary's CreateLobby call shape — NET_MakeNATTraversal is the
  // public binder; the `sGPGNet` shared_ptr is the natural source for the
  // weak_ptr backing the provider).
  LuaPlus::LuaObject natTraversal;
  boost::weak_ptr<INetNATTraversalProvider> natProvider;
  boost::AssignWeakFromShared(natProvider, GPGNET_GetPtr());
  (void)moho::NET_MakeNATTraversal(state, &natTraversal, &natProvider);

  LuaPlus::LuaFunction<LuaPlus::LuaObject> createLobbyFn(createLobby);
  mLobbyObject =
    createLobbyFn.Call_UDP(useUdp, localPort, playerName, playerUidText.c_str(), &natTraversal, natPort);

  gpg::Logf("GPGNET: entering lobby state.");
  SNetCommandArg stateArg(msvc8::string("Lobby"));
  WriteCommandWith1Arg("GameState", &stateArg);
}

/**
 * Address: 0x007B81D0 (FUN_007B81D0)
 *
 * What it does:
 * Invokes lobby `HostGame` script callback with optional scenario path.
 */
void CGpgNetInterface::HostGame(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() > 1) {
    throw std::runtime_error("Wrong number of arguments to HostGame command, expected 0 or 1");
  }

  LuaPlus::LuaObject hostGameObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "HostGame", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> hostGame(hostGameObj);

  msvc8::string scenarioPath;
  if (!args.empty()) {
    const msvc8::string& mapName = ExpectedString(&args[0]);
    scenarioPath = gpg::STR_Printf("/maps/%s/%s_scenario.lua", mapName.c_str(), mapName.c_str());
  }

  hostGame(scenarioPath.c_str());
}

/**
 * Address: 0x007B83C0 (FUN_007B83C0)
 *
 * What it does:
 * Invokes lobby `JoinGame` script callback with host/player/uid parameters.
 */
void CGpgNetInterface::JoinGame(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 3) {
    throw std::runtime_error("Wrong number of arguments to JoinGame command, expected 3");
  }

  LuaPlus::LuaObject joinGameObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "JoinGame", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> joinGame(joinGameObj);

  const msvc8::string& hostAddress = ExpectedString(&args[0]);
  const msvc8::string& playerName = ExpectedString(&args[1]);
  const int playerUid = ExpectIntArg(*this, &args[2]);
  const msvc8::string playerUidText = gpg::STR_Printf("%d", playerUid);

  joinGame(hostAddress.c_str(), false, playerName.c_str(), playerUidText.c_str());
}

/**
 * Address: 0x007B85A0 (FUN_007B85A0)
 *
 * What it does:
 * Invokes lobby `ConnectToPeer` script callback.
 */
void CGpgNetInterface::ConnectToPeer(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 3) {
    throw std::runtime_error("Wrong number of arguments to ConnectToPeer command, expected 3");
  }

  LuaPlus::LuaObject connectToPeerObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "ConnectToPeer", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> connectToPeer(connectToPeerObj);

  const msvc8::string& endpoint = ExpectedString(&args[0]);
  const msvc8::string& playerName = ExpectedString(&args[1]);
  const int peerUid = ExpectIntArg(*this, &args[2]);
  const msvc8::string peerUidText = gpg::STR_Printf("%d", peerUid);

  connectToPeer(endpoint.c_str(), playerName.c_str(), peerUidText.c_str());
}

/**
 * Address: 0x007B8780 (FUN_007B8780)
 *
 * What it does:
 * Invokes lobby `DisconnectFromPeer` script callback for one uid.
 */
void CGpgNetInterface::DisconnectFromPeer(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to DisconnectFromPeer command, expected 1");
  }

  LuaPlus::LuaObject disconnectObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "DisconnectFromPeer", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> disconnectFromPeer(disconnectObj);

  const int peerUid = ExpectIntArg(*this, &args[0]);
  const msvc8::string peerUidText = gpg::STR_Printf("%d", peerUid);
  disconnectFromPeer(peerUidText.c_str());
}

/**
 * Address: 0x007B8920 (FUN_007B8920)
 *
 * What it does:
 * Invokes lobby `SetHasSupcom` script callback.
 */
void CGpgNetInterface::HasSupCom(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to SetHasSupcom command, expected 1");
  }

  LuaPlus::LuaObject hasSupComObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "SetHasSupcom", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> setHasSupCom(hasSupComObj);
  setHasSupCom(ExpectIntArg(*this, &args[0]));
}

/**
 * Address: 0x007B8A70 (FUN_007B8A70)
 *
 * What it does:
 * Invokes lobby `SetHasForgedAlliance` script callback.
 */
void CGpgNetInterface::HasForgedAlliance(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to SetHasForgedAlliance command, expected 1");
  }

  LuaPlus::LuaObject hasFaObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "SetHasForgedAlliance", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> setHasFa(hasFaObj);
  setHasFa(ExpectIntArg(*this, &args[0]));
}

/**
 * Address: 0x007B8BC0 (FUN_007B8BC0)
 *
 * What it does:
 * Validates NAT command args (`"ip:port"`, binary payload), resolves remote
 * endpoint, and forwards payload through registered NAT traversal handler.
 */
void CGpgNetInterface::SendNatPacket(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 2) {
    throw std::runtime_error("Wrong number of arguments to SendNatPacket command, expected 2");
  }

  const auto natHandler = mNATHandler.lock();
  if (!natHandler) {
    throw std::runtime_error("Can't send nat packets if we don't have a nat handler.");
  }

  const msvc8::string& endpoint = ExpectedString(&args[0]);

  u_long remoteAddress = 0;
  u_short remotePort = 0;
  if (!NET_GetAddrInfo(endpoint.c_str(), 0, false, remoteAddress, remotePort) || remotePort == 0) {
    throw std::runtime_error("Invalid remote address");
  }

  const auto& payloadArg = args[1];
  if (payloadArg.mType != SNetCommandArg::NETARG_Data) {
    ExpectedData();
  }

  const auto remoteHost = NET_GetDottedOctetFromUInt32(remoteAddress);
  gpg::Logf("GPGNET: sending nat packet to %s:%d", remoteHost.c_str(), static_cast<int>(remotePort));

  natHandler->ReceivePacket(remoteAddress, remotePort, payloadArg.mStr.data(), payloadArg.mStr.size());
}

/**
 * Address: 0x007B8E20 (FUN_007B8E20)
 *
 * What it does:
 * Validates eject request, resolves the target client from the active sim
 * driver, then disconnects/ejects it and prints the localized console notice.
 */
void CGpgNetInterface::EjectPlayer(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to EjectPlayer, expected 1");
  }

  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (activeDriver == nullptr) {
    throw std::runtime_error("No active session.");
  }

  const int playerUid = ExpectIntArg(*this, &args[0]);
  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  IClient* const targetClient = clientManager->GetClientWithData(playerUid);
  if (targetClient == nullptr) {
    throw std::runtime_error(gpg::STR_Printf("No client with uid %d", playerUid).c_str());
  }

  if (targetClient == clientManager->GetLocalClient()) {
    clientManager->Disconnect();

    const msvc8::string localizedMessage = Loc(
      USER_GetLuaState(),
      "<LOC Engine0016>You have been ejected due to connectivity issues."
    );
    CON_Printf(localizedMessage.c_str());
    return;
  }

  targetClient->Eject();

  const msvc8::string localizedMessage = Loc(
    USER_GetLuaState(),
    "<LOC Engine0017>%s has been ejected due to connectivity issues."
  );
  CON_Printf(localizedMessage.c_str(), targetClient->GetNickname().c_str());
}

/**
 * Address: 0x007BA5E0 (FUN_007BA5E0)
 *
 * What it does:
 * Performs synchronous TCP connect and starts inbound socket read loop.
 */
void CGpgNetInterface::ConnectThread(
  const u_long address,
  const u_short port
)
{
  INetTCPSocket* const connectedSocket = NET_TCPConnect(address, port);
  INetTCPSocket* const oldSocket = mTcpSocket;
  mTcpSocket = connectedSocket;
  if (oldSocket) {
    delete oldSocket;
  }

  if (mTcpSocket) {
    ReadFromSocket();
  } else {
    EnqueueCommand0("ConnectFailed", kNetStateTimedOut);
  }
}

/**
 * Address: 0x007BA640 (FUN_007BA640, func_NET_ConnectThread)
 *
 * What it does:
 * Creates a local loopback TCP listener, launches external GPGNet process
 * using one command-line template, accepts the incoming socket, and starts
 * command read loop.
 */
void CGpgNetInterface::ConnectThread(
  const msvc8::string& launchCommandTemplate
)
{
  const msvc8::string loopbackAddress("127.0.0.1");
  INetTCPServer* const createdServer = NET_CreateTCPServer(
    NET_GetUInt32FromDottedOcted(loopbackAddress),
    0
  );

  INetTCPServer* const oldServer = mTcpServer;
  mTcpServer = createdServer;
  if (oldServer != nullptr) {
    delete oldServer;
  }

  if (mTcpServer == nullptr) {
    EnqueueCommand0("LaunchFailed", kNetStateTimedOut);
    return;
  }

  STARTUPINFOA startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  PROCESS_INFORMATION processInformation{};

  const u_short localPort = mTcpServer->GetLocalPort();
  const msvc8::string listenerAddress = gpg::STR_Printf("127.0.0.1:%d", static_cast<int>(localPort));
  const msvc8::string launchCommand = gpg::STR_Printf(launchCommandTemplate.c_str(), listenerAddress.c_str());

  std::vector<char> launchCommandBuffer(launchCommand.size() + 1u, '\0');
  if (!launchCommand.empty()) {
    std::memcpy(launchCommandBuffer.data(), launchCommand.data(), launchCommand.size());
  }

  const BOOL launchOk = ::CreateProcessA(
    nullptr,
    launchCommandBuffer.data(),
    nullptr,
    nullptr,
    FALSE,
    0,
    nullptr,
    nullptr,
    &startupInfo,
    &processInformation
  );

  if (!launchOk) {
    const msvc8::string lastError = WIN_GetLastError();
    gpg::Logf("CreateProcess() failed: %s", lastError.c_str());
    EnqueueCommand0("LaunchFailed", kNetStateTimedOut);
    return;
  }

  ::CloseHandle(processInformation.hProcess);
  ::CloseHandle(processInformation.hThread);

  INetTCPSocket* const acceptedSocket = mTcpServer->Accept();
  INetTCPSocket* const oldSocket = mTcpSocket;
  mTcpSocket = acceptedSocket;
  if (oldSocket != nullptr) {
    delete oldSocket;
  }

  INetTCPServer* const serverToDestroy = mTcpServer;
  mTcpServer = nullptr;
  if (serverToDestroy != nullptr) {
    delete serverToDestroy;
  }

  if (mTcpSocket == nullptr) {
    EnqueueCommand0("LaunchFailed", kNetStateTimedOut);
    return;
  }

  ReadFromSocket();
}

/**
 * Address: 0x007BA880 (FUN_007BA880)
 *
 * What it does:
 * Reads and decodes framed commands from TCP stream and enqueues them for
 * pull-task dispatch.
 */
void CGpgNetInterface::ReadFromSocket()
{
  if (!mTcpSocket) {
    return;
  }

  EnqueueCommand0("Connected", kNetStateEstablishing);

  try {
    for (;;) {
      uint32_t commandNameLength = 0;
      const size_t got = mTcpSocket->Read(reinterpret_cast<char*>(&commandNameLength), sizeof(commandNameLength));
      if (got == 0) {
        EnqueueCommand0("ConnectionShutdown", kNetStateEstablishing);
        return;
      }
      if (got < sizeof(commandNameLength)) {
        throw std::runtime_error("premature EOF reading from gpg.net socket");
      }

      msvc8::string commandName;
      if (commandNameLength != 0) {
        std::vector<char> nameBuffer(commandNameLength);
        ReadExactFromSocket(
          mTcpSocket, nameBuffer.data(), commandNameLength, "premature EOF reading from gpg.net socket"
        );
        commandName.assign(nameBuffer.data(), commandNameLength);
      }

      gpg::BinaryReader reader(mTcpSocket);
      uint32_t argCount = 0;
      reader.ReadExact(argCount);

      msvc8::vector<SNetCommandArg> args;
      if (argCount) {
        args.reserve(argCount);
      }

      for (uint32_t i = 0; i < argCount; ++i) {
        args.push_back(moho::NET_DecodeSocketArg(reader));
      }

      EnqueueCommand(commandName.c_str(), args, kNetStateEstablishing);
    }
  } catch (const std::exception& ex) {
    msvc8::vector<SNetCommandArg> args;
    args.push_back(SNetCommandArg(msvc8::string(ex.what() ? ex.what() : "communication error")));
    EnqueueCommand("CommunicationError", args, kNetStateTimedOut);
  }
}

/**
 * Address: 0x007BAE50 (FUN_007BAE50)
 *
 * What it does:
 * Queues one decoded command and signals queue event if queue transitions
 * from empty to non-empty.
 */
void CGpgNetInterface::EnqueueCommand(
  const char* name,
  msvc8::vector<SNetCommandArg>& args,
  int val
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mCommands.empty() && mQueueEvent) {
    SetEvent(mQueueEvent);
  }

  const SNetCommand command(name, args, val);
  PushBackQueuedCommand(mCommands, command);
}

namespace
{
  constexpr const char* kLaunchGPGNetName = "LaunchGPGNet";
  constexpr const char* kLaunchGPGNetHelpText = "LaunchGPGNet()";
  constexpr const wchar_t* kGPGNetDefaultPath =
    L"c:\\Program Files\\THQ\\Gas Powered Games\\GPGNet\\GPG.Multiplayer.Client.exe";
  constexpr const wchar_t* kGPGNetDevExePath =
    L"C:\\work\\rts\\main\\code\\src\\Multiplayer\\MultiplayerClient\\bin\\Debug\\MultiplayerClient.exe";
  constexpr const wchar_t* kGPGNetDevParams =
    L"/luapath=\"C:\\work\\rts\\main\\code\\src\\Multiplayer\\MultiplayerClient\\\"";
  constexpr const wchar_t* kGPGNetDevWorkingDir =
    L"C:\\work\\rts\\main\\code\\src\\Multiplayer\\MultiplayerClient\\bin\\Debug\\";

  [[nodiscard]] bool TryLoadGPGNetPathFromRegistry(const char* const keyPath, std::wstring& outPath)
  {
    std::array<std::uint8_t, 256> buffer{};
    const std::uint32_t length = moho::PLAT_GetRegistryValue(keyPath, buffer.data(), static_cast<std::uint32_t>(buffer.size()));
    if (length == 0) {
      return false;
    }

    outPath.assign(length, L'\0');
    std::mbstowcs(outPath.data(), reinterpret_cast<const char*>(buffer.data()), length);

    return GetFileAttributesW(outPath.c_str()) != INVALID_FILE_ATTRIBUTES;
  }
} // namespace

/**
 * Address: 0x007BA340 (FUN_007BA340, cfunc_LaunchGPGNetL)
 *
 * What it does:
 * Resolves the GPGNet client executable path (developer override via
 * `/gpgnetdev`, then `HKCU\Software\GPG\GPGNet\GPGNetPath`, then
 * `HKLM\Software\GPG\GPGNet\GPGNetPath`, then a hardcoded default) and
 * launches it via `ShellExecuteExW` with the main window as owner.
 * Restores the x87 control word afterward and pushes the boolean launch
 * result back to Lua.
 */
int moho::cfunc_LaunchGPGNetL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kLaunchGPGNetHelpText, 0, argumentCount);
  }

  HWND ownerWindow = nullptr;
  if (moho::sMainWindow != nullptr) {
    ownerWindow = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
  }

  SHELLEXECUTEINFOW execInfo{};
  execInfo.cbSize = sizeof(execInfo);
  execInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
  execInfo.hwnd = ownerWindow;
  execInfo.lpVerb = L"open";
  execInfo.nShow = SW_SHOWDEFAULT;

  std::wstring resolvedPath;
  if (moho::CFG_GetArgOption(gpg::StrArg{"/gpgnetdev"}, 0u, nullptr)) {
    execInfo.lpFile = kGPGNetDevExePath;
    execInfo.lpParameters = kGPGNetDevParams;
    execInfo.lpDirectory = kGPGNetDevWorkingDir;
  } else {
    if (TryLoadGPGNetPathFromRegistry("HKEY_CURRENT_USER\\Software\\GPG\\GPGNet\\GPGNetPath", resolvedPath)) {
      execInfo.lpFile = resolvedPath.c_str();
    } else if (TryLoadGPGNetPathFromRegistry("HKEY_LOCAL_MACHINE\\Software\\GPG\\GPGNet\\GPGNetPath", resolvedPath)) {
      execInfo.lpFile = resolvedPath.c_str();
    } else {
      execInfo.lpFile = kGPGNetDefaultPath;
    }
    execInfo.lpParameters = L"";
    execInfo.lpDirectory = L"";
  }

  const BOOL launched = ShellExecuteExW(&execInfo);

  // ShellExecuteExW can perturb the x87 FPU control word; restore the engine's
  // preferred precision/rounding configuration before returning to Lua.
  _controlfp(_PC_64, _MCW_PC);

  lua_pushboolean(rawState, launched ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x007BA2C0 (FUN_007BA2C0, cfunc_LaunchGPGNet)
 *
 * What it does:
 * Unwraps the raw `lua_State` callback context and forwards to
 * `cfunc_LaunchGPGNetL`.
 */
int moho::cfunc_LaunchGPGNet(lua_State* const luaContext)
{
  return cfunc_LaunchGPGNetL(SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007BA2E0 (FUN_007BA2E0, func_LaunchGPGNet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `LaunchGPGNet()` binder into the user Lua init set.
 */
moho::CScrLuaInitForm* moho::func_LaunchGPGNet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kLaunchGPGNetName,
    &moho::cfunc_LaunchGPGNet,
    nullptr,
    "<global>",
    kLaunchGPGNetHelpText
  );
  return &binder;
}

namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct CGpgNetInterfaceLuaFuncDefBootstrap
  {
    CGpgNetInterfaceLuaFuncDefBootstrap()
    {
      (void)::moho::func_GpgNetActive_LuaFuncDef();
      (void)::moho::func_GpgNetSend_LuaFuncDef();
      (void)::moho::func_LaunchGPGNet_LuaFuncDef();
    }
  };

  const CGpgNetInterfaceLuaFuncDefBootstrap gCGpgNetInterfaceLuaFuncDefBootstrap{};
} // namespace
