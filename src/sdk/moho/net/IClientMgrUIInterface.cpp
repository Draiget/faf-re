#include "moho/net/IClientMgrUIInterface.h"

#include <cstdint>
#include <memory>

#include <boost/bind.hpp>
#include <boost/function.hpp>

#include "legacy/containers/String.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/core/Thread.h"
#include "moho/net/CClientBase.h"
#include "moho/net/CGpgNetInterface.h"
#include "moho/sim/SimDriver.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace
{
  /**
   * Address: 0x0088B9D0 (FUN_0088B9D0, Moho::func_ConPrintDisconnect)
   *
   * What it does:
   * Async worker for the disconnect notice: localizes the
   * "<LOC Engine0002>%s disconnected." message and console-prints it with the
   * disconnected client's nickname. Posted onto the main thread by
   * CWldUiInterface::NoteDisconnect.
   *
   * Signature note: the manager RTTI installed by the NoteDisconnect
   * `boost::bind` chain (0x0088FBD0, `get_functor_type_tag`) publishes this
   * function's pointer type as `void (__cdecl *)(gpg::StrArg)`. As with
   * `func_ReceiveChat` (see `UiRuntimeTypes.h`), this SDK's `gpg::StrArg` is
   * currently the simplified `= const char*` alias with no implicit
   * conversion from `msvc8::string`, so the parameter is kept as
   * `const msvc8::string&` -- a known, evidenced gap, not a guess (see
   * `gpg/core/utils/Logging.h`'s `LogScopeEntry` note and
   * `CGpgNetInterface.cpp`'s `MakeConnectThreadLaunchCallback`).
   */
  void ConPrintClientDisconnected(
    const msvc8::string& nickname
  )
  {
    const msvc8::string message = moho::Loc(moho::USER_GetLuaState(), "<LOC Engine0002>%s disconnected.");
    moho::CON_Printf(message.c_str(), nickname.c_str());
  }
} // namespace

namespace moho
{
  CWldUiInterface sCWldUiInterface;

  /**
   * Address: 0x0088B6C0 (FUN_0088B6C0)
   * Address: 0x0088BB90 (FUN_0088BB90)
   *
   * What it does:
   * Restores the base vtable in `sCWldUiInterface`; the two emissions of this
   * destructor for that one object.
   */
  IClientMgrUIInterface::~IClientMgrUIInterface() = default;

  /**
   * Address: 0x0088B6D0 (FUN_0088B6D0, Moho::IClientMgrUIInterface::NoteDisconnect)
   *
   * What it does:
   * Default UI callback lane for disconnect notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::NoteDisconnect(const CClientBase* const client)
  {
    (void)client;
  }

  /**
   * Address: 0x0088B6E0 (FUN_0088B6E0, Moho::IClientMgrUIInterface::Func2)
   *
   * What it does:
   * Default UI callback lane for eject-request notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::NoteEjectRequest(const CClientBase* const requester, const CClientBase* const target)
  {
    (void)requester;
    (void)target;
  }

  /**
   * Address: 0x0088B6F0 (FUN_0088B6F0, Moho::IClientMgrUIInterface::ReceiveChat)
   *
   * What it does:
   * Default UI callback lane for inbound chat payload notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReceiveChat(const CClientBase* const sender, const gpg::MemBuffer<const char>& data)
  {
    (void)sender;
    (void)data;
  }

  /**
   * Address: 0x0088B700 (FUN_0088B700, Moho::IClientMgrUIInterface::NoteGameSpeedChange)
   *
   * What it does:
   * Default UI callback lane for game-speed updates (no-op in base interface).
   */
  void IClientMgrUIInterface::NoteGameSpeedChanged(const CClientBase* const client, const std::int32_t gameSpeed)
  {
    (void)client;
    (void)gameSpeed;
  }

  /**
   * Address: 0x0088B710 (FUN_0088B710, Moho::IClientMgrUIInterface::ReportBottleneck)
   *
   * What it does:
   * Default UI callback lane for bottleneck notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReportBottleneck(const SClientBottleneckInfo& info)
  {
    (void)info;
  }

  /**
   * Address: 0x0088B720 (FUN_0088B720, Moho::IClientMgrUIInterface::ReportBottleneckCleared)
   *
   * What it does:
   * Default UI callback lane for bottleneck-clear notifications (no-op in base interface).
   */
  void IClientMgrUIInterface::ReportBottleneckCleared()
  {}

  /**
   * Address: 0x0088B810 (FUN_0088B810, Moho::CWldUiInterface::NoteDisconnect)
   * Address: 0x0088EA50 (FUN_0088EA50, boost::bind_ConPrintDisconnect) - builds
   *          the `bind_t<void, void(__cdecl*)(gpg::StrArg),
   *          list1<value<std::string>>>` from the captured nickname
   * Address: 0x0088EB10 (FUN_0088EB10) - boost::function0<void>::function<F>
   *          converting constructor (installs the bind_t into the
   *          function_buffer)
   * Address: 0x0088F150 (FUN_0088F150) - assign_to<F> relay
   * Address: 0x0088F270 (FUN_0088F270) - magic-statics guard (dword_110413C)
   *          around the one-time manager/invoker install for this bind_t<>
   * Address: 0x0088F470 (FUN_0088F470) - basic_vtable<F>::init relay
   * Address: 0x0088F500 (FUN_0088F500) - functor-non-empty relay, checked
   *          unconditionally on every assign (not just the guarded first-init
   *          path) to decide whether `*arg0` gets the vtable pointer or null
   * Address: 0x0088F7A0 (FUN_0088F7A0) - the heap-clone branch FUN_0088F500
   *          calls when the bound string does not fit the function_buffer's
   *          SSO slot: copies the string into a local buffer and forwards to
   *          the node allocator below
   * Address: 0x0088FA30 (FUN_0088FA30) - allocates the heap node (checked
   *          32-byte `operator new`, `AllocateChecked32ByteLane` /
   *          FUN_0088FFC0), constructs it (FUN_00890010), and frees the
   *          function_buffer's previous heap block if it held one
   * Address: 0x0088FFC0 (FUN_0088FFC0) - checked 32-byte array-allocation
   *          helper, already recovered generically as
   *          `gpg::core::legacy::AllocateChecked32ByteLane` in
   *          `CheckedArrayAllocationLanes.cpp`; shared by FUN_0088FA30's and
   *          FUN_0088FE40's clone paths
   * Address: 0x00890010 (FUN_00890010) - `list1<value<std::string>>` node
   *          constructor: copy-constructs the bound string into the new heap
   *          node, shared by FUN_0088FA30's and FUN_0088FE40's clone paths
   *          (same "real vendored boost header emits it" shape as the
   *          already-cited `list2<>` node ctor FUN_0088F040 below)
   * Address: 0x0088F700 (FUN_0088F700) - writes {manager=FUN_0088FBD0,
   *          invoker=FUN_0088FBA0} into the static vtable pair
   *          (dword_1104130 / dword_1104134)
   * Address: 0x0088FBD0 (FUN_0088FBD0) - basic_vtable<F>::manager (RTTI-
   *          confirmed via the embedded `bind_t<void,void(__cdecl*)(gpg::StrArg),
   *          list1<value<std::string>>>` type descriptor returned for
   *          `get_functor_type_tag`)
   * Address: 0x0088FE40 (FUN_0088FE40) - functor_manager<F,A>::manager's
   *          heap-allocated-functor overload (mpl::false_), tail-called by
   *          FUN_0088FBD0 for clone/destroy/check_functor_type_tag -- the
   *          NoteDisconnect-side sibling of ReceiveChat's FUN_0088FEC0 below.
   *          `clone_functor_tag` allocates+constructs via FUN_0088FFC0 /
   *          FUN_00890010, `destroy_functor_tag` frees the bound string and
   *          the node, `check_functor_type_tag` compares against the same
   *          `bind_t<>` RTTI descriptor FUN_0088FBD0 returns
   * Address: 0x0088FBA0 (FUN_0088FBA0) - basic_vtable<F>::invoker: SSO-aware
   *          call `(*f_)(_Myres < 0x10 ? &_Bx._Buf[0] : _Bx._Ptr)` against the
   *          bound string
   *
   * What it does:
   * IClientMgrUIInterface::NoteDisconnect override: captures the disconnected
   * client's nickname and posts the localized console disconnect notice onto the
   * main thread (so console output happens on the UI thread). The binary builds
   * this callback via `boost::bind(&ConPrintClientDisconnected, nickname)` (a
   * free-function bind storing a real `std::string` copy, per the manager RTTI)
   * rather than a closure object -- expressed here the same way so this call
   * site is the one that actually instantiates the cited manager/invoker pair.
   *
   * FUN_0088F9F0 sits a few bytes below this chain and stamps the identical
   * {manager=FUN_0088FBD0, invoker=FUN_0088FBA0} pair FUN_0088F700 installs,
   * but it is not cited here: it has zero incoming references anywhere --
   * empty in the IDA-exported xrefs for both analyzed databases, empty in the
   * enriched callgraph index's call_edges/incoming_xrefs tables, and a raw
   * CALL/JMP-rel32 plus absolute-address byte scan of both
   * `bin/2025.7.1/ForgedAlliance.exe` and `bin/external/ForgedAlliance.exe`
   * finds no reference of any kind to 0x0088F9F0. Left `skip`, matching the
   * `FUN_0088FDC0` precedent a few bytes further down (already byte-verified
   * unreferenced the same way) rather than folded into this call site without
   * evidence.
   */
  void CWldUiInterface::NoteDisconnect(const CClientBase* const client)
  {
    const msvc8::string nickname = client->GetNickname();
    boost::function<void(), std::allocator<void>> callback = boost::bind(&ConPrintClientDisconnected, nickname);
    THREAD_InvokeAsync(callback, 0u);
  }

  /**
   * Address: 0x0088B870 (FUN_0088B870, Moho::CWldUiInterface::Func2)
   *
   * What it does:
   * Nothing: the game UI ignores eject requests (`ret 8`).
   */
  void CWldUiInterface::NoteEjectRequest(const CClientBase* const requester, const CClientBase* const target)
  {
    (void)requester;
    (void)target;
  }

  /**
   * Address: 0x0088B880 (FUN_0088B880, Moho::CWldUiInterface::ReceiveChat)
   * Address: 0x0088EB90 (FUN_0088EB90, boost::bind_ReceiveChat) - builds the
   *          `bind_t<void, void(__cdecl*)(gpg::StrArg,gpg::MemBuffer<char
   *          const> const&), list2<value<std::string>,
   *          value<gpg::MemBuffer<char const>>>>` from the captured nickname
   *          and payload (the MemBuffer copy bumps its shared refcount via
   *          `_InterlockedExchangeAdd`, matching `gpg::MemBuffer`'s own copy
   *          semantics)
   * Address: 0x0088EED0 (FUN_0088EED0) - `list2<value<std::string>,
   *          value<gpg::MemBuffer<char const>>>`'s element-copy relay: copies
   *          the bound `std::string` by value (`std::string::assign`), bumps
   *          the `gpg::MemBuffer`'s shared refcount (`_InterlockedExchangeAdd`
   *          on the iterator-base count), then forwards into the node
   *          constructor below; on the way out, releases the caller's
   *          temporary refcount via the same two-phase
   *          `dispose`/`destroy` vtable-slot release this project has
   *          already identified elsewhere as `sp_counted_base::release()`
   *          (RbTree.h's `erase_node` citations document the same shape).
   * Address: 0x0088F040 (FUN_0088F040) - the `list2<...>` node constructor
   *          itself: copy-constructs the `std::string` element in place
   *          (`sub_420DD0`, already `skip` - CRT `std::string` copy-ctor
   *          internals) and stores the `gpg::MemBuffer`'s
   *          {iteratorBase, refcountPtr, begin, end} fields verbatim into the
   *          node's trailing slots.
   * Address: 0x0088ECE0 (FUN_0088ECE0) - boost::function0<void>::function<F>
   *          converting constructor (installs the bind_t into the
   *          function_buffer)
   * Address: 0x0088F1D0 (FUN_0088F1D0) - assign_to<F> relay
   * Address: 0x0088F350 (FUN_0088F350) - magic-statics guard (dword_1104138)
   *          around the one-time manager/invoker install for this bind_t<>
   * Address: 0x0088F590 (FUN_0088F590) - basic_vtable<F>::init relay
   * Address: 0x0088F600 (FUN_0088F600) - functor-non-empty relay, checked
   *          unconditionally on every assign (not just the guarded first-init
   *          path) to decide whether `*arg0` gets the vtable pointer or null
   * Address: 0x0088F8E0 (FUN_0088F8E0) - the heap-clone branch FUN_0088F600
   *          calls when the bound string+MemBuffer node does not fit the
   *          function_buffer's SSO slot: copies the node via FUN_0088EE00
   *          and forwards to the node allocator below
   * Address: 0x0088EE00 (FUN_0088EE00) - `list2<value<std::string>,
   *          value<gpg::MemBuffer<char const>>>`'s implicit copy constructor:
   *          `std::string::assign` (0x004056B0) for the string, then the
   *          MemBuffer's four words with its shared count bumped
   * Address: 0x0088BAB0 (FUN_0088BAB0) - that list's implicit destructor:
   *          releases the MemBuffer's shared count (+0x20), then the string
   * Address: 0x0088FFB0 (FUN_0088FFB0) - the heap node's destroy step:
   *          `add eax, 4` past the manager tag, then FUN_0088BAB0
   * Address: 0x008901D0 (FUN_008901D0) - a second emission of that step
   * Address: 0x00890210 (FUN_00890210) - the same through `esi`, returning
   *          the node
   * Address: 0x0088FAE0 (FUN_0088FAE0) - allocates the heap node (checked
   *          48-byte `operator new`, already recovered generically as
   *          `gpg::core::legacy::AllocateChecked48ByteLane` / FUN_00890080),
   *          constructs it (FUN_008900D0), and releases the caller's
   *          temporary via the same two-phase `FUN_0088BAB0` release used
   *          elsewhere in this chain
   * Address: 0x008900D0 (FUN_008900D0) - `list2<value<std::string>,
   *          value<gpg::MemBuffer<char const>>>` node constructor for the
   *          heap-clone path: copies the manager/vtable-tag field, then
   *          copies the string+MemBuffer element via FUN_0088EE00 -- the heap-clone
   *          counterpart to the already-cited construction-path node ctor
   *          FUN_0088F040 above
   * Address: 0x0088F860 (FUN_0088F860) - writes {manager=FUN_0088FC70,
   *          invoker=FUN_0088FC40} into the static vtable pair (stru_1104128)
   * Address: 0x0088FC70 (FUN_0088FC70) - basic_vtable<F>::manager (RTTI-
   *          confirmed via the embedded `bind_t<void,void(__cdecl*)(gpg::StrArg,
   *          gpg::MemBuffer<char const> const&),list2<value<std::string>,
   *          value<gpg::MemBuffer<char const>>>>` type descriptor returned for
   *          `get_functor_type_tag`)
   * Address: 0x0088FC40 (FUN_0088FC40) - basic_vtable<F>::invoker: SSO-aware
   *          call `(*f_)(_Myres < 0x10 ? &_Bx._Buf[0] : _Bx._Ptr, memBuffer)`
   *          against the bound string and MemBuffer (cdecl, 2 args, `add
   *          esp,8` confirms the arity)
   * Address: 0x0088FEC0 (FUN_0088FEC0) - the heap-allocated-functor overload
   *          `boost::detail::function::functor_manager<Functor,
   *          Allocator>::manager(in_buffer, out_buffer, op, mpl::false_)`
   *          this bind_t<>'s size rules out the small-object buffer for
   *          (`dependencies/boost_1_34_1/boost/function/function_base.hpp`,
   *          the `mpl::false_` overload at ~line 300): `manage` (FUN_0088FC70,
   *          cited above) tail-calls it for every operation except
   *          `get_functor_type_tag`. Body matches line for line -
   *          `clone_functor_tag` (`a1==0`) allocator-constructs a copy
   *          (`sub_890080`/`sub_8900D0`), `destroy_functor_tag` (`a1==1`)
   *          destroys/deallocates it (`sub_88BAB0` + `operator delete`), and
   *          `check_functor_type_tag` (the `else`) compares `*a3`'s
   *          `std::type_info` against the same `bind_t<>` RTTI descriptor
   *          `manage` returns for `get_functor_type_tag`, handing back the
   *          object pointer on a match or null otherwise. `FUN_0088FDE0`
   *          (already `skip`, an ICF-shaped register-order twin) reaches the
   *          same body for a sibling `boost::function` instance built the same
   *          way. No separate C++ body is written for this one either - real
   *          vendored `<boost/function.hpp>`/`<boost/bind.hpp>` (both
   *          `#include`d at the top of this file) already emits it from the
   *          same `boost::bind(&func_ReceiveChat, nickname, data)` call.
   *
   * What it does:
   * IClientMgrUIInterface::ReceiveChat override: captures the sender's nickname
   * and the received chat payload, then posts the recovered func_ReceiveChat
   * decoder (which forwards to /lua/ui/game/gamemain.lua:ReceiveChat) onto the
   * main thread. The binary builds this callback via
   * `boost::bind(&func_ReceiveChat, nickname, data)` (a free-function bind
   * storing real `std::string`/`MemBuffer` copies, per the manager RTTI) rather
   * than a closure object -- expressed here the same way so this call site is
   * the one that actually instantiates the cited manager/invoker pair. The
   * MemBuffer's shared payload is kept alive by the bind_t's own copy.
   *
   * FUN_0088FAA0 sits a few bytes below this chain and stamps the identical
   * stru_1104128 = {manager=FUN_0088FC70, invoker=FUN_0088FC40} pair
   * FUN_0088F860 installs, then tears down a local buffer via FUN_0088BAB0 the
   * same way the rest of this chain does -- but like FUN_0088F9F0 on
   * NoteDisconnect above, it is not cited here: it has zero incoming
   * references anywhere (empty IDA-exported xrefs, empty callgraph-index
   * call_edges/incoming_xrefs, and no hit from a raw CALL/JMP-rel32 plus
   * absolute-address byte scan of both `bin/2025.7.1/ForgedAlliance.exe` and
   * `bin/external/ForgedAlliance.exe`). Left `skip` rather than folded into
   * this call site without evidence.
   */
  void CWldUiInterface::ReceiveChat(const CClientBase* const sender, const gpg::MemBuffer<const char>& data)
  {
    const msvc8::string nickname = sender->GetNickname();
    boost::function<void(), std::allocator<void>> callback = boost::bind(&func_ReceiveChat, nickname, data);
    THREAD_InvokeAsync(callback, 0u);
  }

  /**
   * Address: 0x0088B960 (FUN_0088B960, Moho::CWldUiInterface::NoteGameSpeedChanged)
   * Address: 0x0088F410 (FUN_0088F410) - boost::function0<void>::assign_to<F>,
   *          magic-static-guarded install of the manager/invoker pair for this
   *          bind_t<>
   * Address: 0x0088F6A0 (FUN_0088F6A0) - vtable_type::assign_to payload store:
   *          writes {&UI_DriverNoteGameSpeedChanged, slotZeroBased, gameSpeed}
   *          into the function_buffer
   * Address: 0x0088FD00 (FUN_0088FD00) - basic_vtable<F>::manager (RTTI-
   *          confirmed via the embedded `bind_t<void,void(__cdecl*)(int,int),
   *          list2<value<unsigned int>,value<int>>>` type descriptor)
   * Address: 0x0088FCE0 (FUN_0088FCE0) - basic_vtable<F>::invoker: calls
   *          `(*buf[0])(buf[1], buf[2])`
   *
   * What it does:
   * IClientMgrUIInterface::NoteGameSpeedChanged override for the game UI: posts
   * the driver-gated game-speed-changed notice, tagged with the requesting
   * client's index (`[client+0x20]`, `IClient::mIndex`, read at 0x0088B964),
   * onto the main thread (via THREAD_InvokeAsync -> UI_DriverNoteGameSpeedChanged,
   * which forwards to the Lua UI when a sim driver is active). The binary builds
   * this callback via `boost::bind(&UI_DriverNoteGameSpeedChanged, slotZeroBased,
   * gameSpeed)` (a free-function bind, flat function_buffer, no this-adjustment)
   * rather than a closure object -- expressed here the same way to keep this
   * call site the one that actually instantiates the cited manager/invoker pair.
   */
  void CWldUiInterface::NoteGameSpeedChanged(const CClientBase* const client, const std::int32_t gameSpeed)
  {
    // `value<unsigned int>` in the bind_t RTTI: the index is bound unsigned.
    const auto clientIndex = static_cast<std::uint32_t>(client->GetIndex());
    boost::function<void(), std::allocator<void>> callback =
      boost::bind(&UI_DriverNoteGameSpeedChanged, clientIndex, gameSpeed);
    THREAD_InvokeAsync(callback, 0u);
  }

  /**
   * Address: 0x0088B9B0 (FUN_0088B9B0, Moho::CWldUiInterface::ReportBottleneck)
   *
   * What it does:
   * Forwards one client-bottleneck snapshot to the GPGNet reporting lane.
   */
  void CWldUiInterface::ReportBottleneck(const SClientBottleneckInfo& info)
  {
    GPGNET_ReportBottleneck(info);
  }

  /**
   * Address: 0x0088B9C0 (FUN_0088B9C0, Moho::CWldUiInterface::ReportBottleneckCleared)
   *
   * What it does:
   * Forwards one bottleneck-cleared notification to the GPGNet reporting lane.
   */
  void CWldUiInterface::ReportBottleneckCleared()
  {
    GPGNET_ReportBottleneckCleared();
  }

  /**
   * Address: 0x0088BA50 (FUN_0088BA50, func_DriverNoteGameSpeedChanged)
   *
   * What it does:
   * Forwards game-speed UI callback only while one active simulation driver
   * instance exists.
   */
  void UI_DriverNoteGameSpeedChanged(
    const std::int32_t slotZeroBased,
    const std::int32_t gameSpeed
  )
  {
    if (SIM_GetActiveDriver() != nullptr) {
      UI_NoteGameSpeedChanged(slotZeroBased, gameSpeed);
    }
  }
} // namespace moho
