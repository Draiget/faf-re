#include "moho/ai/CAiBrainConstruct.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiBrain.h"

using namespace moho;

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  [[nodiscard]] gpg::RType* CachedCAiBrainType()
  {
    gpg::RType* type = CAiBrain::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiBrain));
      CAiBrain::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeCAiBrainRef(CAiBrain* const object)
  {
    gpg::RRef ref{};
    gpg::RRef_CAiBrain(&ref, object);
    return ref;
  }

  /**
   * Address: 0x00579D00 (FUN_00579D00)
   *
   * What it does:
   * Allocates one `CAiBrain`, wraps it in a reflected `RRef`, and publishes
   * that reference through `SerConstructResult::SetUnowned`.
   */
  void ConstructCAiBrainForResult(gpg::ReadArchive*, int, int, gpg::SerConstructResult* const result)
  {
    CAiBrain* object = nullptr;
    void* const storage = ::operator new(sizeof(CAiBrain), std::nothrow);
    if (storage) {
      object = new (storage) CAiBrain();
    }

    result->SetUnowned(MakeCAiBrainRef(object), 0u);
  }

  /**
   * Address: 0x00579CF0 (FUN_00579CF0)
   *
   * What it does:
   * Forwards one serializer construct callback lane to
   * `ConstructCAiBrainForResult`.
   */
  void ConstructCAiBrainForResultThunk(
    gpg::ReadArchive* const archive,
    const int objectLane,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    ConstructCAiBrainForResult(archive, objectLane, version, result);
  }

  /**
   * Typed specialization of the generic reflected-object delete callback for
   * this specific registration. The real ctor at 0x00BCB3F0 binds
   * `mDeleteCallback` with a literal immediate at instruction 0x00BCB409
   * (`mov dword_10AD520, offset sub_581890`) -- i.e. the binary stores
   * `&sub_581890` (`DeleteReflectedObjectViaVirtualDtor`, one of a 36-way
   * ICF-identical `delete_func_t` thunk family; canonical twin
   * `FUN_00510AA0`; see moho/ai/CAiBrainTypeInfo.cpp) into this field, not
   * literally the address of this function. `sub_581890` reads the object's
   * own vtable slot 2 (`+0x08`) and calls it with the scalar-delete flag
   * hardcoded to 1. `CAiBrain::~CAiBrain()`'s scalar-deleting-destructor
   * thunk (`FUN_00579F30`) sits at that exact same slot 2 in `CAiBrain`'s own
   * vtable (`VFTABLE: 0x00E19900`, confirmed via `dumps/rtti_dump_all.hpp`),
   * so `delete static_cast<CAiBrain*>(objectPtr)` compiles to an identical
   * dispatch for any real `CAiBrain*` -- this typed specialization and the
   * generic thunk are behaviorally interchangeable here. Recovered as its
   * own named function (rather than reusing the shared thunk by address)
   * per this project's typed-call-site modernization convention.
   */
  void DeleteConstructedCAiBrain(void* const objectPtr)
  {
    auto* const object = static_cast<CAiBrain*>(objectPtr);
    if (!object) {
      return;
    }

    delete object;
  }

  // Address: 0x010AD510 -- process-global `CAiBrainConstruct` singleton.
  // Constructing it runs CAiBrainConstruct::CAiBrainConstruct() (0x00BCB3F0),
  // which splices this helper into gpg::SerHelperBase::sNewHelpers;
  // gpg::SerHelperBase::InitNewHelpers() later dispatches Init() on it from
  // within the first ReadArchive/WriteArchive construction.
  //
  // The binary also contains two BYTE-VERIFIED DUPLICATE emissions of this
  // exact constructor body at 0x00579C60-0x00579C8D and 0x0057E3B0-0x0057E3DD
  // (both untokenized by IDA -- no `functions` table row, no FUN_ export;
  // found via the callgraph address-gap technique and read directly from
  // `bin/2025.7.1/ForgedAlliance.exe` with a pefile+Capstone disassembler).
  // Both write the identical `mConstructCallback`/`mDeleteCallback` field
  // values (`&ConstructCAiBrainForResultThunk` / `&sub_581890`) into this
  // same global storage (`dword_10AD510`/`+0xC`/`+0x10`); one duplicate
  // (0x00579C60) installs the identical `CAiBrainConstruct` vtable
  // (`0xE19A48`), the other (0x0057E3B0) installs the sibling
  // `SerConstructHelper<CAiBrain>` sub-object vtable (`0xE19A50`) whose own
  // sole slot dispatches to the same `Init()` override (`FUN_0057E3E0`) --
  // so both duplicates are behaviorally equivalent to this real ctor even
  // though the vtable constant differs. An exhaustive whole-image scan (every
  // `E8`/`E9` rel32 call/jmp across every PE section, plus a raw 4-byte
  // literal scan for each address) found ZERO references anywhere to either
  // duplicate's start address -- neither is reachable from any call, jump,
  // vtable slot, or function-pointer table. They require no separate
  // recovery: this constructor is their sole source-level representative.
  CAiBrainConstruct gCAiBrainConstructStartupHelper;

  /**
   * Address: 0x00BF62C0 (FUN_00BF62C0)
   *
   * What it does:
   * Unlinks the `CAiBrainConstruct` helper node from whatever intrusive list
   * it currently sits in and restores a self-linked sentinel state.
   * Registered by the real dynamic initializer (0x00BCB3F0) as the global's
   * `atexit` teardown. `FUN_00579C90` and `FUN_00579CC0` are
   * duplicate-emission twins of this exact unlink/reset lane (same
   * `ResetLinks()` shape, folded to separate addresses); they have no
   * distinct source-level body of their own.
   */
  void CleanupCAiBrainConstructStartup()
  {
    gCAiBrainConstructStartupHelper.ResetLinks();
  }
} // namespace

/**
 * Address: 0x00BCB3F0 (FUN_00BCB3F0, dynamic initializer for the global
 * `CAiBrainConstruct` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`), binds the construct/delete callback fields, and
 * registers process-exit cleanup.
 */
CAiBrainConstruct::CAiBrainConstruct()
  : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCAiBrainForResultThunk))
  , mDeleteCallback(&DeleteConstructedCAiBrain)
{
  (void)std::atexit(&CleanupCAiBrainConstructStartup);
}

/**
 * Address: 0x0057E3E0 (FUN_0057E3E0, gpg::SerConstructHelper_CAiBrain::Init)
 *
 * What it does:
 * Lazily resolves CAiBrain RTTI and installs construct/delete callbacks from
 * this helper object into the type descriptor.
 */
void CAiBrainConstruct::Init()
{
  gpg::RType* type = CachedCAiBrainType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mConstructCallback;
  type->deleteFunc_ = mDeleteCallback;
}
