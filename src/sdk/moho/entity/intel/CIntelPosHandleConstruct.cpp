#include "moho/entity/intel/CIntelPosHandleConstruct.h"

#include <cstdlib>
#include <new>

#include "moho/entity/intel/CIntelPosHandle.h"

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
  // Address: 0x010BB3EC -- process-global `CIntelPosHandleConstruct`
  // singleton. Constructing it runs CIntelPosHandleConstruct::
  // CIntelPosHandleConstruct() (0x00BDCCB0), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches RegisterConstructFunction() on it from within the first
  // ReadArchive/WriteArchive construction.
  moho::CIntelPosHandleConstruct gCIntelPosHandleConstruct;

  /**
   * Address: 0x00C01EA0 (FUN_00C01EA0)
   *
   * What it does:
   * Unlinks the `CIntelPosHandleConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BDCCB0) as the
   * global's `atexit` teardown. `FUN_0076F2E0` and `FUN_0076F310` are
   * duplicate-emission twins of this exact unlink/reset lane (same
   * `ResetLinks()` shape, folded to separate addresses); they have no
   * distinct source-level body of their own.
   */
  void CleanupCIntelPosHandleConstruct()
  {
    gCIntelPosHandleConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  namespace
  {
    void ConstructCIntelPosHandleForResult(gpg::SerConstructResult* const result)
    {
      CIntelPosHandle* object = nullptr;
      void* const storage = ::operator new(sizeof(CIntelPosHandle), std::nothrow);
      if (storage != nullptr) {
        object = new (storage) CIntelPosHandle(0u, boost::SharedPtrRaw<CIntelGrid>{});
      }

      gpg::RRef ref{};
      gpg::RRef_CIntelPosHandle(&ref, object);
      result->SetUnowned(ref, 0u);
    }
  } // namespace

  /**
   * Address: 0x0076F340 (FUN_0076F340)
   *
   * What it does:
   * Serializer construct-callback thunk that forwards to the canonical
   * `CIntelPosHandleConstruct::Construct` implementation. This is the exact
   * address the real `CIntelPosHandleConstruct` constructor (0x00BDCCB0)
   * stores into `mConstructCallback`.
   */
  void ConstructCIntelPosHandleSerializerThunk(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    CIntelPosHandleConstruct::Construct(archive, objectPtr, version, result);
  }

  /**
   * Address: 0x0076F350 (FUN_0076F350, Moho::CIntelPosHandleConstruct::Construct)
   */
  void CIntelPosHandleConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    ConstructCIntelPosHandleForResult(result);
  }

  /**
   * Address: 0x0076FCB0 (FUN_0076FCB0)
   *
   * What it does:
   * Deleting-teardown callback: invokes `CIntelPosHandle::Destroy(1)` for one
   * runtime object when the pointer lane is non-null.
   */
  void CIntelPosHandleConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const handle = static_cast<CIntelPosHandle*>(objectPtr);
    if (handle != nullptr) {
      handle->Destroy(1);
    }
  }

  /**
   * Address: 0x00BDCCB0 (FUN_00BDCCB0, dynamic initializer for the global
   * `CIntelPosHandleConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  CIntelPosHandleConstruct::CIntelPosHandleConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCIntelPosHandleSerializerThunk))
    , mDeleteCallback(&CIntelPosHandleConstruct::Deconstruct)
  {
    (void)std::atexit(&CleanupCIntelPosHandleConstruct);
  }

  /**
   * Address: 0x0076FA80 (FUN_0076FA80, gpg::SerConstructHelper_CIntelPosHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelPosHandle RTTI and installs construct/delete callbacks
   * from this helper into the type descriptor.
   */
  void CIntelPosHandleConstruct::Init()
  {
    gpg::RType* const type = CIntelPosHandle::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
