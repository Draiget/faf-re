#include "moho/entity/intel/CIntelCounterHandleConstruct.h"

#include <cstdlib>
#include <new>

#include "moho/entity/intel/CIntelCounterHandle.h"

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
  // Address: 0x010BB400 -- process-global `CIntelCounterHandleConstruct`
  // singleton. Constructing it runs CIntelCounterHandleConstruct::
  // CIntelCounterHandleConstruct() (0x00BDCD50), which splices this helper
  // into gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches RegisterConstructFunction() on it from within the first
  // ReadArchive/WriteArchive construction.
  moho::CIntelCounterHandleConstruct gCIntelCounterHandleConstruct;

  /**
   * Address: 0x00C01F60 (FUN_00C01F60)
   *
   * What it does:
   * Unlinks the `CIntelCounterHandleConstruct` helper node from whatever
   * intrusive list it currently sits in and restores a self-linked sentinel
   * state. Registered by the real dynamic initializer (0x00BDCD50) as the
   * global's `atexit` teardown.
   */
  void CleanupCIntelCounterHandleConstruct()
  {
    gCIntelCounterHandleConstruct.ResetLinks();
  }
} // namespace

namespace moho
{
  namespace
  {
    void ConstructCIntelCounterHandleForResult(gpg::SerConstructResult* const result)
    {
      CIntelCounterHandle* object = nullptr;
      void* const storage = ::operator new(sizeof(CIntelCounterHandle), std::nothrow);
      if (storage != nullptr) {
        object = new (storage) CIntelCounterHandle(0u, nullptr, INTELCOUNTER_None, nullptr);
      }

      gpg::RRef ref{};
      gpg::RRef_CIntelCounterHandle(&ref, object);
      result->SetUnowned(ref, 0u);
    }
  } // namespace

  /**
   * Address: 0x0076F900 (FUN_0076F900)
   *
   * What it does:
   * Serializer construct-callback thunk that forwards to the canonical
   * `CIntelCounterHandleConstruct::Construct` implementation. This is the
   * exact address the real `CIntelCounterHandleConstruct` constructor
   * (0x00BDCD50) stores into `mConstructCallback`.
   */
  void ConstructCIntelCounterHandleSerializerThunk(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    CIntelCounterHandleConstruct::Construct(archive, objectPtr, version, result);
  }

  /**
   * Address: 0x0076F910 (FUN_0076F910, Moho::CIntelCounterHandleConstruct::Construct)
   */
  void CIntelCounterHandleConstruct::Construct(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    ConstructCIntelCounterHandleForResult(result);
  }

  /**
   * Address: 0x0076FD90 (FUN_0076FD90)
   *
   * What it does:
   * Deleting-teardown callback: invokes `CIntelCounterHandle::Destroy(1)` for
   * one runtime object when the pointer lane is non-null.
   */
  void CIntelCounterHandleConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const handle = static_cast<CIntelCounterHandle*>(objectPtr);
    if (handle != nullptr) {
      handle->Destroy(1);
    }
  }

  /**
   * Address: 0x00BDCD50 (FUN_00BDCD50, dynamic initializer for the global
   * `CIntelCounterHandleConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
   * into `sNewHelpers`), binds the construct/delete callback fields, and
   * registers process-exit cleanup.
   */
  CIntelCounterHandleConstruct::CIntelCounterHandleConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructCIntelCounterHandleSerializerThunk))
    , mDeleteCallback(&CIntelCounterHandleConstruct::Deconstruct)
  {
    (void)std::atexit(&CleanupCIntelCounterHandleConstruct);
  }

  /**
   * Address: 0x0076FBA0 (FUN_0076FBA0, gpg::SerConstructHelper_CIntelCounterHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelCounterHandle RTTI and installs construct/delete
   * callbacks from this helper into the type descriptor.
   */
  void CIntelCounterHandleConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CIntelCounterHandle::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
