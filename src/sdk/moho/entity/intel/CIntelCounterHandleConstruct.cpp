#include "moho/entity/intel/CIntelCounterHandleConstruct.h"

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
   * `CIntelCounterHandleConstruct::Construct` implementation.
   */
  [[maybe_unused]] void ConstructCIntelCounterHandleSerializerThunk(
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
