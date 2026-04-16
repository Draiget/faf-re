#include "moho/entity/intel/CIntelPosHandleConstruct.h"

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
   * `CIntelPosHandleConstruct::Construct` implementation.
   */
  [[maybe_unused]] void ConstructCIntelPosHandleSerializerThunk(
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
   * Address: 0x0076FA80 (FUN_0076FA80, gpg::SerConstructHelper_CIntelPosHandle::Init)
   *
   * What it does:
   * Lazily resolves CIntelPosHandle RTTI and installs construct/delete callbacks
   * from this helper into the type descriptor.
   */
  void CIntelPosHandleConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CIntelPosHandle::StaticGetClass();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho
