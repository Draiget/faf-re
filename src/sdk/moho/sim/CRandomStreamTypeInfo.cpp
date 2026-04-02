#include "moho/sim/CRandomStreamTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/sim/CRandomStream.h"

namespace
{
  void InitializeRandomStream(moho::CRandomStream& stream)
  {
    stream.twister.Seed(0x1571u);
    stream.hasMarsagliaPair = false;
  }

  /**
   * Address: 0x0040F450 (FUN_0040F450)
   *
   * What it does:
   * Allocates and seeds a new CRandomStream before wrapping it in an RTTI ref.
   */
  [[nodiscard]] gpg::RRef NewRef()
  {
    auto* const stream = new (std::nothrow) moho::CRandomStream;
    if (stream) {
      InitializeRandomStream(*stream);
    }

    gpg::RRef ref{};
    gpg::AssignCRandomStreamRef(&ref, stream);
    return ref;
  }

  /**
   * Address: 0x0040F4C0 (FUN_0040F4C0)
   *
   * What it does:
   * Seeds an existing CRandomStream storage block before wrapping it in an RTTI ref.
   */
  [[nodiscard]] gpg::RRef CtrRef(void* const storage)
  {
    auto* const stream = static_cast<moho::CRandomStream*>(storage);
    if (stream) {
      InitializeRandomStream(*stream);
    }

    gpg::RRef ref{};
    gpg::AssignCRandomStreamRef(&ref, stream);
    return ref;
  }

  /**
   * Address: 0x0040F4A0 (FUN_0040F4A0)
   *
   * What it does:
   * Deletes a CRandomStream allocation when a reflected instance is released.
   */
  void Delete(void* const storage)
  {
    if (!storage) {
      return;
    }

    ::operator delete(storage);
  }

  /**
   * Address: 0x0040F500 (nullsub_89)
   *
   * What it does:
   * No-op destroy hook used by CRandomStream reflection metadata.
   */
  void Destruct(void*)
  {}
} // namespace

namespace moho
{
  /**
   * Address: 0x0040F070 (FUN_0040F070, Moho::CRandomStreamTypeInfo::CRandomStreamTypeInfo)
   */
  CRandomStreamTypeInfo::CRandomStreamTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CRandomStream), this);
  }

  /**
   * Address: 0x0040F120 (FUN_0040F120, deleting dtor lane)
   */
  CRandomStreamTypeInfo::~CRandomStreamTypeInfo() = default;

  /**
   * Address: 0x0040F110 (FUN_0040F110, Moho::CRandomStreamTypeInfo::GetName)
   */
  const char* CRandomStreamTypeInfo::GetName() const
  {
    return "CRandomStream";
  }

  /**
   * Address: 0x0040F0D0 (FUN_0040F0D0, Moho::CRandomStreamTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::CRandomStreamTypeInfo::Init(gpg::RType *this);
   */
  void CRandomStreamTypeInfo::Init()
  {
    size_ = sizeof(CRandomStream);
    newRefFunc_ = &NewRef;
    deleteFunc_ = &Delete;
    ctorRefFunc_ = &CtrRef;
    dtrFunc_ = &Destruct;
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
