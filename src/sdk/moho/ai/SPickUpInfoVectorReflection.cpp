#include "moho/ai/SPickUpInfoVectorReflection.h"

#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/SPickUpInfo.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedSPickUpInfoType()
  {
    gpg::RType* type = moho::SPickUpInfo::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SPickUpInfo));
      moho::SPickUpInfo::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RVectorType_SPickUpInfo& AcquireSPickUpInfoVectorType()
  {
    static gpg::RVectorType_SPickUpInfo sInstance;
    return sInstance;
  }

  struct SPickUpInfoVectorReflectionBootstrap
  {
    SPickUpInfoVectorReflectionBootstrap()
    {
      (void)moho::register_VectorSPickUpInfoType();
    }
  };

  SPickUpInfoVectorReflectionBootstrap gSPickUpInfoVectorReflectionBootstrap;
} // namespace

/**
 * Address: 0x00626BA0 (FUN_00626BA0, gpg::RVectorType_SPickUpInfo::GetName)
 * Address: 0x00BFA670 (FUN_00BFA670, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds and caches lexical reflection name `vector<element>` for
 * `vector<moho::SPickUpInfo>`.
 */
const char* gpg::RVectorType_SPickUpInfo::GetName() const
{
    static const msvc8::string sName = gpg::STR_Printf("vector<%s>", CachedSPickUpInfoType()->GetName());
    return sName.c_str();
}

/**
 * Address: 0x00626C60 (FUN_00626C60, gpg::RVectorType_SPickUpInfo::GetLexical)
 *
 * What it does:
 * Returns base lexical text plus reflected vector size for one
 * `vector<moho::SPickUpInfo>` instance.
 */
msvc8::string gpg::RVectorType_SPickUpInfo::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
}

/**
 * Address: 0x00626CF0 (FUN_00626CF0, gpg::RVectorType_SPickUpInfo::IsIndexed)
 */
const gpg::RIndexed* gpg::RVectorType_SPickUpInfo::IsIndexed() const
{
  return this;
}

/**
 * Address: 0x00626C40 (FUN_00626C40, gpg::RVectorType_SPickUpInfo::Init)
 *
 * IDA signature:
 * void __thiscall gpg::RVectorType_SPickUpInfo::Init(gpg::RType *this);
 *
 * What it does:
 * Records the element byte-size (16 = sizeof(vector<SPickUpInfo>)), version 1,
 * and installs the reflected element (de)serialize callbacks
 * (`serLoadFunc_ = &SerLoad`, `serSaveFunc_ = &SerSave`). This fn-ptr install
 * is the source-level invocation that keeps SerLoad/SerSave live in the binary.
 */
void gpg::RVectorType_SPickUpInfo::Init()
{
  size_ = sizeof(msvc8::vector<moho::SPickUpInfo>);
  version_ = 1;
  serLoadFunc_ = &RVectorType_SPickUpInfo::SerLoad;
  serSaveFunc_ = &RVectorType_SPickUpInfo::SerSave;
}

/**
 * Address: 0x006270E0 (FUN_006270E0, gpg::RVectorType_SPickUpInfo::SerLoad)
 *
 * What it does:
 * Reads the count, `reserve`s a staging vector (0x006275D0), then per
 * element reads one `SPickUpInfo` into a temporary under an empty owner and
 * `push_back`s it (0x00626E10); the temporary's `WeakPtr<Unit>` unlinks itself
 * at 0x006271A2. The staging vector is swapped into the destination, and the
 * old elements die with it (0x006271D0..0x00627217). Nothing is null-tested.
 */
void gpg::RVectorType_SPickUpInfo::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const
)
{
  auto& storage = *reinterpret_cast<msvc8::vector<moho::SPickUpInfo>*>(objectPtr);

  unsigned int count = 0u;
  archive->ReadUInt(&count);

  msvc8::vector<moho::SPickUpInfo> loaded;
  loaded.reserve(count);
  for (unsigned int i = 0u; i < count; ++i) {
    moho::SPickUpInfo element;
    archive->Read(CachedSPickUpInfoType(), &element, gpg::RRef{});
    loaded.push_back(element);
  }

  storage.swap(loaded);
}

/**
 * Address: 0x00627240 (FUN_00627240, gpg::RVectorType_SPickUpInfo::SerSave)
 *
 * What it does:
 * Writes the count, then each element through the reflected `SPickUpInfo`
 * type with the caller's owner, re-reading `begin()` per element. Nothing is
 * null-tested.
 */
void gpg::RVectorType_SPickUpInfo::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  const auto& storage = *reinterpret_cast<const msvc8::vector<moho::SPickUpInfo>*>(objectPtr);
  const unsigned int count = static_cast<unsigned int>(storage.size());
  archive->WriteUInt(count);
  for (unsigned int i = 0u; i < count; ++i) {
    archive->Write(CachedSPickUpInfoType(), &storage[i], *ownerRef);
  }
}

/**
 * Address: 0x00626D60 (FUN_00626D60, gpg::RVectorType_SPickUpInfo::SubscriptIndex)
 *
 * What it does:
 * Wraps `&vec[ind]` (a `moho::SPickUpInfo*` slot at stride 12) as one
 * `gpg::RRef_SPickUpInfo` reference.
 */
gpg::RRef gpg::RVectorType_SPickUpInfo::SubscriptIndex(void* const obj, const int ind) const
{
  gpg::RRef out{};

  auto* const storage = static_cast<msvc8::vector<moho::SPickUpInfo>*>(obj);
  if (!storage || ind < 0 || static_cast<std::size_t>(ind) >= storage->size()) {
    return out;
  }

  gpg::RRef_SPickUpInfo(&out, &(*storage)[static_cast<std::size_t>(ind)]);
  return out;
}

/**
 * Address: 0x00626D00 (FUN_00626D00, gpg::RVectorType_SPickUpInfo::GetCount)
 *
 * What it does:
 * Returns the vector element count `(last_ - first_) / sizeof(SPickUpInfo)`.
 */
size_t gpg::RVectorType_SPickUpInfo::GetCount(void* const obj) const
{
  const auto* const storage = static_cast<const msvc8::vector<moho::SPickUpInfo>*>(obj);
  return storage ? storage->size() : 0u;
}

/**
 * Address: 0x00626D30 (FUN_00626D30, gpg::RVectorType_SPickUpInfo::SetCount)
 *
 * What it does:
 * `resize(count, SPickUpInfo())` (0x006276F0): the default entry is built on
 * the stack as the by-value fill argument. Nothing is null-tested.
 */
void gpg::RVectorType_SPickUpInfo::SetCount(void* const obj, const int count) const
{
  static_cast<msvc8::vector<moho::SPickUpInfo>*>(obj)->resize(static_cast<std::size_t>(count), moho::SPickUpInfo());
}

/**
 * Address: 0x00628350 (FUN_00628350, preregister_VectorSPickUpInfoType)
 *
 * IDA signature:
 * gpg::RType *sub_628350();
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for the intrusive-weak
 * `vector<moho::SPickUpInfo>` reflected descriptor global and preregisters it
 * under `typeid(vector<moho::SPickUpInfo>)`.
 */
gpg::RType* moho::preregister_VectorSPickUpInfoType()
{
  auto* const typeInfo = &AcquireSPickUpInfoVectorType();
  gpg::PreRegisterRType(typeid(msvc8::vector<moho::SPickUpInfo>), typeInfo);
  return typeInfo;
}

/**
 * Address: 0x00BD1D50 (FUN_00BD1D50, CRT static-init bootstrap thunk)
 *
 * IDA signature:
 * int sub_BD1D50();  // { sub_628350(); return atexit(sub_BFA6A0); }
 *
 * What it does:
 * Runs the vector<SPickUpInfo> preregistration at process static-init and
 * registers the descriptor teardown with `atexit`. This self-roots the family
 * via the CRT static-init array (the db-note edge into CUnitLoadUnits ctor is
 * a phantom edge — the real runtime consumers look the type up by typeid).
 */
void moho::register_VectorSPickUpInfoType()
{
  (void)preregister_VectorSPickUpInfoType();
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_VectorSPickUpInfoType_37b846, moho::preregister_VectorSPickUpInfoType)
GPG_PREREGISTER_INIT(register_VectorSPickUpInfoType_37b846, moho::register_VectorSPickUpInfoType)
