#include "moho/entity/Shield.h"

#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  /**
   * VFTABLE: 0x00E347BC
   *
   * Reflection descriptor for `msvc8::list<moho::Shield*>` — a pointer-element
   * intrusive list. A list is not indexed, so (unlike the RVectorType family)
   * this inherits only `gpg::RType` (no `RIndexed` subobject / SubscriptIndex /
   * GetCount / SetCount). Modeled on the reviewed value-element sibling
   * `gpg::RListType_SDecalInfo` (moho/render/CDecalTypes.cpp).
   */
  class RListType_ShieldPtr final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0074CD20 (FUN_0074CD20, gpg::RListType_ShieldPtr::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0074CDC0 (FUN_0074CDC0, gpg::RListType_ShieldPtr::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0074CDA0 (FUN_0074CDA0, gpg::RListType_ShieldPtr::Init)
     */
    void Init() override;

    /**
     * Address: 0x0074E3C0 (FUN_0074E3C0, gpg::RListType_ShieldPtr::SerLoad)
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);

    /**
     * Address: 0x0074E440 (FUN_0074E440, gpg::RListType_ShieldPtr::SerSave)
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int unusedTag, gpg::RRef* ownerRef);
  };
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00752320 (FUN_00752320, preregister_RListType_ShieldPtr)
   *
   * What it does:
   * Constructs/preregisters the startup-owned `msvc8::list<moho::Shield*>`
   * reflection descriptor.
   */
  gpg::RType* preregister_RListType_ShieldPtr();
} // namespace moho

namespace
{
  struct ShieldPtrListReflectionBootstrap
  {
    ShieldPtrListReflectionBootstrap()
    {
      (void)moho::preregister_RListType_ShieldPtr();
    }
  };

  [[maybe_unused]] ShieldPtrListReflectionBootstrap gShieldPtrListReflectionBootstrap;
} // namespace

namespace gpg
{
  /**
   * Address: 0x0074CD20 (FUN_0074CD20, gpg::RListType_ShieldPtr::GetName)
   * Address: 0x00C00FB0 (FUN_00C00FB0, atexit destructor of GetName's cached name)
   *
   * What it does:
   * Builds `list<Shield *>` once from the element pointer-type name
   * (`moho::Shield::GetPointerType()->GetName()`) and returns it.
   */
  const char* RListType_ShieldPtr::GetName() const
  {
    static const msvc8::string sName = gpg::STR_Printf("list<%s>", moho::Shield::GetPointerType()->GetName());
    return sName.c_str();
  }

  /**
   * Address: 0x0074CDC0 (FUN_0074CDC0, gpg::RListType_ShieldPtr::GetLexical)
   *
   * What it does:
   * Formats the inherited list lexical text with the current element count
   * (`"<base>, size=<count>"`).
   *
   * 0x0074CDFC/0x0074CDFE read `[ref.mObj + 8]` with no null test: the
   * reflected object is the list itself and the count is its `size()`.
   */
  msvc8::string RListType_ShieldPtr::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf(
      "%s, size=%d", base.c_str(), static_cast<int>(static_cast<const msvc8::list<moho::Shield*>*>(ref.mObj)->size())
    );
  }

  /**
   * Address: 0x0074CDA0 (FUN_0074CDA0, gpg::RListType_ShieldPtr::Init)
   *
   * What it does:
   * Configures the reflected `list<Shield*>` layout (0x0C control block) and
   * version lanes, then installs the list (de)serialize callbacks.
   */
  void RListType_ShieldPtr::Init()
  {
    static_assert(sizeof(msvc8::list<moho::Shield*>) == 0x0C, "msvc8::list<moho::Shield*> is 0x0C bytes on x86");
    size_ = sizeof(msvc8::list<moho::Shield*>);
    version_ = 1;
    serLoadFunc_ = &gpg::RListType_ShieldPtr::SerLoad;
    serSaveFunc_ = &gpg::RListType_ShieldPtr::SerSave;
  }

  /**
   * Address: 0x0074E3C0 (FUN_0074E3C0, gpg::RListType_ShieldPtr::SerLoad)
   *
   * What it does:
   * Clears the destination `list<Shield*>`, reads the element count, then reads
   * that many tracked `moho::Shield*` pointers (each via
   * `ReadArchive::ReadPointer_Shield`, forwarding the owner reference) and
   * appends them.
   */
  void RListType_ShieldPtr::SerLoad(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const list = reinterpret_cast<msvc8::list<moho::Shield*>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    unsigned int count = 0u;
    archive->ReadUInt(&count);
    list->clear();

    for (unsigned int i = 0u; i < count; ++i) {
      moho::Shield* element = nullptr;
      archive->ReadPointer(&element, ownerRef);
      list->push_back(element);
    }
  }

  /**
   * Address: 0x0074E440 (FUN_0074E440, gpg::RListType_ShieldPtr::SerSave)
   *
   * What it does:
   * Writes the element count, then serializes each `moho::Shield*` in list
   * traversal order as an unowned tracked raw pointer, owned by `ownerRef`
   * (0x0074E465 hands the callback's fourth argument to every write).
   */
  void RListType_ShieldPtr::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const list = reinterpret_cast<const msvc8::list<moho::Shield*>*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );

    archive->WriteUInt(static_cast<unsigned int>(list->size()));
    for (moho::Shield* const element : *list) {
      gpg::RRef ref{};
      ref = gpg::MakeRRef<moho::Shield>(element);
      gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Unowned, *ownerRef);
    }
  }
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00752320 (FUN_00752320, preregister_RListType_ShieldPtr)
   *
   * What it does:
   * Constructs (base `gpg::RType` ctor + specialization vtable install) and
   * preregisters the startup-owned `msvc8::list<moho::Shield*>` reflection
   * descriptor under `typeid(std::list<Shield*>)`.
   */
  gpg::RType* preregister_RListType_ShieldPtr()
  {
    static gpg::RListType_ShieldPtr typeInfo;
    gpg::PreRegisterRType(typeid(msvc8::list<moho::Shield*>), &typeInfo);
    return &typeInfo;
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RListType_ShieldPtr_095a6f, moho::preregister_RListType_ShieldPtr)
