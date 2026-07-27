#include "moho/entity/Shield.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
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
  using ShieldPtrList = msvc8::list<moho::Shield*>;

  // Cached "list<Shield*>" lexical name (binary global stru_10C80D8).
  msvc8::string gShieldPtrListTypeName{};
  bool gShieldPtrListTypeNameCleanupRegistered = false;

  // std::list control block: {proxy, sentinel, count} — count at +0x08.
  struct ShieldPtrListRuntimeView
  {
    void* mNodeProxy;      // +0x00
    void* mSentinelNode;   // +0x04
    std::uint32_t mCount;  // +0x08
  };
  static_assert(
    offsetof(ShieldPtrListRuntimeView, mCount) == 0x08, "ShieldPtrListRuntimeView::mCount offset must be 0x08"
  );
  static_assert(sizeof(ShieldPtrListRuntimeView) == 0x0C, "ShieldPtrListRuntimeView size must be 0x0C");

  [[nodiscard]] int CountShieldPtrListElements(const void* const object) noexcept
  {
    if (object == nullptr) {
      return 0;
    }
    return static_cast<int>(static_cast<const ShieldPtrListRuntimeView*>(object)->mCount);
  }

  /**
   * Address: 0x00C00FB0 (FUN_00C00FB0, cleanup_ShieldPtrListTypeName)
   *
   * What it does:
   * Releases cached lexical type-name storage for `list<Shield*>`.
   */
  void cleanup_ShieldPtrListTypeName()
  {
    gShieldPtrListTypeName = msvc8::string{};
    gShieldPtrListTypeNameCleanupRegistered = false;
  }

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
   *
   * What it does:
   * Lazily builds and caches `"list<Shield*>"` from the element pointer-type
   * name (`moho::Shield::GetPointerType()->GetName()`), arming a one-shot
   * `atexit` teardown for the cached string.
   */
  const char* RListType_ShieldPtr::GetName() const
  {
    if (gShieldPtrListTypeName.empty()) {
      gpg::RType* const pointerType = moho::Shield::GetPointerType();
      const char* const elementName = pointerType ? pointerType->GetName() : "Shield*";
      gShieldPtrListTypeName = gpg::STR_Printf("list<%s>", elementName ? elementName : "Shield*");
      if (!gShieldPtrListTypeNameCleanupRegistered) {
        gShieldPtrListTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_ShieldPtrListTypeName);
      }
    }

    return gShieldPtrListTypeName.c_str();
  }

  /**
   * Address: 0x0074CDC0 (FUN_0074CDC0, gpg::RListType_ShieldPtr::GetLexical)
   *
   * What it does:
   * Formats the inherited list lexical text with the current element count
   * (`"<base>, size=<count>"`).
   */
  msvc8::string RListType_ShieldPtr::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), CountShieldPtrListElements(ref.mObj));
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
    size_ = 0x0C;
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
    auto* const list = reinterpret_cast<ShieldPtrList*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (archive == nullptr || list == nullptr) {
      return;
    }

    unsigned int count = 0u;
    archive->ReadUInt(&count);
    list->clear();

    for (unsigned int i = 0u; i < count; ++i) {
      moho::Shield* element = nullptr;
      archive->ReadPointer_Shield(&element, ownerRef);
      list->push_back(element);
    }
  }

  /**
   * Address: 0x0074E440 (FUN_0074E440, gpg::RListType_ShieldPtr::SerSave)
   *
   * What it does:
   * Writes the element count, then serializes each `moho::Shield*` in list
   * traversal order as an unowned tracked raw pointer.
   */
  void RListType_ShieldPtr::SerSave(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const
  )
  {
    const auto* const list = reinterpret_cast<const ShieldPtrList*>(
      static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr))
    );
    if (archive == nullptr) {
      return;
    }

    const unsigned int count = list ? static_cast<unsigned int>(list->size()) : 0u;
    archive->WriteUInt(count);
    if (list == nullptr) {
      return;
    }

    const gpg::RRef emptyOwner{};
    for (moho::Shield* const element : *list) {
      gpg::RRef ref{};
      gpg::RRef_Shield(&ref, element);
      gpg::WriteRawPointer(archive, ref, gpg::TrackedPointerState::Unowned, emptyOwner);
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
