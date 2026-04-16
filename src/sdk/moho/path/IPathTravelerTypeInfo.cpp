#include "moho/path/IPathTravelerTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/DList.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/path/IPathTraveler.h"

namespace gpg
{
  class RDListType_IPathTraveler : public RType
  {
  public:
    /**
     * Address: 0x00766ED0 (FUN_00766ED0, gpg::RDListType_IPathTraveler::GetName)
     *
     * What it does:
     * Returns the cached lexical label for the reflected
     * `DList<IPathTraveler,void>` lane.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00766FB0 (FUN_00766FB0, gpg::RDListType_IPathTraveler::GetLexical)
     *
     * What it does:
     * Returns inherited lexical text for the reflected DList lane.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00767480 (FUN_00767480, gpg::RDListType_IPathTraveler::SerSave)
     *
     * What it does:
     * Initializes reflected size/version lanes and serializer callbacks for
     * one `DList<IPathTraveler,void>` payload.
     */
    void Init() override;

    /**
     * Address: 0x00767500 (FUN_00767500, gpg::RDListType_IPathTraveler::SerLoad)
     *
     * What it does:
     * Reads unowned `IPathTraveler` pointers until null and links each
     * traveler node into the destination intrusive list.
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00767480 (FUN_00767480, gpg::RDListType_IPathTraveler::SerSave)
     *
     * What it does:
     * Serializes each intrusive-list traveler as an unowned raw-pointer lane,
     * then emits a trailing null traveler sentinel.
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };
} // namespace gpg

namespace
{
  using PathTravelerListNode = moho::TDatListItem<void, void>;

  msvc8::string gDListIPathTravelerTypeName;
  std::uint32_t gDListIPathTravelerTypeNameInitGuard = 0;
  gpg::RType* gDListVoidType = nullptr;
  gpg::RType* gDListIPathTravelerType = nullptr;

  template <class TObject>
  [[nodiscard]] TObject* PointerFromArchiveInt(const int objectPtr)
  {
    return reinterpret_cast<TObject*>(static_cast<std::uintptr_t>(static_cast<std::uint32_t>(objectPtr)));
  }

  [[nodiscard]] gpg::RType* ResolveDListVoidType()
  {
    if (gDListVoidType == nullptr) {
      gDListVoidType = gpg::REF_FindTypeNamed("void");
      if (gDListVoidType == nullptr) {
        gDListVoidType = gpg::LookupRType(typeid(void));
      }
    }

    return gDListVoidType;
  }

  [[nodiscard]] gpg::RType* ResolveDListIPathTravelerType()
  {
    if (gDListIPathTravelerType == nullptr) {
      constexpr const char* kTypeNames[] = {
        "IPathTraveler",
        "Moho::IPathTraveler",
        "class Moho::IPathTraveler",
      };

      for (const char* const name : kTypeNames) {
        if (gpg::RType* const type = gpg::REF_FindTypeNamed(name); type != nullptr) {
          gDListIPathTravelerType = type;
          break;
        }
      }

      if (gDListIPathTravelerType == nullptr) {
        gDListIPathTravelerType = gpg::LookupRType(typeid(moho::IPathTraveler));
      }
    }

    return gDListIPathTravelerType;
  }

  /**
   * Address: 0x00C01B70 (FUN_00C01B70, cleanup_RDListType_IPathTraveler_Name)
   *
   * What it does:
   * Releases cached lexical storage for
   * `gpg::RDListType_IPathTraveler::GetName`.
   */
  void cleanup_RDListType_IPathTraveler_Name()
  {
    gDListIPathTravelerTypeName.clear();
    gDListIPathTravelerTypeNameInitGuard = 0;
  }
} // namespace

/**
 * Address: 0x00766ED0 (FUN_00766ED0, gpg::RDListType_IPathTraveler::GetName)
 *
 * What it does:
 * Lazily builds and caches one reflection label for the
 * `DList<IPathTraveler,void>` lane.
 */
const char* gpg::RDListType_IPathTraveler::GetName() const
{
  if ((gDListIPathTravelerTypeNameInitGuard & 1u) == 0u) {
    gDListIPathTravelerTypeNameInitGuard |= 1u;

    const gpg::RType* const keyType = ResolveDListIPathTravelerType();
    const gpg::RType* const valueType = ResolveDListVoidType();
    const char* const keyName = keyType != nullptr ? keyType->GetName() : "IPathTraveler";
    const char* const valueName = valueType != nullptr ? valueType->GetName() : "void";

    gDListIPathTravelerTypeName = gpg::STR_Printf("DList<%s,%s>", keyName, valueName);
    (void)std::atexit(&cleanup_RDListType_IPathTraveler_Name);
  }

  return gDListIPathTravelerTypeName.c_str();
}

/**
 * Address: 0x00766FB0 (FUN_00766FB0, gpg::RDListType_IPathTraveler::GetLexical)
 *
 * What it does:
 * Returns inherited lexical text for the reflected DList lane.
 */
msvc8::string gpg::RDListType_IPathTraveler::GetLexical(const gpg::RRef& ref) const
{
  const msvc8::string base = gpg::RType::GetLexical(ref);
  return gpg::STR_Printf("%s", base.c_str());
}

/**
 * Address: 0x00766F90 (FUN_00766F90, gpg::RDListType_IPathTraveler::Init)
 *
 * What it does:
 * Initializes reflected size/version lanes and serializer callbacks for one
 * `DList<IPathTraveler,void>` payload.
 */
void gpg::RDListType_IPathTraveler::Init()
{
  size_ = sizeof(PathTravelerListNode);
  version_ = 1;
  serLoadFunc_ = &RDListType_IPathTraveler::SerLoad;
  serSaveFunc_ = &RDListType_IPathTraveler::SerSave;
}

/**
 * Address: 0x00767500 (FUN_00767500, gpg::RDListType_IPathTraveler::SerLoad)
 *
 * What it does:
 * Reads unowned `IPathTraveler` pointers until null and links each traveler
 * node into the destination intrusive list.
 */
void gpg::RDListType_IPathTraveler::SerLoad(
  gpg::ReadArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const listHead = PointerFromArchiveInt<PathTravelerListNode>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(listHead != nullptr);
  if (!archive || !listHead) {
    return;
  }

  moho::IPathTraveler* traveler = nullptr;
  archive->ReadPointer_IPathTraveler(&traveler, ownerRef);
  while (traveler != nullptr) {
    auto* const travelerNode = &traveler->mPathQueueNode;
    travelerNode->ListLinkAfter(listHead);

    traveler = nullptr;
    archive->ReadPointer_IPathTraveler(&traveler, ownerRef);
  }
}

/**
 * Address: 0x00767480 (FUN_00767480, gpg::RDListType_IPathTraveler::SerSave)
 *
 * What it does:
 * Walks one intrusive `DList<IPathTraveler,void>` lane from head `mNext` to
 * sentinel, writes each traveler as an unowned raw pointer, then writes one
 * trailing null pointer sentinel.
 */
void gpg::RDListType_IPathTraveler::SerSave(
  gpg::WriteArchive* const archive,
  const int objectPtr,
  const int,
  gpg::RRef* const ownerRef
)
{
  auto* const listHead = PointerFromArchiveInt<PathTravelerListNode>(objectPtr);
  if (archive == nullptr || listHead == nullptr) {
    return;
  }

  const gpg::RRef owner = ownerRef != nullptr ? *ownerRef : gpg::RRef{};

  for (auto* node = listHead->mNext; node != listHead; node = node->mNext) {
    auto* const traveler = reinterpret_cast<moho::IPathTraveler*>(
      reinterpret_cast<std::uint8_t*>(node) - offsetof(moho::IPathTraveler, mPathQueueNode)
    );
    gpg::RRef travelerRef{};
    (void)gpg::RRef_IPathTraveler(&travelerRef, traveler);
    gpg::WriteRawPointer(archive, travelerRef, gpg::TrackedPointerState::Unowned, owner);
  }

  gpg::RRef nullTravelerRef{};
  (void)gpg::RRef_IPathTraveler(&nullTravelerRef, nullptr);
  gpg::WriteRawPointer(archive, nullTravelerRef, gpg::TrackedPointerState::Unowned, owner);
}

/**
 * Address: 0x00769190 (FUN_00769190, preregister_RDListType_IPathTraveler)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for
 * `gpg::DList<moho::IPathTraveler,void>`.
 */
[[nodiscard]] gpg::RType* preregister_RDListType_IPathTraveler()
{
  static gpg::RDListType_IPathTraveler typeInfo;
  gpg::PreRegisterRType(typeid(gpg::DList<moho::IPathTraveler, void>), &typeInfo);
  return &typeInfo;
}

/**
 * Address: 0x0076D560 (FUN_0076D560, preregister_IPathTravelerTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `moho::IPathTraveler`.
 */
[[nodiscard]] gpg::RType* preregister_IPathTravelerTypeInfo()
{
  static moho::IPathTravelerTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(moho::IPathTraveler), &typeInfo);
  return &typeInfo;
}

namespace moho
{
  /**
   * Address: 0x0076D5F0 (FUN_0076D5F0, Moho::IPathTravelerTypeInfo::dtr)
   */
  IPathTravelerTypeInfo::~IPathTravelerTypeInfo() = default;

  /**
   * Address: 0x0076D5E0 (FUN_0076D5E0, Moho::IPathTravelerTypeInfo::GetName)
   */
  const char* IPathTravelerTypeInfo::GetName() const
  {
    return "IPathTraveler";
  }

  /**
   * Address: 0x0076D5C0 (FUN_0076D5C0, Moho::IPathTravelerTypeInfo::Init)
   *
   * IDA signature:
   * void __thiscall Moho::IPathTravelerTypeInfo::Init(gpg::RType *this);
   */
  void IPathTravelerTypeInfo::Init()
  {
    size_ = sizeof(IPathTraveler);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
