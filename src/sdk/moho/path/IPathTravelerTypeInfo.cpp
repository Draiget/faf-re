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
#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{
  class RDListType_IPathTraveler : public RType
  {
  public:
    /**
     * Address: 0x00769290 (FUN_00769290, gpg::RDListType_IPathTraveler::dtr)
     */
    ~RDListType_IPathTraveler() override;

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
  using PathTravelerList = gpg::DList<moho::IPathTraveler>;

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
      gDListVoidType = gpg::LookupRType(typeid(void));
    }

    return gDListVoidType;
  }

  [[nodiscard]] gpg::RType* ResolveDListIPathTravelerType()
  {
    if (gDListIPathTravelerType == nullptr) {
      gDListIPathTravelerType = gpg::LookupRType(typeid(moho::IPathTraveler));
    }

    return gDListIPathTravelerType;
  }
} // namespace

gpg::RDListType_IPathTraveler::~RDListType_IPathTraveler() = default;

/**
 * Address: 0x00766ED0 (FUN_00766ED0, gpg::RDListType_IPathTraveler::GetName)
 * Address: 0x00C01B70 (FUN_00C01B70, atexit destructor of GetName's cached name)
 *
 * What it does:
 * Builds `DList<IPathTraveler,void>` once and returns it.
 */
const char* gpg::RDListType_IPathTraveler::GetName() const
{
  static const msvc8::string sName =
    gpg::STR_Printf("DList<%s,%s>", ResolveDListIPathTravelerType()->GetName(), ResolveDListVoidType()->GetName());
  return sName.c_str();
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
  size_ = sizeof(PathTravelerList);
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
  auto* const listHead = PointerFromArchiveInt<PathTravelerList>(objectPtr);
  GPG_ASSERT(archive != nullptr);
  GPG_ASSERT(listHead != nullptr);
  if (!archive || !listHead) {
    return;
  }

  // 0x0076752D: unlink, then link before the head -- a push_back, so the
  // list comes back in the order it was saved. The tree linked after the
  // head, reversing it.
  moho::IPathTraveler* traveler = nullptr;
  archive->ReadPointer(&traveler, ownerRef);
  while (traveler != nullptr) {
    listHead->push_back(traveler);

    traveler = nullptr;
    archive->ReadPointer(&traveler, ownerRef);
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
  auto* const listHead = PointerFromArchiveInt<PathTravelerList>(objectPtr);
  if (archive == nullptr || listHead == nullptr) {
    return;
  }

  const gpg::RRef owner = ownerRef != nullptr ? *ownerRef : gpg::RRef{};

  for (moho::IPathTraveler* const traveler : listHead->owners()) {
    gpg::RRef travelerRef{};
    travelerRef = gpg::MakeRRef<moho::IPathTraveler>(traveler);
    gpg::WriteRawPointer(archive, travelerRef, gpg::TrackedPointerState::Unowned, owner);
  }

  gpg::RRef nullTravelerRef{};
  nullTravelerRef = gpg::MakeRRef<moho::IPathTraveler>(nullptr);
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

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_RDListType_IPathTraveler_4b32d3, preregister_RDListType_IPathTraveler)
GPG_PREREGISTER_INIT(preregister_IPathTravelerTypeInfo_4b32d3, preregister_IPathTravelerTypeInfo)
