#include "moho/audio/SAudioRequest.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * Address: 0x007626E0 (FUN_007626E0, preregister_FastVectorSAudioRequestType)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for
   * `gpg::fastvector<moho::SAudioRequest>`.
   */
  gpg::RType* preregister_FastVectorSAudioRequestType();

  /**
   * Address: 0x00C01620 (FUN_00C01620, cleanup_FastVectorSAudioRequestType)
   *
   * What it does:
   * Releases startup-owned `fastvector<SAudioRequest>` reflection storage.
   */
  void cleanup_FastVectorSAudioRequestType();

  /**
   * Address: 0x00BDC5F0 (FUN_00BDC5F0, register_FastVectorSAudioRequestTypeAtexit)
   *
   * What it does:
   * Preregisters `fastvector<SAudioRequest>` RTTI and installs process-exit
   * cleanup via `atexit`.
   */
  int register_FastVectorSAudioRequestTypeAtexit();
} // namespace moho

namespace gpg
{
  template <class T>
  class RFastVectorType;

  /**
   * Address family:
   * - 0x007626E0 (preregister) / 0x00BDC5F0 (register + atexit)
   * - 0x00C01620 (type teardown) / 0x00C015F0 (name teardown)
   * - 0x007619D0 (GetName) / 0x00761A70 (Init) / 0x00761A90 (GetLexical)
   * - 0x00761B20 (IsIndexed) / 0x00761B30 (GetCount) / 0x00761B50 (SetCount)
   * - 0x00761B70 (SubscriptIndex) / 0x00762220 (load) / 0x007622B0 (save)
   * - 0x00762120 (resize-fill) / 0x007627B0 (scalar-deleting dtor)
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<moho::SAudioRequest>` — a
   * value-element FastVector reflection modeled on the reviewed sibling
   * `RFastVectorType<moho::SAniManipBinding>`. `SAudioRequest` is a 28-byte
   * (0x1C) audio request record; the element (de)serialize lanes read/write
   * request values through `moho::SAudioRequest::sType`.
   */
  template <>
  class RFastVectorType<moho::SAudioRequest> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x007619D0 (FUN_007619D0, gpg::RFastVectorType_SAudioRequest::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00761A90 (FUN_00761A90, gpg::RFastVectorType_SAudioRequest::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00761B20 (FUN_00761B20, gpg::RFastVectorType_SAudioRequest::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00761A70 (FUN_00761A70, gpg::RFastVectorType_SAudioRequest::Init)
     */
    void Init() override;

    /**
     * Address: 0x00761B70 (FUN_00761B70, gpg::RFastVectorType_SAudioRequest::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00761B30 (FUN_00761B30, gpg::RFastVectorType_SAudioRequest::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00761B50 (FUN_00761B50, gpg::RFastVectorType_SAudioRequest::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::SAudioRequest>) == 0x68,
    "RFastVectorType<SAudioRequest> size must be 0x68"
  );
  static_assert(sizeof(moho::SAudioRequest) == 0x1C, "SAudioRequest size must be 0x1C");
} // namespace gpg

namespace
{
  using FastVectorSAudioRequestType = gpg::RFastVectorType<moho::SAudioRequest>;

  // Startup-owned reflection descriptor storage (binary global stru_1106BA8).
  alignas(FastVectorSAudioRequestType)
    unsigned char gFastVectorSAudioRequestTypeStorage[sizeof(FastVectorSAudioRequestType)]{};
  bool gFastVectorSAudioRequestTypeConstructed = false;

  // Cached "fastvector<SAudioRequest>" lexical name (binary global stru_10C7FDC).
  msvc8::string gFastVectorSAudioRequestTypeName;
  bool gFastVectorSAudioRequestTypeNameCleanupRegistered = false;

  [[nodiscard]] FastVectorSAudioRequestType* AcquireFastVectorSAudioRequestType()
  {
    if (!gFastVectorSAudioRequestTypeConstructed) {
      new (gFastVectorSAudioRequestTypeStorage) FastVectorSAudioRequestType();
      gFastVectorSAudioRequestTypeConstructed = true;
    }

    return reinterpret_cast<FastVectorSAudioRequestType*>(gFastVectorSAudioRequestTypeStorage);
  }

  [[nodiscard]] FastVectorSAudioRequestType* PeekFastVectorSAudioRequestType() noexcept
  {
    if (!gFastVectorSAudioRequestTypeConstructed) {
      return nullptr;
    }

    return reinterpret_cast<FastVectorSAudioRequestType*>(gFastVectorSAudioRequestTypeStorage);
  }

  // Lazily resolves and caches the element RType* (binary Moho::SAudioRequest::sType).
  [[nodiscard]] gpg::RType* CachedSAudioRequestType()
  {
    if (!moho::SAudioRequest::sType) {
      moho::SAudioRequest::sType = gpg::LookupRType(typeid(moho::SAudioRequest));
    }
    return moho::SAudioRequest::sType;
  }

  /**
   * Address: 0x00C015F0 (FUN_00C015F0, cleanup_FastVectorSAudioRequestTypeName)
   *
   * What it does:
   * Releases cached lexical type-name storage for `fastvector<SAudioRequest>`.
   */
  void cleanup_FastVectorSAudioRequestTypeName()
  {
    gFastVectorSAudioRequestTypeName = msvc8::string{};
    gFastVectorSAudioRequestTypeNameCleanupRegistered = false;
  }

  /**
   * Address: 0x00762120 (FUN_00762120, sub_762120)
   *
   * What it does:
   * Resizes one `fastvector<SAudioRequest>` runtime view to `requestedCount`,
   * filling appended lanes from `fillValue` (growing past capacity reallocates).
   */
  [[maybe_unused]] unsigned int ResizeFastVectorSAudioRequestFill(
    const unsigned int requestedCount,
    const moho::SAudioRequest* const fillValue,
    gpg::fastvector_runtime_view<moho::SAudioRequest>& view
  )
  {
    moho::SAudioRequest* const begin = view.begin;
    const unsigned int currentCount = begin ? static_cast<unsigned int>(view.end - begin) : 0u;
    if (requestedCount < currentCount) {
      moho::SAudioRequest* const newEnd = begin + requestedCount;
      if (newEnd != view.end) {
        view.end = newEnd;
      }
      return currentCount;
    }

    if (requestedCount > currentCount) {
      const unsigned int currentCapacity = begin ? static_cast<unsigned int>(view.capacityEnd - begin) : 0u;
      const moho::SAudioRequest fill = fillValue ? *fillValue : moho::SAudioRequest{};
      if (requestedCount > currentCapacity) {
        gpg::FastVectorRuntimeResizeFill(&fill, requestedCount, view);
        return requestedCount;
      }

      moho::SAudioRequest* const targetEnd = view.begin + requestedCount;
      while (view.end != targetEnd) {
        moho::SAudioRequest* const slot = view.end;
        view.end = slot + 1;
        if (slot) {
          *slot = fill;
        }
      }
    }

    return requestedCount;
  }

  /**
   * Address: 0x00762220 (FUN_00762220, gpg::RFastVectorType_SAudioRequest::SerLoad)
   *
   * What it does:
   * Reads the element count, resizes the destination `fastvector<SAudioRequest>`
   * runtime view, and deserializes each element in place (forwarding the
   * caller's owner reference). Bound as `serLoadFunc_`.
   */
  void LoadFastVectorSAudioRequest(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    unsigned int count = 0;
    archive->ReadUInt(&count);

    auto& view = gpg::AsFastVectorRuntimeView<moho::SAudioRequest>(reinterpret_cast<void*>(objectPtr));
    moho::SAudioRequest fill{};
    ResizeFastVectorSAudioRequestFill(count, &fill, view);

    gpg::RType* const elementType = CachedSAudioRequestType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Read(elementType, &view.begin[i], owner);
    }
  }

  /**
   * Address: 0x007622B0 (FUN_007622B0, gpg::RFastVectorType_SAudioRequest::SerSave)
   *
   * What it does:
   * Writes the element count then serializes each `SAudioRequest` in place
   * (forwarding the caller's owner reference). Bound as `serSaveFunc_`.
   */
  void SaveFastVectorSAudioRequest(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef)
  {
    if (!archive || objectPtr == 0) {
      return;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SAudioRequest>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = view.begin ? static_cast<unsigned int>(view.end - view.begin) : 0u;
    archive->WriteUInt(count);

    gpg::RType* const elementType = CachedSAudioRequestType();
    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, &view.begin[i], owner);
    }
  }

  struct SAudioRequestFastVectorReflectionBootstrap
  {
    SAudioRequestFastVectorReflectionBootstrap()
    {
      (void)moho::register_FastVectorSAudioRequestTypeAtexit();
    }
  };

  [[maybe_unused]] SAudioRequestFastVectorReflectionBootstrap gSAudioRequestFastVectorReflectionBootstrap;
} // namespace

namespace gpg
{
  /**
   * Address: 0x007619D0 (FUN_007619D0, gpg::RFastVectorType_SAudioRequest::GetName)
   *
   * What it does:
   * Builds and caches `"fastvector<SAudioRequest>"` from the element type name,
   * arming a one-shot `atexit` teardown for the cached string.
   */
  const char* RFastVectorType<moho::SAudioRequest>::GetName() const
  {
    if (gFastVectorSAudioRequestTypeName.empty()) {
      const gpg::RType* const elementType = CachedSAudioRequestType();
      const char* const elementName = elementType ? elementType->GetName() : "SAudioRequest";
      gFastVectorSAudioRequestTypeName =
        gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SAudioRequest");
      if (!gFastVectorSAudioRequestTypeNameCleanupRegistered) {
        gFastVectorSAudioRequestTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSAudioRequestTypeName);
      }
    }

    return gFastVectorSAudioRequestTypeName.c_str();
  }

  /**
   * Address: 0x00761A90 (FUN_00761A90, gpg::RFastVectorType_SAudioRequest::GetLexical)
   *
   * What it does:
   * Renders `"<base RType lexical>, size=<count>"`.
   */
  msvc8::string RFastVectorType<moho::SAudioRequest>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x00761B20 (FUN_00761B20, gpg::RFastVectorType_SAudioRequest::IsIndexed)
   *
   * What it does:
   * Returns the `RIndexed` subobject (`this ? this+0x64 : nullptr`).
   */
  const gpg::RIndexed* RFastVectorType<moho::SAudioRequest>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x00761A70 (FUN_00761A70, gpg::RFastVectorType_SAudioRequest::Init)
   *
   * What it does:
   * Records the container byte-size (0x10 = `sizeof(fastvector runtime view)`),
   * version 1, and installs the element (de)serialize callbacks.
   */
  void RFastVectorType<moho::SAudioRequest>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &LoadFastVectorSAudioRequest;
    serSaveFunc_ = &SaveFastVectorSAudioRequest;
  }

  /**
   * Address: 0x00761B70 (FUN_00761B70, gpg::RFastVectorType_SAudioRequest::SubscriptIndex)
   *
   * What it does:
   * Wraps `&vec[ind]` (a `moho::SAudioRequest*` slot inside the FastVector
   * storage) as one `gpg::RRef_SAudioRequest` reference.
   */
  gpg::RRef RFastVectorType<moho::SAudioRequest>::SubscriptIndex(void* const obj, const int ind) const
  {
    gpg::RRef out{};
    gpg::RRef_SAudioRequest(&out, nullptr);
    if (!obj || ind < 0) {
      return out;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SAudioRequest>(obj);
    if (!view.begin || static_cast<std::size_t>(ind) >= GetCount(obj)) {
      return out;
    }

    gpg::RRef_SAudioRequest(&out, view.begin + ind);
    return out;
  }

  /**
   * Address: 0x00761B30 (FUN_00761B30, gpg::RFastVectorType_SAudioRequest::GetCount)
   *
   * What it does:
   * Returns the element count (`(end - begin) / 28`), or 0 when unallocated.
   */
  size_t RFastVectorType<moho::SAudioRequest>::GetCount(void* const obj) const
  {
    if (!obj) {
      return 0u;
    }

    const auto& view = gpg::AsFastVectorRuntimeView<moho::SAudioRequest>(obj);
    if (!view.begin) {
      return 0u;
    }

    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x00761B50 (FUN_00761B50, gpg::RFastVectorType_SAudioRequest::SetCount)
   *
   * What it does:
   * Resizes the underlying `fastvector<SAudioRequest>` storage to `count`,
   * zero-filling any growth.
   */
  void RFastVectorType<moho::SAudioRequest>::SetCount(void* const obj, const int count) const
  {
    if (!obj || count < 0) {
      return;
    }

    auto& view = gpg::AsFastVectorRuntimeView<moho::SAudioRequest>(obj);
    moho::SAudioRequest fill{};
    ResizeFastVectorSAudioRequestFill(static_cast<unsigned int>(count), &fill, view);
  }
} // namespace gpg

namespace moho
{
  gpg::RType* preregister_FastVectorSAudioRequestType()
  {
    FastVectorSAudioRequestType* const typeInfo = AcquireFastVectorSAudioRequestType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<SAudioRequest>), typeInfo);
    return typeInfo;
  }

  void cleanup_FastVectorSAudioRequestType()
  {
    FastVectorSAudioRequestType* const type = PeekFastVectorSAudioRequestType();
    if (type == nullptr) {
      return;
    }

    type->~FastVectorSAudioRequestType();
    gFastVectorSAudioRequestTypeConstructed = false;
  }

  int register_FastVectorSAudioRequestTypeAtexit()
  {
    (void)preregister_FastVectorSAudioRequestType();
    return std::atexit(&cleanup_FastVectorSAudioRequestType);
  }
} // namespace moho
