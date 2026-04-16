#include "moho/effects/rendering/SEfxCurve.h"

#include <cstddef>
#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/math/MathReflection.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <>
  class RFastVectorType<moho::SEfxCurve> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0065EEC0 (FUN_0065EEC0, gpg::RFastVectorType_SEfxCurve::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0065EF80 (FUN_0065EF80, gpg::RFastVectorType_SEfxCurve::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0065F010 (FUN_0065F010, gpg::RFastVectorType_SEfxCurve::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0065EF60 (FUN_0065EF60, gpg::RFastVectorType_SEfxCurve::Init)
     */
    void Init() override;

    /**
     * Address: 0x0065F0C0 (FUN_0065F0C0, gpg::RFastVectorType_SEfxCurve::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0065F020 (FUN_0065F020, gpg::RFastVectorType_SEfxCurve::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0065F040 (FUN_0065F040, gpg::RFastVectorType_SEfxCurve::SetCount)
     */
    void SetCount(void* obj, int count) const override;

    /**
     * Address: 0x0065FC70 (FUN_0065FC70, gpg::RFastVectorType_SEfxCurve::dtr)
     */
    ~RFastVectorType() override;

  private:
    /**
     * Address: 0x0065F450 (FUN_0065F450, gpg::RFastVectorType_SEfxCurve::SerLoad)
     */
    static void SerLoad(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0065F540 (FUN_0065F540, gpg::RFastVectorType_SEfxCurve::SerSave)
     */
    static void SerSave(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  static_assert(sizeof(RFastVectorType<moho::SEfxCurve>) == 0x68, "RFastVectorType<SEfxCurve> size must be 0x68");
} // namespace gpg

namespace
{
  using FastVectorSEfxCurveType = gpg::RFastVectorType<moho::SEfxCurve>;

  alignas(FastVectorSEfxCurveType) unsigned char gFastVectorSEfxCurveTypeStorage[sizeof(FastVectorSEfxCurveType)]{};
  bool gFastVectorSEfxCurveTypeConstructed = false;
  msvc8::string gFastVectorSEfxCurveTypeName;
  bool gFastVectorSEfxCurveTypeNameCleanupRegistered = false;

  [[nodiscard]] FastVectorSEfxCurveType* AcquireFastVectorSEfxCurveType()
  {
    if (!gFastVectorSEfxCurveTypeConstructed) {
      new (gFastVectorSEfxCurveTypeStorage) FastVectorSEfxCurveType();
      gFastVectorSEfxCurveTypeConstructed = true;
    }
    return reinterpret_cast<FastVectorSEfxCurveType*>(gFastVectorSEfxCurveTypeStorage);
  }

  [[nodiscard]] gpg::RType* CachedSEfxCurveType()
  {
    return moho::SEfxCurve::StaticGetClass();
  }

  void cleanup_FastVectorSEfxCurveTypeName()
  {
    gFastVectorSEfxCurveTypeName = msvc8::string{};
    gFastVectorSEfxCurveTypeNameCleanupRegistered = false;
  }
} // namespace

namespace gpg
{
  /**
   * Address: 0x0065F450 (FUN_0065F450, gpg::RFastVectorType_SEfxCurve::SerLoad)
   *
   * What it does:
   * Reads vector length, resizes payload storage with default `SEfxCurve`
   * fill, then deserializes each element with the archived owner reference.
   */
  void RFastVectorType<moho::SEfxCurve>::SerLoad(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const ownerRef
  )
  {
    auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(reinterpret_cast<void*>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    moho::SEfxCurve fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, count, view);

    for (unsigned int i = 0; i < count; ++i) {
      gpg::RType* elementType = CachedSEfxCurveType();
      archive->Read(elementType, &view.begin[i], *ownerRef);
    }
  }

  /**
   * Address: 0x0065F540 (FUN_0065F540, gpg::RFastVectorType_SEfxCurve::SerSave)
   *
   * What it does:
   * Writes current vector length, then serializes each `SEfxCurve` element.
   */
  void RFastVectorType<moho::SEfxCurve>::SerSave(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const ownerRef
  )
  {
    const auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(reinterpret_cast<const void*>(objectPtr));
    const unsigned int count = static_cast<unsigned int>(view.end - view.begin);
    archive->WriteUInt(count);

    for (unsigned int i = 0; i < count; ++i) {
      gpg::RType* elementType = CachedSEfxCurveType();
      archive->Write(elementType, &view.begin[i], *ownerRef);
    }
  }

  /**
   * Address: 0x0065EEC0 (FUN_0065EEC0, gpg::RFastVectorType_SEfxCurve::GetName)
   *
   * What it does:
   * Lazily builds and caches the reflected `fastvector<SEfxCurve>` name and
   * registers process-exit cleanup for the cached string storage.
   */
  const char* RFastVectorType<moho::SEfxCurve>::GetName() const
  {
    if (gFastVectorSEfxCurveTypeName.empty()) {
      const gpg::RType* const elementType = CachedSEfxCurveType();
      const char* const elementName = elementType ? elementType->GetName() : "SEfxCurve";
      gFastVectorSEfxCurveTypeName = gpg::STR_Printf("fastvector<%s>", elementName ? elementName : "SEfxCurve");
      if (!gFastVectorSEfxCurveTypeNameCleanupRegistered) {
        gFastVectorSEfxCurveTypeNameCleanupRegistered = true;
        (void)std::atexit(&cleanup_FastVectorSEfxCurveTypeName);
      }
    }

    return gFastVectorSEfxCurveTypeName.c_str();
  }

  /**
   * Address: 0x0065EF80 (FUN_0065EF80, gpg::RFastVectorType_SEfxCurve::GetLexical)
   *
   * What it does:
   * Appends `size=<count>` to the base reflection lexical dump string.
   */
  msvc8::string RFastVectorType<moho::SEfxCurve>::GetLexical(const gpg::RRef& ref) const
  {
    const msvc8::string base = gpg::RType::GetLexical(ref);
    return gpg::STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(GetCount(ref.mObj)));
  }

  /**
   * Address: 0x0065F010 (FUN_0065F010, gpg::RFastVectorType_SEfxCurve::IsIndexed)
   *
   * What it does:
   * Exposes indexed reflection interface for fastvector element lookup.
   */
  const gpg::RIndexed* RFastVectorType<moho::SEfxCurve>::IsIndexed() const
  {
    return this;
  }

  /**
   * Address: 0x0065EF60 (FUN_0065EF60, gpg::RFastVectorType_SEfxCurve::Init)
   *
   * What it does:
   * Initializes runtime layout/version metadata and archive callbacks.
   */
  void RFastVectorType<moho::SEfxCurve>::Init()
  {
    size_ = 0x10;
    version_ = 1;
    serLoadFunc_ = &RFastVectorType<moho::SEfxCurve>::SerLoad;
    serSaveFunc_ = &RFastVectorType<moho::SEfxCurve>::SerSave;
  }

  /**
   * Address: 0x0065F0C0 (FUN_0065F0C0, gpg::RFastVectorType_SEfxCurve::SubscriptIndex)
   *
   * What it does:
   * Returns reflected element reference for index `ind` in raw vector storage.
   */
  gpg::RRef RFastVectorType<moho::SEfxCurve>::SubscriptIndex(void* obj, const int ind) const
  {
    gpg::RRef out{};
    auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(obj);
    gpg::RRef_SEfxCurve(&out, view.begin + ind);
    return out;
  }

  /**
   * Address: 0x0065F020 (FUN_0065F020, gpg::RFastVectorType_SEfxCurve::GetCount)
   *
   * What it does:
   * Returns number of `SEfxCurve` elements in raw fastvector storage.
   */
  size_t RFastVectorType<moho::SEfxCurve>::GetCount(void* obj) const
  {
    const auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(obj);
    return static_cast<std::size_t>(view.end - view.begin);
  }

  /**
   * Address: 0x0065F040 (FUN_0065F040, gpg::RFastVectorType_SEfxCurve::SetCount)
   *
   * What it does:
   * Resizes raw fastvector storage to `count`, default-constructing fill values.
   */
  void RFastVectorType<moho::SEfxCurve>::SetCount(void* obj, const int count) const
  {
    auto& view = gpg::AsFastVectorRuntimeView<moho::SEfxCurve>(obj);
    moho::SEfxCurve fill{};
    gpg::FastVectorRuntimeResizeFill(&fill, static_cast<unsigned int>(count), view);
  }

  /**
   * Address: 0x0065FC70 (FUN_0065FC70, gpg::RFastVectorType_SEfxCurve::dtr)
   *
   * What it does:
   * Destroys vector/reflection owned buffers through `RType` base teardown.
   */
  RFastVectorType<moho::SEfxCurve>::~RFastVectorType() = default;
} // namespace gpg

namespace moho
{
  namespace
  {
    /**
     * Address: 0x00514FF0 (FUN_00514FF0, SEfxCurve y-bounds recompute lane)
     *
     * What it does:
     * Recomputes Y min/max bounds from the current key vector by scanning
     * every `(x,y,z)` key lane.
     */
    void RecomputeEmitterCurveYBounds(SEfxCurve& curve)
    {
      curve.mBoundsMin.y = std::numeric_limits<float>::infinity();
      curve.mBoundsMax.y = -std::numeric_limits<float>::infinity();

      for (Wm3::Vector3f* key = curve.mKeys.begin(); key != curve.mKeys.end(); ++key) {
        if (curve.mBoundsMin.y > key->y) {
          curve.mBoundsMin.y = key->y;
        }
        if (key->y > curve.mBoundsMax.y) {
          curve.mBoundsMax.y = key->y;
        }
      }
    }
  } // namespace

  SEfxCurve::SEfxCurve(const SEfxCurve& other)
    : mBoundsMin(other.mBoundsMin)
    , mBoundsMax(other.mBoundsMax)
    , mKeys()
  {
    mKeys.ResetFrom(other.mKeys);
  }

  SEfxCurve& SEfxCurve::operator=(const SEfxCurve& other)
  {
    if (this == &other) {
      return *this;
    }

    mBoundsMin = other.mBoundsMin;
    mBoundsMax = other.mBoundsMax;
    mKeys.ResetFrom(other.mKeys);
    return *this;
  }

  /**
   * Address: 0x00514E50 (FUN_00514E50, Moho::SEfxCurve::GetValue)
   *
   * What it does:
   * Evaluates one interpolated curve sample at `interp` and applies per-key
   * random spread (Z lane) through the process-global random helper.
   */
  float SEfxCurve::GetValue(const float interp) const
  {
    const Wm3::Vector3f* const keysBegin = mKeys.begin();
    const Wm3::Vector3f* const keysEnd = mKeys.end();
    if (keysBegin == keysEnd) {
      return 0.0f;
    }

    const auto RandomizedValue = [](const float center, const float spread) {
      const double randomUnit = moho::MathGlobalRandomUnitSafe();
      return static_cast<float>((randomUnit - 0.5) * spread + center);
    };

    const Wm3::Vector3f* key = keysBegin;
    while (key != keysEnd && key->x <= interp) {
      ++key;
    }

    if (key == keysEnd) {
      const Wm3::Vector3f& lastKey = keysEnd[-1];
      return RandomizedValue(lastKey.y, lastKey.z);
    }

    if (key == keysBegin) {
      return RandomizedValue(key->y, key->z);
    }

    const Wm3::Vector3f& currentKey = *key;
    const Wm3::Vector3f& previousKey = key[-1];
    const float interpolation = (interp - previousKey.x) / (currentKey.x - previousKey.x);
    const float yCenter = previousKey.y + (currentKey.y - previousKey.y) * interpolation;
    const float zSpread = previousKey.z + (currentKey.z - previousKey.z) * interpolation;
    return RandomizedValue(yCenter, zSpread);
  }

  /**
   * Address: 0x00515090 (FUN_00515090, rescale_emitter_curve_x_range)
   *
   * What it does:
   * Rescales the curve key X lanes to a new X range, updates stored X bounds,
   * then recomputes Y min/max bounds from all retained keys.
   */
  SEfxCurve* RescaleEmitterCurveXRange(SEfxCurve* const curve, const float minX, const float maxX)
  {
    if (curve == nullptr) {
      return nullptr;
    }

    const float scale = (maxX - minX) / (curve->mBoundsMax.x - curve->mBoundsMin.x);
    for (Wm3::Vector3f* key = curve->mKeys.begin(); key != curve->mKeys.end(); ++key) {
      key->x = key->x * scale;
    }

    curve->mBoundsMax.x = maxX;
    curve->mBoundsMin.x = minX;
    RecomputeEmitterCurveYBounds(*curve);
    return curve;
  }

  /**
   * Address: 0x005151B0 (FUN_005151B0, insert_emitter_curve_key)
   *
   * What it does:
   * Inserts one key into ascending-X order and refreshes Y bounds from all
   * retained keys.
   */
  void InsertEmitterCurveKey(SEfxCurve& curve, const Wm3::Vector3f& key)
  {
    Wm3::Vector3f* insertPosition = curve.mKeys.begin();
    while (insertPosition != curve.mKeys.end() && insertPosition->x <= key.x) {
      ++insertPosition;
    }

    curve.mKeys.InsertAt(insertPosition, &key, &key + 1);
    RecomputeEmitterCurveYBounds(curve);
  }

  /**
   * Address: 0x00515320 (FUN_00515320, make_emitter_curve_from_blueprint)
   *
   * What it does:
   * Clears runtime key storage, imports all blueprint keys in ascending-X
   * order, and assigns default bounds/key when source keys are empty.
   */
  void BuildEmitterCurveFromBlueprint(SEfxCurve& destination, const REmitterBlueprintCurve& source)
  {
    destination.mKeys.ResetStorageToInline();

    if (!source.Keys.Empty()) {
      for (const REmitterCurveKey* key = source.Keys.mBegin; key != source.Keys.mEnd; ++key) {
        InsertEmitterCurveKey(destination, Wm3::Vector3f(key->X, key->Y, key->Z));
      }

      destination.mBoundsMin.x = 0.0f;
      destination.mBoundsMax.x = source.XRange;
      return;
    }

    destination.mBoundsMin.x = 0.0f;
    destination.mBoundsMax.x = 10.0f;
    InsertEmitterCurveKey(destination, Wm3::Vector3f(5.0f, 0.0f, 0.0f));
  }

  gpg::RType* SEfxCurve::sType = nullptr;

  gpg::RType* SEfxCurve::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SEfxCurve));
    }
    return sType;
  }

  /**
   * Address: 0x00514D40 (FUN_00514D40, Moho::SEfxCurveSerializer::Deserialize)
   */
  void SEfxCurve::DeserializeFromArchive(
    gpg::ReadArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const curve = reinterpret_cast<SEfxCurve*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(curve != nullptr);
    if (!archive || !curve) {
      return;
    }

    curve->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00514D50 (FUN_00514D50, Moho::SEfxCurveSerializer::Serialize)
   */
  void SEfxCurve::SerializeToArchive(
    gpg::WriteArchive* const archive, const int objectPtr, const int /*version*/, gpg::RRef* const /*ownerRef*/
  )
  {
    const auto* const curve = reinterpret_cast<const SEfxCurve*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(curve != nullptr);
    if (!archive || !curve) {
      return;
    }

    curve->MemberSerialize(archive);
  }

  /**
   * Address: 0x00516D20 (FUN_00516D20, Moho::SEfxCurve::MemberDeserialize)
   *
   * IDA signature:
   * void __usercall func_ReadArchive_SEfxCurve(Moho::SEfxCurve *a1@<eax>, gpg::ReadArchive *a2@<ebx>);
   */
  void SEfxCurve::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const vector2Type = gpg::LookupRType(typeid(Wm3::Vector2f));
    gpg::RType* const keyVectorType = gpg::LookupRType(typeid(gpg::fastvector<Wm3::Vector3f>));

    archive->Read(vector2Type, &mBoundsMin, nullOwner);
    archive->Read(vector2Type, &mBoundsMax, nullOwner);
    archive->Read(keyVectorType, &mKeys, nullOwner);
  }

  /**
   * Address: 0x00516DD0 (FUN_00516DD0, Moho::SEfxCurve::MemberSerialize)
   *
   * IDA signature:
   * void __usercall Moho::SEfxCurve::MemberSerialize(Moho::SEfxCurve *a1@<eax>, BinaryWriteArchive *a2@<ebx>);
   */
  void SEfxCurve::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const vector2Type = gpg::LookupRType(typeid(Wm3::Vector2f));
    gpg::RType* const keyVectorType = gpg::LookupRType(typeid(gpg::fastvector<Wm3::Vector3f>));

    archive->Write(vector2Type, &mBoundsMin, nullOwner);
    archive->Write(vector2Type, &mBoundsMax, nullOwner);
    archive->Write(keyVectorType, &mKeys, nullOwner);
  }

  /**
   * Address: 0x0065FBA0 (FUN_0065FBA0, preregister_FastVectorSEfxCurveType)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `gpg::fastvector<SEfxCurve>`.
   */
  gpg::RType* preregister_FastVectorSEfxCurveType()
  {
    FastVectorSEfxCurveType* const type = AcquireFastVectorSEfxCurveType();
    gpg::PreRegisterRType(typeid(gpg::fastvector<SEfxCurve>), type);
    return type;
  }

  /**
   * Address: 0x00BFBED0 (FUN_00BFBED0, cleanup_FastVectorSEfxCurveType)
   *
   * What it does:
   * Tears down startup-owned `fastvector<SEfxCurve>` reflection storage.
   */
  void cleanup_FastVectorSEfxCurveType()
  {
    if (!gFastVectorSEfxCurveTypeConstructed) {
      return;
    }

    AcquireFastVectorSEfxCurveType()->~FastVectorSEfxCurveType();
    gFastVectorSEfxCurveTypeConstructed = false;
  }

  /**
   * Address: 0x00BD4430 (FUN_00BD4430, register_FastVectorSEfxCurveTypeAtexit)
   *
   * What it does:
   * Registers `fastvector<SEfxCurve>` reflection and installs process-exit teardown.
   */
  int register_FastVectorSEfxCurveTypeAtexit()
  {
    (void)preregister_FastVectorSEfxCurveType();
    return std::atexit(&cleanup_FastVectorSEfxCurveType);
  }
} // namespace moho

namespace
{
  struct SEfxCurveFastVectorReflectionBootstrap
  {
    SEfxCurveFastVectorReflectionBootstrap()
    {
      (void)moho::register_FastVectorSEfxCurveTypeAtexit();
    }
  };

  [[maybe_unused]] SEfxCurveFastVectorReflectionBootstrap gSEfxCurveFastVectorReflectionBootstrap;
} // namespace
