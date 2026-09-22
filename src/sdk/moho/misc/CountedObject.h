#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * RTTI-only intrusive-counted pointer wrapper.
   *
   * Binary layout contract:
   * - one raw pointee lane at +0x00
   * - static `sType` cache lane for reflected descriptor lookup
   */
  /**
   * Intrusive owning pointer for `CountedObject`-derived payloads.
   *
   * The reference counting is not decoration: `Moho::SParticle::~SParticle`
   * (0x0049BD30) is a compiler-generated member destructor whose entire body is
   * the string teardown at +0x68 followed by, for each of the two counted
   * pointers at +0x60 and +0x5C (reverse declaration order, as an implicit
   * destructor emits),
   *
   *     lock xadd [ptr+4], -1          ; atomic decrement of CountedObject::mRefCount
   *     jnz  skip                      ; only the thread that saw 1 destroys
   *     call [[ptr]](1)                ; vtable slot 0, scalar deleting destructor
   *
   * which is exactly `ReleaseReferenceAtomic`. That destructor exists only
   * because this template has one, so the counting belongs here and `SParticle`
   * declares no destructor of its own.
   *
   * Every instantiation in the tree (`CParticleTexture`, `IFormationInstance`,
   * `CountedObject` itself) derives from `CountedObject`, so the constraints
   * below are satisfied throughout; they remain as the statement of what this
   * template needs from `T`. Note that a slot the binary hands to
   * `RCountedPtrType<T>` is not automatically a `CountedPtr<T>` object --
   * `CUnitCommand`'s two formation slots are bare pointer words with no
   * retain/release around them, and are typed that way.
   */
  template <class T>
  struct CountedPtr
  {
    inline static gpg::RType* sType = nullptr;
    T* tex = nullptr;

    CountedPtr() noexcept = default;

    CountedPtr(const CountedPtr& other) noexcept : tex(other.tex)
    {
      Retain(tex);
    }

    /**
     * Address: 0x0049C1A0 (FUN_0049C1A0 -- `CountedPtr<CParticleTexture>::operator=`
     * as emitted for the beam vector copies (retain the new texture, release the
     * old one). Formerly `CopyCountedParticleTextureLaneRetain` in
     * BeamRenderHelpers.cpp, removed 2026-09-10.)
     * Address: 0x00794E10 (FUN_00794E10 -- `CountedPtr<T>::operator=` reading the source handle through a slot: retain the new object, release the old one; callers `DrawUnitCustomNameLabel` 0x0085E0A0 and `DrawUnitSelectionSetNameLabel` 0x0085E3A0 (CWldSession.cpp); formerly `AssignIntrusiveRefCountedWordFromSlot` in moho/containers/LegacyContainerFillLanes.cpp (RULE ONE), file removed 2026-09-10.)
     * Address: 0x0089E580 (FUN_0089E580 -- the same `CountedPtr<T>::operator=` shape for a second handle type; zero callers, unreachable; formerly `AssignIntrusiveRefCountedWordFromSlot` in moho/containers/LegacyContainerFillLanes.cpp (RULE ONE), file removed 2026-09-10.)
     */
    CountedPtr& operator=(const CountedPtr& other) noexcept
    {
      if (this != &other) {
        T* const previous = tex;
        tex = other.tex;
        Retain(tex);
        Release(previous); // released last, so self-referential aliases survive
      }
      return *this;
    }

    ~CountedPtr()
    {
      Release(tex);
      tex = nullptr;
    }

  private:
    static void Retain(T* const payload) noexcept
    {
      if constexpr (requires(T* p) { p->AddReferenceAtomic(); }) {
        if (payload != nullptr) {
          payload->AddReferenceAtomic();
        }
      }
    }

    static void Release(T* const payload) noexcept
    {
      if constexpr (requires(T* p) { p->ReleaseReferenceAtomic(); }) {
        if (payload != nullptr) {
          (void)payload->ReleaseReferenceAtomic();
        }
      }
    }
  };

  class CountedObject
  {
  public:
    /**
     * Address: 0x004228E0 (FUN_004228E0, scalar deleting destructor thunk)
     * Mangled: ??_GCountedObject@Moho@@UAEPAXI@Z
     *
     * What it does:
     * Resets this object's vtable to `CountedObject` and optionally deletes `this`.
     */
    virtual ~CountedObject();

    /**
     * What it does:
     * Increments intrusive reference count for this object.
     */
    void AddReference() noexcept;

    /**
     * What it does:
     * Atomically increments intrusive reference count.
     */
    void AddReferenceAtomic() noexcept;

    /**
     * What it does:
     * Decrements intrusive reference count and deletes this object when it
     * reaches zero.
     *
     * @return true when this call deleted the object.
     */
    [[nodiscard]] bool ReleaseReference() noexcept;

    /**
     * What it does:
     * Atomically decrements intrusive reference count and deletes this object
     * when it reaches zero.
     *
     * @return true when this call deleted the object.
     */
    [[nodiscard]] bool ReleaseReferenceAtomic() noexcept;

  protected:
    /**
     * Address: 0x004228D0 (FUN_004228D0, sub_4228D0)
     *
     * What it does:
     * Initializes the base counted-object lanes and clears reference count.
     */
    CountedObject() noexcept;

  public:
    // Intrusive reference counter used by `CountedPtr<T>`-style ownership paths.
    std::int32_t mRefCount; // +0x04
  };

  static_assert(offsetof(CountedObject, mRefCount) == 0x04, "CountedObject::mRefCount offset must be 0x04");
  static_assert(sizeof(CountedObject) == 0x08, "CountedObject size must be 0x08");
} // namespace moho
