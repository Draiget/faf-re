#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Entity;

  struct WeakPtr_Entity
  {
    /**
      * Alias of FUN_0067CD30 (non-canonical helper lane).
     *
     * What it does:
     * Deserializes one `WeakPtr<Entity>` payload from tracked pointer lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
      * Alias of FUN_0067CD60 (non-canonical helper lane).
     *
     * What it does:
     * Serializes one `WeakPtr<Entity>` payload as an unowned tracked pointer.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);
  };

  template <class T>
  class RWeakPtrType;

  template <>
  class RWeakPtrType<Entity> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0067BDF0 (FUN_0067BDF0, Moho::RWeakPtrType_Entity::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0067BEB0 (FUN_0067BEB0, Moho::RWeakPtrType_Entity::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0067C040 (FUN_0067C040, Moho::RWeakPtrType_Entity::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0067C050 (FUN_0067C050, Moho::RWeakPtrType_Entity::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x0067BE90 (FUN_0067BE90, Moho::RWeakPtrType_Entity::Init)
     */
    void Init() override;

    /**
     * Address: 0x0067C090 (FUN_0067C090, Moho::RWeakPtrType_Entity::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0067C060 (FUN_0067C060, Moho::RWeakPtrType_Entity::GetCount)
     */
    size_t GetCount(void* obj) const override;
  };

  static_assert(sizeof(RWeakPtrType<Entity>) == 0x68, "RWeakPtrType<Entity> size must be 0x68");
}

namespace gpg
{
  template <class T>
  class RFastVectorType;

  template <class T>
  class RVectorType;

  template <>
  class RVectorType<moho::Entity*> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0067C0F0 (FUN_0067C0F0, gpg::RVectorType_Entity_P::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0067C190 (FUN_0067C190, gpg::RVectorType_Entity_P::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0067C220 (FUN_0067C220, gpg::RVectorType_Entity_P::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0067C170 (FUN_0067C170, gpg::RVectorType_Entity_P::Init)
     */
    void Init() override;

    /**
     * Address: 0x0067C260 (FUN_0067C260, gpg::RVectorType_Entity_P::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0067C230 (FUN_0067C230, gpg::RVectorType_Entity_P::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0067C250 (FUN_0067C250, gpg::RVectorType_Entity_P::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType<moho::Entity*>) == 0x68, "RVectorType<Entity*> size must be 0x68");

  /**
   * Address owner: 0x00694380 (FUN_00694380)
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<moho::Entity*>`.
   */
  template <>
  class RFastVectorType<moho::Entity*> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00693C00 (FUN_00693C00, gpg::RFastVectorType_EntityP::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
      * Alias of FUN_00694380 (non-canonical helper lane).
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
      * Alias of FUN_00694380 (non-canonical helper lane).
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
      * Alias of FUN_00694380 (non-canonical helper lane).
     */
    void Init() override;

    /**
      * Alias of FUN_00694380 (non-canonical helper lane).
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
      * Alias of FUN_00694380 (non-canonical helper lane).
     */
    size_t GetCount(void* obj) const override;

    /**
      * Alias of FUN_00694380 (non-canonical helper lane).
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<moho::Entity*>) == 0x68, "RFastVectorType<Entity*> size must be 0x68");
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x0067FF00 (FUN_0067FF00, register_WeakPtr_Entity_Type_00)
   *
   * What it does:
   * Constructs and preregisters RTTI for `WeakPtr<Entity>`.
   */
  [[nodiscard]] gpg::RType* register_WeakPtr_Entity_Type_00();

  /**
   * Address: 0x00BFC9F0 (FUN_00BFC9F0, cleanup_WeakPtr_Entity_Type)
   *
   * What it does:
   * Tears down startup-owned `WeakPtr<Entity>` reflection storage.
   */
  void cleanup_WeakPtr_Entity_Type();

  /**
   * Address: 0x00BD5090 (FUN_00BD5090, register_WeakPtr_Entity_Type_AtExit)
   *
   * What it does:
   * Registers `WeakPtr<Entity>` reflection and installs process-exit cleanup.
   */
  int register_WeakPtr_Entity_Type_AtExit();

  /**
   * Address: 0x0067FF70 (FUN_0067FF70, register_VectorEntityPtr_Type_00)
   *
   * What it does:
   * Constructs and preregisters RTTI for `vector<Entity*>`.
   */
  [[nodiscard]] gpg::RType* register_VectorEntityPtr_Type_00();

  /**
   * Address: 0x00BFC990 (FUN_00BFC990, cleanup_VectorEntityPtr_Type)
   *
   * What it does:
   * Tears down startup-owned `vector<Entity*>` reflection storage.
   */
  void cleanup_VectorEntityPtr_Type();

  /**
   * Address: 0x00BD50B0 (FUN_00BD50B0, register_VectorEntityPtr_Type_AtExit)
   *
   * What it does:
   * Registers `vector<Entity*>` reflection and installs process-exit cleanup.
   */
  int register_VectorEntityPtr_Type_AtExit();

  /**
    * Alias of FUN_00694380 (non-canonical helper lane).
   *
   * What it does:
   * Constructs and preregisters RTTI for `fastvector<Entity*>`.
   */
  [[nodiscard]] gpg::RType* register_FastVectorEntityPtrType_00();

  /**
    * Alias of FUN_00BFCEA0 (non-canonical helper lane).
   *
   * What it does:
   * Tears down startup-owned `fastvector<Entity*>` reflection storage.
   */
  void cleanup_FastVectorEntityPtrType();

  /**
   * Address: 0x00BD5890 (FUN_00BD5890, register_FastVectorEntityPtrType_AtExit)
   *
   * What it does:
   * Registers `fastvector<Entity*>` reflection and installs process-exit cleanup.
   */
  int register_FastVectorEntityPtrType_AtExit();
} // namespace moho
