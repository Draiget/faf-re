#pragma once

#include <typeinfo>

#include "boost/shared_ptr.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  namespace detail
  {
    inline constexpr char kReflectSharedPtrHeaderPath[] =
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/reflect_shared_ptr.h";
  }

  /**
   * Reflection for `boost::shared_ptr<T>`: the class template behind every
   * `gpg::RSharedPointerType<T>` in the binary (`.?AU?$RSharedPointerType@...@gpg@@`,
   * a struct over `RType`/`RObject` with an `RIndexed` base at +0x64). The
   * 11-slot primary vtable overrides the destructor, `GetName`, `GetLexical`,
   * `IsIndexed`, `IsPointer` and `Init`; the 4-slot `RIndexed` one overrides
   * `SubscriptIndex` and `GetCount` and keeps the base `SetCount` and
   * `AssignPointer`. `Init` sets only the size: a shared pointer is loaded and
   * saved through the archive's pointer table (`ReadPointerShared`,
   * `WritePointer`), never through this type.
   *
   * Constructing one preregisters it for `typeid(boost::shared_ptr<T>)`.
   *
   * `RSharedPointerType<moho::CAniPose>`, vtables 0x00E188A0 / 0x00E188D0, the
   * object at 0x01104D30:
   *
   * Address: 0x0055EB50 (FUN_0055EB50 -- the implicit scalar deleting destructor.)
   * Address: 0x0055CE20 (FUN_0055CE20 -- `GetName`.)
   * Address: 0x00BF54E0 (FUN_00BF54E0 -- the atexit destructor of that name string.)
   * Address: 0x0055CED0 (FUN_0055CED0 -- `GetLexical`.)
   * Address: 0x0055D050 (FUN_0055D050 -- `IsIndexed`.)
   * Address: 0x0055D060 (FUN_0055D060 -- `IsPointer`.)
   * Address: 0x0055CEC0 (FUN_0055CEC0 -- `Init`.)
   * Address: 0x0055D080 (FUN_0055D080 -- `SubscriptIndex`.)
   * Address: 0x0055D070 (FUN_0055D070 -- `GetCount`.)
   *
   * `RSharedPointerType<moho::STrigger>`, vtables 0x00E31134 / 0x00E31164:
   *
   * Address: 0x00713190 (FUN_00713190 -- the implicit scalar deleting destructor.)
   * Address: 0x0070EA60 (FUN_0070EA60 -- `GetName`.)
   * Address: 0x00BFF940 (FUN_00BFF940 -- the atexit destructor of that name string.)
   * Address: 0x0070EB10 (FUN_0070EB10 -- `GetLexical`.)
   * Address: 0x0070EC90 (FUN_0070EC90 -- `IsIndexed`.)
   * Address: 0x0070ECA0 (FUN_0070ECA0 -- `IsPointer`.)
   * Address: 0x0070EB00 (FUN_0070EB00 -- `Init`.)
   * Address: 0x0070ECC0 (FUN_0070ECC0 -- `SubscriptIndex`.)
   * Address: 0x0070ECB0 (FUN_0070ECB0 -- `GetCount`.)
   */
  template <class T>
  struct RSharedPointerType : RType, RIndexed
  {
    using pointer_type = boost::shared_ptr<T>;

    RSharedPointerType()
    {
      PreRegisterRType(typeid(pointer_type), this);
    }

    /**
     * What it does:
     * `boost::shared_ptr<` + the pointee type's name + `>`, formatted once.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName = STR_Printf("boost::shared_ptr<%s>", RTypeOf<T>()->GetName());
      return sName.c_str();
    }

    /**
     * What it does:
     * `NULL` for an empty pointer, otherwise the pointee's lexical text in
     * brackets.
     */
    [[nodiscard]] msvc8::string GetLexical(const RRef& ref) const override
    {
      const pointer_type& pointer = *static_cast<const pointer_type*>(ref.mObj);
      if (!pointer) {
        return msvc8::string("NULL");
      }
      const msvc8::string pointee = RTypeOf<T>()->GetLexical(MakeRRef(pointer.get()));
      return STR_Printf("[%s]", pointee.c_str());
    }

    [[nodiscard]] const RIndexed* IsIndexed() const override
    {
      return this;
    }

    [[nodiscard]] const RIndexed* IsPointer() const override
    {
      return this;
    }

    void Init() override
    {
      size_ = sizeof(pointer_type);
    }

    /**
     * What it does:
     * The pointee as element 0; any other index trips the assert.
     */
    [[nodiscard]] RRef SubscriptIndex(void* const obj, const int ind) const override
    {
      if (ind != 0) {
        HandleAssertFailure("index == 0", 65, detail::kReflectSharedPtrHeaderPath);
      }
      return MakeRRef(static_cast<pointer_type*>(obj)->get());
    }

    /**
     * What it does:
     * One element while the pointer is set.
     */
    [[nodiscard]] size_t GetCount(void* const obj) const override
    {
      return static_cast<pointer_type*>(obj)->get() != nullptr ? 1u : 0u;
    }
  };
} // namespace gpg
