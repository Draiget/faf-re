#pragma once

#include <cstdint>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
  /**
   * Reflection for `msvc8::list<T>`: the class template behind every
   * `gpg::RListType<T>` in the binary (`.?AU?$RListType@...@gpg@@`, a struct
   * over `RType`/`RObject` whose 11-slot vtable overrides the destructor,
   * `GetName`, `GetLexical` and `Init`).
   *
   * Constructing one preregisters it for `typeid(msvc8::list<T>)`; the startup
   * function that builds each instance is this constructor inlined
   * (`preregister_SNamedFootprintListTypeInfo` 0x005149D0: `RType::RType`
   * 0x008DD950, the vptr store, `PreRegisterRType` 0x008DF850).
   *
   * `RListType<moho::SNamedFootprint>`, vtable 0x00E0F770:
   *
   * Address: 0x00514AB0 (FUN_00514AB0 -- the implicit scalar deleting destructor: `RType`'s field and base
   * vectors freed, the `RObject` vptr restored, then `operator delete` when asked.)
   * Address: 0x00513FB0 (FUN_00513FB0 -- `GetName`; its name string is guarded by bit 1 of 0x010C8EC0.)
   * Address: 0x00BF28E0 (FUN_00BF28E0 -- the atexit destructor of that name string.)
   * Address: 0x00514070 (FUN_00514070 -- `GetLexical`.)
   * Address: 0x00514050 (FUN_00514050 -- `Init`.)
   * Address: 0x00514110 (FUN_00514110 -- `SerLoad`; the list's `clear` is 0x00514340, `_Buynode` 0x005144A0
   * and `_Incsize` 0x00514530.)
   * Address: 0x00514240 (FUN_00514240 -- `SerSave`.)
   */
  template <class T>
  struct RListType : RType
  {
    using list_type = msvc8::list<T>;

    RListType()
    {
      PreRegisterRType(typeid(list_type), this);
    }

    /**
     * What it does:
     * `list<` + the element type's name + `>`, formatted once.
     */
    [[nodiscard]] const char* GetName() const override
    {
      static const msvc8::string sName = STR_Printf("list<%s>", RTypeOf<T>()->GetName());
      return sName.c_str();
    }

    /**
     * What it does:
     * The inherited lexical text followed by the list's size. The binary reads
     * `_Mysize` straight off `ref.mObj` with no null test.
     */
    [[nodiscard]] msvc8::string GetLexical(const RRef& ref) const override
    {
      const msvc8::string base = RType::GetLexical(ref);
      return STR_Printf("%s, size=%d", base.c_str(), static_cast<int>(static_cast<const list_type*>(ref.mObj)->size()));
    }

    /**
     * What it does:
     * A 0x0C list header at version 1, loaded and saved by `SerLoad`/`SerSave`.
     */
    void Init() override
    {
      size_ = sizeof(list_type);
      version_ = 1;
      serLoadFunc_ = &SerLoad;
      serSaveFunc_ = &SerSave;
    }

    /**
     * What it does:
     * Reads the element count, clears the list, then for each element reads a
     * default-constructed `T` through its reflected type and appends a copy.
     */
    static void SerLoad(ReadArchive* const archive, const int objectPtr, const int, RRef* const ownerRef)
    {
      list_type& list = *reinterpret_cast<list_type*>(static_cast<std::uintptr_t>(objectPtr));

      unsigned int count = 0;
      archive->ReadUInt(&count);
      list.clear();
      for (unsigned int i = 0; i < count; ++i) {
        T value;
        archive->Read(RTypeOf<T>(), &value, *ownerRef);
        list.push_back(value);
      }
    }

    /**
     * What it does:
     * Writes the element count, then each element through its reflected type.
     */
    static void SerSave(WriteArchive* const archive, const int objectPtr, const int, RRef* const ownerRef)
    {
      const list_type& list = *reinterpret_cast<const list_type*>(static_cast<std::uintptr_t>(objectPtr));

      archive->WriteUInt(static_cast<unsigned int>(list.size()));
      for (const T& value : list) {
        archive->Write(RTypeOf<T>(), &value, *ownerRef);
      }
    }
  };
} // namespace gpg
