// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "legacy/containers/String.h"

namespace gpg { class REnumType; class RIndexed; class RRef; class RType; } // forward decl

namespace moho {
  /**
   * VFTABLE: 0x00E1CA28
   * COL:  0x00E72C2C
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  class CAiPersonalityTypeInfo
  {
  public:
    /**
     * Address: 0x00401370
     * Slot: 0
     * Demangled: public: virtual class gpg::RType near * __thiscall gpg::RType::GetClass(void)const
     */
    virtual gpg::RType * GetClass() const = 0;

    /**
     * Address: 0x00401390
     * Slot: 1
     * Demangled: public: virtual class gpg::RRef __thiscall gpg::RType::GetDerivedObjectRef(void)
     */
    virtual gpg::RRef GetDerivedObjectRef() = 0;

    /**
     * Address: 0x005B68A0
     * Slot: 2
     * Demangled: sub_5B68A0
     */
    virtual void sub_5B68A0() = 0;

    /**
     * Address: 0x005B6890
     * Slot: 3
     * Demangled: Moho::CAiPersonalityTypeInfo::GetName
     */
    virtual void GetName() = 0;

    /**
     * Address: 0x008DB100
     * Slot: 4
     * Demangled: public: virtual class std::basic_string<char,struct std::char_traits<char>,class std::allocator<char>> __thiscall gpg::RType::GetLexical(class gpg::RRef const near &)const
     */
    virtual msvc8::string GetLexical(gpg::RRef const &) const = 0;

    /**
     * Address: 0x008D86E0
     * Slot: 5
     * Demangled: public: virtual bool __thiscall gpg::RType::SetLexical(class gpg::RRef const near &,char const near *)const
     */
    virtual bool SetLexical(gpg::RRef const &, char const *) const = 0;

    /**
     * Address: 0x004013B0
     * Slot: 6
     * Demangled: public: virtual struct gpg::RIndexed const near * __thiscall gpg::RType::IsIndexed(void)const
     */
    virtual gpg::RIndexed const * IsIndexed() const = 0;

    /**
     * Address: 0x004013C0
     * Slot: 7
     * Demangled: public: virtual struct gpg::RIndexed const near * __thiscall gpg::RType::IsPointer(void)const
     */
    virtual gpg::RIndexed const * IsPointer() const = 0;

    /**
     * Address: 0x004013D0
     * Slot: 8
     * Demangled: public: virtual class gpg::REnumType const near * __thiscall gpg::RType::IsEnumType(void)const
     */
    virtual gpg::REnumType const * IsEnumType() const = 0;

    /**
     * Address: 0x005B6870
     * Slot: 9
     * Demangled: Moho::CAiPersonalityTypeInfo::Init
     */
    virtual void Init() = 0;

    /**
     * Address: 0x008DF4A0
     * Slot: 10
     * Demangled: protected: virtual void __thiscall gpg::RType::Finish(void)
     */
    virtual void Finish() = 0;
  };
} // namespace moho
