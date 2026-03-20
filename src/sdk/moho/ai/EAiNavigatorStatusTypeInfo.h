// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "legacy/containers/String.h"

namespace gpg
{
  class REnumType;
  class RIndexed;
  class RRef;
  class RType;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x1073B180
   * COL:  0x10782AA4
   * Source hints:
   *  - c:\work\rts\main\code\src\libs\gpgcore\reflection\reflection.cpp
   */
  class EAiNavigatorStatusTypeInfo
  {
  public:
    /**
     * Address: 0x00401370
     * Slot: 0
     * Demangled: gpg::RType::GetClass
     */
    virtual gpg::RType* GetClass() const = 0;

    /**
     * Address: 0x00401390
     * Slot: 1
     * Demangled: gpg::RType::GetDerivedObjectRef
     */
    virtual gpg::RRef GetDerivedObjectRef() = 0;

    /**
     * Address: 0x10192D60
     * Slot: 2
     * Demangled: (likely scalar deleting destructor thunk)
     */
    virtual ~EAiNavigatorStatusTypeInfo() = default;

    /**
     * Address: 0x10192D50
     * Slot: 3
     * Demangled: Moho::EAiNavigatorStatusTypeInfo::GetName
     */
    virtual const char* GetName() const = 0;

    /**
     * Address: 0x104D7E08
     * Slot: 4
     * Demangled: gpg::REnumType::GetLexical
     */
    virtual msvc8::string GetLexical(gpg::RRef const&) const = 0;

    /**
     * Address: 0x104D7E02
     * Slot: 5
     * Demangled: gpg::REnumType::SetLexical
     */
    virtual bool SetLexical(gpg::RRef const&, char const*) const = 0;

    /**
     * Address: 0x004013B0
     * Slot: 6
     * Demangled: gpg::RType::IsIndexed
     */
    virtual gpg::RIndexed const* IsIndexed() const = 0;

    /**
     * Address: 0x004013C0
     * Slot: 7
     * Demangled: gpg::RType::IsPointer
     */
    virtual gpg::RIndexed const* IsPointer() const = 0;

    /**
     * Address: 0x104D7E14
     * Slot: 8
     * Demangled: gpg::REnumType::IsEnumType
     */
    virtual gpg::REnumType const* IsEnumType() const = 0;

    /**
     * Address: 0x10192D30
     * Slot: 9
     * Demangled: Moho::EAiNavigatorStatusTypeInfo::Init
     */
    virtual void Init() = 0;

    /**
     * Address: 0x104D7CE2
     * Slot: 10
     * Demangled: gpg::RType::Finish
     */
    virtual void Finish() = 0;
  };
} // namespace moho
