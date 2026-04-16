#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "Wm3Vector2.h"

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class Entity;

  /**
   * Runtime scroll-configuration payload stored by `CTextureScroller`.
   */
  struct SScroller
  {
    static gpg::RType* sType;

    /**
     * Address: 0x00676B50 (FUN_00676B50, Moho::SScroller::SScroller defaults lane)
     *
     * What it does:
     * Seeds one scroller payload with mode `None`, zero timing/scroll lanes,
     * and unit scale factors for both UV channels.
     */
    void InitializeDefaults() noexcept;

    std::int32_t mType; // +0x00
    float mFloat04;     // +0x04
    float mFloat08;     // +0x08
    float mFloat0C;     // +0x0C
    float mFloat10;     // +0x10
    Wm3::Vector2f mScroll1; // +0x14
    Wm3::Vector2f mScroll2; // +0x1C
    float mFloat24; // +0x24
    float mFloat28; // +0x28
  };

  class CTextureScroller
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00683190 (FUN_00683190)
     *
     * What it does:
     * Returns cached reflected type metadata for `CTextureScroller`,
     * resolving it through RTTI lookup on first use.
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00676BA0 (FUN_00676BA0, ??0CTextureScroller@Moho@@QAE@@Z)
     *
     * Moho::Entity *
     *
     * IDA signature:
     * Moho::CTextureScroller * __usercall
     *   Moho::CTextureScroller::CTextureScroller@<eax>(
     *     Moho::CTextureScroller *this@<eax>, Moho::Entity *owner@<ecx>);
     *
     * What it does:
     * Binds one owning entity pointer and seeds one default "none" scroller
     * payload with zero direction/speed lanes.
     */
    explicit CTextureScroller(Entity* owner);

    /**
     * Address: 0x00777730 (FUN_00777730, Moho::CTextureScroller::Tick)
     *
     * What it does:
     * Advances one texture-scroll lane according to configured mode:
     * ping-pong stepping, manual UV drift, or motion-derived UV projection.
     */
    void Tick();

    /**
     * Address: 0x00778470 (FUN_00778470, Moho::CTextureScroller::MemberDeserialize)
     *
     * What it does:
     * Deserializes owner entity pointer, scroller configuration payload, then
     * reads direction/speed lanes.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00778510 (FUN_00778510, Moho::CTextureScroller::MemberSerialize)
     *
     * What it does:
     * Serializes owner entity pointer, scroller configuration payload, then
     * emits direction/speed lanes.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

  public:
    Entity* mEntity;     // +0x00
    SScroller mScroller; // +0x04
    std::uint8_t mDir[2]; // +0x30
    std::uint8_t mPad32[2];
    std::int32_t mSpeed[2]; // +0x34
  };

  static_assert(offsetof(SScroller, mType) == 0x00, "SScroller::mType offset must be 0x00");
  static_assert(offsetof(SScroller, mFloat04) == 0x04, "SScroller::mFloat04 offset must be 0x04");
  static_assert(offsetof(SScroller, mFloat08) == 0x08, "SScroller::mFloat08 offset must be 0x08");
  static_assert(offsetof(SScroller, mFloat0C) == 0x0C, "SScroller::mFloat0C offset must be 0x0C");
  static_assert(offsetof(SScroller, mFloat10) == 0x10, "SScroller::mFloat10 offset must be 0x10");
  static_assert(offsetof(SScroller, mScroll1) == 0x14, "SScroller::mScroll1 offset must be 0x14");
  static_assert(offsetof(SScroller, mScroll2) == 0x1C, "SScroller::mScroll2 offset must be 0x1C");
  static_assert(offsetof(SScroller, mFloat24) == 0x24, "SScroller::mFloat24 offset must be 0x24");
  static_assert(offsetof(SScroller, mFloat28) == 0x28, "SScroller::mFloat28 offset must be 0x28");
  static_assert(sizeof(SScroller) == 0x2C, "SScroller size must be 0x2C");

  static_assert(offsetof(CTextureScroller, mEntity) == 0x00, "CTextureScroller::mEntity offset must be 0x00");
  static_assert(offsetof(CTextureScroller, mScroller) == 0x04, "CTextureScroller::mScroller offset must be 0x04");
  static_assert(offsetof(CTextureScroller, mDir) == 0x30, "CTextureScroller::mDir offset must be 0x30");
  static_assert(offsetof(CTextureScroller, mSpeed) == 0x34, "CTextureScroller::mSpeed offset must be 0x34");
  static_assert(sizeof(CTextureScroller) == 0x3C, "CTextureScroller size must be 0x3C");
} // namespace moho
