#pragma once
#include <cassert>
#include <cstdint>

namespace moho
{
#pragma pack(push, 4)
  struct Set
  {
    // +0  (a2+232 earlier): absolute base word index (integer_base >> 5)
    int32_t baseWordIndex;

    // +4  (a2+236): unknown meta; not touched in shown code
    int32_t meta;

    // +8  (a2+240): begin of words window
    uint32_t *items_begin;

    // +12 (a2+244): end (one past) of used words
    uint32_t *items_end;

    // +16 (a2+248): capacity end (one past)
    uint32_t *items_capacity_end;

    // +20 (a2+252): allocator / owner cookie (unknown)
    void *alloc_or_cookie;

    // +24 (a2+256): inline short-set storage (SSO) for one 32-bit word
    uint32_t sso_word;

    // +28 (a2+260): owner/pad (unknown)
    void *owner_or_pad;

    [[nodiscard]] bool IsSso() const noexcept
    {
      return items_begin == const_cast<uint32_t *>(&sso_word) && items_capacity_end == items_begin + 1;
    }

    [[nodiscard]] uint32_t UsedWords() const noexcept
    {
      return static_cast<uint32_t>(items_end - items_begin);
    }

    [[nodiscard]] uint32_t EndIndexAbs() const noexcept
    {
      return 32u * (static_cast<uint32_t>(baseWordIndex) + UsedWords());
    }

    [[nodiscard]] bool Contains(const uint32_t id) const noexcept
    {
      const unsigned rel = (id >> 5) - static_cast<unsigned>(baseWordIndex);
      const unsigned words = UsedWords();
      if (rel >= words)
        return false;
      const uint32_t w = items_begin[rel];
      return ((w >> (id & 31)) & 1u) != 0;
    }

    // add/remove mirror the hot paths; reallocation is engine-specific
    void Add(const uint32_t id)
    {
      const int relSigned = static_cast<int>(id >> 5) - baseWordIndex;
      assert(relSigned >= 0 && "grow-left not implemented in this view");
      uint32_t *wp = items_begin + relSigned;
      if (wp >= items_end)
        items_end = wp + 1;
      assert(items_end <= items_capacity_end && "realloc required");
      *wp |= (1u << (id & 31));
    }

    void Remove(const uint32_t id) const
    {
      const int relSigned = static_cast<int>(id >> 5) - baseWordIndex;
      if (relSigned < 0 || static_cast<unsigned>(relSigned) >= UsedWords())
        return;
      items_begin[relSigned] &= ~(1u << (id & 31));
    }
  };
#pragma pack(pop)

  static_assert(sizeof(Set) == 0x20, "moho::Set must be 32 bytes on x86");
} // namespace moho
