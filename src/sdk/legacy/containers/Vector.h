#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <memory>
#include <new>
#include <type_traits>
#include <stdexcept>
#include <vector>

#ifndef MSVC8_VECTOR_DISABLE_FREE
#define MSVC8_VECTOR_DISABLE_FREE 0
#endif

namespace msvc8
{
#ifndef MSVC8_CONTAINER_PROXY_DEFINED
#define MSVC8_CONTAINER_PROXY_DEFINED 1
    struct _Container_proxy
    {
        void* _Myfirstiter;
    };
#endif

    // Base that holds the proxy pointer (debug iterator support footprint)
    struct _Container_base
    {
        _Container_proxy* _Myproxy;

        _Container_base()
            : _Myproxy(0)
        {
        }
    };

    namespace detail
    {
        /**
         * Runtime cursor for legacy vector<bool>-style word/bit iteration.
         *
         * Layout:
         *   +0x00: word pointer
         *   +0x04: bit index inside word [0..31]
         */
        struct vector_bool_word_cursor
        {
            std::uint32_t* word;
            std::uint32_t bit;

            /**
             * Address: 0x004467E0 (FUN_004467E0)
             * Address: 0x004469B0 (FUN_004469B0)
             *
             * What it does:
             * Advances the cursor to the next 32-bit storage word.
             */
            vector_bool_word_cursor& AdvanceWord() noexcept
            {
                word += 1;
                return *this;
            }

            /**
             * Address: 0x004467F0 (FUN_004467F0)
             * Address: 0x004469C0 (FUN_004469C0)
             * Address: 0x00446A40 (FUN_00446A40)
             *
             * What it does:
             * Advances one bit, carrying to the next word when the bit lane reaches 31.
             */
            vector_bool_word_cursor& Increment() noexcept
            {
                if (bit >= 31u) {
                    word += 1;
                    bit = 0u;
                } else {
                    ++bit;
                }
                return *this;
            }

            /**
             * Address: 0x00446810 (FUN_00446810)
             * Address: 0x004469E0 (FUN_004469E0)
             * Address: 0x00446A20 (FUN_00446A20)
             *
             * What it does:
             * Moves one bit backward, borrowing from the previous word when bit lane is 0.
             */
            vector_bool_word_cursor& Decrement() noexcept
            {
                if (bit != 0u) {
                    --bit;
                } else {
                    word -= 1;
                    bit = 31u;
                }
                return *this;
            }
        };

        static_assert(sizeof(vector_bool_word_cursor) == 0x08, "vector_bool_word_cursor size must be 0x08");

        /**
         * Address: 0x00446830 (FUN_00446830)
         *
         * What it does:
         * Returns cursor inequality by comparing both word and bit lanes.
         */
        [[nodiscard]] inline bool CursorNotEqual(
            const vector_bool_word_cursor& lhs,
            const vector_bool_word_cursor& rhs
        ) noexcept
        {
            return lhs.word != rhs.word || lhs.bit != rhs.bit;
        }

        /**
         * Address: 0x00446A00 (FUN_00446A00)
         *
         * What it does:
         * Returns cursor equality by comparing both word and bit lanes.
         */
        [[nodiscard]] inline bool CursorEqual(
            const vector_bool_word_cursor& lhs,
            const vector_bool_word_cursor& rhs
        ) noexcept
        {
            return lhs.word == rhs.word && lhs.bit == rhs.bit;
        }

        /**
         * Address: 0x00443F60 (FUN_00443F60)
         * Address: 0x004440D0 (FUN_004440D0)
         * Address: 0x00444F80 (FUN_00444F80)
         * Address: 0x00445430 (FUN_00445430)
         * Address: 0x00446AB0 (FUN_00446AB0)
         * Address: 0x00446BD0 (FUN_00446BD0)
         * Address: 0x00446C90 (FUN_00446C90)
         * Address: 0x00537ED0 (FUN_00537ED0)
         *
         * What it does:
         * Fills `count` 32-bit words in `destination` using one dereferenced source word.
         */
        template <class WordT>
        [[nodiscard]] inline const WordT* FillWordsFromValuePointer(
            const WordT* const valueWordPtr,
            WordT* const destination,
            const std::size_t count
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "FillWordsFromValuePointer expects 32-bit words");
            if (count != 0u) {
                std::fill_n(destination, count, *valueWordPtr);
            }
            return valueWordPtr;
        }

        /**
         * Address: 0x00446AC0 (FUN_00446AC0)
         * Address: 0x00446C10 (FUN_00446C10)
         * Address: 0x00446CB0 (FUN_00446CB0)
         * Address: 0x00445B50 (FUN_00445B50)
         * Address: 0x00445FA0 (FUN_00445FA0)
         * Address: 0x00446450 (FUN_00446450)
         * Address: 0x00446780 (FUN_00446780)
         * Address: 0x00446DC0 (FUN_00446DC0)
         * Address: 0x00446E00 (FUN_00446E00)
         * Address: 0x00446EC0 (FUN_00446EC0)
         * Address: 0x004C6B40 (FUN_004C6B40)
         * Address: 0x004C6CA0 (FUN_004C6CA0)
         * Address: 0x004C6D10 (FUN_004C6D10)
         *
         * What it does:
         * Repeats one source word into destination for `remainingWords` iterations
         * and returns the final remaining-word count (always zero after completion).
         */
        template <class WordT>
        [[nodiscard]] inline std::size_t CopyValueWordLoop(
            std::size_t remainingWords,
            const WordT* const sourceWordPtr,
            WordT* destination
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "CopyValueWordLoop expects 32-bit words");
            while (remainingWords != 0u) {
                *destination = *sourceWordPtr;
                ++destination;
                --remainingWords;
            }
            return remainingWords;
        }

        /**
         * Address: 0x00446AE0 (FUN_00446AE0)
         * Address: 0x00446B30 (FUN_00446B30)
         * Address: 0x00446B80 (FUN_00446B80)
         * Address: 0x00446BE0 (FUN_00446BE0)
         * Address: 0x00445970 (FUN_00445970)
         * Address: 0x00445B00 (FUN_00445B00)
         * Address: 0x00445BE0 (FUN_00445BE0)
         * Address: 0x00445C20 (FUN_00445C20)
         * Address: 0x00445D50 (FUN_00445D50)
         * Address: 0x00445E10 (FUN_00445E10)
         * Address: 0x00445ED0 (FUN_00445ED0)
         * Address: 0x00445F20 (FUN_00445F20)
         * Address: 0x004464D0 (FUN_004464D0)
         * Address: 0x004465E0 (FUN_004465E0)
         * Address: 0x00446660 (FUN_00446660)
         * Address: 0x004466F0 (FUN_004466F0)
         * Address: 0x00446CD0 (FUN_00446CD0)
         * Address: 0x00446D00 (FUN_00446D00)
         * Address: 0x00446D30 (FUN_00446D30)
         * Address: 0x00446D80 (FUN_00446D80)
         * Address: 0x00446E90 (FUN_00446E90)
         * Address: 0x004C6570 (FUN_004C6570)
         * Address: 0x004C6A30 (FUN_004C6A30)
         * Address: 0x004C6BE0 (FUN_004C6BE0)
         * Address: 0x004C6CE0 (FUN_004C6CE0)
         * Address: 0x00525E90 (FUN_00525E90)
         * Address: 0x00506470 (FUN_00506470)
         * Address: 0x00506500 (FUN_00506500)
         * Address: 0x005065A0 (FUN_005065A0)
         * Address: 0x005065F0 (FUN_005065F0)
         * Address: 0x00506660 (FUN_00506660)
         * Address: 0x00506690 (FUN_00506690)
         * Address: 0x00538010 (FUN_00538010)
         * Address: 0x00538160 (FUN_00538160)
         * Address: 0x00538200 (FUN_00538200)
         * Address: 0x00538260 (FUN_00538260)
         *
         * What it does:
         * Moves one half-open source word range `[sourceBegin, sourceEnd)` into
         * `destination` and returns one-past the last written destination word.
         */
        template <class WordT>
        [[nodiscard]] inline WordT* MoveWordRange(
            WordT* const destination,
            const WordT* const sourceBegin,
            const WordT* const sourceEnd
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "MoveWordRange expects 32-bit words");
            const std::size_t wordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
            if (wordCount != 0u) {
                std::memmove(destination, sourceBegin, wordCount * sizeof(WordT));
            }
            return destination + wordCount;
        }

        /**
         * Address: 0x00445C60 (FUN_00445C60)
         * Address: 0x00445D90 (FUN_00445D90)
         * Address: 0x00445E50 (FUN_00445E50)
         * Address: 0x00445F70 (FUN_00445F70)
         * Address: 0x00446520 (FUN_00446520)
         * Address: 0x00446630 (FUN_00446630)
         * Address: 0x004466B0 (FUN_004466B0)
         * Address: 0x00446750 (FUN_00446750)
         * Address: 0x004C65B0 (FUN_004C65B0)
         * Address: 0x004C6A80 (FUN_004C6A80)
         * Address: 0x004FDE90 (FUN_004FDE90)
         * Address: 0x005060E0 (FUN_005060E0)
         * Address: 0x00506110 (FUN_00506110)
         * Address: 0x005061A0 (FUN_005061A0)
         * Address: 0x00506270 (FUN_00506270)
         * Address: 0x005064C0 (FUN_005064C0)
         * Address: 0x00506550 (FUN_00506550)
         * Address: 0x00526120 (FUN_00526120)
         * Address: 0x00537030 (FUN_00537030)
         * Address: 0x00538080 (FUN_00538080)
         * Address: 0x005381B0 (FUN_005381B0)
         *
         * What it does:
         * Moves one source word range `[sourceBegin, sourceEnd)` so the copied block
         * ends at `destinationEnd`, and returns the destination begin pointer.
         */
        template <class WordT>
        [[nodiscard]] inline WordT* MoveWordRangeToEnd(
            WordT* const destinationEnd,
            const WordT* const sourceBegin,
            const WordT* const sourceEnd
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "MoveWordRangeToEnd expects 32-bit words");
            const std::size_t wordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
            WordT* const destinationBegin = destinationEnd - wordCount;
            if (wordCount != 0u) {
                std::memmove(destinationBegin, sourceBegin, wordCount * sizeof(WordT));
            }
            return destinationBegin;
        }

        /**
         * Address: 0x00445B30 (FUN_00445B30)
         * Address: 0x00445F10 (FUN_00445F10)
         * Address: 0x00446430 (FUN_00446430)
         * Address: 0x004466E0 (FUN_004466E0)
         * Address: 0x00506300 (FUN_00506300)
         * Address: 0x00506310 (FUN_00506310)
         * Address: 0x00506580 (FUN_00506580)
         * Address: 0x00506590 (FUN_00506590)
         * Address: 0x00506640 (FUN_00506640)
         * Address: 0x00506650 (FUN_00506650)
         * Address: 0x005066D0 (FUN_005066D0)
         * Address: 0x005066F0 (FUN_005066F0)
         * Address: 0x00506740 (FUN_00506740)
         * Address: 0x00506750 (FUN_00506750)
         * Address: 0x005380C0 (FUN_005380C0)
         * Address: 0x005381F0 (FUN_005381F0)
         * Address: 0x00538250 (FUN_00538250)
         * Address: 0x005382A0 (FUN_005382A0)
         * Address: 0x005382D0 (FUN_005382D0)
         * Address: 0x00446D70 (FUN_00446D70)
         * Address: 0x00446DF0 (FUN_00446DF0)
         * Address: 0x00446E80 (FUN_00446E80)
         *
         * What it does:
         * Dereferences one value-pointer slot, fills `count` words in destination,
         * and returns the dereferenced value pointer.
         */
        template <class WordT>
        [[nodiscard]] inline const WordT* FillWordsFromReferencedValuePointer(
            const WordT* const* const referencedValuePtr,
            WordT* const destination,
            const std::size_t count
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "FillWordsFromReferencedValuePointer expects 32-bit words");
            const WordT* const valuePtr = *referencedValuePtr;
            if (count != 0u) {
                std::fill_n(destination, count, *valuePtr);
            }
            return valuePtr;
        }

        /**
         * Address: 0x00445C50 (FUN_00445C50)
         * Address: 0x00445D80 (FUN_00445D80)
         * Address: 0x00445E40 (FUN_00445E40)
         * Address: 0x00506190 (FUN_00506190)
         * Address: 0x00506260 (FUN_00506260)
         * Address: 0x005064A0 (FUN_005064A0)
         * Address: 0x00506530 (FUN_00506530)
         * Address: 0x00445F50 (FUN_00445F50)
         * Address: 0x00446500 (FUN_00446500)
         * Address: 0x00446610 (FUN_00446610)
         * Address: 0x00446690 (FUN_00446690)
         * Address: 0x00446720 (FUN_00446720)
         * Address: 0x004C6A60 (FUN_004C6A60)
         * Address: 0x00538070 (FUN_00538070)
         * Address: 0x00538190 (FUN_00538190)
         *
         * What it does:
         * Fills one destination word range `[destinationBegin, destinationEnd)` from
         * one source value pointer and returns destination end.
         */
        template <class WordT>
        [[nodiscard]] inline WordT* FillWordRangeFromValuePointer(
            WordT* destinationBegin,
            WordT* const destinationEnd,
            const WordT* const valueWordPtr
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "FillWordRangeFromValuePointer expects 32-bit words");
            while (destinationBegin != destinationEnd) {
                *destinationBegin = *valueWordPtr;
                ++destinationBegin;
            }
            return destinationBegin;
        }

        /**
         * Address: 0x00446B10 (FUN_00446B10)
         * Address: 0x00446B60 (FUN_00446B60)
         * Address: 0x00446BB0 (FUN_00446BB0)
         * Address: 0x004C6C10 (FUN_004C6C10)
         * Address: 0x004C6DC0 (FUN_004C6DC0)
         * Address: 0x00506440 (FUN_00506440)
         * Address: 0x005065D0 (FUN_005065D0)
         * Address: 0x00506620 (FUN_00506620)
         * Address: 0x00538230 (FUN_00538230)
         *
         * What it does:
         * Moves `wordCount` 32-bit words from `source` into `destination`.
         */
        template <class WordT>
        [[nodiscard]] inline WordT* MoveWords(
            const WordT* const source,
            const std::size_t wordCount,
            WordT* const destination
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "MoveWords expects 32-bit words");
            std::memmove(destination, source, wordCount * sizeof(WordT));
            return destination;
        }

        /**
         * Address: 0x004462D0 (FUN_004462D0)
         * Address: 0x00446410 (FUN_00446410)
         * Address: 0x004464A0 (FUN_004464A0)
         * Address: 0x00446E20 (FUN_00446E20)
         * Address: 0x00446E40 (FUN_00446E40)
         * Address: 0x00446E60 (FUN_00446E60)
         * Address: 0x005063C0 (FUN_005063C0)
         * Address: 0x00506400 (FUN_00506400)
         * Address: 0x00506700 (FUN_00506700)
         * Address: 0x00506720 (FUN_00506720)
         * Address: 0x00538140 (FUN_00538140)
         * Address: 0x005382B0 (FUN_005382B0)
         *
         * What it does:
         * Moves `wordCount` words from `source` to `destination` and returns one
         * passthrough tag argument unchanged.
         */
        template <class WordT, class TagT>
        [[nodiscard]] inline TagT MoveWordsAndReturnTag(
            const WordT* const source,
            WordT* const destination,
            const std::size_t wordCount,
            const TagT passthroughTag
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "MoveWordsAndReturnTag expects 32-bit words");
            std::memmove(destination, source, wordCount * sizeof(WordT));
            return passthroughTag;
        }

        /**
         * Address: 0x004462C0 (FUN_004462C0)
         * Address: 0x00446320 (FUN_00446320)
         * Address: 0x00446400 (FUN_00446400)
         * Address: 0x00446490 (FUN_00446490)
         * Address: 0x00446510 (FUN_00446510)
         * Address: 0x00446620 (FUN_00446620)
         * Address: 0x004466A0 (FUN_004466A0)
         * Address: 0x00446740 (FUN_00446740)
         * Address: 0x004C6800 (FUN_004C6800)
         * Address: 0x004C6840 (FUN_004C6840)
         * Address: 0x004C69F0 (FUN_004C69F0)
         * Address: 0x004C6A70 (FUN_004C6A70)
         *
         * What it does:
         * Returns the high-byte lane from one 32-bit word.
         */
        [[nodiscard]] inline std::uint8_t HighByteOfWord(const std::uint32_t value) noexcept
        {
            return static_cast<std::uint8_t>((value >> 8) & 0xFFu);
        }

        /**
         * Address: 0x00446EF0 (FUN_00446EF0)
         *
         * What it does:
         * Returns true when `value` is non-zero and has exactly one bit set.
         */
        [[nodiscard]] inline bool IsSingleBitSetNonZero(const std::uint32_t value) noexcept
        {
            return value != 0u && ((value & (value - 1u)) == 0u);
        }

        /**
         * Address: 0x00446F10 (FUN_00446F10)
         *
         * What it does:
         * Returns index of the highest set bit in a non-zero 32-bit value.
         */
        [[nodiscard]] inline int HighestSetBitIndex(std::uint32_t value) noexcept
        {
            assert(value != 0u);
            int index = 0;
            while ((value >>= 1u) != 0u) {
                ++index;
            }
            return index;
        }

        /**
         * Address: 0x00446DB0 (FUN_00446DB0)
         *
         * What it does:
         * Returns one integer argument unchanged.
         */
        [[nodiscard]] inline int IdentityInt(const int value) noexcept
        {
            return value;
        }

        /**
         * Runtime dword-lane view with one leading 32-bit metadata lane.
         *
         * Layout:
         *   +0x00: metadata/prefix lane
         *   +0x04: begin
         *   +0x08: end
         *   +0x0C: capacity end
         */
        struct dword_lane_vector_view
        {
            std::uint32_t prefix;
            std::uint32_t* begin;
            std::uint32_t* end;
            std::uint32_t* capacityEnd;
        };

        static_assert(sizeof(dword_lane_vector_view) == 0x10, "dword_lane_vector_view size must be 0x10");

        /**
         * Address: 0x00443C10 (FUN_00443C10)
         * Address: 0x00443EF0 (FUN_00443EF0)
         * Address: 0x00444050 (FUN_00444050)
         *
         * What it does:
         * Initializes begin/end/capacity dword lanes for one requested word count.
         */
        template <class ThrowTooLongFn, class AllocateWordsFn>
        [[nodiscard]] inline bool InitializeDwordLanes(
            dword_lane_vector_view* const view,
            const std::size_t wordCount,
            ThrowTooLongFn throwTooLong,
            AllocateWordsFn allocateWords
        )
        {
            if (wordCount > 0x3FFFFFFFu) {
                throwTooLong();
            }

            std::uint32_t* const words = (wordCount != 0u)
                ? static_cast<std::uint32_t*>(allocateWords(static_cast<unsigned int>(wordCount)))
                : static_cast<std::uint32_t*>(::operator new(0));

            view->begin = words;
            view->end = words;
            view->capacityEnd = words + wordCount;
            return true;
        }

        /**
         * Address: 0x004443C0 (FUN_004443C0)
         *
         * What it does:
         * Inserts `count` copies of `fillValue` at `insertAt` in one legacy dword
         * lane vector, preserving VC8 growth/shift behavior.
         */
        template <class ThrowTooLongFn, class AllocateWordsFn>
        [[nodiscard]] inline std::uint32_t* InsertFillWordsIntoLanes(
            dword_lane_vector_view* const view,
            std::uint32_t* insertAt,
            const std::size_t count,
            const std::uint32_t fillValue,
            ThrowTooLongFn throwTooLong,
            AllocateWordsFn allocateWords
        )
        {
            if (count == 0u) {
                return insertAt;
            }

            const std::size_t currentSize = static_cast<std::size_t>(view->end - view->begin);
            const std::size_t currentCapacity = static_cast<std::size_t>(view->capacityEnd - view->begin);
            const std::size_t insertIndex = static_cast<std::size_t>(insertAt - view->begin);

            if (count > (0x3FFFFFFFu - currentSize)) {
                throwTooLong();
            }

            if (currentCapacity >= currentSize + count) {
                const std::size_t tailCount = static_cast<std::size_t>(view->end - insertAt);
                if (tailCount < count) {
                    MoveWordRange(insertAt + count, insertAt, view->end);
                    view->end += count;
                    FillWordsFromValuePointer(&fillValue, insertAt, count);
                    return insertAt;
                }

                MoveWordRange(view->end, view->end - count, view->end);
                view->end += count;
                MoveWordRange(insertAt + count, insertAt, view->end - count);
                FillWordsFromValuePointer(&fillValue, insertAt, count);
                return insertAt;
            }

            std::size_t newCapacity = currentCapacity + (currentCapacity >> 1);
            if (newCapacity < (currentSize + count)) {
                newCapacity = currentSize + count;
            }
            if (newCapacity > 0x3FFFFFFFu) {
                newCapacity = currentSize + count;
            }

            std::uint32_t* const newBegin = (newCapacity != 0u)
                ? static_cast<std::uint32_t*>(allocateWords(static_cast<unsigned int>(newCapacity)))
                : static_cast<std::uint32_t*>(::operator new(0));
            std::uint32_t* const newInsert = newBegin + insertIndex;

            MoveWordRange(newBegin, view->begin, view->begin + insertIndex);
            FillWordsFromValuePointer(&fillValue, newInsert, count);
            MoveWordRange(newInsert + count, insertAt, view->end);

            if (view->begin != nullptr) {
                ::operator delete(view->begin);
            }

            view->begin = newBegin;
            view->end = newBegin + (currentSize + count);
            view->capacityEnd = newBegin + newCapacity;
            return newInsert;
        }

        /**
         * Address: 0x00444800 (FUN_00444800)
         * Address: 0x00444AC0 (FUN_00444AC0)
         *
         * What it does:
         * Inserts one word value at `insertAt` in one legacy dword lane vector.
         */
        template <class ThrowTooLongFn, class AllocateWordsFn>
        [[nodiscard]] inline std::uint32_t* InsertOneWordIntoLanes(
            dword_lane_vector_view* const view,
            std::uint32_t* const insertAt,
            const std::uint32_t value,
            ThrowTooLongFn throwTooLong,
            AllocateWordsFn allocateWords
        )
        {
            return InsertFillWordsIntoLanes(view, insertAt, 1u, value, throwTooLong, allocateWords);
        }

        /**
         * Address: 0x00444780 (FUN_00444780)
         *
         * What it does:
         * Stores bit-count prefix, trims extra words through caller-provided eraser,
         * and masks tail bits in the last retained word.
         */
        template <class EraseWordRangeFn>
        [[nodiscard]] inline std::uint32_t NormalizeBitCountAndTrimTail(
            dword_lane_vector_view* const view,
            const std::uint32_t bitCount,
            EraseWordRangeFn eraseWordRange
        )
        {
            const std::size_t requiredWordCount = static_cast<std::size_t>((bitCount + 31u) >> 5u);
            if (view->begin != nullptr) {
                const std::size_t currentWordCount = static_cast<std::size_t>(view->end - view->begin);
                if (requiredWordCount < currentWordCount) {
                    eraseWordRange(view, view->begin + requiredWordCount, view->end);
                }
            }

            view->prefix = bitCount;
            const std::uint32_t trailingBits = bitCount & 0x1Fu;
            if (trailingBits != 0u && requiredWordCount != 0u && view->begin != nullptr) {
                view->begin[requiredWordCount - 1u] &= ((1u << trailingBits) - 1u);
            }
            return bitCount;
        }

        /**
         * Address: 0x00444E90 (FUN_00444E90)
         *
         * What it does:
         * Ensures logical word count by delegating grow/erase operations while
         * preserving legacy pointer-lane update ordering.
         */
        template <class GrowWordsFn, class EraseWordRangeFn>
        [[nodiscard]] inline std::size_t EnsureWordCountInLanes(
            dword_lane_vector_view* const view,
            const std::size_t desiredWordCount,
            const std::uint32_t fillWord,
            GrowWordsFn growWords,
            EraseWordRangeFn eraseWordRange
        )
        {
            const std::size_t currentWordCount =
                (view->begin != nullptr) ? static_cast<std::size_t>(view->end - view->begin) : 0u;

            if (desiredWordCount > currentWordCount) {
                growWords(view, view->end, desiredWordCount - currentWordCount, fillWord);
            } else if (view->begin != nullptr && desiredWordCount < currentWordCount) {
                eraseWordRange(view, view->begin + desiredWordCount, view->end);
            }
            return desiredWordCount;
        }

        /**
         * Address: 0x00444240 (FUN_00444240)
         * Address: 0x00444E80 (FUN_00444E80)
         *
         * What it does:
         * Copies one 32-bit word-pointer lane from a source slot into destination.
         */
        [[nodiscard]] inline std::uint32_t** CopyWordPointerSlot(
            std::uint32_t** const destination,
            std::uint32_t* const* const sourceSlot
        ) noexcept
        {
            *destination = *sourceSlot;
            return destination;
        }

        /**
         * Address: 0x00444DB0 (FUN_00444DB0)
         * Address: 0x00444DE0 (FUN_00444DE0)
         * Address: 0x00444E30 (FUN_00444E30)
         * Address: 0x004453E0 (FUN_004453E0)
         * Address: 0x00445110 (FUN_00445110)
         * Address: 0x00445140 (FUN_00445140)
         * Address: 0x00445170 (FUN_00445170)
         * Address: 0x00445390 (FUN_00445390)
         * Address: 0x00535FE0 (FUN_00535FE0)
         * Address: 0x00536830 (FUN_00536830)
         * Address: 0x00536850 (FUN_00536850)
         * Address: 0x00537FA0 (FUN_00537FA0)
         * Address: 0x00537FE0 (FUN_00537FE0)
         *
         * What it does:
         * Stores one 32-bit word pointer lane and returns the destination slot.
         */
        [[nodiscard]] inline std::uint32_t** SetWordPointer(
            std::uint32_t** const destination,
            std::uint32_t* const value
        ) noexcept
        {
            *destination = value;
            return destination;
        }

        /**
         * Address: 0x00505040 (FUN_00505040)
         * Address: 0x005051B0 (FUN_005051B0)
         * Address: 0x005051D0 (FUN_005051D0)
         * Address: 0x00505B30 (FUN_00505B30)
         * Address: 0x00505CB0 (FUN_00505CB0)
         * Address: 0x00505EA0 (FUN_00505EA0)
         * Address: 0x00561F30 (FUN_00561F30)
         * Address: 0x00562590 (FUN_00562590)
         * Address: 0x005625A0 (FUN_005625A0)
         * Address: 0x005625B0 (FUN_005625B0)
         * Address: 0x005625C0 (FUN_005625C0)
         * Address: 0x0056D060 (FUN_0056D060)
         * Address: 0x0056E820 (FUN_0056E820)
         * Address: 0x0056E850 (FUN_0056E850)
         * Address: 0x0056EED0 (FUN_0056EED0)
         * Address: 0x005927D0 (FUN_005927D0)
         * Address: 0x005928E0 (FUN_005928E0)
         * Address: 0x005928F0 (FUN_005928F0)
         * Address: 0x00592DC0 (FUN_00592DC0)
         * Address: 0x00592DF0 (FUN_00592DF0)
         * Address: 0x00592FB0 (FUN_00592FB0)
         *
         * What it does:
         * Stores one 32-bit word value and returns the destination slot.
         */
        [[nodiscard]] inline std::uint32_t* SetWordSlotValue(
            std::uint32_t* const destination,
            const std::uint32_t value
        ) noexcept
        {
            *destination = value;
            return destination;
        }

        /**
         * Address: 0x00446FA0 (FUN_00446FA0)
         * Address: 0x00504820 (FUN_00504820)
         * Address: 0x00505050 (FUN_00505050)
         * Address: 0x00595190 (FUN_00595190)
         * Address: 0x00595280 (FUN_00595280)
         *
         * What it does:
         * Zeros one 32-bit slot and returns the same slot pointer.
         */
        [[nodiscard]] inline std::uint32_t* ZeroWordSlot(std::uint32_t* const slot) noexcept
        {
            *slot = 0u;
            return slot;
        }

        /**
         * Address: 0x00506390 (FUN_00506390)
         *
         * What it does:
         * Copies one 32-bit word from `source` when `destination` is non-null
         * and returns the destination slot.
         */
        [[nodiscard]] inline std::uint32_t* CopyWordSlotIfNonNull(
            std::uint32_t* const destination,
            const std::uint32_t* const source
        ) noexcept
        {
            if (destination != nullptr) {
                *destination = *source;
            }
            return destination;
        }

        /**
         * Address: 0x00444DF0 (FUN_00444DF0)
         * Address: 0x00445080 (FUN_00445080)
         * Address: 0x00445360 (FUN_00445360)
         *
         * What it does:
         * Initializes a vector<bool>-style cursor from a word pointer and clears bit lane.
         */
        [[nodiscard]] inline vector_bool_word_cursor* SetCursorWordAndClearBit(
            vector_bool_word_cursor* const cursor,
            std::uint32_t* const word
        ) noexcept
        {
            cursor->word = word;
            cursor->bit = 0u;
            return cursor;
        }

        /**
         * Address: 0x00443CA0 (FUN_00443CA0)
         *
         * What it does:
         * Loads one source word slot into a cursor and clears its bit lane.
         */
        [[nodiscard]] inline vector_bool_word_cursor* SetCursorFromWordSlotAndClearBit(
            vector_bool_word_cursor* const cursor,
            std::uint32_t* const* const sourceSlot
        ) noexcept
        {
            cursor->word = *sourceSlot;
            cursor->bit = 0u;
            return cursor;
        }

        /**
         * Address: 0x004467B0 (FUN_004467B0)
         *
         * What it does:
         * Copies one source cursor bit value into destination cursor bit lane.
         */
        [[nodiscard]] inline vector_bool_word_cursor* CopyBitAtCursor(
            vector_bool_word_cursor* const destination,
            const vector_bool_word_cursor& source
        ) noexcept
        {
            const std::uint32_t sourceMask = (1u << source.bit);
            const std::uint32_t destinationMask = (1u << destination->bit);
            if ((*source.word & sourceMask) == 0u) {
                *destination->word &= ~destinationMask;
            } else {
                *destination->word |= destinationMask;
            }
            return destination;
        }

        /**
         * Address: 0x00446330 (FUN_00446330)
         * Address: 0x00445A70 (FUN_00445A70)
         * Address: 0x007BDA50 (FUN_007BDA50)
         *
         * What it does:
         * Copies bits from one source cursor range into destination cursor range
         * in forward order and stores resulting destination cursor.
         */
        [[nodiscard]] inline vector_bool_word_cursor* CopyBitCursorRangeForward(
            vector_bool_word_cursor* const outDestinationCursor,
            vector_bool_word_cursor sourceCursor,
            const vector_bool_word_cursor sourceEnd,
            vector_bool_word_cursor destinationCursor
        ) noexcept
        {
            while (sourceCursor.word != sourceEnd.word || sourceCursor.bit != sourceEnd.bit) {
                const std::uint32_t sourceMask = (1u << sourceCursor.bit);
                const std::uint32_t destinationMask = (1u << destinationCursor.bit);
                if ((*sourceCursor.word & sourceMask) != 0u) {
                    *destinationCursor.word |= destinationMask;
                } else {
                    *destinationCursor.word &= ~destinationMask;
                }

                if (destinationCursor.bit >= 31u) {
                    destinationCursor.bit = 0u;
                    ++destinationCursor.word;
                } else {
                    ++destinationCursor.bit;
                }

                if (sourceCursor.bit >= 31u) {
                    sourceCursor.bit = 0u;
                    ++sourceCursor.word;
                } else {
                    ++sourceCursor.bit;
                }
            }

            *outDestinationCursor = destinationCursor;
            return outDestinationCursor;
        }

        /**
         * Address: 0x004463A0 (FUN_004463A0)
         * Address: 0x00445AD0 (FUN_00445AD0)
         *
         * What it does:
         * Sets or clears each bit in destination cursor range from one boolean slot
         * and returns resulting destination word pointer.
         */
        [[nodiscard]] inline std::uint32_t* FillBitCursorRangeFromBooleanSlot(
            const bool* const sourceBoolean,
            vector_bool_word_cursor destinationCursor,
            const vector_bool_word_cursor destinationEnd
        ) noexcept
        {
            const bool setBit = (*sourceBoolean != false);
            while (destinationCursor.word != destinationEnd.word || destinationCursor.bit != destinationEnd.bit) {
                const std::uint32_t destinationMask = (1u << destinationCursor.bit);
                if (setBit) {
                    *destinationCursor.word |= destinationMask;
                } else {
                    *destinationCursor.word &= ~destinationMask;
                }

                if (destinationCursor.bit >= 31u) {
                    destinationCursor.bit = 0u;
                    ++destinationCursor.word;
                } else {
                    ++destinationCursor.bit;
                }
            }

            return destinationCursor.word;
        }

        /**
         * Address: 0x00446550 (FUN_00446550)
         * Address: 0x00445CE0 (FUN_00445CE0)
         *
         * What it does:
         * Copies bits from one source cursor range into destination cursor range
         * in reverse order and stores resulting destination cursor.
         */
        [[nodiscard]] inline vector_bool_word_cursor* CopyBitCursorRangeBackward(
            vector_bool_word_cursor* const outDestinationCursor,
            const vector_bool_word_cursor sourceBegin,
            vector_bool_word_cursor sourceEnd,
            vector_bool_word_cursor destinationEnd
        ) noexcept
        {
            while (sourceBegin.word != sourceEnd.word || sourceBegin.bit != sourceEnd.bit) {
                if (sourceEnd.bit != 0u) {
                    --sourceEnd.bit;
                } else {
                    --sourceEnd.word;
                    sourceEnd.bit = 31u;
                }

                if (destinationEnd.bit != 0u) {
                    --destinationEnd.bit;
                } else {
                    --destinationEnd.word;
                    destinationEnd.bit = 31u;
                }

                const std::uint32_t sourceMask = (1u << sourceEnd.bit);
                const std::uint32_t destinationMask = (1u << destinationEnd.bit);
                if ((*sourceEnd.word & sourceMask) != 0u) {
                    *destinationEnd.word |= destinationMask;
                } else {
                    *destinationEnd.word &= ~destinationMask;
                }
            }

            *outDestinationCursor = destinationEnd;
            return outDestinationCursor;
        }

        /**
         * Address: 0x00444DC0 (FUN_00444DC0)
         * Address: 0x00444E40 (FUN_00444E40)
         * Address: 0x00444E70 (FUN_00444E70)
         * Address: 0x00445180 (FUN_00445180)
         * Address: 0x00535FF0 (FUN_00535FF0)
         * Address: 0x00537E80 (FUN_00537E80)
         *
         * What it does:
         * Stores `base + wordOffset` into one pointer destination slot.
         */
        [[nodiscard]] inline std::uint32_t** SetWordPointerFromBaseOffset(
            std::uint32_t** const destination,
            std::uint32_t* const base,
            const int wordOffset
        ) noexcept
        {
            *destination = base + wordOffset;
            return destination;
        }

        /**
         * Address: 0x00443E60 (FUN_00443E60)
         * Address: 0x00443FC0 (FUN_00443FC0)
         *
         * What it does:
         * Executes one insertion lane and then rebinds output pointer to the same
         * logical word offset in possibly reallocated storage.
         */
        template <class InsertAtWordFn>
        [[nodiscard]] inline std::uint32_t** RebindWordPointerAfterInsert(
            std::uint32_t** const outPointer,
            dword_lane_vector_view* const view,
            std::uint32_t* const sourceWord,
            InsertAtWordFn insertAtWord
        )
        {
            int sourceWordOffset = 0;
            if (view->begin != nullptr && view->end != view->begin) {
                sourceWordOffset = static_cast<int>(sourceWord - view->begin);
            }

            insertAtWord(view, sourceWord);
            *outPointer = view->begin + sourceWordOffset;
            return outPointer;
        }

        /**
         * Address: 0x00445060 (FUN_00445060)
         * Address: 0x00445100 (FUN_00445100)
         * Address: 0x00445150 (FUN_00445150)
         * Address: 0x004453A0 (FUN_004453A0)
         * Address: 0x004453C0 (FUN_004453C0)
         * Address: 0x00445370 (FUN_00445370)
         * Address: 0x00445380 (FUN_00445380)
         * Address: 0x00445460 (FUN_00445460)
         * Address: 0x00537FB0 (FUN_00537FB0)
         * Address: 0x00537FF0 (FUN_00537FF0)
         *
         * What it does:
         * Adds one word offset to an existing pointer slot in place.
         */
        [[nodiscard]] inline std::uint32_t** AdvanceWordPointerInPlace(
            std::uint32_t** const destination,
            const int wordOffset
        ) noexcept
        {
            *destination += wordOffset;
            return destination;
        }

        /**
         * Address: 0x00444DD0 (FUN_00444DD0)
         * Address: 0x00444E50 (FUN_00444E50)
         * Address: 0x00445070 (FUN_00445070)
         * Address: 0x00445120 (FUN_00445120)
         *
         * What it does:
         * Returns the signed word-distance between two pointers.
         */
        [[nodiscard]] inline int WordPointerDistance(
            const std::uint32_t* const lhs,
            const std::uint32_t* const rhs
        ) noexcept
        {
            return static_cast<int>(lhs - rhs);
        }

        /**
         * Address: 0x00445130 (FUN_00445130)
         * Address: 0x004453B0 (FUN_004453B0)
         * Address: 0x00445480 (FUN_00445480)
         *
         * What it does:
         * Returns pointer equality for one-word iterator lanes.
         */
        [[nodiscard]] inline bool WordPointerEqual(
            const std::uint32_t* const lhs,
            const std::uint32_t* const rhs
        ) noexcept
        {
            return lhs == rhs;
        }

        /**
         * Address: 0x00446F90 (FUN_00446F90)
         *
         * What it does:
         * Returns pointer-lane strict-less relation.
         */
        [[nodiscard]] inline bool WordPointerLess(
            const std::uint32_t* const lhs,
            const std::uint32_t* const rhs
        ) noexcept
        {
            return lhs < rhs;
        }

        /**
         * Address: 0x00445160 (FUN_00445160)
         * Address: 0x004453F0 (FUN_004453F0)
         *
         * What it does:
         * Returns pointer inequality for one-word iterator lanes.
         */
        [[nodiscard]] inline bool WordPointerNotEqual(
            const std::uint32_t* const lhs,
            const std::uint32_t* const rhs
        ) noexcept
        {
            return lhs != rhs;
        }

        /**
         * Address: 0x00445A00 (FUN_00445A00)
         * Address: 0x00445A20 (FUN_00445A20)
         * Address: 0x00445A40 (FUN_00445A40)
         * Address: 0x00445A50 (FUN_00445A50)
         * Address: 0x00445A60 (FUN_00445A60)
         *
         * What it does:
         * Swaps two 32-bit word lanes in place.
         */
        template <class WordT>
        [[nodiscard]] inline WordT* SwapWordLanes(WordT* const lhs, WordT* const rhs) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "SwapWordLanes expects 32-bit words");
            const WordT tmp = *lhs;
            *lhs = *rhs;
            *rhs = tmp;
            return lhs;
        }

        /**
         * Address: 0x00444E00 (FUN_00444E00)
         * Address: 0x00445090 (FUN_00445090)
         *
         * What it does:
         * Advances vector<bool>-style cursor by a signed bit delta.
         */
        [[nodiscard]] inline vector_bool_word_cursor* AdvanceCursorBits(
            vector_bool_word_cursor* const cursor,
            const int bitDelta
        ) noexcept
        {
            if (bitDelta != 0) {
                if (bitDelta >= 0 || cursor->bit >= static_cast<std::uint32_t>(-bitDelta)) {
                    const std::uint32_t advancedBits =
                        static_cast<std::uint32_t>(static_cast<int>(cursor->bit) + bitDelta);
                    cursor->word += advancedBits >> 5;
                    cursor->bit = advancedBits & 0x1Fu;
                } else {
                    const int advancedBits = static_cast<int>(cursor->bit) + bitDelta;
                    cursor->word += -1 - ((-1 - advancedBits) >> 5);
                    cursor->bit = static_cast<std::uint32_t>(advancedBits) & 0x1Fu;
                }
            }

            return cursor;
        }

        /**
         * Address: 0x00443CB0 (FUN_00443CB0)
         *
         * What it does:
         * Loads one source word slot into a cursor, clears bit lane, then advances
         * by signed bit delta.
         */
        [[nodiscard]] inline vector_bool_word_cursor* SetCursorFromWordSlotAndAdvanceBits(
            vector_bool_word_cursor* const cursor,
            std::uint32_t* const* const sourceSlot,
            const int bitDelta
        ) noexcept
        {
            (void)SetCursorFromWordSlotAndClearBit(cursor, sourceSlot);
            if (bitDelta != 0) {
                (void)AdvanceCursorBits(cursor, bitDelta);
            }
            return cursor;
        }

        /**
         * Address: 0x00444190 (FUN_00444190)
         *
         * What it does:
         * Copies one cursor and applies a signed bit offset to the copy.
         */
        [[nodiscard]] inline vector_bool_word_cursor* CopyCursorAndAdvance(
            vector_bool_word_cursor* const destination,
            const vector_bool_word_cursor& source,
            const int bitDelta
        ) noexcept
        {
            *destination = source;
            (void)AdvanceCursorBits(destination, bitDelta);
            return destination;
        }

        /**
         * Address: 0x00444E10 (FUN_00444E10)
         * Address: 0x004450E0 (FUN_004450E0)
         *
         * What it does:
         * Computes signed bit distance from `from` cursor to `to` cursor.
         */
        [[nodiscard]] inline int CursorBitDistance(
            const vector_bool_word_cursor& from,
            const vector_bool_word_cursor& to
        ) noexcept
        {
            return static_cast<int>(to.bit + 32 * (to.word - from.word) - from.bit);
        }

        /**
         * Address: 0x00444F60 (FUN_00444F60)
         * Address: 0x00445410 (FUN_00445410)
         * Address: 0x00537E90 (FUN_00537E90)
         *
         * What it does:
         * Returns word span count when begin pointer is present; otherwise returns zero.
         */
        [[nodiscard]] inline std::size_t WordSpanCountFromOptionalBegin(
            const std::uint32_t* const begin,
            const std::uint32_t* const end
        ) noexcept
        {
            if (begin == 0) {
                return 0u;
            }

            return static_cast<std::size_t>(end - begin);
        }

        /**
         * Address: 0x00444F00 (FUN_00444F00)
         *
         * What it does:
         * Erases one shifted word range `[source, endWord)` into `destination`,
         * updates `endWord`, and stores destination as the return iterator slot.
         */
        template <class WordT>
        [[nodiscard]] inline WordT** EraseWordRangeAndStoreDestination(
            WordT** const destinationOut,
            WordT*& endWord,
            WordT* const destination,
            const WordT* const source
        ) noexcept
        {
            static_assert(sizeof(WordT) == sizeof(std::uint32_t), "EraseWordRangeAndStoreDestination expects 32-bit words");
            if (destination != source) {
                const std::size_t wordCount = static_cast<std::size_t>(endWord - source);
                if (wordCount != 0u) {
                    std::memmove(destination, source, wordCount * sizeof(WordT));
                }
                endWord = destination + wordCount;
            }

            *destinationOut = destination;
            return destinationOut;
        }

        /**
         * Address: 0x00444FB0 (FUN_00444FB0)
         *
         * What it does:
         * Returns the legacy `-1` sentinel lane used by VC8 vector<bool> helpers.
         */
        [[nodiscard]] inline int NegativeOneSentinel() noexcept
        {
            return -1;
        }

        /**
         * Address: 0x00444FC0 (FUN_00444FC0)
         *
         * What it does:
         * Converts bit count to storage-word count using 32-bit words.
         */
        [[nodiscard]] inline std::size_t BitCountToWordCount(const std::size_t bitCount) noexcept
        {
            return (bitCount + 31u) >> 5;
        }

        /**
         * Address: 0x00444FD0 (FUN_00444FD0)
         *
         * What it does:
         * Throws `std::length_error` with the VC8 vector<bool> overflow message.
         */
        [[noreturn]] inline void ThrowVectorBoolTooLong()
        {
            throw std::length_error("vector<bool> too long");
        }
    } // namespace detail

    /**
     * MSVC8-compatible vector with fixed ABI (16 bytes).
     * Only pointer fields are stored: proxy (opaque), begin, end, capacity-end.
     * Provides a minimal modern API: reserve/resize/push_back/emplace_back/clear,
     * copy/move, and conversions to/from std::vector<T>.
     *
     * WARNING about ownership: this implementation assumes it owns the memory it allocates.
     * If you map this struct over foreign memory from the original binary, you MUST NOT let
     * it destroy/deallocate that memory. See MSVC8_VECTOR_DISABLE_FREE macro above.
     *
     * Why do we have this `Dbg` in Release? This is common default practice of VS2005,
     * they have `_SECURE_SCL=1` defined in Release, so we can see that debug iterator that
     * aren't used by anything really and just sitting alone there.
     */
    template <class T>
    class vector
	{
        using iterator = T*;
        using const_iterator = const T*;

        void* myProxy_; // +0x0  (opaque _Container_proxy*)
        T* first_;      // +0x4
        T* last_;       // +0x8
        T* end_;        // +0xC

    public:
        /**
         * Default constructor: empty
         */
        vector() noexcept :
    		myProxy_(nullptr),
    		first_(nullptr),
    		last_(nullptr),
    		end_(nullptr)
    	{
        }

        /**
         * Address: 0x00442B50 (FUN_00442B50)
         * Address: 0x00443090 (FUN_00443090)
         * Address: 0x00443290 (FUN_00443290)
         * Address: 0x00443390 (FUN_00443390)
         *
         * What it does:
         * Resets data-range pointer lanes while preserving allocator/proxy lane.
         */
        void reset_range_lanes_preserve_proxy() noexcept {
            first_ = nullptr;
            last_ = nullptr;
            end_ = nullptr;
        }

        /**
         * Construct with count default-inserted elements
         */
        explicit vector(std::size_t count) : vector() {
            if (count) {
                reserve(count);
                uninit_value_construct_n(first_, count);
                last_ = first_ + count;
            }
        }

        /**
         * Construct from std::vector (copy)
         */
        explicit vector(const std::vector<T>& src) : vector() {
            if (!src.empty()) {
                reserve(src.size());
                uninit_copy_n(src.data(), src.size(), first_);
                last_ = first_ + src.size();
            }
        }

        /**
         * Copy constructor (deep copy)
         */
        vector(const vector& other) : vector() {
            const std::size_t n = other.size();
            if (n) {
                reserve(n);
                uninit_copy_n(other.first_, n, first_);
                last_ = first_ + n;
            }
        }

        /**
         * Move constructor (steals pointers)
         */
        vector(vector&& other) noexcept :
    		myProxy_(other.myProxy_),
			first_(other.first_),
			last_(other.last_),
			end_(other.end_)
    	{
            other.myProxy_ = nullptr;
            other.first_ = other.last_ = other.end_ = nullptr;
        }

        /**
         * Destructor: destroy elements and free storage if allowed
         */
        ~vector() {
            destroy_all();
            deallocate_all();
        }

        /**
         * Copy assignment (strong exception safety)
         */
        vector& operator=(const vector& rhs) {
            if (this == &rhs) return *this;
            assign(rhs.first_, rhs.size());
            return *this;
        }

        /**
         * Move assignment (steals pointers)
         */
        vector& operator=(vector&& rhs) noexcept {
            if (this == &rhs) return *this;
            destroy_all();
            deallocate_all();
            myProxy_ = rhs.myProxy_;
            first_ = rhs.first_;
            last_ = rhs.last_;
            end_ = rhs.end_;
            rhs.myProxy_ = nullptr;
            rhs.first_ = rhs.last_ = rhs.end_ = nullptr;
            return *this;
        }

        /**
         * Address: 0x004433D0 (FUN_004433D0)
         * Address: 0x00443E40 (FUN_00443E40)
         * Address: 0x00444330 (FUN_00444330)
         *
         * What it does:
         * Returns the first element pointer lane (`first_`).
         */
        T* begin() const noexcept { return first_; }

        /**
         * Address: 0x004433E0 (FUN_004433E0)
         * Address: 0x00443E50 (FUN_00443E50)
         * Address: 0x00444340 (FUN_00444340)
         *
         * What it does:
         * Returns the one-past-end pointer lane (`last_`).
         */
        T* end() const noexcept { return last_; }
        [[nodiscard]] bool empty() const noexcept {
	        return first_ == last_;
        }
        /**
         * Address: 0x00442B90 (FUN_00442B90)
         * Address: 0x004430E0 (FUN_004430E0)
         * Address: 0x004432D0 (FUN_004432D0)
         * Address: 0x004433F0 (FUN_004433F0)
         *
         * What it does:
         * Returns element count from retained `[first_, last_)` range.
         */
        [[nodiscard]] std::size_t size() const noexcept {
	        return static_cast<std::size_t>(last_ - first_);
        }
        /**
         * Address: 0x00443E20 (FUN_00443E20)
         * Address: 0x00443FA0 (FUN_00443FA0)
         *
         * What it does:
         * Returns reserved element capacity from retained `[first_, end_)` range.
         */
        [[nodiscard]] std::size_t capacity() const noexcept {
	        return static_cast<std::size_t>(end_ - first_);
        }
        T& operator[](std::size_t i) const noexcept {
	        return first_[i];
        }
        /**
         * Address: 0x00442BB0 (FUN_00442BB0)
         * Address: 0x00443100 (FUN_00443100)
         * Address: 0x004432F0 (FUN_004432F0)
         * Address: 0x00443410 (FUN_00443410)
         *
         * What it does:
         * Returns raw pointer to element slot at `index` in the active range.
         */
        T* ptr_at(std::size_t index) const noexcept {
            return first_ + index;
        }
        T* data() const noexcept {
	        return first_;
        }

        /**
         * Front element (no check)
         */
        T& front() const noexcept { return *first_; }

        /**
         * Back element (no check)
         */
        T& back() const noexcept { return *(last_ - 1); }

        /**
         * Reserve storage for at least new_cap elements
         */
        void reserve(const std::size_t newCap) {
            if (newCap <= capacity()) {
                return;
            }
            reallocate_to(newCap);
        }

        /**
         * Address: 0x004430D0 (FUN_004430D0, forwarding lane)
         * Address: 0x00443B80 (FUN_00443B80)
         *
         * What it does:
         * Resizes logical element count to `newSize` by erasing tail elements when
         * shrinking or value-initializing appended slots when growing.
         */
        void resize(std::size_t newSize) {
            const std::size_t cur = size();
            if (newSize <= cur) {
                destroy_n(first_ + newSize, cur - newSize);
                last_ = first_ + newSize;
                return;
            }
            const std::size_t add = newSize - cur;
            if (newSize > capacity())
                reallocate_to(recommended_capacity(newSize));
            uninit_value_construct_n(last_, add);
            last_ += add;
        }

        /**
         * Resize with fill value for new elements
         */
        void resize(std::size_t newSize, const T& value) {
            const std::size_t cur = size();
            if (newSize <= cur) {
                destroy_n(first_ + newSize, cur - newSize);
                last_ = first_ + newSize;
                return;
            }
            const std::size_t add = newSize - cur;
            if (newSize > capacity())
                reallocate_to(recommended_capacity(newSize));
            uninit_fill_n(last_, add, value);
            last_ += add;
        }

        /**
         * Clear all elements; keep capacity
         *
         * Address: 0x00443350 (FUN_00443350)
         * Address: 0x004434A0 (FUN_004434A0)
         *
         * What it does:
         * Collapses logical range to empty by rebasing `last_` to `first_`.
         */
        void clear() noexcept {
            destroy_all();
            last_ = first_;
        }

        /**
         * Push by const&
         *
         * Address: 0x00443300 (FUN_00443300)
         * Address: 0x00443420 (FUN_00443420)
         *
         * What it does:
         * Appends one value at the end, growing capacity when the active range
         * reaches `end_`.
         */
        void push_back(const T& value) {
            ensure_grow_for(1);
            new (static_cast<void*>(last_)) T(value);
            ++last_;
        }

        /** Push by rvalue */
        void push_back(T&& value) {
            ensure_grow_for(1);
            ::new (static_cast<void*>(last_)) T(std::move(value));
            ++last_;
        }

        /**
         * Emplace in-place
         */
        template <class... Args>
        T& emplace_back(Args&&... args) {
            ensure_grow_for(1);
            ::new (static_cast<void*>(last_)) T(std::forward<Args>(args)...);
            return *(last_++);
        }

        /**
         * Pop last (no check)
         */
        void pop_back() noexcept {
            --last_;
            last_->~T();
        }

        /**
         * Assign from raw pointer + count (deep copy)
         */
        void assign(const T* src, std::size_t n) {
            if (n <= size()) {
                // Overwrite existing, destroy rest
                copy_or_move_assign(first_, src, n);
                destroy_n(first_ + n, size() - n);
                last_ = first_ + n;
            } else {
                // Grow if needed, overwrite existing, uninitialized-copy tail
                if (n > capacity())
                    reallocate_to(n);
                const std::size_t cur = size();
                copy_or_move_assign(first_, src, cur);
                uninit_copy_n(src + cur, n - cur, first_ + cur);
                last_ = first_ + n;
            }
        }

        /**
         * Assign from std::vector (deep copy)
         */
        void assign(const std::vector<T>& src) {
            assign(src.data(), src.size());
        }

        /**
         * Convert to std::vector<T> (copy)
         */
        [[nodiscard]]
    	std::vector<T> to_std() const {
            std::vector<T> out;
            out.reserve(size());
            out.insert(out.end(), first_, last_);
            return out;
        }

        /**
         * Replace contents from std::vector<T> (copy)
         */
        void from_std(const std::vector<T>& src) {
            assign(src);
        }

        /**
         * Erase one element at position `pos`.
         * Shifts the tail left by 1, destroys the last duplicated slot,
         * and returns iterator to the position of erased element.
         *
         * Address: 0x00443470 (FUN_00443470)
         * Address: 0x00443EA0 (FUN_00443EA0)
         * Address: 0x00444000 (FUN_00444000)
         * Address: 0x00444360 (FUN_00444360)
         */
        iterator erase(iterator pos) {
            assert(pos >= first_ && pos < last_);
            iterator next = pos + 1;
            const std::size_t tail = static_cast<std::size_t>(last_ - next);
            if (tail) {
                if constexpr (std::is_trivially_copyable_v<T>) {
                    if constexpr (sizeof(T) == sizeof(std::uint32_t)) {
                        detail::MoveWords(next, tail, pos);
                    } else {
                        std::memmove(pos, next, tail * sizeof(T));
                    }
                } else {
                    for (std::size_t i = 0; i < tail; ++i)
                        pos[i] = std::move(next[i]);
                }
            }
            --last_;
            if constexpr (!std::is_trivially_destructible_v<T>) {
                last_->~T();
            }
            return pos;
        }

        /**
         * Erase a range [first,last). Returns iterator to the position that
         * now contains the element that followed the last erased element.
         */
        iterator erase(iterator first, iterator last) {
            assert(first_ <= first && first <= last && last <= last_);
            const std::size_t count = static_cast<std::size_t>(last - first);
            if (count == 0) return first;

            const std::size_t tail = static_cast<std::size_t>(last_ - last);
            if (tail) {
                if constexpr (std::is_trivially_copyable_v<T>) {
                    if constexpr (sizeof(T) == sizeof(std::uint32_t)) {
                        detail::MoveWords(last, tail, first);
                    } else {
                        std::memmove(first, last, tail * sizeof(T));
                    }
                } else {
                    for (std::size_t i = 0; i < tail; ++i)
                        first[i] = std::move(last[i]);
                }
            }
            if constexpr (!std::is_trivially_destructible_v<T>) {
                destroy_range(last_ - count, last_);
            }
            last_ -= count;
            return first;
        }

    private:
        /**
         * Destroy [first,last)
         */
        static void destroy_range(T* first, T* last) noexcept {
            if constexpr (!std::is_trivially_destructible_v<T>) {
                for (; first != last; ++first) first->~T();
            } else {
                (void)first; (void)last;
            }
        }

        /**
         * Destroy N elements starting at p
         */
        static void destroy_n(T* p, std::size_t n) noexcept {
            destroy_range(p, p + n);
        }

        /**
         * Uninitialized copy N from src to dst
         */
        static void uninit_copy_n(const T* src, const std::size_t n, T* dst) {
            if constexpr (std::is_trivially_copyable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) ::new (static_cast<void*>(dst + i)) T(src[i]);
                } catch (...) {
                    destroy_n(dst, i);
                    throw;
                }
            }
        }

        /**
         * Uninitialized fill N with value starting at dst
         */
        static void uninit_fill_n(T* dst, const std::size_t n, const T& value) {
            std::size_t i = 0;
            try {
                for (; i < n; ++i) ::new (static_cast<void*>(dst + i)) T(value);
            } catch (...) {
                destroy_n(dst, i);
                throw;
            }
        }

        /**
         * Uninitialized value-initialize N elements at dst
         */
        static void uninit_value_construct_n(T* dst, const std::size_t n) {
            std::size_t i = 0;
            try {
                for (; i < n; ++i) ::new (static_cast<void*>(dst + i)) T();
            } catch (...) {
                destroy_n(dst, i);
                throw;
            }
        }

        /**
         * Assign n elements from src to dst (dst already constructed)
         */
        static void copy_or_move_assign(T* dst, const T* src, const std::size_t n) {
            if constexpr (std::is_trivially_copy_assignable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                for (std::size_t i = 0; i < n; ++i) dst[i] = src[i];
            }
        }

        /**
         * Growth policy: double, but at least new_cap
         */
        [[nodiscard]]
    	static std::size_t recommended_capacity(const std::size_t need) {
		    const std::size_t cur = need > 0 ? need : 1;
            // Try to double from current capacity if possible
            if (need > 0) {
                // Overflow-safe doubling
                const std::size_t doubled = (need > (static_cast<std::size_t>(-1) / 2)) ? need : need * 2;
                return doubled;
            }
            return cur;
        }

        /**
         * Ensure capacity for 'add' more elements
         */
        void ensure_grow_for(const std::size_t add) {
            const std::size_t newSize = size() + add;
            if (newSize > capacity()) {
                const std::size_t target = recommended_capacity(newSize);
                reallocate_to(target);
            }
        }

        /**
         * Destroy all elements
         */
        void destroy_all() noexcept {
            if (first_) destroy_range(first_, last_);
            last_ = first_;
        }

        /**
         * Deallocate buffer if owned/allowed
         *
         * Address: 0x004433A0 (FUN_004433A0)
         * Address: 0x004439A0 (FUN_004439A0)
         * Address: 0x00443C50 (FUN_00443C50)
         * Address: 0x00443F30 (FUN_00443F30)
         * Address: 0x004440A0 (FUN_004440A0)
         *
         * What it does:
         * Frees retained heap storage and clears all pointer lanes.
         */
        void deallocate_all() noexcept {
#if MSVC8_VECTOR_DISABLE_FREE
            first_ = last_ = end_ = nullptr;
#else
            if (first_) {
                ::operator delete(static_cast<void*>(first_));
                first_ = last_ = end_ = nullptr;
            }
#endif
        }

    public:
        /**
         * Address: 0x004439D0 (FUN_004439D0)
         *
         * What it does:
         * Returns `this` unchanged in trivial legacy lane wrappers that carry one
         * extra ignored tag argument.
         */
        [[nodiscard]] static void* identity_this_with_tag(void* const self, int) noexcept
        {
            return self;
        }

        /**
         * Address: 0x004439E0 (FUN_004439E0)
         * Address: 0x004442F0 (FUN_004442F0)
         *
         * What it does:
         * Returns `this` unchanged in trivial legacy lane wrappers.
         */
        [[nodiscard]] static void* identity_this(void* const self) noexcept
        {
            return self;
        }

        /**
         * Address: 0x00444300 (FUN_00444300)
         * Address: 0x00444670 (FUN_00444670)
         * Address: 0x00444A80 (FUN_00444A80)
         * Address: 0x00444D60 (FUN_00444D60)
         *
         * What it does:
         * Releases one heap block through the legacy VC8 delete lane.
         */
        static void delete_heap_block(void* const ptr) noexcept
        {
            ::operator delete(ptr);
        }

        /**
         * Address: 0x00444310 (FUN_00444310)
         * Address: 0x00444680 (FUN_00444680)
         * Address: 0x00444A90 (FUN_00444A90)
         * Address: 0x00444D70 (FUN_00444D70)
         *
         * What it does:
         * Allocates one raw 4-byte-slot heap block for `count` elements, preserving
         * the zero-count path that still routes through `operator new(0)`.
         */
        [[nodiscard]] static void* allocate_dword_slots(const std::size_t count)
        {
            if (count == 0) {
                return ::operator new(0);
            }

            return ::operator new(sizeof(std::uint32_t) * count);
        }

        /**
         * Address: 0x00445B80 (FUN_00445B80)
         * Address: 0x00445C90 (FUN_00445C90)
         * Address: 0x00445DC0 (FUN_00445DC0)
         * Address: 0x00445E80 (FUN_00445E80)
         * Address: 0x004C65E0 (FUN_004C65E0)
         * Address: 0x005DF3F0 (FUN_005DF3F0)
         * Address: 0x005DF520 (FUN_005DF520)
         * Address: 0x0067F7F0 (FUN_0067F7F0)
         * Address: 0x00704530 (FUN_00704530)
         *
         * IDA signature:
         * void *__fastcall sub_xxxx(unsigned int a1);
         *
         * What it does:
         * Allocates one raw 4-byte-slot heap block with explicit overflow guard.
         * Matches the legacy VC8 `std::_Allocate<T>(count, T*)` instantiation for
         * element types whose `sizeof(T) == 4` (typically `T*` pointer element).
         * On `count > 0x3FFFFFFF`, constructs a `std::bad_alloc` by invoking
         * `std::exception(const char *&)` then overwriting the vtable with
         * `std::bad_alloc::`vftable'`, then routes through `_CxxThrowException`.
         */
        [[nodiscard]] static void* allocate_dword_slots_checked(const std::size_t count)
        {
            if (count > (static_cast<std::size_t>(-1) / sizeof(std::uint32_t))) {
                throw std::bad_alloc();
            }

            return ::operator new(sizeof(std::uint32_t) * count);
        }

        /**
         * Address: 0x005A1D60 (FUN_005A1D60)
         *
         * IDA signature:
         * Moho::WeakPtr_CUnitCommand *__fastcall sub_5A1D60(unsigned int a1);
         *
         * What it does:
         * Allocates one raw 8-byte-slot heap block with explicit overflow guard.
         * Matches the legacy VC8 `std::_Allocate<T>(count, T*)` instantiation for
         * `moho::WeakPtr<moho::CUnitCommand>` (owner-link + next-in-chain, 8B).
         * On `count > 0x1FFFFFFF`, constructs a `std::bad_alloc` via the same
         * VC8 exception-then-vtable-swap lane routed through `_CxxThrowException`.
         */
        [[nodiscard]] static void* allocate_qword_slots_checked(const std::size_t count)
        {
            constexpr std::size_t kElementSize = 8u;
            if (count > (static_cast<std::size_t>(-1) / kElementSize)) {
                throw std::bad_alloc();
            }

            return ::operator new(kElementSize * count);
        }

        /**
         * Address: 0x004C6520 (FUN_004C6520)
         *
         * What it does:
         * Allocates one raw 64-byte-slot heap block with explicit overflow guard.
         * Matches the legacy VC8 `std::_Allocate<T>(count, T*)` instantiation for
         * a 64-byte element type.
         */
        [[nodiscard]] static void* allocate_struct64_slots_checked(const std::size_t count)
        {
            constexpr std::size_t kElementSize = 64u;
            if (count > (static_cast<std::size_t>(-1) / kElementSize)) {
                throw std::bad_alloc();
            }

            return ::operator new(kElementSize * count);
        }

        /**
         * Address: 0x00526080 (FUN_00526080)
         *
         * IDA signature:
         * void *__fastcall sub_526080(unsigned int a1);
         *
         * What it does:
         * Allocates one raw 388-byte-slot heap block with explicit overflow guard.
         * Matches the legacy VC8 `std::_Allocate<T>(count, T*)` instantiation for
         * `moho::RUnitBlueprintWeapon` (`sizeof = 0x184`). On
         * `count > 0xFFFFFFFF / 0x184 == 0x00AF7314`, constructs `std::bad_alloc`
         * and routes through `_CxxThrowException`.
         */
        [[nodiscard]] static void* allocate_unit_blueprint_weapon_slots_checked(const std::size_t count)
        {
            constexpr std::size_t kElementSize = 0x184u;
            if (count > (static_cast<std::size_t>(-1) / kElementSize)) {
                throw std::bad_alloc();
            }

            return ::operator new(kElementSize * count);
        }

        /**
         * Address: 0x00444250 (FUN_00444250)
         * Address: 0x00444350 (FUN_00444350)
         * Address: 0x004447E0 (FUN_004447E0)
         * Address: 0x00444F50 (FUN_00444F50)
         * Address: 0x00444FA0 (FUN_00444FA0)
         * Address: 0x00445040 (FUN_00445040)
         * Address: 0x00445050 (FUN_00445050)
         * Address: 0x00444AB0 (FUN_00444AB0)
         *
         * What it does:
         * Returns legacy max-element sentinel used by VC8 vector growth checks.
         */
        [[nodiscard]] static constexpr std::size_t max_elements_sentinel() noexcept
        {
            return 0x3FFFFFFFu;
        }

        /**
         * Address: 0x00444270 (FUN_00444270)
         * Address: 0x004445E0 (FUN_004445E0)
         * Address: 0x004449F0 (FUN_004449F0)
         * Address: 0x00444CD0 (FUN_00444CD0)
         *
         * What it does:
         * Throws `std::length_error` with the legacy VC8 vector overflow message.
         */
        [[noreturn]] static void throw_too_long()
        {
            throw std::length_error("vector<T> too long");
        }

    private:
        /**
         * Reallocate to exactly new_cap, preserving elements
         */
        void reallocate_to(std::size_t newCap) {
            assert(newCap >= size());
            // Route element-size-matched allocators through the VC8 legacy
            // `std::_Allocate` lanes so recovered decompiler addresses bind by
            // name from their original vector<T> call sites.
            void* rawBuf;
            if constexpr (sizeof(T) == sizeof(std::uint32_t)) {
                rawBuf = allocate_dword_slots_checked(newCap);
            } else if constexpr (sizeof(T) == 8u) {
                rawBuf = allocate_qword_slots_checked(newCap);
            } else if constexpr (sizeof(T) == 64u) {
                rawBuf = allocate_struct64_slots_checked(newCap);
            } else if constexpr (sizeof(T) == 0x184u) {
                rawBuf = allocate_unit_blueprint_weapon_slots_checked(newCap);
            } else {
                rawBuf = ::operator new(sizeof(T) * newCap);
            }
            T* newBuf = static_cast<T*>(rawBuf);
            T* newFirst = newBuf;
            T* newLast;
            const std::size_t n = size();

            // Move or copy existing elements
            if constexpr (
                std::is_move_constructible_v<T> &&
                (std::is_nothrow_move_constructible_v<T> || !std::is_copy_constructible_v<T>)
            ) {
                // Prefer move if nothrow or copy is unavailable
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) {
                        ::new (static_cast<void*>(newFirst + i)) T(std::move(first_[i]));
                    }
                    newLast = newFirst + n;
                } catch (...) {
                    destroy_n(newFirst, i);
                    ::operator delete(static_cast<void*>(newBuf));
                    throw;
                }
            } else if constexpr (
                std::is_trivially_copyable_v<T> ||
                (!std::is_move_constructible_v<T> && !std::is_copy_constructible_v<T>)
            ) {
                std::memcpy(newFirst, first_, n * sizeof(T));
                newLast = newFirst + n;
            } else {
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) {
                        ::new (static_cast<void*>(newFirst + i)) T(first_[i]);
                    }
                    newLast = newFirst + n;
                } catch (...) {
                    destroy_n(newFirst, i);
                    ::operator delete(static_cast<void*>(newBuf));
                    throw;
                }
            }

            // Destroy old elements and free old buffer
            destroy_all(); // destroys moved-from values too (OK)
#if MSVC8_VECTOR_DISABLE_FREE
            // If freeing disabled, just forget the old buffer
#else
            if (first_) {
                ::operator delete(static_cast<void*>(first_));
            }
#endif

            // Install new buffer
            first_ = newFirst;
            last_ = newLast;
            end_ = newFirst + newCap;
        }
    };
    static_assert(sizeof(vector<int>) == 16, "msvc8::set must be 16 bytes on x86");

    /**
     * Non-owning runtime view for legacy MSVC8 vector layout.
     *
     * Layout:
     *   +0x00: proxy pointer
     *   +0x04: begin
     *   +0x08: end
     *   +0x0C: capacity end
     */
    template <class T>
    struct vector_runtime_view
    {
        void* proxy;   // +0x00
        T* begin;      // +0x04
        T* end;        // +0x08
        T* capacityEnd;// +0x0C
    };
    static_assert(sizeof(vector_runtime_view<void>) == 0x10, "vector_runtime_view<T> must be 0x10");

    template <class T>
    [[nodiscard]] inline vector_runtime_view<T>& AsVectorRuntimeView(vector<T>& vec) noexcept
    {
        return *reinterpret_cast<vector_runtime_view<T>*>(&vec);
    }

    template <class T>
    [[nodiscard]] inline const vector_runtime_view<T>& AsVectorRuntimeView(const vector<T>& vec) noexcept
    {
        return *reinterpret_cast<const vector_runtime_view<T>*>(&vec);
    }

    /**
	 * Small-vector with inline storage and heap fallback (non-owning SDK view).
	 *
	 * Layout:
	 *   +0x00: T* first_          // begin
	 *   +0x04: T* last_           // one past last
	 *   +0x08: T* end_            // end of storage (inline or heap)
	 *   +0x0C: T* _InlineMirror   // points to &_Inline[0] (debug/mirror)
	 *   +0x10: T  _Inline[N]      // inline storage (N elements)
	 *
	 * This matches engine containers that keep a small inline buffer and switch
	 * to heap when overflowed. The triad always reflects the active storage.
	 *
	 * NOTE:
	 *  - This is a non-owning view over already-laid-out memory inside engine objects.
	 *  - Safe to use for reads/iteration; do not mutate unless you fully control engine logic.
	 */
    template <class T, std::size_t N>
    struct inline_vector {
        T* first_;         // 0x00
        T* last_;          // 0x04
        T* end_;           // 0x08
        T* _InlineMirror;  // 0x0C (usually == &_Inline[0])
        T   _Inline[N];     // 0x10 .. 0x10 + N*sizeof(T)

        // --- std-like API (read-only friendly) ---
        T* begin() const noexcept { return first_; }
        T* end()   const noexcept { return last_; }
        [[nodiscard]] bool empty() const noexcept { return first_ == last_; }
        [[nodiscard]] std::size_t size() const noexcept { return static_cast<std::size_t>(last_ - first_); }
        [[nodiscard]] std::size_t capacity() const noexcept { return static_cast<std::size_t>(end_ - first_); }
        T& operator[](std::size_t i) const noexcept { return first_[i]; }
        T* data() const noexcept { return first_; }

        // Diagnostics helpers
        [[nodiscard]] T* inline_begin() const noexcept { return const_cast<T*>(&_Inline[0]); }
        [[nodiscard]] T* inlineend_()   const noexcept { return const_cast<T*>(&_Inline[0]) + N; }
        [[nodiscard]] static std::size_t inline_capacity() noexcept { return N; }
        [[nodiscard]] bool using_inline() const noexcept {
            return first_ >= inline_begin() && first_ <= inlineend_();
        }
    };

    template <class T, class Alloc = std::allocator<T> >
    class list : public _Container_base
    {
    public:
        typedef T                value_type;
        typedef Alloc            allocator_type;
        typedef std::size_t      size_type;
        typedef std::ptrdiff_t   difference_type;
        typedef T* pointer;
        typedef const T* const_pointer;
        typedef T& reference;
        typedef const T& const_reference;

    private:
        struct _Node;
        struct _Node_base
        {
            _Node_base* _Next;
            _Node_base* _Prev;
        };

        struct _Node : _Node_base
        {
            value_type _Value;

            _Node()
                : _Node_base()
                , _Value()
            {
                this->_Next = this;
                this->_Prev = this;
            }

            explicit _Node(const value_type& v)
                : _Node_base()
                , _Value(v)
            {
                this->_Next = this;
                this->_Prev = this;
            }
        };

        typedef typename std::allocator_traits<Alloc>::template rebind_alloc<_Node> _Node_alloc_type;
        typedef _Node_base* _Nodeptr;

        _Nodeptr  _Myhead;   // offset +4 from base
        size_type _Mysize;   // offset +8 from base

    public:
        class iterator
        {
            friend class list;
            _Nodeptr _Ptr;

            explicit iterator(_Nodeptr p)
                : _Ptr(p)
            {
            }

        public:
            typedef std::bidirectional_iterator_tag iterator_category;
            typedef value_type        value_type;
            typedef difference_type   difference_type;
            typedef pointer           pointer;
            typedef reference         reference;

            iterator()
                : _Ptr(0)
            {
            }

            reference operator*() const
            {
                return static_cast<_Node*>(_Ptr)->_Value;
            }

            pointer operator->() const
            {
                return &static_cast<_Node*>(_Ptr)->_Value;
            }

            iterator& operator++()
            {
                _Ptr = _Ptr->_Next;
                return *this;
            }

            iterator operator++(int)
            {
                iterator tmp(*this);
                ++(*this);
                return tmp;
            }

            iterator& operator--()
            {
                _Ptr = _Ptr->_Prev;
                return *this;
            }

            iterator operator--(int)
            {
                iterator tmp(*this);
                --(*this);
                return tmp;
            }

            bool operator==(const iterator& other) const
            {
                return _Ptr == other._Ptr;
            }

            bool operator!=(const iterator& other) const
            {
                return _Ptr != other._Ptr;
            }
        };

        class const_iterator
        {
            friend class list;
            _Nodeptr _Ptr;

            explicit const_iterator(_Nodeptr p)
                : _Ptr(p)
            {
            }

        public:
            typedef std::bidirectional_iterator_tag iterator_category;
            typedef value_type        value_type;
            typedef difference_type   difference_type;
            typedef const_pointer     pointer;
            typedef const_reference   reference;

            const_iterator()
                : _Ptr(0)
            {
            }

            const_iterator(const iterator& it)
                : _Ptr(it._Ptr)
            {
            }

            reference operator*() const
            {
                return static_cast<_Node*>(_Ptr)->_Value;
            }

            pointer operator->() const
            {
                return &static_cast<_Node*>(_Ptr)->_Value;
            }

            const_iterator& operator++()
            {
                _Ptr = _Ptr->_Next;
                return *this;
            }

            const_iterator operator++(int)
            {
                const_iterator tmp(*this);
                ++(*this);
                return tmp;
            }

            const_iterator& operator--()
            {
                _Ptr = _Ptr->_Prev;
                return *this;
            }

            const_iterator operator--(int)
            {
                const_iterator tmp(*this);
                --(*this);
                return tmp;
            }

            bool operator==(const const_iterator& other) const
            {
                return _Ptr == other._Ptr;
            }

            bool operator!=(const const_iterator& other) const
            {
                return _Ptr != other._Ptr;
            }
        };

        typedef std::reverse_iterator<iterator>       reverse_iterator;
        typedef std::reverse_iterator<const_iterator> const_reverse_iterator;

        list()
            : _Myhead(0)
            , _Mysize(0)
        {
            _Init();
        }

        explicit list(const allocator_type&)
            : _Myhead(0)
            , _Mysize(0)
        {
            _Init();
        }

        ~list()
        {
            _Tidy();
            _Free_head();
            _Free_proxy();
        }

        bool empty() const
        {
            return _Mysize == 0;
        }

        size_type size() const
        {
            return _Mysize;
        }

        iterator begin()
        {
            return iterator(_Myhead->_Next);
        }

        const_iterator begin() const
        {
            return const_iterator(_Myhead->_Next);
        }

        iterator end()
        {
            return iterator(_Myhead);
        }

        const_iterator end() const
        {
            return const_iterator(_Myhead);
        }

        reverse_iterator rbegin()
        {
            return reverse_iterator(end());
        }

        const_reverse_iterator rbegin() const
        {
            return const_reverse_iterator(end());
        }

        reverse_iterator rend()
        {
            return reverse_iterator(begin());
        }

        const_reverse_iterator rend() const
        {
            return const_reverse_iterator(begin());
        }

        reference front()
        {
            return *begin();
        }

        const_reference front() const
        {
            return *begin();
        }

        reference back()
        {
            iterator it = end();
            --it;
            return *it;
        }

        const_reference back() const
        {
            const_iterator it = end();
            --it;
            return *it;
        }

        void clear()
        {
            _Tidy();
        }

        void push_back(const value_type& v)
        {
            insert(end(), v);
        }

        void push_front(const value_type& v)
        {
            insert(begin(), v);
        }

        iterator insert(const_iterator pos, const value_type& v)
        {
            _Node_alloc_type al;
            _Node* node = al.allocate(1);
            new (node) _Node(v);

            _Nodeptr where = pos._Ptr;
            _Nodeptr prev = where->_Prev;

            node->_Next = where;
            node->_Prev = prev;
            prev->_Next = node;
            where->_Prev = node;

            ++_Mysize;
            return iterator(node);
        }

        iterator erase(const_iterator pos)
        {
            _Nodeptr node = pos._Ptr;
            _Nodeptr next = node->_Next;
            _Nodeptr prev = node->_Prev;

            prev->_Next = next;
            next->_Prev = prev;

            _Node_alloc_type al;
            _Node* ptr = static_cast<_Node*>(node);
            ptr->~_Node();
            al.deallocate(ptr, 1);

            --_Mysize;
            return iterator(next);
        }

    private:
        void _Init()
        {
            _Alloc_proxy();
            _Buy_head();
        }

        void _Alloc_proxy()
        {
            this->_Myproxy = new _Container_proxy();
            this->_Myproxy->_Myfirstiter = 0;
        }

        void _Free_proxy()
        {
            delete this->_Myproxy;
            this->_Myproxy = 0;
        }

        void _Buy_head()
        {
            _Node_alloc_type al;
            _Node* head = al.allocate(1);
            new (head) _Node();      // sentinel
            _Myhead = head;
            _Mysize = 0;
        }

        void _Free_head()
        {
            if (!_Myhead)
                return;

            _Node_alloc_type al;
            _Node* head = static_cast<_Node*>(_Myhead);
            head->~_Node();
            al.deallocate(head, 1);
            _Myhead = 0;
        }

        void _Tidy()
        {
            if (!_Myhead)
                return;

            _Node_alloc_type al;
            _Nodeptr head = _Myhead;
            _Nodeptr cur = head->_Next;

            while (cur != head)
            {
                _Nodeptr next = cur->_Next;
                _Node* node = static_cast<_Node*>(cur);
                node->~_Node();
                al.deallocate(node, 1);
                cur = next;
            }

            head->_Next = head;
            head->_Prev = head;
            _Mysize = 0;
        }
    };
    static_assert(sizeof(list<int>) == 0xC, "list<int> == 0xC");

    template<class T>
	struct linked_list
    {
	    void* head;
    	void* tail;
    };
    static_assert(sizeof(linked_list<int>) == 8, "linked_list<int> == 8");
}
