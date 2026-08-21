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
         * Address: 0x005C5580 (FUN_005C5580,
         * msvc8::vector<Moho::SPerArmyReconInfo>::~vector -- VC8's `_Tidy()`:
         * destroys `[mFirst, mLast)` then `operator delete`s the block and nulls
         * all three pointer lanes. MSVC emits the call automatically because
         * `mReconDat` is `Moho::ReconBlip`'s last-declared member, which is why
         * it is the first teardown step of `~ReconBlip` at 0x005BECBB.)
         * Address: 0x005C3C10 (FUN_005C3C10, the calling-convention thunk MSVC
         * emits for the same destructor when reached from a constructor's
         * unwind funclet)
         *
         * Destructor: destroy elements and free storage if allowed
         */
        ~vector() {
            destroy_all();
            deallocate_all();
        }

        /**
         * Address: 0x008D76B0 (FUN_008D76B0, msvc8::vector<std::int32_t>::operator=(const vector&))
         * Address: 0x008D77E0 (FUN_008D77E0, msvc8::vector<std::int32_t>::operator=(const vector&) twin)
         * Address: 0x008D7550 (FUN_008D7550, msvc8::vector<gpg::gal::HeadAdapterMode>::operator=(const vector&))
         * Address: 0x006E2F30 (FUN_006E2F30, msvc8::vector<void*>::operator=(const vector&))
         * Address: 0x008D4800 (FUN_008D4800, msvc8::vector<gpg::gal::Head>::operator=(const vector&))
         * Address: 0x008D73C0 (FUN_008D73C0, msvc8::vector<gpg::gal::HeadSampleOption>::operator=(const vector&))
         * Address: 0x005ED190 (FUN_005ED190, msvc8::vector<int>::operator=(const vector&))
         * Address: 0x0071E030 (FUN_0071E030,
         * msvc8::vector<Moho::InfluenceGrid>::operator=(const vector&) --
         * the same VC8 assign shape with rollback-safe copy-construction on
         * both the capacity-reuse and full-reallocation paths)
         * Address: 0x0077E100 (FUN_0077E100,
         * msvc8::vector<Moho::SDecalInfo>::operator=(const vector&) for the
         * 0x90-byte element -- same VC8 assign shape: clear on an empty
         * source, assign-over-then-uninit-copy-the-excess when the source is
         * longer but fits, _Tidy + _Buy + _Ucopy when it does not)
         * Address: 0x005CA980 (FUN_005CA980,
         * msvc8::vector<Moho::SPerArmyReconInfo>::operator=(const vector&) for the
         * 52-byte element -- the full VC8 `assign` shape: erase-all on an empty
         * source, copy-assign-over-then-uninit-copy-the-excess when the source is
         * longer but fits in capacity, `_Tidy` + `_Buy` + `_Ucopy` when it does
         * not, and copy-assign-then-destroy-the-tail when the source is shorter)
         * Address: 0x00548ED0 (FUN_00548ED0,
         * msvc8::vector<Moho::ResourceDeposit>::operator=(const vector&) for
         * the 20-byte element -- 148 instructions carrying the same VC8 assign
         * shape, calling the `std::copy` lane FUN_00548C00 three times, once
         * per branch. Reached from `RVectorType_ResourceDeposit::SerLoad`'s
         * closing `*storage = loaded;`.)
         *
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
         * Address: 0x0054C170 (FUN_0054C170,
         * msvc8::vector<Moho::SAniSkelBoneNameIndex>::begin -- the out-pointer
         * form MSVC emits when the result is returned through a caller slot)
         *
         * What it does:
         * Returns the first element pointer lane (`first_`).
         */
        T* begin() const noexcept { return first_; }

        /**
         * Address: 0x004433E0 (FUN_004433E0)
         * Address: 0x00443E50 (FUN_00443E50)
         * Address: 0x00444340 (FUN_00444340)
         * Address: 0x0054C180 (FUN_0054C180,
         * msvc8::vector<Moho::SAniSkelBoneNameIndex>::end -- same out-pointer
         * form as FUN_0054C170)
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
         * Address: 0x005DB5E0 (FUN_005DB5E0, msvc8::vector<EntityCategorySet>::size,
         *   `weapon->mTargetPriorities.size()` in CAiAttackerImpl.cpp)
         *
         * What it does:
         * Address: 0x0054C1B0 (FUN_0054C1B0,
         * msvc8::vector<Moho::SAniSkelBoneNameIndex>::size)
         *
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
         * Address: 0x0054DC40 (FUN_0054DC40,
         * msvc8::vector<Moho::SAniSkelBone>::capacity)
         * Address: 0x0054DCA0 (FUN_0054DCA0,
         * msvc8::vector<Moho::SAniSkelBoneNameIndex>::capacity)
         *
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
         * Address: 0x00882920 (FUN_00882920, msvc8::vector<moho::SSavedGameArmyInfo>::reserve
         * out-of-line emission — reallocate-to-capacity for the 0x1C-byte element)
         * Address: 0x006DC3C0 (FUN_006DC3C0, msvc8::vector<moho::EntityCategorySet>::reserve
         * out-of-line emission — reallocate-to-capacity for the 0x28-byte element)
         * Address: 0x006DC9F0 (FUN_006DC9F0, msvc8::vector<moho::SBlackListInfo>::reserve
         * out-of-line emission — reallocate-to-capacity for the 0x0C-byte element;
         * invoked by name from moho::LoadSBlackListInfoVector's reserve(count) path)
         * Address: 0x0067D9B0 (FUN_0067D9B0, msvc8::vector<moho::Entity*>::reserve
         * out-of-line emission — reallocate-to-capacity for the 4-byte pointer element;
         * invoked by name from moho::LoadEntityPointerVector's reserve(count) path)
         * Address: 0x005437F0 (FUN_005437F0, msvc8::vector<moho::ArmyLaunchInfo>::reserve
         * out-of-line emission — reallocate-to-capacity for the 0x20-byte element;
         * invoked by name from ArmyLaunchInfoVectorTypeInfo::SerLoad's reserve(count) path)
         * Address: 0x006EB1D0 (FUN_006EB1D0, msvc8::vector<moho::WeakPtr<moho::CUnitCommand>>::reserve
         * out-of-line emission — reallocate-to-capacity for the 8-byte weak-link element;
         * invoked by name from moho::LoadWeakPtrCUnitCommandVector's reserve(count) path)
         * Address: 0x005EAE10 (FUN_005EAE10, msvc8::vector<moho::SAiReservedTransportBone>::reserve
         * out-of-line emission — reallocate-to-capacity for the 0x20-byte element;
         * invoked by name from gpg::RVectorType_SAiReservedTransportBone::SerLoad's reserve(count) path)
         * Address: 0x005DD400 (FUN_005DD400, msvc8::vector<Moho::CAcquireTargetTask*>::reserve
         * out-of-line emission — reallocate-to-capacity for the 4-byte pointer element;
         * invoked by name from gpg::RVectorType_CAcquireTargetTask_P::SerLoad's reserve(count) path)
         * Address: 0x0057FF70 (FUN_0057FF70, msvc8::vector<moho::SPointVector>::reserve
         * out-of-line emission — reallocate-to-capacity for the 0x18-byte element;
         * invoked by name from gpg::RVectorType_SPointVector::SerLoad's reserve(count) path)
         * Address: 0x005DCFB0 (FUN_005DCFB0, msvc8::vector<Moho::UnitWeapon*>::reserve
         * out-of-line emission — reallocate-to-capacity for the 4-byte pointer element;
         * invoked by name from gpg::RVectorType_UnitWeapon_P::SerLoad's reserve(count) path)
         * Address: 0x0071B730 (FUN_0071B730, msvc8::vector<moho::InfluenceGrid>::reserve
         * out-of-line emission for the 0x8C-byte non-trivial element. Unlike the
         * `_Insert_n` bodies it opens with a bare `count > max_size()` test
         * (`cmp esi, 1D41D41h` at 0x0071B750 — 0xFFFFFFFF/140 — then
         * `call FUN_0071BCA0`, the `vector<T> too long` throw lane), takes a single
         * stack argument (`retn 4`), performs no tail shift and no fill: it moves the
         * live range into the fresh block (0x0071B7C3), destroys and frees the old
         * one, then rebases `{first,last,end}` (0x0071B82A-0x0071B830). Emitted by
         * moho::LoadInfluenceGridVectorArchive's `loaded.reserve(count)`
         * (CInfluenceMap.cpp:1860), which is the binary's own call at 0x0071A383)
         *
         * Reserve storage for at least new_cap elements
         */
        /**
         * Address: 0x005082B0 (FUN_005082B0,
         * msvc8::vector<Moho::SDelayedSubVizInfo>::reserve -- exact-capacity
         * grow: max_size guard, one `operator new(requiredCapacity * 0x18)`,
         * element-wise copy of the live range into it, free the old block,
         * rebase all three lanes. Reached from the delayed-sub-viz reflection
         * loader and from `operator=`'s _Buy path.)
         * Address: 0x00547E00 (FUN_00547E00,
         * msvc8::vector<Moho::ResourceDeposit>::reserve -- opens with the
         * max_size guard against 0x0CCCCCCC, which is exactly
         * `0xFFFFFFFF / 0x14`, then allocates, uninit-copies the live range
         * through FUN_00549BC0, frees the old block and rebases the lanes.
         * Reached from `RVectorType_ResourceDeposit::SerLoad` (0x00547950),
         * which reserves the archived count before filling.)
         *
         * Reserve at least `newCap` elements without changing size.
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
         * Address: 0x0074DC40 (FUN_0074DC40, msvc8::vector<Moho::CArmyImpl*>::resize)
         * Address: 0x005EA3F0 (FUN_005EA3F0, SEH-wrapped entry lane)
         * Address: 0x005EAF30 (FUN_005EAF30, msvc8::vector<Moho::SAiReservedTransportBone>::resize)
         * Address: 0x005EA590 (FUN_005EA590, grow/insert-tail helper)
         * Address: 0x005A0740 (FUN_005A0740, msvc8::vector<Moho::WeakPtr<Moho::CUnitCommand>>::resize
         * — specialized "resize from empty" fast path: unconditionally allocates a
         * fresh `newSize`-element block with no prior-buffer check, matching this
         * method's grow branch when `cur == 0`. Every real call site reaches it with
         * a genuinely empty destination: `CopyWeakPtrCUnitCommandVector`'s own
         * `destination.resize(sourceSize)` call is only ever made on a freshly
         * constructed local vector or one just emptied by
         * `ResetWeakPtrCUnitCommandVectorStorage` (see
         * `CFactoryBuildTask.cpp`'s `SnapshotFactoryCommandQueue`, which resets
         * `commands` between its two copy calls for exactly this reason) —
         * `CopyWeakPtrCUnitCommandVector` is itself called from
         * `CFactoryBuildTask::InheritQueuedCommandsTo`, `CUnitFerryTask::GetUnitCommands`,
         * and `ReplaceWithRouteCommandsIfAny`)
         *
         * What it does:
         * Resizes logical element count to `newSize` by erasing tail elements when
         * shrinking or value-initializing appended slots when growing. The 4-byte
         * stride binary specialization at `0x0074DC40` is the
         * `std::vector<CArmyImpl*>::resize` emission used by `Moho::Sim::SerArmies`
         * (line `mArmiesList.resize(...)`) and `Moho::Sim::CreateArmies` — these
         * sites invoke this method by name through the `msvc8::vector<T>` API. The
         * 0x20-byte stride specialization at `0x005EAF30` (`SAiReservedTransportBone`,
         * reached through the SEH-wrapped call-site lane at `0x005EA3F0`) is the
         * `RVectorType<SAiReservedTransportBone>` reflection SetCount emission; its
         * own grow path (`0x005EA590`) matches this method's grow branch exactly
         * (same 1.5x growth and value-initialized new slots), just compiled with
         * the extra SEH landing pad MSVC emits when element construction can
         * throw.
         *
         * Address: 0x005C3C20 (FUN_005C3C20,
         * msvc8::vector<Moho::SPerArmyReconInfo>::resize(size_type) -- builds the
         * value-initialized `_Ty()` temporary on the stack and tail-calls the
         * two-argument overload FUN_005C5460, which is precisely VC8's
         * `resize(_Newsize) { resize(_Newsize, _Ty()); }`.)
         */
        void resize(std::size_t newSize) {
            // VC8 defines this as `resize(_Newsize, _Ty())` -- the temporary is
            // what FUN_005C3C20 builds before tail-calling FUN_005C5460.
            resize(newSize, T());
        }

        /**
         * Address: 0x0082D820 (FUN_0082D820, msvc8::vector<void*>::resize for
         * UICommandGraph's hash-bucket vector -- grows through the `_Insert_n`
         * lane FUN_0082F210, shrinks by rebasing `mLast` (the erase call
         * degenerates to a pointer update because the element is trivially
         * destructible). Reached from the bucket-table rehash path.)
         * Address: 0x005083C0 (FUN_005083C0,
         * msvc8::vector<Moho::SDelayedSubVizInfo>::resize -- grows through the
         * `_Insert_n` lane FUN_00508480 at `end()`, shrinks by erasing the
         * `[begin() + n, end())` tail. Reached from the reflection SetCount
         * lane, which passes a value-initialised fill.)
         * Address: 0x005C5460 (FUN_005C5460,
         * msvc8::vector<Moho::SPerArmyReconInfo>::resize for the 52-byte element
         * -- `size()` computed with the 4EC4EC4Fh/`sar 4` divide-by-0x34 magic
         * pair at 0x005C5497, growth tail-calling the `_Insert_n` lane
         * FUN_005C6F90 at 0x005C54D1 with `(mLast, newSize - size())`, shrink
         * tail-calling `erase(begin() + newSize, end())` (FUN_005C6F00) at
         * 0x005C54F6. Reached from `Moho::CReconBlipManagerImpl`'s per-army
         * table sizing.)
         * Address: 0x00547F20 (FUN_00547F20,
         * msvc8::vector<Moho::ResourceDeposit>::resize for the 20-byte element
         * -- `size()` via the 66666667h/`sar 3` divide-by-0x14 magic pair,
         * growing through the `_Insert_n` lane FUN_00547FE0 and shrinking by
         * recomputing `_Mylast` through the copy lane FUN_00548C00. Its caller
         * `RVectorType_ResourceDeposit::SetCount` (0x00547650) shows the
         * one-argument overload inlined into it: it reserves 0x14 stack bytes,
         * zeroes all five dwords to build the `ResourceDeposit()` temporary,
         * loads `edi`/`ebx` with the vector and the new count and falls into
         * this body, which pops the by-value `_Val` with `retn 14h`.)
         *
         * What it does:
         * The VC8 `vector<T>::resize(_Newsize, _Val)` lane: grows by inserting
         * `_Newsize - size()` copies of `_Val` at `end()`, shrinks by erasing
         * the `[begin() + _Newsize, end())` tail, and does nothing when the
         * sizes already match.
         *
         * Note the binary takes `_Val` **by value** (VC8's signature is
         * `resize(size_type, _Ty)`), which is why FUN_005C5460 destroys a stack
         * temporary on exit; taking it by const-ref here is equivalent because
         * `insert` copies into its own local before any reallocation.
         */
        void resize(std::size_t newSize, const T& value) {
            const std::size_t cur = size();
            if (cur < newSize) {
                insert(last_, newSize - cur, value);
            } else if (newSize < cur) {
                erase(first_ + newSize, last_);
            }
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
        /**
         * Address: 0x0077E2D0 (FUN_0077E2D0,
         * msvc8::vector<Moho::SDecalInfo>::clear -- destroys the live run and
         * rewinds mLast to mFirst without releasing capacity)
         */
        void clear() noexcept {
            destroy_all();
            last_ = first_;
        }

        /**
         * Exchange contents with another vector.
         *
         * What it does:
         * Swaps the three data-range lanes `{first_, last_, end_}` with `other`.
         * The VC8 debug-iterator lane (`myProxy_`) is intentionally left in
         * place: release builds never populate it, and the binary's swap sites
         * touch only the three range lanes — see the tail of
         * `moho::LoadInfluenceGridVectorArchive` (FUN_0071A330), where the
         * scratch vector's lanes are stored into the destination at
         * 0x0071A44E / 0x0071A458 / 0x0071A45F while the destination's previous
         * `{first, last}` pair is kept in registers and torn down by the
         * scratch's scope-exit teardown at 0x0071A477 / 0x0071A47D.
         */
        void swap(vector& other) noexcept {
            T* const otherFirst = other.first_;
            T* const otherLast = other.last_;
            T* const otherEnd = other.end_;
            other.first_ = first_;
            other.last_ = last_;
            other.end_ = end_;
            first_ = otherFirst;
            last_ = otherLast;
            end_ = otherEnd;
        }

        /**
         * Push by const&
         *
         * Address: 0x00443300 (FUN_00443300)
         * Address: 0x00443420 (FUN_00443420)
         * Address: 0x0057D820 (FUN_0057D820, msvc8::vector<SAiAttackVectorDebug>::push_back)
         * Address: 0x007C8F30 (FUN_007C8F30, msvc8::vector<Moho::LaunchPlayerOptionEntry>::push_back)
         * Address: 0x007E3850 (FUN_007E3850, msvc8::vector<Moho::MeshLOD*>::push_back — Mesh::CreateLOD lods.push_back)
         * Address: 0x0075F1A0 (FUN_0075F1A0, msvc8::vector<Moho::Sim::DumpUnitsCountEntry>::push_back
         * splitter for the 8-byte element {const RUnitBlueprint* blueprint; int count};
         * Sim::DumpUnits invokes counts.push_back({blueprint,1}) by name — on the
         * capacity-full path this routes to insert(end(),1,value) → _Insert_n
         * (FUN_0075F810), on the fast path it appends in place)
         * Address: 0x00769D00 (FUN_00769D00, msvc8::vector<gpg::AStarOpenHeap<TCell>::Entry>::insert
         * iterator-returning wrapper — gpg::AStarSearch.h's AStarOpenHeap::Push calls
         * mEntries.push_back(entry) by name; the 12-byte Entry stride routes through
         * this insert(end(),1,value)-shaped lane on the capacity-full path. Grow core
         * at 0x00769F60)
         * Address: 0x007BB120 (FUN_007BB120, msvc8::vector<Moho::SNetCommandArg>::push_back
         * — its own capacity-full path routes through the 36-byte insert-return
         * wrapper at 0x007BB780, whose grow core is 0x007BBD60)
         * Address: 0x006D1960 (FUN_006D1960, msvc8::vector<moho::SUpgradeNotifyPair>::push_back
         * for the 8-byte `{mSourceId, mDestId}` element — `sar 3` stride at 0x006D1974
         * and 0x006D1980. The fast path copies the two dwords through FUN_006D2730
         * (0x006D19A0); the capacity-full path tail-calls the `_Insert_n` grow lane
         * FUN_006D1A90 at 0x006D19BA, skipping the iterator-returning wrapper because
         * push_back discards the iterator. A 16-byte linker-emitted bridge (FUN_006C38E0)
         * whose whole body is `call sub_6D1960` at 0x006C38E9 folds onto this same
         * symbol, so both addresses resolve here. Emitted via
         * globalUserdata->mAllyUpgradeNotifications.push_back(pair) in
         * moho::cfunc_NotifyUpgradeL (Unit.cpp:11966), whose owner lane is
         * Moho::Sim::mAllyUpgradeNotifications at Sim+0x9D8)
         * Address: 0x0057E6A0 (FUN_0057E6A0, msvc8::vector<Moho::Unit*>::push_back
         * — fast path only (no grow-core citation found); emitted via
         * storedCargo.push_back(storedUnit) in Sim::TransferUnit (Sim.cpp:11097),
         * one of several local msvc8::vector<Unit*> scratch lists in that function)
         * Address: 0x0075F050 (FUN_0075F050, msvc8::vector<Moho::SPendingPoseCopy>::push_back
         * splitter for the 12-byte `{EntId, boost::shared_ptr<CAniPose>}` element —
         * fast path copies one element in place via `uninit_copy_n`'s per-T emission
         * (FUN_0075FEA0, refcount-bumping copy of the `shared_ptr<CAniPose>` tail);
         * capacity-full path tail-calls the insert(end(),1,value) grow lane
         * (FUN_0075F240 → `_Insert_n` core FUN_0075F4B0). Emitted via
         * sim->mPendingPoseCopies.push_back(entry) in cfunc_TryCopyPoseL
         * (Sim.cpp), whose owner lane is Moho::Sim::mPendingPoseCopies at Sim+0x9E8)
         * Address: 0x0067B780 (FUN_0067B780, msvc8::vector<Moho::SEntityVariableUpdateEntry>::push_back
         * for the 0xD8-byte `{EntId, reserved, SSTIEntityVariableData}` record —
         * IDA's own type library names the element `pair_EntId_SSTIEntityVariableData`,
         * matching this struct's real shape. Emitted via
         * syncData->mEntityUpdates.push_back(defaultEntry) in
         * QueueEntityVariableUpdate (SimDriver.cpp), called from
         * Entity::SyncInterface)
         * Address: 0x005DBD90 (FUN_005DBD90, msvc8::vector<Moho::UnitWeapon*>::push_back
         * for `CAiAttackerImplRuntimeView::mWeapons` — fast path appends the raw
         * pointer in place; capacity-full path tail-calls the insert(end(),1,value)
         * grow lane `_Insert_n` (FUN_005DD120, already cited above). Emitted via
         * view->mWeapons.push_back(weapon) in CAiAttackerImpl::CreateWeapon
         * (CAiAttackerImpl.cpp:973))
         * Address: 0x008522A0 (FUN_008522A0, msvc8::vector<Wm3::Vector3f>::push_back
         * for the 12-byte `Wm3::Vector3f` element — fast path only (no grow-core
         * citation found). Emitted via attackIconPositions.push_back(targetPosition)
         * / teleportIconPositions.push_back(targetPosition) in
         * Moho::CWldSession::DrawCommandSplats (CWldSession.cpp), queuing each
         * command-splat's icon-billboard world position for the batched
         * attack_btn_up.dds / teleport_btn_up.dds draw passes that follow the
         * main per-command-link loop)
         *
         * What it does:
         * Appends one value at the end, growing capacity when the active range
         * reaches `end_`. The MSVC8 STL emits one inlined fast-path body per
         * engine-type specialization; each `Address:` tag above identifies the
         * binary symbol for one such specialization, and the recovered caller
         * (e.g. `CAiBrain::ProcessAttackVectors`, `cfunc_GpgNetSendL`,
         * `CLobby::LaunchGame`) invokes this method by name through the
         * `msvc8::vector<T>` API surface — that is the source-level invocation
         * the linker uses to keep the symbol shape in the recovered binary.
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
         * Drops the last element without running its destructor.
         *
         * Intrusive-node vectors in the shipped engine shorten their run with
         * a bare `_Mylast` decrement after having already re-seated every
         * affected owner chain slot by hand (see the quick-select registry
         * compaction at FUN_008B2470 @ 0x008B2513). Running `~T()` there would
         * walk a chain the node is no longer part of.
         */
        void pop_back_no_destroy() noexcept {
            --last_;
        }

        /**
         * Publishes one already-constructed slot past `mLast` without running a
         * constructor.
         *
         * The mirror of `pop_back_no_destroy`, for the other half of the same
         * binary idiom: several recovered lanes reserve exact capacity, fill
         * the reserved slots through a per-type uninitialised-copy helper, and
         * then advance `_Mylast` with a bare store to publish the new size (see
         * the factory build-queue publish path at 0x00836DBF/0x00836DEC).
         * Running `T()` here would overwrite what the fill just built.
         *
         * The caller is responsible for having constructed the slot; capacity
         * must already cover it.
         */
        void push_back_no_construct() noexcept {
            assert(last_ != end_);
            ++last_;
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
         * Address: 0x00899880 (FUN_00899880, msvc8::vector<moho::UserArmy*>::assign
         * -- nulls the three lanes, returns early on `_Count == 0`, guards
         * `0xFFFFFFFF / 4 < _Count` with a `vector<T> too long` throw, then makes
         * one exact-size `operator new(_Count * 4)` and fills every slot from the
         * by-ref value. Reached from `CWldSession`'s session-init path, which
         * pre-sizes `userArmies` to one null slot per launch-info army because
         * `DoBeat` addresses it by army index rather than appending.)
         * Address: 0x00898EC0 (FUN_00898EC0, the null-fill adapter around it --
         * builds the `nullptr` temporary and returns the destination for
         * chaining)
         * Address: 0x0082F110 (FUN_0082F110, msvc8::vector<void*>::assign(9, sentinel)
         * for UICommandGraph's MapAB hash-bucket table)
         * Address: 0x0082F680 (FUN_0082F680, the MapC emission of the same)
         * Address: 0x0082FB80 (FUN_0082FB80, the MapD emission of the same)
         *
         * What it does:
         * The VC8 `vector<T>::assign(_Count, _Val)` lane: copies `_Val` into a
         * local, empties the vector, then inserts `_Count` copies at `begin()`.
         * On an empty vector that lands as a single exact-size allocation --
         * which is why the three emissions above show a bare
         * `operator new(9 * 4)` followed by a nine-slot sentinel fill.
         */
        void assign(std::size_t count, const T& value) {
            const T localValue(value);
            clear();
            insert(first_, count, localValue);
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
                        // MoveWords returns its destination cursor; erase only needs the
                        // shift performed, so the result is deliberately discarded.
                        (void)detail::MoveWords(next, tail, pos);
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
         * Address: 0x008555E0 (FUN_008555E0,
         * msvc8::vector<boost::shared_ptr<T>>::erase(first, last) -- move-assigns
         * the surviving tail forward over the erased slots, releases the
         * now-orphan trailing control blocks, and rewinds mLast. Returns
         * `first`, the MSVC iterator-after-erase contract. Reached from
         * `CUIWorldViewBuildDragRuntimeView::ClearBuildPreviewCache`.)
         * Address: 0x005C6F00 (FUN_005C6F00,
         * msvc8::vector<Moho::SPerArmyReconInfo>::erase(first, last) for the
         * 52-byte element -- copy-assigns the `[last, mLast)` tail down over the
         * gap, destroys the vacated tail slots through the range-destroy lane
         * FUN_005C6F70, and rebases `mLast`. Reached from `resize`'s shrink
         * branch (FUN_005C5460) and from the recon-info vector copy-assign
         * lane's empty-source path in ReconBlip.cpp.)
         *
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
                        // MoveWords returns its destination cursor; erase only needs the
                        // shift performed, so the result is deliberately discarded.
                        (void)detail::MoveWords(last, tail, first);
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

        /**
         * Insert `count` copies of `value` at iterator `pos`.
         *
         * Address: 0x008DD050 (FUN_008DD050, msvc8::vector<gpg::RType*>::_Insert_n
         * grow lane for the global reflection TypeVec; the recovered caller
         * gpg::RType::RegisterType invokes insert(end(), 1, this) by name so this
         * per-T symbol is emitted).
         * Address: 0x006E24D0 (FUN_006E24D0, msvc8::vector<Moho::CmdId>::_Insert_n
         * scalar-int32 grow lane; emitted via AppendPendingReleasedCommandId
         * push_back (Sim.cpp:5045)).
         * Address: 0x00692930 (FUN_00692930, msvc8::vector<Moho::SyncCameraShakeRequest>::_Insert_n
         * grow lane; emitted via mSyncCamShake.push_back (Entity.cpp:879)).
         * Address: 0x00940D40 (FUN_00940D40, msvc8::vector<gpg::gal::AdapterModeD3D9>::_Insert_n
         * 16-byte-element grow lane; emitted via PushBackAdapterModeD3D9 modes.push_back
         * (D3D9Interfaces.cpp:3258)).
         * Address: 0x00882BA0 (FUN_00882BA0, msvc8::vector<msvc8::string>::_Insert_n
         * grow-and-fill lane; emitted via ResizeLegacyStringVectorExact
         * outStrings.resize(n, fillValue) (CSaveGameRequestImpl.cpp:125)).
         * Address: 0x005DD120 (FUN_005DD120, msvc8::vector<Moho::UnitWeapon*>::_Insert_n
         * grow lane for CAiAttackerImpl::mWeapons; the recovered caller
         * CAiAttackerImpl::CreateWeapon invokes mWeapons.push_back(weapon) by name
         * — MSVC8's push_back (FUN_005DBD90) is insert(end(),1,value) when full —
         * so this per-T pointer symbol is emitted).
         * Address: 0x005DD570 (FUN_005DD570, msvc8::vector<moho::CAcquireTargetTask*>::_Insert_n
         * grow lane for the AiAttacker CAcquireTargetTask* reflection vector; the
         * recovered helper InsertNCopiesCAcquireTargetTaskPtrVector (IAiAttacker.cpp)
         * invokes storage.insert(begin()+offset, count, value) by name, and both
         * RVectorType_CAcquireTargetTaskPtr::SerLoad (FUN_005DC660) and
         * ResizeCAcquireTargetTaskPointerVector (FUN_005DC9B0) route their
         * append/grow lanes through it, so this per-T 4-byte pointer symbol is
         * emitted).
         * Address: 0x0067DB40 (FUN_0067DB40, msvc8::vector<Moho::Entity*>::_Insert_n
         * grow lane for Moho::Entity::mAttachedEntities @+0x17C; the recovered
         * helper InsertNCopiesEntityPtrVector (Entity.cpp) invokes
         * storage.insert(begin()+offset, count, value) by name, and
         * Moho::Entity::AttachTo (FUN_00679550) routes its attached-entities
         * append through the push_back-shape helper AppendAttachedEntity which
         * calls it on the capacity-full path (MSVC8's push_back is
         * insert(end(),1,value) when full), so this per-T 4-byte pointer symbol
         * is emitted. Shared by 7 vector<Entity*> _Insert_n sites in the Entity
         * subsystem, all folding to this emission).
         * Address: 0x00543DB0 (FUN_00543DB0, msvc8::vector<moho::ArmyLaunchInfo>::_Insert_n
         * grow lane for the 0x20-byte non-trivial ArmyLaunchInfo element (element
         * copies route through the BVIntSet copy-ctor FUN_00545130, never a raw
         * byte copy); the recovered helper moho::AppendArmyLaunchInfo
         * (LaunchInfoBase.cpp) invokes armyLaunchInfo.push_back(value) by name from
         * Moho::SessionStartup (SessionStartup.cpp:475 & :1224), and MSVC8's
         * push_back is insert(end(),1,value) on the capacity-full path — pos is
         * _Mylast=end() (append, verified), so this per-T 0x20-byte symbol is emitted).
         * Address: 0x0087A830 (FUN_0087A830, msvc8::vector<Moho::CWldTerrainDecal*>::_Insert_n
         * grow lane for Moho::CDecalManager::mDecals @+0x10; the recovered helper
         * InsertNCopiesCWldTerrainDecalPtrVector (CWldSplat.cpp) invokes
         * storage.insert(begin()+offset, count, value) by name, and
         * CDecalManager::LoadDecal / NewSplat route their mDecals append through the
         * push_back-shape helper AppendDecal which calls it on the capacity-full path
         * (MSVC8's push_back is insert(end(),1,value) when full), so this per-T 4-byte
         * pointer symbol is emitted).
         * Address: 0x0087BB40 (FUN_0087BB40, msvc8::vector<Moho::CWldSplat*>::_Insert_n
         * grow lane for Moho::CDecalManager::mSplats @+0x48; the recovered helper
         * InsertNCopiesCWldSplatPtrVector (CWldSplat.cpp) invokes
         * storage.insert(begin()+offset, count, value) by name, and
         * CDecalManager::NewSplat routes its mSplats append through the
         * push_back-shape helper AppendSplat which calls it on the capacity-full path
         * (MSVC8's push_back is insert(end(),1,value) when full), so this per-T 4-byte
         * pointer symbol is emitted. Byte-identical body to the FUN_0087A830 sibling —
         * both are 4-byte trivially-copyable pointer instantiations sharing this
         * canonical template method).
         * Address: 0x00813900 (FUN_00813900, msvc8::vector<boost::shared_ptr<moho::ShoreCell>>::_Insert_n
         * grow lane for Moho::Shoreline::mCells; the recovered caller
         * AppendShoreCellRef (Shoreline.cpp) invokes shorelineCells.push_back(cell)
         * by name — MSVC8's push_back (FUN_008135A0) is insert(end(),1,value) when
         * full — so this per-T 8-byte shared_ptr symbol is emitted).
         * Address: 0x008EF500 (FUN_008EF500, msvc8::vector<std::int32_t>::_Insert_n
         * grow lane for gpg::gal::Head::validFormats1 @+0x70; the recovered caller
         * gpg::gal::DeviceD3D9::BuildDeviceCapabilities appends valid texture formats
         * and, on the capacity-full path, invokes validFormats1.insert(end(),1,token)
         * by name (MSVC8's push_back is insert(end(),1,value) when full), so this
         * per-T scalar-int32 symbol is emitted).
         * Address: 0x008EF2B0 (FUN_008EF2B0, msvc8::vector<std::int32_t>::_Insert_n
         * grow lane for gpg::gal::Head::validFormats2 @+0x60; the same recovered
         * caller appends valid GAL-format tokens and invokes
         * validFormats2.insert(end(),1,token) by name, so this per-T scalar-int32
         * symbol is emitted).
         * Address: 0x008DCB70 (FUN_008DCB70, msvc8::vector<gpg::REnumType::ROptionValue>::_Insert_n
         * grow/insert lane for the 8-byte enum-option element {int mValue; const char* mName;};
         * the recovered caller gpg::AppendEnumOptionValue (Reflection.cpp) invokes
         * options.insert(options.end(), 1, value) by name (MSVC8's push_back at FUN_008DF290
         * is insert(end(),1,value) on the capacity-full path), so this per-T 8-byte
         * trivially-copyable symbol is emitted).
         * Address: 0x007B0340 (FUN_007B0340, msvc8::vector<Moho::RCamCamera*>::_Insert_n
         * grow lane for the 4-byte camera-pointer element; the recovered caller
         * Moho::CAM_GetAllRCamCameras (FUN_007AADE0, RCamManager.cpp) copies the
         * manager's temporary camera vector into the returned result via
         * result.push_back(cam) by name — MSVC8's push_back is insert(end(),1,value)
         * on the capacity-full path — so this per-T 4-byte pointer symbol is
         * emitted. RCamCamera is the public alias of CameraImpl).
         * Address: 0x0075F810 (FUN_0075F810, msvc8::vector<Moho::Sim::DumpUnitsCountEntry>::_Insert_n
         * grow lane for the 8-byte trivially-copyable element {const RUnitBlueprint* blueprint; int count};
         * >>3 stride, 0x1FFFFFFF max, 1.5x growth. Sim::DumpUnits invokes
         * counts.push_back({blueprint,1}) by name — MSVC8's push_back (FUN_0075F1A0)
         * is insert(end(),1,value) on the capacity-full path — so this per-T 8-byte
         * symbol is emitted).
         * Address: 0x0071AF90 (FUN_0071AF90, msvc8::vector<moho::SThreat>::_Insert_n
         * grow-and-fill lane for the 0x38-byte element (stride divide by the
         * 92492493h/`sar 5` magic pair, max_size 0x4924924 = 0xFFFFFFFF/56, overflow
         * throw through FUN_0071B260, 1.5x growth with clamp-to-zero at
         * 0x0071B051-0x0071B067). The value arrives by pointer in edx and is copied
         * into a local `_Tmp` by the 14-dword `rep movsd` at 0x0071AFB8. Emitted via
         * moho::ResizeSThreatVectorWithFill's storage.resize(requestedCount, fillValue)
         * (CInfluenceMap.cpp:1972)).
         * Address: 0x0071B970 (FUN_0071B970, msvc8::vector<moho::InfluenceGrid>::_Insert_n
         * grow-and-fill lane for the 0x8C-byte non-trivial element (stride divide by
         * the EA0EA0EBh/`sar 7` magic pair, max_size 0x1D41D41 = 0xFFFFFFFF/140,
         * overflow throw through FUN_0071BCA0, 1.5x growth with clamp-to-zero at
         * 0x0071BA35-0x0071BA46). Element copies route through
         * Moho::InfluenceGrid::Cpy (the copy constructor, 0x0071C150 — taken for the
         * local `_Tmp` at 0x0071B9A2) and ~InfluenceGrid, never a raw byte copy.
         * Emitted via moho::ResizeInfluenceGridVectorWithFill's
         * storage.resize(requestedCount, fillValue) (CInfluenceMap.cpp:219), which is
         * the binary's own call at 0x0071B8D9).
         * Address: 0x0071BEE0 (FUN_0071BEE0, msvc8::vector<moho::SPositionThreat>::_Insert_n
         * grow lane for the 0x10-byte element (`sar 4` stride, max_size 0xFFFFFFF =
         * 0xFFFFFFFF/16, overflow throw through FUN_00592830). `_Count` is folded to
         * the constant 1 (`cmp edx, 1` at 0x0071BF57) because both binary callers are
         * single-element append lanes: MSVC8's push_back (FUN_00718A40, tail-calling
         * it at 0x00718A9A on the capacity-full path) and the single-value insert
         * lane FUN_0071A1B0 (0x0071A1D9); the value's four floats are copied into a local
         * `_Tmp` by the movss block at 0x0071BEFE-0x0071BF2D. Emitted via
         * out.push_back(sample) in Moho::CInfluenceMap::GetThreatsAroundPosition
         * (CInfluenceMap.cpp:4906)).
         * Address: 0x00535D60 (FUN_00535D60, msvc8::vector<Moho::RBlueprint*>::_Insert_n
         * grow lane for the 4-byte pointer element (`sar 2` stride, max_size 0x3FFFFFFF
         * = 0xFFFFFFFF/4 loaded at 0x00535D96, overflow test `max_size() - size() < 1`
         * then the `vector<T> too long` throw lane FUN_0052EC30 at 0x00535DA2).
         * `_Count` is folded to the constant 1 (`add ecx, 1` / `cmp edx, ecx` at
         * 0x00535DB7) because both of its callers are single-element lanes: MSVC8's
         * push_back at FUN_005347A0, which reaches it at 0x005347DC on the
         * capacity-full path, and the `insert(iterator, const T&)` overload of the
         * same instantiation — an IDA-unclassified chunk at 0x005355E0-0x00535619
         * that computes `_Off`, calls this lane at 0x00535607, and returns
         * `begin() + _Off`. Growth is the 1.5x lane with clamp-to-zero at
         * 0x00535DC2-0x00535DDD, and the value arrives by pointer in eax
         * (`mov ecx, [eax]` at 0x00535D63). Emitted via
         * rules.mBlueprintsByOrdinal.push_back(...) in moho::AppendBlueprintOrdinal
         * (Sim.cpp:14253), whose registry lives at `rules + 0xB4` — the operand of
         * `add ecx, 0B4h` at 0x00531FE9 in func_CreateRUnitBlueprint)
         * Address: 0x006D1A90 (FUN_006D1A90, msvc8::vector<moho::SUpgradeNotifyPair>::_Insert_n
         * grow lane for the 8-byte `{mSourceId, mDestId}` element (`sar 3` stride,
         * max_size 0x1FFFFFFF = 0xFFFFFFFF/8 at 0x006D1AE6, overflow throw through
         * FUN_006D1D30). `_Count` is folded to the constant 1 (`cmp edi, 1` at
         * 0x006D1AED, `mov ecx, 1` at 0x006D1BB6) — the element is copied two dwords
         * at a time by FUN_006D2730 with no destroy pass, so the element is trivially
         * copyable. Its live caller is MSVC8's push_back at FUN_006D1960, which skips
         * the iterator-returning wrapper (FUN_006D1A20, itself xref-less) and tail-calls
         * this lane directly at 0x006D19BA because push_back discards the iterator.
         * Emitted via globalUserdata->mAllyUpgradeNotifications.push_back(pair) in
         * moho::cfunc_NotifyUpgradeL (Unit.cpp:11966), whose owner lane is
         * Moho::Sim::mAllyUpgradeNotifications at Sim+0x9D8)
         * Address: 0x006DC600 (FUN_006DC600, msvc8::vector<moho::EntityCategorySet>::_Insert_n
         * grow-and-fill lane for the 0x28-byte non-trivial element (stride divide by
         * the 66666667h/`sar 4` magic pair, max_size 0x6666666 = 0xFFFFFFFF/40 at
         * 0x006DC68B, overflow throw through FUN_006DC930 which pushes the
         * `vector<T> too long` literal at 0x006DC950). `_Count` is a live parameter
         * with a `test esi, esi` zero early-out at 0x006DC665. Element copies route
         * through the EntityCategorySet copy path — the inlined temp ctor at
         * 0x006DC61B copies mUniverse (+0x00), the first-word index (+0x08) and deep-
         * copies the fastvector_n<uint,2> word lane (+0x10..+0x28) — and the old range
         * is torn down by FUN_006DEB80 before the buffer is freed, never a raw byte
         * copy. Two binary lanes reach it: push_back (FUN_006DB010) through
         * insert(end(),1,val) (FUN_006DBAE0), and the by-value
         * resize(n, EntityCategorySet) emission FUN_006DC4E0 at 0x006DC554. Emitted via
         * storage->resize(count, zeroFill) in
         * gpg::RVectorType<moho::EntityCategorySet>::SetCount
         * (EntityCategorySetVectorReflection.cpp:467), a slot of the reflection type
         * that register_EntityCategorySetVectorType actually constructs)
         * Address: 0x008F6A50 (FUN_008F6A50, msvc8::vector<DXGI_MODE_DESC>::_Insert_n
         * grow lane for the 0x1C-byte POD element (stride divide by the
         * 92492493h/`add`/`sar 4` magic triple at 0x008F6A90, max_size 0x9249249 =
         * 0xFFFFFFFF/28 at 0x008F6ACF, overflow throw through FUN_008F6890 which
         * pushes the `vector<T> too long` literal). `_Count` is a live parameter with
         * a zero early-out at 0x008F6AA8, and the 28-byte value is copied into a local
         * `_Tmp` by the `rep movsd` with ecx=7 at 0x008F6A73. Element moves are raw
         * byte copies with no destroy pass, so the element is trivially copyable.
         * Reached from insert(end(),val) (FUN_008F6FB0) under push_back (FUN_008F7230).
         * Emitted via entry.modes_.push_back(mode) in
         * gpg::gal::AppendDisplayModeToAdapterModeEntry (D3D10Interfaces.cpp:2809),
         * whose owner lane is AdapterModeD3D10::modes_ at +0x64)
         * Address: 0x00900630 (FUN_00900630, msvc8::vector<gpg::gal::AdapterD3D10>::_Insert_n
         * grow lane for the 0x13C-byte polymorphic element (stride divide by the
         * 67B23A55h/`sar 7` magic pair at 0x0090069E with explicit `imul reg, 13Ch`
         * multiply-back at 0x009007FB, max_size 0xCF6474 = 0xFFFFFFFF/316 at
         * 0x009006D8 — IDA misprints that literal as an `__xc_a` offset — overflow
         * throw through FUN_008FAA50). `_Count` is a live parameter with a zero
         * early-out at 0x009006B4. The local `_Tmp` is a real copy-construct: it
         * stores `??_7AdapterD3D10@gal@gpg@@6B@` at 0x00900662, copies the 0x124-byte
         * description block, copy-constructs the `modes_` member through FUN_008FF220,
         * and is torn down by ~AdapterD3D10 at 0x00900939 — and the old range is
         * destroyed by FUN_008FA890 before the buffer is freed. Reached from
         * insert(end(),val) (FUN_00900960) under push_back (FUN_009009D0). Emitted via
         * adapters.push_back(adapter) in gpg::gal::AppendBackendAdapter
         * (D3D10Interfaces.cpp:2837), whose owner lane is
         * DeviceD3D10BackendObject::adapters_ at +0x94)
         * Address: 0x0093FEB0 (FUN_0093FEB0, msvc8::vector<gpg::gal::EffectMacro>::_Insert_n
         * grow lane for the 0x3C-byte element (stride divide by the
         * 88888889h/`add`/`sar 5` magic triple at 0x0093FEF3 with the
         * `shl ecx,4; sub ecx,ebx; lea edx,[eax+ecx*4]` multiply-back at 0x00940059,
         * max_size 0x4444444 = 0xFFFFFFFF/60 at 0x0093FF30, overflow throw through
         * FUN_004331F0). `_Count` is a live parameter with a zero early-out at
         * 0x0093FF0B. The element is polymorphic and owns two msvc8::strings
         * (vftable +0x00, keyText_ +0x04, valueText_ +0x20), so the local `_Tmp` is
         * copy-constructed by FUN_008FA9A0 at 0x0093FEDD and destroyed by FUN_0093F710
         * at 0x0094019C, and the old range is destroyed by FUN_004331C0 before the
         * buffer is freed. Reached from insert(end(),val) (FUN_009401C0) under
         * push_back (FUN_00940230). Emitted via vec->push_back(source) in
         * gpg::gal::PushBackEffectMacroIntoLane (ContextInterfaces.cpp:266), whose
         * owner lane is EffectContext's macro vector at +0x54)
         * Address: 0x007F1D50 (FUN_007F1D50, msvc8::vector<moho::SRangeExtractionPayload>::_Insert_n
         * grow lane for the 0x10-byte `{centerX,centerZ,innerRadius,outerRadius}` element
         * (`sar 4` stride, max_size 0xFFFFFFF = 0xFFFFFFFF/16 at 0x007F1DB0, overflow
         * throw through FUN_007F1F90, which raises `std::length_error("vector<T> too
         * long")`). `_Count` is folded to the constant 1 (`cmp esi,ecx` against
         * `size+1` at 0x007F1DD4) because its only reachable caller is a
         * single-element append lane: MSVC8's push_back tail-calls it at 0x007F036A
         * on the capacity-full path (FUN_007F0310, recovered as
         * AppendRangeExtractionPayload). The value's four floats are copied into a
         * local `_Tmp` by the dword-move block at 0x007F1D6B-0x007F1D8F up front, so
         * reallocation cannot invalidate the source. In-place growth splits the
         * generic tail-shift into two binary calls for the count=1 case: FUN_007F3500
         * (tail-calling the forward-copy primitive FUN_007F3EF0 to move the single
         * trailing element into the newly uninitialized slot past `mLast`), then
         * FUN_007F3560 (a backward per-element copy shifting the remaining
         * `[pos, mLast-0x10)` run right by one slot); FUN_007F3530 then fills the
         * vacated slot at `pos` from `_Tmp`. The pure-append case (`pos == mLast`)
         * instead reaches FUN_007F0D20, which tail-calls the fill primitive
         * FUN_007F39B0 to write `_Tmp` directly at `mLast`. Reallocation allocates via
         * FUN_007F3590 (`operator new(16 * newCap)`, guarded by an
         * `0xFFFFFFFF / newCap < 0x10` overflow check) and moves the head/gap/tail
         * spans through the same FUN_007F3EF0 (copy) / FUN_007F39B0 (fill) primitives.
         * A second code xref into this function's body at 0x007F0C39 sits inside an
         * unexported `insert(iterator, value)` overload (0x007F0C10-0x007F0C49:
         * computes the insert offset as an index, delegates here, then rebinds the
         * returned iterator against the possibly-reallocated `first_`) -- that
         * wrapper itself has zero callers anywhere in the shipped binary (verified by
         * an exhaustive `call rel32` / `jmp rel32` / short-`jcc` / raw-pointer scan of
         * every section, not just `.text`), so it is a dead template instantiation
         * and is not wired into recovered source; only the push_back caller chain
         * above is load-bearing)
         * Address: 0x006DBAE0 (FUN_006DBAE0, msvc8::vector<moho::EntityCategorySet>::insert
         * single-value lane — `insert(end(), 1, val)` for the 0x28-byte element. Computes
         * the insert offset twice with the 66666667h/`sar 4` magic pair (0x006DBAF8 and
         * 0x006DBB13 — 0xFFFFFFFF/40) and tail-calls the `_Insert_n` grow lane
         * FUN_006DC600 at 0x006DBB2D. Its only code xref is 0x006DB08B inside
         * msvc8::vector<EntityCategorySet>::push_back (FUN_006DB010), so the lane is
         * reached only through push_back. Emitted via destination.push_back(value) in
         * moho::PushBackEntityCategorySetVector
         * (EntityCategorySetVectorReflection.cpp:591), whose own callers are
         * UnitWeapon::cfunc_UnitWeaponSetTargetingPrioritiesL and
         * CPlatoon::cfunc_CPlatoonSetPrioritizedTargetListL)
         * Address: 0x008F6FB0 (FUN_008F6FB0, msvc8::vector<DXGI_MODE_DESC>::insert
         * single-value lane for the 0x1C-byte POD element (92492493h/`sar 4` magic pair
         * at 0x008F6FC5 and 0x008F6FE2 — 0xFFFFFFFF/28), tail-calling the `_Insert_n`
         * grow lane FUN_008F6A50 at 0x008F6FFF. Emitted via entry.modes_.push_back(mode)
         * in gpg::gal::AppendDisplayModeToAdapterModeEntry (D3D10Interfaces.cpp:2809),
         * whose owner lane is AdapterModeD3D10::modes_ at +0x64)
         * Address: 0x00900960 (FUN_00900960, msvc8::vector<gpg::gal::AdapterD3D10>::insert
         * single-value lane for the 0x13C-byte polymorphic element (67B23A55h/`sar 7`
         * magic pair at 0x00900975 and 0x00900990 — 0xFFFFFFFF/316), tail-calling the
         * `_Insert_n` grow lane FUN_00900630 at 0x009009AB. Emitted via
         * adapters.push_back(adapter) in gpg::gal::AppendBackendAdapter
         * (D3D10Interfaces.cpp:2837), whose owner lane is
         * DeviceD3D10BackendObject::adapters_ at +0x94)
         * Address: 0x009401C0 (FUN_009401C0, msvc8::vector<gpg::gal::EffectMacro>::insert
         * single-value lane for the 0x3C-byte element owning two msvc8::strings
         * (88888889h/`sar 5` magic pair at 0x009401D5 and 0x009401F2 — 0xFFFFFFFF/60),
         * tail-calling the `_Insert_n` grow lane FUN_0093FEB0 at 0x0094020F. Emitted via
         * vec->push_back(source) in gpg::gal::PushBackEffectMacroIntoLane
         * (ContextInterfaces.cpp:266), whose owner lane is EffectContext's macro
         * vector at +0x54)
         * Address: 0x0075F240 (FUN_0075F240, msvc8::vector<Moho::SPendingPoseCopy>::insert
         * iterator-rebasing wrapper for the 12-byte element — converts the
         * append-position pointer to an index, delegates to the `_Insert_n` grow
         * core (FUN_0075F4B0), then rebinds the returned iterator against the
         * (possibly reallocated) `first_`. Reached from push_back's capacity-full
         * path (FUN_0075F050) in cfunc_TryCopyPoseL (Sim.cpp))
         * Address: 0x0075F4B0 (FUN_0075F4B0, msvc8::vector<Moho::SPendingPoseCopy>::insert
         * `_Insert_n` grow core for the 12-byte element — copies the by-ref value
         * into a local temporary first (bumping its `shared_ptr<CAniPose>` refcount
         * via `_InterlockedExchangeAdd`, guarding against reallocation invalidating
         * the source), then either shifts the tail in place when capacity allows or
         * reallocates and moves head/tail through the same refcount-bumping copy
         * helper (FUN_0075FEA0). The binary's growth factor here is a true VC8 1.5x
         * (`(cap>>1)+cap`, overflow-clamped to max_size, floored to the needed size)
         * rather than this template's doubling approximation — final element
         * contents and refcounts match exactly; only the post-growth `capacity()`
         * value can differ from the original binary)
         *
         * Address: 0x00951F30 (FUN_00951F30, msvc8::vector<gpg::TypeHandle>::_Insert_n
         * grow lane for the 8-byte `{type,version}` element (`sar 3` stride, max_size
         * 0x1FFFFFFF, overflow throw through FUN_009514A0's `std::length_error("vector<T>
         * too long")`). Its only reachable caller is `gpg::AppendTypeHandle` (FUN_00952C90,
         * ReadArchive.cpp), which always calls it as a single-element append at `mLast`
         * (from `gpg::ReadArchive::ReadTypeHandle`), so `_Count` is effectively always 1.
         * The in-place growth path's tail-shift (empty here, since inserts land at
         * `mLast`) corresponds to FUN_00950670; reallocation allocates via FUN_0094F1B0
         * (`operator new(8 * newCap)`, `0xFFFFFFFF/count < 8` overflow guard))
         *
         * Address: 0x005C68E0 (FUN_005C68E0,
         * msvc8::vector<Moho::SUnitVariableUpdateEntry>::_Insert_n for the
         * 568-byte (0x238) element -- max_size 0xFFFFFFFF/568, 1.5x growth,
         * allocation through the checked 568-byte lane, with a reallocate
         * branch, an in-place tail-shift branch, and a pure-append fast path.
         * Reached through the position-preserving wrapper FUN_005C51B0, which
         * converts the insert position to an index before the call because a
         * reallocation moves mFirst. Its caller is
         * `Moho::QueueUnitVariableUpdate` in SimDriver.cpp.)
         * Address: 0x005C51B0 (FUN_005C51B0, that wrapper)
         * Address: 0x00508480 (FUN_00508480,
         * msvc8::vector<Moho::SDelayedSubVizInfo>::_Insert_n for the 0x18-byte
         * element -- max_size guard through FUN_00507F80's throw lane, in-place
         * tail shift when capacity allows, otherwise 1.5x growth
         * (`cap + (cap >> 1)`, floored to size + count) with head/gap/tail
         * rebuilt into the fresh block. Reached from `resize` (FUN_005083C0)
         * and the single-element push path FUN_005079C0.)
         * Address: 0x00524780 (FUN_00524780, msvc8::vector<float>::_Insert_n --
         * max_size 0x3FFFFFFF, in-place tail-shift when capacity covers the new
         * size, otherwise geometric grow. Reached from push_back in the
         * reflected vector<float> SerLoad lane.)
         * Address: 0x008FE010 (FUN_008FE010, msvc8::vector<void*>::_Insert_n for
         * the D3D10 backend swap-chain vector -- same 4-byte-element shape:
         * length-error throw / in-place tail-shift / grow-and-copy at
         * max(cap + cap/2, size + count). Reached from push_back when capacity
         * is exhausted.)
         * Address: 0x0082F210 (FUN_0082F210, msvc8::vector<void*>::_Insert_n for
         * UICommandGraph's hash-bucket vector -- 4-byte element, max_size
         * 0x3FFFFFFF, overflow throw through FUN_00830620, 1.5x growth
         * (`(cap >> 1) + cap`), allocation through FUN_00831B40. Reached from
         * `resize` (FUN_0082D820) when a bucket table is rehashed.)
         * Address: 0x00680BD0 (FUN_00680BD0, the out-of-line `std::fill` emission
         * this method's gap-overwrite compiles to for the 0xD8-byte
         * `Moho::SEntityVariableUpdateEntry` -- `for (p = first; p != last;
         * p += 0xD8) { p->mEntityId = proto->mEntityId;
         * p->mVariableData = proto->mVariableData; }`, the second field through
         * `SSTIEntityVariableData::operator=`. Reached because
         * `syncData->mEntityUpdates.push_back(...)` in QueueEntityVariableUpdate
         * (SimDriver.cpp) routes here on the capacity-full path, where the
         * tail is empty and the gap fill runs with count == 1. The element's
         * push_back emission is cited on that method above, FUN_0067B780.)
         * Address: 0x005C6F90 (FUN_005C6F90, msvc8::vector<Moho::SPerArmyReconInfo>::_Insert_n
         * grow lane for the 52-byte element (`4EC4EC4Fh`/`sar 4` divide-by-0x34
         * magic pair, max_size 0x4EC4EC4 = 0xFFFFFFFF/52, overflow throw through
         * FUN_005C7290 at 0x005C7014, 1.5x growth `shr eax,1`/`add edi,eax` at
         * 0x005C7043-0x005C705C clamped by FUN_005C3C70, allocation via
         * FUN_005C9F40). The by-ref `_Val` is copy-constructed into a stack local
         * up front at 0x005C6FB4 (FUN_005C84D0, `SPerArmyReconInfo`'s copy ctor)
         * so a reallocation cannot invalidate it. Range mechanics route through
         * `uninit_copy_n` (FUN_005CDAE0 / FUN_005C9EC0), `uninit_fill_n`
         * (FUN_005CC2D0, and its advance-returning adapter FUN_005C8720), and the
         * forward/backward copy-assign lanes FUN_005C9EF0 / FUN_005C9F10. Reached
         * from `resize` (FUN_005C5460) and the single-append adapter FUN_005C86B0.)
         *
         * Mirrors the MSVC8 STL `vector::_Insert_n` lane: when capacity is
         * sufficient, the live tail `[pos, end)` is shifted right by `count`
         * slots and the gap is filled with copies of `value`; when capacity
         * is insufficient, a reallocated buffer of 1.5x-or-needed size is
         * built up by moving the head, fill-constructing the gap, and moving
         * the tail. The recovered per-T resize/insert helper lanes
         * (`InsertNCopies*Vector`) call this method by name through the
         * `msvc8::vector<T>` API surface, which is the source-level
         * invocation that keeps the canonical symbol shape in the recovered
         * binary.
         */
        iterator insert(const_iterator pos, std::size_t count, const T& value) {
            assert(pos >= first_ && pos <= last_);
            const std::size_t offset = static_cast<std::size_t>(pos - first_);
            if (count == 0) {
                return first_ + offset;
            }

            const std::size_t cur = size();
            if (max_size() - cur < count) {
                throw_too_long();
            }

            // VC8 copies `_Val` into a local before touching storage, so an
            // element aliased into this very vector survives reallocation and
            // the tail shift.
            const T localValue(value);

            if (cur + count <= capacity()) {
                T* const insertAt = first_ + offset;
                T* const oldLast = last_;
                const std::size_t tail = static_cast<std::size_t>(oldLast - insertAt);
                // Shift the tail right by `count` slots.
                if (tail >= count) {
                    // Move the trailing `count` elements into uninitialized
                    // slots past the live range.
                    uninit_move_n(oldLast - count, count, oldLast);
                    // Shift the remaining tail elements in-place to the right.
                    if constexpr (std::is_trivially_copyable_v<T>) {
                        std::memmove(insertAt + count, insertAt, (tail - count) * sizeof(T));
                    } else {
                        for (std::size_t i = tail - count; i > 0; --i) {
                            insertAt[count + i - 1] = std::move(insertAt[i - 1]);
                        }
                    }
                    // Overwrite the gap with copies of `value`.
                    for (std::size_t i = 0; i < count; ++i) {
                        insertAt[i] = localValue;
                    }
                } else {
                    // Tail smaller than gap: move-construct the whole tail
                    // into its new slot, fill the trailing-gap section with
                    // value, and copy-assign the head-gap section.
                    uninit_move_n(insertAt, tail, insertAt + count);
                    uninit_fill_n(insertAt + tail, count - tail, localValue);
                    for (std::size_t i = 0; i < tail; ++i) {
                        insertAt[i] = localValue;
                    }
                }
                last_ = oldLast + count;
                return first_ + offset;
            }

            // Reallocation path: build a fresh buffer with head | fill | tail.
            const std::size_t newCap = recommended_capacity(cur + count);
            T* const newBuf = allocate_slots_checked(newCap);
            try {
                uninit_move_n(first_, offset, newBuf);
                try {
                    uninit_fill_n(newBuf + offset, count, localValue);
                    try {
                        uninit_move_n(first_ + offset, cur - offset, newBuf + offset + count);
                    } catch (...) {
                        destroy_n(newBuf + offset, count);
                        throw;
                    }
                } catch (...) {
                    destroy_n(newBuf, offset);
                    throw;
                }
            } catch (...) {
                ::operator delete(static_cast<void*>(newBuf));
                throw;
            }
            destroy_range(first_, last_);
            deallocate_all();
            first_ = newBuf;
            last_ = newBuf + cur + count;
            end_ = newBuf + newCap;
            return first_ + offset;
        }

    private:
        /**
         * Address: 0x00519BA0 (FUN_00519BA0, the range-destroy lane for the
         * 0xCC-byte `Moho::RMeshBlueprintLOD` -- a bare
         * `while (p != end) { p->~RMeshBlueprintLOD(); p += 0xCC; }` walk calling
         * FUN_00519800. Instantiated by `RMeshBlueprint::mLods`
         * (RMeshBlueprint.h:110) and reached from
         * `gpg::RVectorType_RMeshBlueprintLOD::SerLoad`'s cleanup path.)
         * Address: 0x005617C0 (FUN_005617C0, the range-destroy lane for 568-byte
         * `Moho::SUnitVariableUpdateEntry` -- runs `~SSTIUnitVariableData` on the
         * payload at each slot's +0x08)
         * Address: 0x005C6F70 (FUN_005C6F70, the range-destroy lane for 52-byte
         * `Moho::SPerArmyReconInfo` -- forward `~T()` sweep over `[first, last)`,
         * used by `erase` (FUN_005C6F00) and by `_Insert_n`'s reallocation path
         * (FUN_005C6F90) to tear down the old buffer)
         *
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
         * Address: 0x0075FEA0 (FUN_0075FEA0, msvc8::vector<Moho::SPendingPoseCopy>::uninit_copy_n
         * for the 12-byte `{EntId, boost::shared_ptr<CAniPose>}` element — per-slot
         * dword-triple copy with an `_InterlockedExchangeAdd` refcount bump on the
         * third dword (the `shared_ptr<CAniPose>` control-block pointer) when
         * non-null; no try/catch scaffolding in the binary because a `shared_ptr`
         * copy cannot throw. Used both by push_back's fast path (FUN_0075F050,
         * single-element copy) and by the `_Insert_n` grow core (FUN_0075F4B0,
         * head/tail range moves) for `Sim::mPendingPoseCopies`)
         *
         * Address: 0x0077E7B0 (FUN_0077E7B0,
         * msvc8::vector<Moho::SDecalInfo>::uninit_copy_n, with the
         * destroy-what-was-built rollback on throw)
         * Address: 0x0077E910 (FUN_0077E910, its fastcall-shape adapter)
         * Address: 0x00563430 (FUN_00563430,
         * msvc8::vector<Moho::SUnitVariableUpdateEntry>::uninit_copy_n -- the
         * range form, with the destroy-what-was-built rollback on throw)
         * Address: 0x00562B70 (FUN_00562B70, register-shape adapter for FUN_00563430)
         * Address: 0x00563070 (FUN_00563070, register-shape adapter for FUN_00563430)
         * Address: 0x00563250 (FUN_00563250, register-shape adapter for FUN_00563430)
         * Address: 0x005CD1C0 (FUN_005CD1C0, source-first adapter for FUN_00563430)
         * Address: 0x00562680 (FUN_00562680, register-shape adapter for FUN_00563430)
         * Address: 0x005CBB20 (FUN_005CBB20, the counted form of the same)
         * Address: 0x005C9AD0 (FUN_005C9AD0, register-shape adapter for FUN_005CBB20)
         * Address: 0x005CDAE0 (FUN_005CDAE0, msvc8::vector<Moho::SPerArmyReconInfo>::
         * uninit_copy_n for the 52-byte element -- the `_Insert_n` reallocation
         * path's head/tail range copies, FUN_005C6F90)
         * Address: 0x005C9EC0 (FUN_005C9EC0, the same specialisation emitted a
         * second time for FUN_005C6F90's in-place-insert branch, where it
         * copy-constructs the relocated tail past the old `mLast`)
         * Address: 0x00549BC0 (FUN_00549BC0,
         * msvc8::vector<Moho::ResourceDeposit>::uninit_copy_n for the 20-byte
         * element -- copies five dwords per slot at stride 0x14, taking
         * `[srcBegin, srcEnd)` on the stack and the destination cursor in
         * `eax`. The `test eax, eax` guard sits *inside* the loop because the
         * destination is freshly-allocated storage the compiler cannot prove
         * non-null. Reached from `reserve` (FUN_00547E00).)
         * Address: 0x00549A90 (FUN_00549A90, the identical 24-instruction body
         * emitted a second time -- same mnemonics, same 60 bytes. This build
         * did not fold them, so both COMDATs survive.)
         * Address: 0x00548AB0 (FUN_00548AB0, register-shape adapter for FUN_00549BC0)
         * Address: 0x00549480 (FUN_00549480, register-shape adapter for FUN_00549BC0)
         * Address: 0x005498F0 (FUN_005498F0, register-shape adapter for FUN_00549BC0)
         * Address: 0x00549A50 (FUN_00549A50, register-shape adapter for FUN_00549BC0)
         * Address: 0x00549750 (FUN_00549750, source-first adapter for FUN_00549A90)
         * Address: 0x00549940 (FUN_00549940, source-first adapter for FUN_00549A90)
         *
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
         * Address: 0x006DEA30 (FUN_006DEA30, msvc8::vector<moho::EntityCategorySet>::uninit_fill_n
         * — reallocation fill-n-with-copy path of push_back for the 0x28-byte element)
         * Address: 0x007F39B0 (FUN_007F39B0, msvc8::vector<moho::SRangeExtractionPayload>::
         * uninit_fill_n for the 0x10-byte trivially-copyable element -- a plain
         * count-driven dword-quad fill loop (`for(;count;--count,dst+=4) copy 4 dwords
         * from the fixed source`). Used by the `_Insert_n` grow lane FUN_007F1D50
         * (cited above on `insert`) both to fill the reallocated buffer's one-element
         * gap and, via the pure-append dispatcher FUN_007F0D20, to write the new
         * element directly at `mLast` when there is no tail to shift)
         *
         * Address: 0x005261D0 (FUN_005261D0,
         * msvc8::vector<Moho::RUnitBlueprintWeapon>::uninit_fill_n -- the
         * broadcast-fill of `_Insert_n`'s vacated gap)
         * Address: 0x00884330 (FUN_00884330,
         * msvc8::vector<Moho::SSavedGameArmyInfo>::uninit_fill_n -- fills the
         * reserved tail from a prototype after the resize-with-fill lane has
         * reserved the exact target capacity)
         * Address: 0x005CC2D0 (FUN_005CC2D0, msvc8::vector<Moho::SPerArmyReconInfo>::
         * uninit_fill_n for the 52-byte element -- copy-constructs `count` copies
         * of the by-ref prototype, used by FUN_005C6F90 to fill the inserted gap)
         * Address: 0x005C8720 (FUN_005C8720, the advance-returning `_Ufill`
         * adapter around FUN_005CC2D0: fills then returns `dst + count`)
         *
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
         * Address: 0x007F3EF0 (FUN_007F3EF0, msvc8::vector<moho::SRangeExtractionPayload>::
         * uninit_move_n for the 0x10-byte trivially-copyable element -- a plain
         * forward per-element dword-quad copy loop (`for(;src!=srcEnd;++dst,src+=4)
         * copy 4 dwords`, no destroy pass since the element is POD). Used by the
         * `_Insert_n` grow lane FUN_007F1D50 (cited above on `insert`) both to move
         * the single trailing element past `mLast` on the in-place path (via the
         * count=1 dispatcher FUN_007F3500) and to move the head/tail spans into the
         * reallocated buffer)
         *
         * Uninitialized move (or copy if non-movable) N elements src->dst.
         * Used by `insert(pos, count, value)` to shift the tail and to
         * populate the reallocated buffer's head/tail spans.
         */
        static void uninit_move_n(T* src, const std::size_t n, T* dst) {
            if constexpr (std::is_trivially_copyable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) {
                        ::new (static_cast<void*>(dst + i)) T(std::move_if_noexcept(src[i]));
                    }
                } catch (...) {
                    destroy_n(dst, i);
                    throw;
                }
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
         * Address: 0x005C9EF0 (FUN_005C9EF0, the forward `std::copy` lane for
         * 52-byte `Moho::SPerArmyReconInfo` -- copy-assigns a parallel source run
         * over `[destBegin, destEnd)`; used by FUN_005C6F90 to overwrite the
         * vacated insert gap)
         * Address: 0x005CD1F0 (FUN_005CD1F0, the `std::copy` / `std::copy_backward`
         * pair for 568-byte `Moho::SUnitVariableUpdateEntry` -- ICF-folded to one
         * address)
         * Address: 0x005C9E00 (FUN_005C9E00, register-shape adapter for FUN_005CD1F0)
         * Address: 0x005EC880 (FUN_005EC880, the `std::copy_backward` emission for
         * the 0x20-byte `Moho::SAiReservedTransportBone` -- two cursors walking
         * down together, `dst -= 0x20; src -= 0x20;` then
         * `SAiReservedTransportBone::operator=` (FUN_005EE740) per element,
         * returning the final source cursor. Reached from that element's
         * `resize` grow path, FUN_005EA590, which is cited on resize above; the
         * backward direction is what stops the tail shift corrupting itself
         * when the ranges overlap.)
         * Address: 0x00583130 (FUN_00583130, the `std::copy` emission for
         * `Moho::SPointVector`, used by `clear()`'s degenerate self-range shift
         * in the AI brain's point-vector reset)
         * Address: 0x008A9DC0 (FUN_008A9DC0, the `std::copy` emission for
         * `Moho::TerrainEnvironmentLookupPair` -- the pair's two member strings
         * are copied through their own assign lanes, so this is the
         * copy-assign form, used by `erase(first, last)` to shift survivors
         * down)
         * Address: 0x005C9E70 (FUN_005C9E70, the `std::copy` emission used by
         * `msvc8::vector<Moho::SPerArmyReconInfo>::operator=` (FUN_005CA980) to
         * assign over the retained prefix; returns the one-past-end destination
         * cursor so the caller can destroy the excess tail)
         * Address: 0x005261F0 (FUN_005261F0, the `std::copy_backward` lane for
         * `Moho::RUnitBlueprintWeapon` -- shifts `_Insert_n`'s live tail right
         * by `count` slots on the spare-capacity path)
         * Address: 0x005C9F10 (FUN_005C9F10, the matching `std::copy_backward`
         * lane -- copy-assigns `[srcBegin, srcEnd)` backward into
         * `[destEnd - n, destEnd)`; used by FUN_005C6F90's in-place branch to
         * shift the live tail right without overlap corruption)
         * Address: 0x00548C00 (FUN_00548C00, the `std::copy` emission for the
         * 20-byte `Moho::ResourceDeposit` -- the same five-dword stride-0x14
         * loop as FUN_00549BC0 but with all three cursors in registers and
         * **no** null guard, because here the destination is already-live
         * storage. Used by `resize`'s shrink branch (FUN_00547F20, to compute
         * the new `_Mylast`) and three times by `operator=` (FUN_00548ED0) for
         * its assign-over-the-retained-prefix paths.)
         *
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
         * The VC8 `vector<T>::_Grow_to(_Count)` lane.
         *
         * MSVC8 grows by **1.5x** (`capacity() + capacity() / 2`), not by
         * doubling, clamping to 0 on max_size overflow and flooring to the
         * requested count. Every recovered `_Insert_n` body in this binary
         * shows the same `shr reg, 1` + `add` pair -- e.g. `0x005C7043` /
         * `0x005C705C` in `msvc8::vector<Moho::SPerArmyReconInfo>::_Insert_n`
         * (FUN_005C6F90), preceded by the `sub_5C3C70` max_size clamp.
         */
        [[nodiscard]] std::size_t recommended_capacity(const std::size_t need) const noexcept {
            const std::size_t cur = capacity();
            std::size_t grown = (max_size() - cur / 2u < cur) ? 0u : cur + cur / 2u;
            if (grown < need) {
                grown = need;
            }
            return grown;
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
         * The VC8 `std::_Allocate<T>(_Count, T*)` instantiation. MSVC emits one
         * out-of-line copy per distinct `sizeof(T)`, so the addresses below are
         * all the *same* function template specialised on different element
         * widths -- they are grouped here rather than duplicated as per-width
         * free functions.
         *
         * sizeof(T) == 4 (`count > 0x3FFFFFFF` throws):
         * Address: 0x00445B80 (FUN_00445B80)
         * Address: 0x00445C90 (FUN_00445C90)
         * Address: 0x00445DC0 (FUN_00445DC0)
         * Address: 0x00445E80 (FUN_00445E80)
         * Address: 0x004C65E0 (FUN_004C65E0)
         * Address: 0x005DF3F0 (FUN_005DF3F0)
         * Address: 0x005DF520 (FUN_005DF520)
         * Address: 0x0067F7F0 (FUN_0067F7F0)
         * Address: 0x00704530 (FUN_00704530)
         * Address: 0x007B1240 (FUN_007B1240)
         * Address: 0x007B1390 (FUN_007B1390)
         * Address: 0x007DA660 (FUN_007DA660)
         * Address: 0x008319C0 (FUN_008319C0)
         * Address: 0x00831A30 (FUN_00831A30)
         * Address: 0x00831B40 (FUN_00831B40)
         * Address: 0x00831C20 (FUN_00831C20)
         * Address: 0x008D6F60 (FUN_008D6F60)
         * Address: 0x008D9060 (FUN_008D9060)
         * Address: 0x0092C1E0 (FUN_0092C1E0)
         * Address: 0x00931BF0 (FUN_00931BF0)
         *
         * sizeof(T) == 8 (`count > 0x1FFFFFFF` throws):
         * Address: 0x005A1D60 (FUN_005A1D60, `moho::WeakPtr<moho::CUnitCommand>`)
         * Address: 0x00783D90 (FUN_00783D90)
         * Address: 0x008B3700 (FUN_008B3700)
         * Address: 0x0094F1B0 (FUN_0094F1B0, `msvc8::vector<gpg::TypeHandle>`'s
         * `_Insert_n` reallocation path, FUN_00951F30)
         *
         * sizeof(T) == 12 / 16 / 52 / 60 / 64 / 116 / 388:
         * Address: 0x007E5650 (FUN_007E5650, 12B, e.g. `Wm3::Vector3<float>`)
         * Address: 0x008E87F0 (FUN_008E87F0, 0x10B)
         * Address: 0x0085F930 (FUN_0085F930, 0x34B)
         * Address: 0x005C9F40 (FUN_005C9F40, 0x34B, the
         * `msvc8::vector<Moho::SPerArmyReconInfo>::_Insert_n` reallocation path,
         * FUN_005C6F90)
         * Address: 0x007FB950 (FUN_007FB950, 0x3CB)
         * Address: 0x004C6520 (FUN_004C6520, 64B)
         * Address: 0x008F6040 (FUN_008F6040, 0x74B)
         * Address: 0x00526080 (FUN_00526080, 0x184B, `moho::RUnitBlueprintWeapon`)
         *
         * sizeof(T) == 56:
         * Address: 0x0044E650 (FUN_0044E650, allocator for one 56-byte
         * intrusive sentinel/head node used by `CD3DFileBatchTexture.cpp`'s
         * BVSet lanes)
         *
         * IDA signature:
         * void *__fastcall sub_xxxxxxxx(unsigned int a1);
         *
         * What it does:
         * Allocates one raw `count`-slot heap block with the VC8 overflow guard.
         * On `count > 0xFFFFFFFF / sizeof(T)`, constructs a `std::bad_alloc` by
         * invoking `std::exception(const char *&)` then overwriting the vtable
         * with `std::bad_alloc::`vftable'`, and routes through
         * `_CxxThrowException`.
         */
        [[nodiscard]] static T* allocate_slots_checked(const std::size_t count)
        {
            if (count > max_size()) {
                throw std::bad_alloc();
            }

            return static_cast<T*>(::operator new(sizeof(T) * count));
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
         * The VC8 `vector<T>::max_size()` lane: `0xFFFFFFFF / sizeof(T)` for the
         * 32-bit target. The addresses above are the `sizeof(T) == 4`
         * specialisation, which MSVC constant-folds to the `0x3FFFFFFF`
         * immediate; every other element width appears inline in its owning
         * `_Insert_n` / `reserve` body as a folded `0xFFFFFFFF / sizeof(T)`
         * constant (see the per-`T` `Address:` lines on `insert`).
         */
        [[nodiscard]] static constexpr std::size_t max_size() noexcept
        {
            return static_cast<std::size_t>(0xFFFFFFFFu) / sizeof(T);
        }

        /**
         * Address: 0x00444270 (FUN_00444270)
         * Address: 0x004445E0 (FUN_004445E0)
         * Address: 0x004449F0 (FUN_004449F0)
         * Address: 0x00444CD0 (FUN_00444CD0)
         * Address: 0x00830620 (FUN_00830620, the 4-byte-stride throw lane for
         * UICommandGraph's hash-bucket vector, reached from FUN_0082F210)
         * Address: 0x005C7290 (FUN_005C7290, the 52-byte-stride throw lane shared
         * by `BuyVectorStorage52Byte` and the `Moho::SPerArmyReconInfo`
         * `_Insert_n` grow lane FUN_005C6F90)
         * Address: 0x00452890 (FUN_00452890, reached from
         * `Moho::CAiSteeringImpl`'s vtable-anchored task chain via
         * `func_DebugLineArrayAppend`, FUN_004524F0)
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
            // Routes through the VC8 legacy `std::_Allocate<T>` lane so the
            // recovered decompiler addresses bind by name from their original
            // vector<T> call sites.
            T* newBuf = allocate_slots_checked(newCap);
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

    namespace detail
    {
        /**
         * Address: 0x007027A0 (FUN_007027A0)
         *
         * Slow-path body the legacy MSVC8 STL emitted for
         * `std::vector<T,A>::_Insert_n` when `sizeof(T) == sizeof(void*)`.
         * Inserts `count` copies of `*valuePtr` into the dword-element vector
         * referenced by `vectorStorage`, at logical position `insertPosition`,
         * growing the buffer when capacity is exhausted. The IDA shape is:
         *
         *   void __userpurge sub_7027A0@<eax>(int* a1@<eax>,
         *                                     unsigned ecx,
         *                                     int* a3,
         *                                     _DWORD* Source);
         *
         * Where `a1` carries the value lane pointer, `ecx` carries `count`,
         * `a3` is the vector pointer (`{proxy, _Myfirst, _Mylast, _Myend}`),
         * and `Source` is the `_Mylast` insert iterator.
         *
         * The function dispatches between the in-place tail-shift path and the
         * grow-and-copy reallocation path exactly as MSVC8 emitted, reusing the
         * recovered helpers `MoveDwordRangeToEnd`, `MoveDwordRangeAndReturnEnd`,
         * and `moho::runtime::RuntimeThrowVectorTooLongBW`. The inline counted
         * fills match the body the binary reaches through `FUN_00701FA0`.
         */
        void LegacyVectorDwordInsertN(
            vector_runtime_view<std::uint32_t>& vectorStorage,
            std::uint32_t* insertPosition,
            std::uint32_t count,
            const std::uint32_t* valuePtr) noexcept;
    } // namespace detail

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

        // A destructor without copy operations leaves the compiler generating
        // shallow ones, and a shallow copy hands two lists the same sentinel
        // node: the first destructor frees the nodes and the head, the second
        // walks freed memory. `ARMOR_GetArmorDefinations` returns one of these
        // by value and hit exactly that as soon as units started being built.
        list(const list& other)
            : _Myhead(0)
            , _Mysize(0)
        {
            _Init();
            for (const_iterator it = other.begin(); it != other.end(); ++it) {
                push_back(*it);
            }
        }

        list& operator=(const list& other)
        {
            if (this != &other) {
                clear();
                for (const_iterator it = other.begin(); it != other.end(); ++it) {
                    push_back(*it);
                }
            }
            return *this;
        }

        // Moving hands over the whole node chain and leaves the source as a
        // fresh empty list, so its destructor stays valid.
        list(list&& other) noexcept
            : _Myhead(other._Myhead)
            , _Mysize(other._Mysize)
        {
            this->_Myproxy = other._Myproxy;
            other._Myhead = 0;
            other._Mysize = 0;
            other._Myproxy = 0;
            other._Init();
        }

        list& operator=(list&& other) noexcept
        {
            if (this != &other) {
                _Tidy();
                _Free_head();
                _Free_proxy();
                _Myhead = other._Myhead;
                _Mysize = other._Mysize;
                this->_Myproxy = other._Myproxy;
                other._Myhead = 0;
                other._Mysize = 0;
                other._Myproxy = 0;
                other._Init();
            }
            return *this;
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

        /**
         * Transfers the node range `[first, last)` out of `other` and relinks it
         * immediately before `where`, without allocating or destroying nodes.
         *
         * This is the MSVC8 `std::list::splice` primitive. `msvc8::hash_map::_Grow`
         * uses the same-list form to migrate one node to the list tail while the
         * bucket index is being split, which is why the size bookkeeping is skipped
         * when `&other == this` (the binary's grow lane at 0x007693F4 branches over
         * its size-transfer helper for exactly that reason).
         */
        void splice(const_iterator where, list& other, const_iterator first, const_iterator last)
        {
            _Nodeptr whereNode = where._Ptr;
            _Nodeptr firstNode = first._Ptr;
            _Nodeptr lastNode = last._Ptr;

            if (firstNode == lastNode || whereNode == firstNode) {
                return;
            }

            if (&other != this) {
                const size_type moved = static_cast<size_type>(std::distance(first, last));
                other._Mysize -= moved;
                _Mysize += moved;
            }

            firstNode->_Prev->_Next = lastNode;
            lastNode->_Prev->_Next = whereNode;
            whereNode->_Prev->_Next = firstNode;

            _Nodeptr const previousTail = whereNode->_Prev;
            whereNode->_Prev = lastNode->_Prev;
            lastNode->_Prev = firstNode->_Prev;
            firstNode->_Prev = previousTail;
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
