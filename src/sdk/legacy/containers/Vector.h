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

    namespace detail
    {
        /**
         * Empty tag type standing in for `myProxy_` when a `vector<T,
         * HasDebugProxy>` instantiation carries no VC8 debug-iterator lane at
         * all -- see `vector`'s `HasDebugProxy` template parameter below.
         * `[[msvc::no_unique_address]]` lets the compiler fully elide this
         * tag's storage, dropping the class from 16 to 12 bytes.
         */
        struct NoDebugProxyLane {};
    } // namespace detail

    /**
     * MSVC8-compatible vector with fixed ABI (16 bytes by default).
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
     *
     * `HasDebugProxy` (default `true`): every existing `msvc8::vector<T>` spelling
     * in this codebase omits this parameter and is byte-for-byte unchanged by its
     * addition. The `false` arm models a leaner, confirmed-narrower 12-byte shape
     * for instantiations whose binary evidence shows no reserved proxy slot at
     * all -- e.g. `Moho::CDiscoveryService::mGames` (`moho/net/CDiscoveryService.h`):
     * its constructor (0x007BF650), destructor (0x007BF7F0), and the destructor's
     * EH-unwind cleanup funclet (0x007C8720) each touch exactly 3 consecutive
     * pointer-sized slots, never a 4th, with the group sitting directly against
     * `gpg::time::Timer`'s 8-byte-aligned `LONGLONG` member and no room for one.
     * Per RULE ONE this is one template modeling both observed shapes, not a
     * forked per-type copy.
     */
    template <class T, bool HasDebugProxy = true>
    class vector
	{
    public:
        // `iterator`/`const_iterator` are public (unlike the fields below) so
        // that generic code written against this container -- e.g.
        // `boost::range_iterator<msvc8::vector<T>>` resolving
        // `boost::algorithm::split`'s `SequenceSequenceT` for
        // `BuildLobbyIgnoreNameList` (`CLobby.cpp`) -- can name them, the same
        // way every real STL/Dinkumware container exposes its iterator
        // typedefs publicly. Purely a visibility fix: both aliases already
        // existed with this exact meaning, just unreachable from outside the
        // class.
        using iterator = T*;
        using const_iterator = const T*;

    private:
        [[msvc::no_unique_address]] std::conditional_t<HasDebugProxy, void*, detail::NoDebugProxyLane> myProxy_; // +0x0 when present (opaque _Container_proxy*)
        T* first_;      // +0x4 (+0x0 when HasDebugProxy=false)
        T* last_;       // +0x8 (+0x4 when HasDebugProxy=false)
        T* end_;        // +0xC (+0x8 when HasDebugProxy=false)

    public:
        /**
         * Default constructor: empty
         */
        vector() noexcept :
    		myProxy_{},
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
         * Address: 0x007E3730 (FUN_007E3730, `msvc8::vector<Wm3::Vector3f>::
         * vector(size_type)` for the 12-byte three-float element) -- VC8's
         * real `vector(size_type _Count)` constructor does not
         * value-construct each slot independently. It materialises one
         * default-constructed `_Ty()` temporary on the caller's stack and
         * forwards `(count, that temporary)` into the exact same
         * allocate-then-fill path as `vector(count, value)` below --
         * confirmed from this address's own raw disassembly: it zeroes
         * `last_`/`end_` on entry (leaving the debug-proxy lane at `+0x0`
         * alone), and when `count != 0` calls `FUN_007E4370` (cited just
         * below) followed by `FUN_007E6460` (`uninit_fill_n`, cited above
         * on that member) to broadcast-copy the temporary into the
         * freshly-allocated slots, then commits `last_ = first_ + count`.
         * Reached from three call sites: `Moho::DrawPathPreview`
         * (`FUN_0082A380`, recovered, `moho/sim/CWldSession.cpp`) --
         * constructs the `cellCount`-sized `worldPts` scratch buffer that
         * the very next loop overwrites element-by-element via
         * `COORDS_ToWorldPos`, so the broadcast fill value is provably dead
         * before it would ever be observed -- `Moho::MeshRenderer::
         * RenderSkeleton` (`FUN_007E2290`, still blocked on the
         * `CD3DPrimBatcher` draw-call surface), and `sub_7E2FC0`
         * (unrecovered). DB previously listed this token `blocked` citing
         * only the `RenderSkeleton` caller and missing the already-
         * recovered `DrawPathPreview` call site -- corrected here per the
         * caller-chain rule (one recovered caller is sufficient even while
         * a sibling caller is still open).
         *
         * Address: 0x007E4370 (FUN_007E4370) -- this instantiation's fused
         * allocate-and-arm-the-triplet lane, called only from
         * `FUN_007E3730` above. Takes `(unused register, output vector*,
         * count)`; the first parameter is loaded but never read in the
         * body. Guards `count > 0x15555555` (`max_size()` for a 12-byte
         * element, `0xFFFFFFFF/12`) and throws through `throw_too_long`
         * (`FUN_007E4CE0`, cited on that member) exactly like this
         * template's own `max_size() - cur < count` guards elsewhere; when
         * `count == 0` allocates via a bare `operator new(0)`, otherwise
         * defers to the overflow-checked raw allocate `FUN_007E5650`
         * (`allocate_slots_checked`, already cited above with this exact
         * address for `sizeof(T)==12`) -- either way arming `first_ =
         * last_ = <new block>`, `end_ = first_ + 12*count` in one fused
         * step rather than the separate allocate-call-then-field-commit
         * shape `insert()`'s reallocation path below uses; same net
         * effect, just realised as one out-of-line body by the compiler
         * for this instantiation. DB previously listed this token
         * `blocked` ("blocked only on its caller chain") -- corrected here
         * now that `FUN_007E3730`'s own caller chain is resolved.
         *
         * Construct with count default-inserted elements.
         *
         * VC8's own `vector(size_type)` does not independently
         * value-construct each slot -- it forwards to `vector(count,
         * value)` below with a default-constructed temporary (see the
         * addresses above), so this delegates the same way rather than
         * modelling a distinct value-construct-in-place mechanic.
         */
        explicit vector(std::size_t count) : vector(count, T()) {
        }

        /**
         * Address: 0x007BB6A0 (FUN_007BB6A0, msvc8::vector<Moho::
         * SNetCommandArg>::vector(count, value) -- the count/value
         * constructor for the 36-byte element, which VC8 implements as
         * `_Buy(count)` (see `reserve`) followed by an `insert(begin(),
         * count, value)` fill on the fresh empty storage -- exactly this
         * constructor's body. Reached from `CGpgNetInterface::ReadFromSocket`
         * (`FUN_007BAF70`'s real per-command arg-vector prefill, each slot
         * overwritten in place with its decoded value afterward).
         *
         * Construct with count copies of value
         */
        vector(std::size_t count, const T& value) : vector() {
            if (count) {
                insert(first_, count, value);
            }
        }

        /**
         * Address: 0x007CE770 (FUN_007CE770, tail-called through
         * 0x007CDBC0/0x007CEBD0's by-value-parameter shells) --
         * `msvc8::vector<Moho::CLobby's msvc8::string>::vector(InputIt,
         * InputIt)` for `boost::algorithm::split`'s `SequenceSequenceT
         * Tmp(itBegin, itEnd);` step in `func_GetIgnoreNames` (`CLobby.cpp`,
         * `BuildLobbyIgnoreNameList`). The shipped body zero-inits
         * `first_`/`last_`/`end_` (an ordinary empty-vector start, not a
         * `reserve()` fast path) and then inserts one element per iterator
         * step (`FUN_00411EA0`, cited on `insert(pos, value)` below) --
         * because `boost::algorithm`'s `transform_iterator<copy_range_type,
         * split_iterator<T>>` dereferences to a *by-value* `msvc8::string`
         * rather than a real reference, `iterator_facade` downgrades its
         * traversal category below `forward` even though the wrapped
         * `split_iterator` is itself forward-traversal, so VC8's own
         * `vector(InputIt,InputIt)` picks the naive single-pass insert-loop
         * overload instead of the `_Distance`+`reserve`+`uninit_copy` bulk
         * path every other citation on this file's constructors describes.
         * This member models that same generic (always-single-pass) shape
         * rather than trying to distinguish iterator categories, since nothing
         * in this codebase's own container types provides a smaller-than-
         * forward-but-labelled-forward iterator otherwise.
         *
         * Construct from an iterator range, inserting one element per step.
         *
         * Guarded against `InputIt` deducing to an integral type so that
         * `vector(count, value)`-shaped calls keep resolving to the
         * count/value constructor above instead of this one (the classic
         * `vector(InputIt,InputIt)` vs. `vector(size_type,const T&)`
         * overload-resolution pitfall).
         */
        template <class InputIt, class = std::enable_if_t<!std::is_integral_v<InputIt>>>
        vector(InputIt first, InputIt last) : vector() {
            for (; first != last; ++first) {
                push_back(*first);
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
         * Address: 0x006DE100 (FUN_006DE100, msvc8::vector<Moho::
         * EntityCategorySet>::vector(const vector&) for the 40-byte
         * element -- `Moho::CSquad::mCats` (`CPlatoon.h`). Reached from
         * `CPlatoon::FindPrioritizedUnit`'s `const msvc8::vector<
         * EntityCategorySet> priorityList = squad->mCats;` (CPlatoon.cpp)
         * via the thin calling-convention bridge `FUN_00723A80`.)
         * Address: 0x008F6D20 (FUN_008F6D20, `msvc8::vector<DXGI_MODE_DESC>::
         * vector(const vector&)` for the 0x1C-byte (28, `DXGI_MODE_DESC` --
         * Width/Height/RefreshRate{Num,Denom}/Format/ScanlineOrdering/Scaling)
         * POD element -- `n = other.size()` (the `(other.last_-other.first_)/28`
         * divide, null-guarded so an empty `other` never subtracts through a
         * null `first_`), then `if (Buy(n)) { last_ = uninit_copy(other.first_,
         * other.last_, first_); }`, exactly this constructor's `if (n) {
         * reserve(n); uninit_copy_n(...); last_ = first_+n; }` body with the
         * default-construct-then-reserve steps fused by the compiler into one
         * helper. That fused zero-the-triple-then-conditionally-buy(n) helper is
         * `FUN_008F69A0` (`char __thiscall(this, count)`): zeroes `first_`/
         * `last_`/`end_` unconditionally, returns `false` on `count==0` (so the
         * caller's `if(...)` guard skips the copy for an empty source), else
         * checks `count > 0x9249249` (`max_size()` for this element,
         * `0xFFFFFFFF/28`) and throws through `FUN_008F6890`
         * (`std::length_error("vector<T> too long")`, cited below on
         * `throw_too_long`) exactly like `reserve()`'s own guard above, then
         * calls the checked allocator `FUN_008F5FD0` (cited below on
         * `allocate_slots_checked`) and arms `first_ = last_ = <new block>`,
         * `end_ = first_ + 28*count` -- `allocate_slots_checked`'s own
         * `0xFFFFFFFF/count < 0x1C` guard is the same defense-in-depth
         * `bad_alloc` backstop `reserve()`'s doc above describes, not a
         * duplicate check. The same `FUN_008F69A0` body is reused verbatim by
         * this specialization's `operator=` (`FUN_008F6DD0`, cited below on
         * `operator=`) for its post-free rebuy step -- both call sites need the
         * identical "start from an all-null/just-freed triple, buy blank
         * storage for `count` elements" operation, so one compiled body serves
         * both. The 0x1C-byte uninitialized-copy step is `FUN_008F6470` (cited
         * below on `uninit_copy_n`); its two calling-convention bridges --
         * `FUN_008F65F0` (`__cdecl`, `return sub_8F6470(a1,a2,a3);`) and
         * `FUN_008F6690` (`__stdcall`, same tail call) -- carry no logic of
         * their own and need no separate citation. Source-level trigger:
         * `AdapterD3D10::AdapterD3D10(const AdapterD3D10& other) : ...,
         * modes_(other.modes_) {}` (D3D10Interfaces.cpp) deep-copies
         * `AdapterD3D10::modes_` (`msvc8::vector<AdapterModeD3D10>`,
         * `AdapterD3D10.hpp`), whose own copy constructor placement-constructs
         * each 116-byte `AdapterModeD3D10` element via
         * `uninit_copy_n<AdapterModeD3D10>`, which invokes `AdapterModeD3D10`'s
         * compiler-synthesized memberwise copy constructor -- that in turn
         * copy-constructs `AdapterModeD3D10::modes_` (`+0x64`, this exact
         * `msvc8::vector<DXGI_MODE_DESC>`) through this token.
         * `AdapterModeD3D10` has no user-declared special member functions, so
         * no further `src/sdk` change is needed at that link -- the compiler
         * default already produces this call chain (the `AdapterModeD3D10`-
         * level copy constructor/`operator=` pair itself, `FUN_008F7020`/
         * `FUN_008F7110`, remains a separate `msvc8::vector<AdapterModeD3D10>`
         * instantiation gap -- see below, still uncited). DB previously listed
         * `FUN_008F6D20` and `FUN_008F69A0` `external_dependency`
         * ("all-external-callees thunk" / body "references only third-party
         * runtime... no Moho/gpg engine references") -- wrong: both are
         * `DXGI_MODE_DESC`/`AdapterModeD3D10` engine-instantiated vector
         * internals reached from committed `gpg::gal::AdapterD3D10` source;
         * corrected to `recovered` here.)
         * Address: 0x008FF220 (FUN_008FF220, `msvc8::vector<AdapterModeD3D10>::
         * vector(const vector&)` for the 0x74-byte (116, `AdapterModeD3D10` --
         * format_/output_/outputDesc_/modes_) non-trivial element -- the
         * one-level-up sibling of `FUN_008F6D20` above, fully inlined into a
         * single body rather than split into a `FUN_008F69A0`-style fused
         * helper: zeroes `first_`/`last_`/`end_` unconditionally, computes
         * `n = (other.last_-other.first_)/116` null-guarded exactly like the
         * inner instantiation, checks `n > 0x234F72C` (`max_size()` for this
         * element, `0xFFFFFFFF/116`) throwing through `FUN_008F6900` (cited
         * below on `insert`), allocates via the checked allocator
         * `FUN_008F6040` (`allocate_struct116_slots_checked`, already
         * recovered), arms the triple, then uninitialized-copies the whole
         * source range via `FUN_008FE940` (cited below on `uninit_copy_n`).
         * Source-level trigger: `AdapterD3D10::AdapterD3D10(const
         * AdapterD3D10& other) : ..., modes_(other.modes_) {}`
         * (D3D10Interfaces.cpp, already committed) -- `modes_` here is
         * `AdapterD3D10::modes_` itself (`+0x12C`, the *outer*
         * `msvc8::vector<AdapterModeD3D10>`), one level above the
         * `AdapterModeD3D10::modes_` (`+0x64`) the `FUN_008F6D20` citation
         * above describes. Confirmed via `_callgraph_index.sqlite`
         * `call_edges`: this token's sole caller is `FUN_008FF450`
         * (`AdapterD3D10`'s recovered copy constructor). DB previously
         * listed this token `external_dependency` ("all-external-callees
         * thunk") -- wrong for the same reason `FUN_008F6D20`/`FUN_008F69A0`
         * were: its only real callee besides the throw/allocate helpers is
         * `FUN_008FE940`, an engine-instantiated `AdapterModeD3D10` vector
         * internal, not third-party runtime; corrected to `recovered` here.
         *
         * `FUN_008F7020`/`FUN_008F7110` (the single-`AdapterModeD3D10`-level
         * copy constructor and a second, structurally near-identical
         * single-element construct helper) remain uncited despite an
         * exhaustive search: neither is called by any traced
         * `msvc8::vector<AdapterModeD3D10>` internal (`FUN_008F7390`,
         * `FUN_008FE940`, `FUN_008F74A0`, `FUN_008F72D0`, `FUN_008F70A0`,
         * `FUN_008F7770`, `FUN_008FF220`, or `AppendAdapterModeEntry`/
         * `ProbeOutputsAndModes` in D3D10Interfaces.cpp -- all of them inline
         * their own field-by-field copy rather than delegating to either
         * token). `FUN_008F7020` (plain `__thiscall`, no null guard, `retn
         * 4`, `.asm`-confirmed) has zero incoming code or data xrefs anywhere
         * in `_callgraph_index.sqlite` (`call_edges`, `data_refs`,
         * `incoming_xrefs` all empty) and is absent from the `reachable`
         * table even at the conservative seeded-root BFS. `FUN_008F7110`
         * (mixed-convention entry -- `ecx`-passed dest pushed to a local,
         * plain `retn`, its own dedicated `SEH_8F7110`/`stru_EA3368`
         * `__CxxFrameHandler3` scope table, null-guarded copy body -- the
         * same "defensive-null" shape already documented elsewhere on this
         * member for `FUN_00549BC0`/`FUN_007CCEB0`) has exactly one caller,
         * `FUN_008F734A` -- confirmed, independently of a prior
         * investigation that reached the same wall, via a direct `functions`
         * table query against `_callgraph_index.sqlite`: no row for that
         * address, and no tracked function's `[start_ea,end_ea)` contains it
         * either -- it falls in a genuine 0x25-byte unclassified gap between
         * `FUN_008F7320` (ends `0x008F733B`) and `FUN_008F7360` (starts
         * `0x008F7360`). No further evidence found; left un-recovered rather
         * than force a citation. A future pass with IDA available could try
         * re-analyzing that gap directly (manual function creation over
         * `[0x8F733B,0x8F7360)`) to recover `FUN_008F734A`'s own body and
         * settle which of `FUN_008F7020`/`FUN_008F7110` it is.)
         *
         * Address: 0x00753020 (FUN_00753020, `msvc8::vector<moho::
         * SExtraUnitData>::vector(const vector&)` for the 0x20-byte element
         * -- SEH-guarded copy constructor, `.asm`-confirmed: `(mLast-mFirst)
         * >> 5` element count, `if(n){ zero the triple; buy(n); uninit_copy;
         * }` shape matching this constructor exactly. Its fused
         * allocate-and-arm-the-triplet lane (the `reserve(n)` guard +
         * `reallocate_to(n)` steps fused into one out-of-line body, same
         * pattern as `FUN_007E4370`/`FUN_008F69A0` above) is `FUN_0074DBA0`:
         * guards `count > 0x7FFFFFF` (`max_size()` for this element) and
         * throws through `throw_too_long` (`FUN_0074F680`, cited below),
         * else calls the checked allocator `allocate_slots_checked`
         * (`FUN_00751C40`, cited
         * below) and arms `first_ = last_ = <new block>`. The uninitialized
         * copy step is `uninit_copy_n`'s primary emission `FUN_00756A00`
         * (cited below). Calls-into evidence is solid -- `FUN_00756A00` is
         * independently reached from `Sim::AdvanceBeat`'s `push_back`/
         * `insert` chain (cited above), and `FUN_0074DBA0` is independently
         * reached a second way, from `operator=`'s (`FUN_007530C0`, cited
         * below) reallocation branch, itself confirmed via a real, direct
         * `.xrefs.txt` code xref from `Moho::CWldSession::DoBeat`; however,
         * exhaustive search
         * (`FUN_00753020.xrefs.txt`: zero code/data xrefs;
         * `_callgraph_index.sqlite` `call_edges`/`incoming_xrefs`: empty;
         * `function_icf_twins`: no match; `reachable`: UNREACHED) found no
         * caller for this specific address, direct or indirect. Recorded
         * per the un-recovered-`FUN_008F7020` precedent above rather than
         * forced -- the element shape, stride, and callee chain leave no
         * plausible owner other than this instantiation, but a genuine
         * source-level trigger (a `msvc8::vector<SExtraUnitData>` copied by
         * value somewhere in `Sim.cpp`/`CWldSession::DoBeat`) has not yet
         * been located. Re-examine if a caller surfaces during a future
         * `DoBeat` recovery pass. Migrated off
         * `CopyConstructInlineQwordVectorWithTagStorage` in
         * `gpg/core/containers/FastVectorInsertLanes.cpp` (RULE ONE
         * hand-rolled `msvc8::vector<T>` reimplementation, see `push_back`
         * above for the full evidence chain).
         *
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
            if constexpr (HasDebugProxy) {
                other.myProxy_ = nullptr;
            }
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
         * Address: 0x0088A150 (FUN_0088A150, msvc8::vector<Moho::WaveParameters>::
         * ~vector for the 136-byte polymorphic element -- same `_Tidy()` shape
         * as the SPerArmyReconInfo instantiation above: `for (it = myFirst;
         * it != myLast; it += 34 dwords) (**it)(it, 0)` then
         * `operator delete(myFirst)` and null all three pointer lanes. The
         * per-element teardown dispatches through `WaveParameters`'s own
         * vtable slot 0 (the `(**it)(it, 0)` call, `0` = "don't free, this is
         * placement destroy only" per the standard MSVC deleting-destructor
         * ABI) because `WaveParameters` declares a virtual destructor; this
         * `destroy_range` member already expresses that as an ordinary
         * `first->~T()` call, which is what a polymorphic `T`'s explicit
         * destructor call compiles to here -- no raw vtable/offset dispatch
         * needed in the recovered source. Called from `WavePattern`'s
         * destructor (`FUN_008877E0`, `moho/terrain/water/WaveSystem.cpp`)
         * automatically, since `mWaves` is `WavePattern`'s last-declared
         * member. `FUN_00889C50` (a one-instruction tail-call thunk,
         * `skip`-classified as an ICF-foldable shard) also reaches this same
         * body from `WavePattern`'s Lua constructor's EH unwind funclet.)
         *
         * Address: 0x0085A1F0 (FUN_0085A1F0, msvc8::vector<T>::~vector for a
         * 16-byte element made of two independent shared/weak-pointer-style
         * handle pairs -- same element shape as `FUN_0085AB80`'s
         * `uninit_copy_n` cited above, reached via `Moho::CUIWorldView`'s
         * subsystem): destroys each element through `FUN_00859E90` (dual
         * `_InterlockedExchangeAdd` release at elem+4/elem+12, confirming
         * the two handle pairs) then frees the buffer and nulls the three
         * pointer lanes at file-scope globals `dword_10C425C`/`_4260`/
         * `_4264` -- a global instance, not a class member. Real caller is
         * `FUN_00C06B20`, a one-instruction `jmp` thunk (`sub_85A1F0();
         * return;`) address-taken into the CRT static-teardown table by
         * `FUN_00BE52F0` (an `__xc_a`-lane registrar, the same shape as 327
         * sibling atexit cleanup thunks already `skip`-tagged in this
         * codebase) -- a known linker-emitted bridge citing this body's own
         * evidence, not an independent function.
         *
         * Address: 0x00740700 (FUN_00740700, msvc8::vector<moho::
         * GeomCamera3>::~vector for the 0x2C8 (712)-byte element --
         * destroys the live `[first_,last_)` run through `GeomCamera3::
         * ~GeomCamera3` then frees the buffer, the same `destroy_all()` +
         * `deallocate_all()` shape as this member's generic body, just not
         * tail-calling it directly.
         * Address: 0x0073F620 (FUN_0073F620, tail-forwarding `jmp` thunk
         * into 0x00740700, not a distinct body.) Three real call sites, all
         * already recovered: `Moho::SSyncFilter::~SSyncFilter`
         * (`SSyncFilter.cpp` -- `geoCams`'s own compiler-generated member
         * teardown; that destructor's own doc comment already calls out
         * "the compiler-generated member teardown continues with
         * `geoCams`"), `Moho::WLD_DoPlayingAction` (`CWldSession.cpp` --
         * the local `const msvc8::vector<GeomCamera3> cameras` populated
         * from `CAM_GetAllCameras()` and destroyed at the end of its `if`
         * block), and `Moho::CAM_GetAllCameras` itself (`RCamManager.cpp`
         * -- reached through the thunk per the raw xref at 0x00BA3DE3, the
         * EH-unwind path for its local `result` on an exception from
         * `push_back`/`CameraGetView` mid-loop). Formerly modeled as a
         * standalone `LegacyGeomCameraVectorSlot` reach-in struct plus
         * `DestroyLegacyGeomCameraVectorSlot`/
         * `DestroyLegacyGeomCameraVectorSlotThunk` free functions in
         * `moho/sim/SimDriver.cpp` with no source-level caller --
         * `GeomCamera3` does not appear anywhere in `SSyncData`'s real
         * declaration, so that prior siting was never correct -- collapsed
         * into this template instantiation, RULE ONE.
         *
         * Address: 0x00740C00 (FUN_00740C00, msvc8::vector<Moho::
         * SEntityVariableUpdateEntry>::~vector for the 0xD8 (216)-byte
         * element -- destroys the live `[first_,last_)` run through
         * `SSTIEntityVariableData::~SSTIEntityVariableData` on each
         * record's `mVariableData` sub-field (the `mEntityId`/
         * `mReserved04` header dwords are trivially destructible) then
         * frees the buffer. IDA's own demangler mislabels this
         * `??1fastvector_struct_SSTIEntitytVariableData@gpg@@QAE@@Z` (note
         * the "Entityt" typo -- a synthesized, not a genuine mangled, name;
         * there is no `gpg::fastvector_struct<T>` template anywhere in this
         * codebase). The element shape/size (entity id + reserved dword +
         * `SSTIEntityVariableData` payload) matches `SSyncData::
         * mEntityUpdates` (`SimDriver.h`) exactly.
         * Address: 0x00740400 (FUN_00740400, `j_` jump-thunk into
         * 0x00740C00.) Two real call sites, both already recovered and both
         * compiler-generated (no explicit source line names either):
         * `Moho::SSyncData::~SSyncData` (`SimDriver.cpp`, normal-path
         * member teardown -- direct `call` at 0x007400D2) and `Moho::
         * SSyncData::SSyncData` (`SimDriver.cpp`, the `= default` ctor's
         * EH-unwind funclet, reached through the thunk, in case a later
         * member's constructor throws after `mEntityUpdates`
         * default-constructs). Formerly modeled as a standalone
         * `LegacySyncEntityVariableVectorSlot`/`LegacySyncEntityVariableEntry`
         * (a duplicate of the header's real `SEntityVariableUpdateEntry`)
         * reach-in struct pair plus a
         * `DestroyLegacySyncEntityVariableVectorSlot` free function in
         * `moho/sim/SimDriver.cpp` -- collapsed into this template
         * instantiation, RULE ONE.
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
         * Address: 0x0084FF80 (FUN_0084FF80, msvc8::vector<wxWindowBase*>::
         * operator=(const vector&) -- the full VC8 assign shape (self-check,
         * empty-source clear, fits-in-capacity assign-over-then-append,
         * grows-beyond-capacity free-and-rebuy, shrinks-in-place memmove)
         * for the 4-byte trivially-copyable pointer element (`wxWindowBase*`
         * is this codebase's type-erased stand-in for the real wx
         * `wxEvtHandler*` -- see `PopEventHandler`/`PushEventHandler` in
         * WxRuntimeTypes.h). This is the per-window saved-handler inner
         * vector `moho::SuspendInputWindowEventHandlersAndFlushQueue`
         * (UiRuntimeTypes.cpp) builds as `msvc8::vector<msvc8::vector<
         * wxWindowBase*>>`; reached through the outer vector's grow-relocate
         * step (`FUN_0084F820`, `copy_or_move_assign` for the 16-byte
         * `vector<wxWindowBase*>` element, cited below on
         * `copy_or_move_assign`), which the source
         * call `suspended.resize(g_UIManager->mInputWindows.size())`
         * instantiates regardless of how many old elements that particular
         * call site happens to relocate at runtime.)
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
         * Address: 0x008F6DD0 (FUN_008F6DD0, `msvc8::vector<DXGI_MODE_DESC>::
         * operator=(const vector&)` for the 0x1C-byte (28, `DXGI_MODE_DESC`)
         * POD element -- the full VC8 `assign` shape: self-check guard first
         * (`this == &rhs` early return); empty source -> `erase(begin(),
         * end())` on `this` (`FUN_008F6790`, cited below on `erase`) to clear
         * it, the returned iterator discarded; source longer but fits in
         * capacity -> assign-over the retained prefix (`FUN_008F64A0`,
         * `copy_or_move_assign` shape, already recovered as
         * `CopyForward28ByteLaneSourceFirst` in
         * `gpg/core/containers/FastVectorInsertLanes.cpp`) then
         * uninitialized-copy the excess tail (`FUN_008F66E0` -> `FUN_008F64D0`,
         * `uninit_copy_n` shape, already recovered in the same file --
         * `FUN_008F64D0` is additionally a byte-identical `function_sha256` ICF
         * twin of `FUN_008F6470`, cited below on `uninit_copy_n`); source
         * longer and does not fit -> `operator delete` the old block, rebuy
         * blank storage for `other.size()` through `FUN_008F69A0` (the same
         * fused zero-then-buy helper cited above on `vector(const vector&)`),
         * then uninitialized-copy everything via the same `FUN_008F66E0`/
         * `FUN_008F64D0` pair; source shorter or equal -> assign-over the
         * prefix (`FUN_008F64A0` again) and rebase `last_` directly, with no
         * explicit destroy call for the truncated tail because the element is
         * trivially destructible. `FUN_008F5E00` (`this->first_ ?
         * (this->last_-this->first_)/28 : 0`, i.e. `size()`, cited below)
         * computes both sides of every length comparison in this body.
         * Source-level trigger: same chain as `vector(const vector&)` above,
         * but through `AdapterD3D10::operator=(const AdapterD3D10&)`'s
         * `modes_ = other.modes_;` (D3D10Interfaces.cpp) instead of the copy
         * constructor -- the *outer* `msvc8::vector<AdapterModeD3D10>::
         * operator=` (not yet individually recovered) has its own
         * assign-over step which, like every other `AdapterModeD3D10`-level
         * copy/assign operation traced in this cluster, inlines the
         * field-by-field copy directly rather than calling out to a
         * standalone `AdapterModeD3D10::operator=` symbol -- no such symbol
         * exists anywhere in the traced call graph (see the exhaustive
         * `FUN_008F7020`/`FUN_008F7110` search on `vector(const vector&)`
         * above). That inlined assign-over loop is `FUN_008F72D0` (cited
         * below on `insert`, `msvc8::vector<AdapterModeD3D10>`'s
         * `std::fill`-shaped gap-overwrite step), which calls this token
         * directly for the `AdapterModeD3D10::modes_` sub-object of each
         * already-constructed destination element. DB previously listed
         * this token `blocked` ("stale in_progress claim after reboot, no
         * Address evidence") with zero citations anywhere in `src/sdk`;
         * corrected to `recovered` here.)
         * Address: 0x008EF870 (FUN_008EF870,
         * msvc8::vector<gpg::gal::AdapterModeD3D9>::operator=(const vector&)
         * -- the full VC8 assign shape for this element, called on
         * `gpg::gal::AdapterD3D9::modes` (offset +0x60) as part of
         * `AdapterD3D9`'s compiler-synthesized memberwise `operator=`
         * (`AdapterD3D9` declares no user `operator=` in `AdapterD3D9.hpp`,
         * only a copy ctor/dtor). `AdapterD3D9::operator=` itself is needed
         * by this method's own gap-fill (`insertAt[i] = localValue`) and
         * tail-shift (`insertAt[count+i-1] = ...insertAt[i-1]`) assign
         * expressions once `T = AdapterD3D9` -- the real binary keeps the
         * tail-shift loop out of line as `FUN_008EFCD0` (112-byte element,
         * reverse pointer-walk, bridged through `FUN_008F0380` from the
         * `_Insert_n`-shaped grow/shift lane `FUN_008F1890`), while this
         * template inlines the equivalent loop directly into `insert`.
         * Empirically confirmed, not just theorized: compiling
         * `D3D9Interfaces.cpp` (tucheck, unchanged by this pass) and
         * inspecting the object file with `dumpbin /symbols` shows both
         * `msvc8::vector<AdapterModeD3D9,1>::operator=` and
         * `gpg::gal::AdapterD3D9::operator=` as real `SECT`-defined symbols
         * -- genuinely instantiated, not merely declared. Source trigger:
         * `AsDeviceD3D9Runtime(device).adapters.push_back(adapter);` in
         * `D3D9Interfaces.cpp`, where `adapters` is
         * `DeviceD3D9BackendObject::adapters` /
         * `DeviceD3D9RuntimeView::adapters`, both
         * `msvc8::vector<gpg::gal::AdapterD3D9>`. Note:
         * `msvc8::vector<AdapterD3D9>::copy_or_move_assign` itself does
         * *not* appear in that object file -- confirming this template's
         * `insert` never calls the separate `copy_or_move_assign` helper,
         * unlike `assign`/`operator=`, which is why `FUN_008EFCD0` is cited
         * on `insert` below rather than on `copy_or_move_assign`.)
         *
         * Address: 0x007530C0 (FUN_007530C0, `msvc8::vector<moho::
         * SExtraUnitData>::operator=(const vector&)` for the 0x20-byte
         * element, `Sim::mSyncSerializeGroup2`) -- `.c`-confirmed the full
         * VC8 assign shape this member's `assign()` helper implements:
         * self-check: `if (a1==a2) return a1;`; empty-source clear branch
         * tail-calling `FUN_007536D0` (a small dedicated helper for this
         * branch only: no-op when the destination is already empty, else
         * assign-then-destroy-the-tail through `copy_or_move_assign`
         * [`FUN_00755DE0`, `n=0`] + `destroy_range` [`FUN_00742170`], both
         * cited elsewhere on this template); source-longer-than-
         * capacity branch calling `copy_or_move_assign` over the retained
         * prefix (`FUN_007549D0`), `destroy_range` on the excess dead tail
         * (`FUN_00742170`, cited above), freeing the old block and rebuying
         * through the fused buy helper (`FUN_0074DBA0`, cited below on the
         * copy constructor -- this operator= is its SECOND confirmed
         * caller, not "only from the constructor" as first thought) then
         * `uninit_copy_n`'s alias emission (`FUN_00754A00`, cited above);
         * source-fits-in-capacity branch assigns over the prefix
         * (`FUN_00755DE0`) and rebases `last_`.
         *
         * Real, direct, `.xrefs.txt`-confirmed code xref: `call sub_7530C0`
         * at `0x00895214`, inside `Moho::CWldSession::DoBeat`
         * (`FUN_00894530`, already recovered, `CWldSession.cpp`).
         *
         * Follow-up landed: `DoBeat`'s call site at 0x00895214 is now
         * `mSyncExtraUnitData = beat.mSyncExtraUnitData;`
         * (`CWldSession.cpp`), a real `msvc8::vector<SExtraUnitData>::
         * operator=` invocation satisfying the source-level-invocation rule
         * for this token. The prior `AssignSyncInlineVectors(
         * mSyncInlineVectors, beat.mInlineScratchVectors)` wiring at that
         * exact call site was a citation-integrity bug -- this address's own
         * callees explicitly copy a nested 8-byte-element sub-vector
         * (`FUN_00755DE0`/`FUN_00750A80`, `>>3` capacity arithmetic) plus
         * one trailing scalar dword at +0x18, matching only
         * `SExtraUnitData`'s layout (`gpg::core::FastVectorN<
         * SExtraUnitDataPair,1> pairs; EntId unitEntityId; ...`), never a
         * bare `FastVectorN<int32_t,4>`. `moho::SyncInlineVector` and
         * `AssignSyncInlineVectors` had zero other citations anywhere in
         * `src/sdk` and were removed; `CWldSession::mSyncExtraUnitData` /
         * `SSyncData::mSyncExtraUnitData` (`SimDriver.h`) and
         * `CWldSession::DrawCommandSplats`'s reader (0x008515B0,
         * 0x008518A4..0x0085189A) were retyped to match. Cited on shape,
         * callee chain, and the confirmed real xref.
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
            if constexpr (HasDebugProxy) {
                rhs.myProxy_ = nullptr;
            }
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
         * Address: 0x0052BE20 (FUN_0052BE20, `msvc8::vector<
         * Moho::RRuleGameRulesLuaExportBinding>::begin` for the 16-byte
         * element, `RRuleGameRulesImpl::mMaps` -- same out-pointer form as
         * `FUN_0054C170` above (`*outBinding = bindingArray->first_; return
         * outBinding;`). Previously modeled in RRuleGameRules.cpp as a
         * bespoke pair of wrapper functions
         * (`StoreLuaExportBindingBeginLane`/`...Adapter`) reaching into a
         * hand-rolled `RRuleGameRulesLuaExportBindingArray` struct's raw
         * `mBegin` field -- removed once that field became a real
         * `msvc8::vector<T>` and this member's own `begin()` covers it
         * directly. Zero recorded callers in `_callgraph_index.sqlite`
         * (same as several of this member's other per-instantiation
         * emissions above); reached transitively once real code calls
         * `mMaps.begin()`, which the migrated `FindExportBinding`/
         * `RegisterBlueprintInCategoryMaps` (RRuleGameRules.cpp, Sim.cpp)
         * now do by name.)
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
         * Address: 0x0052BE30 (FUN_0052BE30, `msvc8::vector<
         * Moho::RRuleGameRulesLuaExportBinding>::end` sibling of
         * `FUN_0052BE20` above -- same out-pointer form, same removed
         * `StoreLuaExportBindingEndLane`/`...Adapter` wrapper pair. Reached
         * transitively once real code calls `mMaps.end()`, which
         * `FindExportBinding`/`ExportBindingCount`/
         * `RegisterBlueprintInCategoryMaps` now do by name.)
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
         * Address: 0x008F5E00 (FUN_008F5E00, msvc8::vector<DXGI_MODE_DESC>::size
         *   for the 0x1C-byte element -- `this->first_ ? (this->last_-
         *   this->first_)/28 : 0`. Reached from the `_Insert_n` grow lane
         *   `FUN_008F6A50` (cited below on `insert`) and from `operator=`
         *   (`FUN_008F6DD0`, cited above). `StartupHelpers.cpp` previously
         *   mis-attributed this token to `AllowedProtocolsCountUnsafe`
         *   (`gAllowedProtocols.size()`, an unrelated `std::wstring` vector)
         *   grouped alongside two genuinely-unrelated addresses -- wrong: both
         *   of this token's real callers, confirmed from
         *   `_callgraph_index.sqlite` `call_edges`, are this `DXGI_MODE_DESC`
         *   vector's own internals, not the allowed-protocols list. Citation
         *   moved here; the stray `Address:` line removed from
         *   `StartupHelpers.cpp`.)
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
         * Address: 0x008F5D90 (FUN_008F5D90, `msvc8::vector<AdapterModeD3D10>::
         * capacity` for the 0x74-byte (116) element -- `this->first_ ?
         * (this->end_-this->first_)/116 : 0`, same ternary null-guard shape
         * as the sibling `FUN_008F5E00`/`size()` entry above. Reached from
         * `_Insert_n`'s growth-branch capacity check (`FUN_008F7770`, cited
         * below on `insert`, `cur+count > capacity()`). DB previously
         * mis-attributed this token to `CrtRuntimeHelpers.cpp` with no real
         * citation there (same "DB-integrity bulk fix 2026-08-24... plausible-
         * sounding boilerplate" contamination already documented for several
         * other tokens this session); corrected to `recovered` here -- this
         * member's own prose already named it as `FUN_008F7770`'s
         * `recommended_capacity` input but never gave it a formal Address
         * block until now.)
         * Address: 0x0092BCA0 (FUN_0092BCA0, `msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::capacity` for the 12-byte
         * element -- `first_ ? (end_-first_)/12 : 0`. Reached from the
         * `_Insert_n` growth-branch capacity check `FUN_0092F630` (cited
         * above on `insert`).)
         * Address: 0x0092C280 (FUN_0092C280, `msvc8::vector<gpg::HaStar::
         * ClusterSearchOpenHeapEntryRuntime>::capacity` for the sibling
         * 12-byte open-heap-entry instantiation -- same shape, reached from
         * that element's own `_Insert_n` growth check `FUN_0092F240`.)
         * Address: 0x0052CFB0 (FUN_0052CFB0, `msvc8::vector<
         * Moho::RRuleGameRulesLuaExportBinding>::capacity` for the 16-byte
         * element, `RRuleGameRulesImpl::mMaps` -- `beginRaw == 0 ? 0 :
         * (capacityRaw - beginRaw) / 16`, the same null-guarded
         * `(end_-first_)/sizeof(T)` fold as `FUN_008F5D90`/`FUN_0092BCA0`
         * above, just computed in raw byte terms via `reinterpret_cast`
         * rather than `T*` pointer subtraction. Previously modeled in
         * RRuleGameRules.cpp as `ComputeLuaExportBindingCapacityLane`/
         * `GetLuaExportBindingCapacityLane`, reaching into the hand-rolled
         * `RRuleGameRulesLuaExportBindingArray`'s raw `mBegin`/
         * `mCapacityEnd` fields -- removed once that field became a real
         * `msvc8::vector<T>` and this member's own `capacity()` covers it
         * directly; reached transitively once real code calls
         * `mMaps.capacity()`, which the migrated `AddOrGetExportBinding`
         * (RRuleGameRules.cpp, via `reserve()`/`insert()`'s own internal
         * capacity check) now does.)
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
         *
         * A trivial 2-instruction return-by-value form of this member
         * (`*out = *first_`, `out` a hidden return-value pointer, `first_`
         * read from `this+4`) is byte-identical across 133 confirmed
         * instantiations for different 4-byte element types (`function_sha256`
         * match in `_callgraph_index.sqlite`) -- e.g. `FUN_0041F360`,
         * `FUN_00431AE0`, `FUN_005142F0`, `FUN_004E2C60`. All 133 have zero
         * callers/incoming_xrefs/data_refs anywhere in the shipped binary
         * (independently re-verified for the whole group, not sampled) --
         * fully inlined at every real call site, these out-of-line copies are
         * never referenced. Most are already `skip`/`recovered` from prior
         * passes with their own justification; not individually re-cited
         * here to avoid duplicating 133 near-identical Address lines for a
         * body this trivial. Do not add new bespoke per-type `front()`
         * free functions if more of these twins surface -- they are this
         * member, dead-COMDAT-classified, nothing further to write.
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
         * Address: 0x00560D60 (FUN_00560D60,
         * msvc8::vector<Moho::SSTIArmyVariableData>::reserve -- exact-capacity
         * grow for the 0x160-byte element: max_size guard against 0x1999999
         * (`0xFFFFFFFF / 0x160`), allocates via the checked allocator
         * FUN_00562700, uninit-copies the live range through FUN_005632D0
         * (both already recovered), frees the old block implicitly and
         * rebases the lanes. Reached from `Moho::SSyncData::ReserveSizes`
         * (FUN_00560A00) as `syncData->mArmyUpdates.reserve(sizes->mArmyData)`
         * -- recovered as `ReserveSyncDataSizes` in Sim.cpp, called from
         * `Sim::Sync` right after `SnapshotSyncReserveCounts`.)
         * Address: 0x00560EB0 (FUN_00560EB0,
         * msvc8::vector<Moho::SEntityVariableUpdateEntry>::reserve --
         * exact-capacity grow for the 0xD8-byte
         * `pair<EntId, SSTIEntityVariableData>` element: max_size guard
         * against 0x12F684B (`0xFFFFFFFF / 0xD8`), allocates via the checked
         * allocator FUN_00562770, uninit-copies the live range through
         * FUN_00563380 (both already recovered), frees the old block
         * implicitly and rebases the lanes. Reached from
         * `Moho::SSyncData::ReserveSizes` (FUN_00560A00) as
         * `syncData->mEntityUpdates.reserve(sizes->mEntityData)` -- recovered
         * as `ReserveSyncDataSizes` in Sim.cpp, same call site as
         * `mArmyUpdates.reserve` above.)
         * Address: 0x00561000 (FUN_00561000,
         * msvc8::vector<Moho::SUnitVariableUpdateEntry>::reserve --
         * exact-capacity grow for the 0x238-byte element: max_size guard
         * against 0xB60B60 (`0xFFFFFFFF / 0x238`, throw lane FUN_005617E0,
         * already cited as this specialization's `throw_too_long`),
         * allocates via the checked allocator FUN_005627E0, uninit-copies
         * the live range through FUN_00563430 (the `uninit_copy_n` range
         * form cited above), frees the old block implicitly and rebases the
         * lanes. Reached from `Moho::SSyncData::ReserveSizes` (FUN_00560A00)
         * as `syncData->mUnitUpdates.reserve(sizes->mUnitData)` -- recovered
         * as `ReserveSyncDataSizes` in Sim.cpp, same call site as
         * `mArmyUpdates.reserve`/`mEntityUpdates.reserve` above.)
         * Address: 0x00561160 (FUN_00561160,
         * msvc8::vector<Moho::SSyncPublishedCommandPacket>::reserve --
         * exact-capacity grow for the 0x78-byte element: max_size guard
         * against 0x2222222 (`0xFFFFFFFF / 0x78`, throw lane FUN_00561900),
         * allocates via the checked allocator FUN_00562850, uninit-copies
         * the live range through FUN_005634F0, frees the old block
         * implicitly and rebases the lanes. Reached from
         * `Moho::SSyncData::ReserveSizes` (FUN_00560A00) as
         * `syncData->mPublishedCommandPackets.reserve(sizes->mCommandData)`
         * -- recovered as `ReserveSyncDataSizes` in Sim.cpp, same call site
         * as `mArmyUpdates.reserve`/`mEntityUpdates.reserve` above.)
         *
         * Reserve at least `newCap` elements without changing size.
         *
         * Address: 0x007BB7F0 (FUN_007BB7F0, msvc8::vector<Moho::
         * SNetCommandArg>::_Buy on an empty vector -- allocates raw storage
         * for `count` elements and arms the triplet with nothing constructed
         * yet. The folded guard constant `0x71C71C7` is exactly `max_size()`
         * for the 36-byte `SNetCommandArg` -- `0xFFFFFFFF / 0x24`.)
         *
         * VC8's `reserve()` guards against an unrepresentable request itself
         * (`_Xlen()`, `std::length_error("vector<T> too long")`) before ever
         * reaching the allocator -- the same guard `_Buy` opens with.
         * `allocate_slots_checked`'s `bad_alloc` guard below is `_Allocate<T>`'s
         * own backstop for internal grow paths that call it directly; the two
         * are separate real guards, not duplicates.
         *
         * Address: 0x005C7680 (FUN_005C7680, sub_5C7680) --
         * `msvc8::vector<Moho::ReconBlip*>::reserve` for the 4-byte pointer
         * element (`Moho::CAiReconDBImpl::mBblips`/`mTempBlips`,
         * `CAiReconDBImpl.h`). Opens with the max_size guard against
         * 0x3FFFFFFF (`0xFFFFFFFF / 4`, throw lane `FUN_005C79A0`), allocates
         * via `FUN_005CA040`, uninit-copies the live range through
         * `FUN_005CE060` (cited below on `uninit_copy_n`), frees the old
         * block and rebases the three lanes -- confirmed against the `.asm`.
         * Reached from `DeserializeReconBlipPointerVector`'s (`FUN_005C58E0`,
         * `CAiReconDBImplTypeInfo.cpp`, already recovered) `storage->
         * reserve(count)` call, made immediately after reading the archived
         * element count and before the per-element read loop -- confirmed
         * against the `.c`: `sub_5C7680(v6)` is the first call after
         * `ReadUInt`. Previously mis-tracked `external_dependency`
         * ("all-external-callees thunk"); every real callee is this
         * template's own engine code, not third-party runtime.
         *
         * Address: 0x005C6D10 (FUN_005C6D10, msvc8::vector<Moho::
         * SPerArmyReconInfo>::reserve for the 52-byte element) -- exact
         * shape of this member: early return when `newCap <= capacity()`
         * (`result < a2` guard on the current `(myEnd-myFirst)/52` capacity),
         * max_size guard against `0x4EC4EC4` (`0xFFFFFFFF/52`, throw lane
         * `FUN_005C7290`, cited on `throw_too_long` above), checked
         * allocation via `FUN_005C9F40` (cited below on
         * `allocate_slots_checked`), uninit-copies the live range through
         * `FUN_005CE020` (a separate compiled `uninit_copy_n` copy for this
         * call site, cited below), then destroys and frees the old buffer
         * and rebases the three lanes. Reached from `LoadVectorSPerArmyReconInfo`
         * (`FUN_005C5700`, `ArchiveSerialization.cpp`) as `loaded.reserve(
         * count)`, called immediately after reading the archived element
         * count and before the per-element read loop -- confirmed against
         * the `.c`: `sub_5C6D10(&v9, a6)` is the first call after
         * `ReadUInt`. DB-integrity fix: was fake-recovered (batch r14/
         * codex-needs-evidence, zero real src/sdk citation for this token or
         * its caller `FUN_005C3EF0`).
         */
        void reserve(const std::size_t newCap) {
            if (newCap <= capacity()) {
                return;
            }
            if (newCap > max_size()) {
                throw_too_long();
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
         * Address: 0x00867890 (FUN_00867890,
         * msvc8::vector<Moho::WeakEntitySetUserEntity>::resize(size_type) for the
         * bucket vector `Moho::SelectionDragger::DragRelease`'s priority-bucket
         * path grows -- builds the empty-tree `WeakEntitySetUserEntity()`
         * temporary on the stack (`sub_7B08D0` head-alloc + self-link, matching
         * `WeakEntitySetUserEntity::BuyNode`/`InitWeakEntitySetHead` in
         * WeakEntitySet.h) and tail-calls the two-argument overload FUN_00867B90.
         * Real call site: `priorityBuckets.resize(bucketIndex)`
         * (moho/ui/SelectionDragger.cpp), the exact source line
         * `Moho::SelectionDragger::DragRelease` (0x00863870) reaches this from at
         * 0x00863C4F in the shipped binary.)
         *
         * Address: 0x00537B40 (FUN_00537B40, sub_537B40) --
         * `msvc8::vector<const char*>::resize(size_type)` for the 4-byte
         * pointer element (`CAniSkel.cpp`'s `FillSScmBoneNamePointers`
         * scratch vector, `outNamePointers.resize(boneCount)`). Unlike the
         * two instantiations cited above, this emission does not tail-call
         * a separate two-argument `resize(n, value)` body: since `T()` for
         * `const char*` is the trivial literal `nullptr`, the compiler
         * fused the size comparison directly into this function and
         * dispatches straight to this instantiation's `erase(first_+
         * newSize, last_)` (`FUN_00537C10`, not yet individually recovered)
         * on shrink, or straight to its `_Insert_n` grow core
         * (`FUN_00537C60`, cited above on `insert`) on growth, passing
         * `newSize - size()` as the count and the address of a
         * stack-local `nullptr` as the value -- behaviourally identical to
         * `resize(newSize, T())`, just without a separate out-of-line
         * `resize(n,value)` symbol to tail-call. Reached from
         * `FillSScmBoneNamePointers` (`FUN_005379D0`,
         * `CAniSkel.cpp`, already recovered), itself reached from
         * `CAniSkel::CAniSkel` (`FUN_0054A0A0`, already recovered).
         * Previously mis-tracked `skip` as a generic RULE ONE boilerplate
         * note with no caller evidence; this pass supplies the concrete
         * caller chain.
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
         * Address: 0x006DC4E0 (FUN_006DC4E0,
         * msvc8::vector<Moho::EntityCategorySet>::resize for the 0x28-byte
         * element -- growth through the `_Insert_n` lane FUN_006DC600, shrink
         * through the destroy lane FUN_006DBB50. Reached from
         * `RVectorType<EntityCategorySet>::SetCount` (0x006DB410).)
         * 0x005C54F6. Reached from `Moho::CReconBlipManagerImpl`'s per-army
         * table sizing.)
         * Address: 0x00547F20 (FUN_00547F20,
         * msvc8::vector<Moho::ResourceDeposit>::resize for the 20-byte element
         * -- `size()` via the 66666667h/`sar 3` divide-by-0x14 magic pair,
         * growing through the `_Insert_n` lane FUN_00547FE0 and shrinking by
         * recomputing `_Mylast` through the copy lane FUN_00548C00. Its
         * caller `RVectorType_ResourceDeposit::SetCount` (0x00547650) shows the
         * one-argument overload inlined into it: it reserves 0x14 stack bytes,
         * zeroes all five dwords to build the `ResourceDeposit()` temporary,
         * loads `edi`/`ebx` with the vector and the new count and falls into
         * this body, which pops the by-value `_Val` with `retn 14h`.)
         * Address: 0x00547FE0 (FUN_00547FE0, the `_Insert_n` grow lane
         * described above for `msvc8::vector<Moho::ResourceDeposit>`)
         * Address: 0x00547C30 (FUN_00547C30, the advance-returning fill/copy
         * adapter this grow lane calls: pushes a zeroed dummy byte twice as
         * stack args, calls the count-based forward copy primitive
         * FUN_005493B0 (`dest=edi`, `count=esi`, cited below), then computes
         * and returns `dest + count*20` (`lea edx,[esi+esi*4]` / `lea
         * eax,[edi+edx*4]` = `edi + esi*20`) -- the same `_Ufill`-style
         * advance-returning shape already documented for other `uninit_fill_n`
         * adapters in this file.)
         * Address: 0x005493B0 (FUN_005493B0, the count-based forward copy
         * primitive for the 20-byte `Moho::ResourceDeposit` element -- moves
         * `_Count` elements from `edx` into `eax` (5-dword field copy per
         * iteration, `add eax,14h` stride, null-guarded so a `dest==nullptr`
         * call only computes the advance). This is the old-range-into-new-
         * buffer copy step of the `_Insert_n` grow lane FUN_00547FE0 and is
         * also reached directly from `push_back`'s capacity-full path
         * (FUN_00547750, cited on `PushBackVector<ResourceDeposit>` in
         * moho/misc/EngineVectorHelpers.h) — same family, same caller chain
         * as the resize entry above.)
         * Address: 0x0082CBA0 (FUN_0082CBA0, `msvc8::vector<void*>::resize`
         * for one of `Moho::UICommandGraph`'s hash-bucket vectors -- `size()`
         * via a plain `(finish - start) >> 2` (4-byte pointer stride),
         * shrinking through the erase lane FUN_0082DE20, growing through the
         * `_Insert_n` lane FUN_0082DE90 (both cited on their own members).
         * Reached from `InsertOrFindHashListNode` FUN_0082B5E0, the sibling
         * of the `HashListNode10`/`HashListNode2C` insert helper
         * CWldSession.cpp's `AddCommandQueueToCommandGraph` reconstruction
         * notes already document (0x0082C750/0x0082C950/0x0082C480/
         * 0x0082B5E0) -- this is the one-bucket-rehash growth/shrink for
         * `UICommandGraph`'s other hash table's bucket array.)
         * Address: 0x00867B90 (FUN_00867B90,
         * msvc8::vector<Moho::WeakEntitySetUserEntity>::resize(size_type,
         * const_reference) for the 12-byte-stride selection-priority bucket
         * vector -- computes `size()` via the exact `(mLast-mFirst)/12` shape
         * this template's `size()` already produces, tail-calls the
         * `_Insert_n` grow lane FUN_00868040 at `end()` when growing, `erase`
         * (FUN_00867FC0) when shrinking, and always destroys the by-value
         * `_Val` temporary on exit (`sub_7AF740` + `operator delete`, matching
         * `WeakEntitySetUserEntity`'s new destructor in WeakEntitySet.h) --
         * this is VC8's take-`_Val`-by-value shape the note below already
         * describes. Reached from the one-argument overload above, itself
         * reached from `DragRelease`'s bucket-vector growth.)
         * Address: 0x00702450 (FUN_00702450,
         * msvc8::vector<SEntitySetTemplateUnit>::resize for the 0x28-byte
         * element -- `size()` via `(mLast-mFirst)/40`, growth tail-calling
         * the `_Insert_n` lane FUN_007030C0 at `end()`, shrink tail-calling
         * the erase lane FUN_00703040. Reached from
         * `InitializeArmyUnitCategorySets` (CArmyImpl.cpp), the one-argument
         * overload above inlined into `CArmyImpl::CArmyImpl` at 0x006FF2E1,
         * which builds the default `SEntitySetTemplateUnit()` value on the
         * stack before the call -- VC8's `resize(_Newsize, _Ty())` shape.)
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
         *
         * Address: 0x0082DB00 (FUN_0082DB00, `msvc8::vector<void*>::resize`
         * for the 4-byte pointer element -- shrinks via the destroy-range
         * helper FUN_0082F750 (recovered, LegacyContainerRuntime.cpp) or
         * grows via the `_Insert_n` emission FUN_0082F7A0 (already cited on
         * this template, stride 4). Reached from `UICommandGraph::
         * ObtainHashListNodePair<TNode,TValue>`'s rehash-growth branch,
         * `table.mBuckets.resize(newMask + 2u, table.mListHead)` -- the fill
         * value is the table's sentinel head pointer, not a raw byte,
         * matching this member's `const T&` shape. Element type correction:
         * `HashTable<TNode>::mBuckets` (`CWldSession.cpp`) is declared
         * `HashBucketVector = msvc8::vector<void*>` UNPARAMETERIZED by
         * `TNode` -- there is no `vector<HashListNode2C*>` type anywhere in
         * `src/sdk` (grep-confirmed zero hits); this citation previously
         * claimed one. The binary genuinely emits 3 separate, non-ICF-folded
         * `resize` bodies for the 3 hash tables (`FUN_0082D820`/mMapAB0,
         * `FUN_0082CBA0`/mMapD, this one/mMapC -- confirmed via
         * `_callgraph_index.sqlite`, each with exactly one disjoint real
         * caller) despite all three being the textually-identical
         * `vector<void*>` instantiation; this is presumably a build-
         * configuration/TU-boundary artifact of the original 2007 compile
         * (each `HashTable<TNode>` specialization living in its own
         * translation unit prevented the linker from folding them), not
         * evidence of a real per-TNode type. Recovering this source as one
         * shared `vector<void*>` instantiation is the correct 1:1-behavior
         * fidelity target regardless of how the original build happened to
         * split the symbols.)
         * Address: 0x0074DDD0 (FUN_0074DDD0, IDA infers `std::
         * vector_CSimConVarInstanceBase::reserve` but the real behavior is
         * `msvc8::vector<Moho::CSimConVarInstanceBase*>::resize(newSize,
         * nullptr)` for the 4-byte pointer element -- compares `newSize`
         * against `size()` (not `capacity()`, ruling out a real `reserve`),
         * no-ops when equal, tail-calls the shrink erase lane `sub_74F880`
         * when `newSize < size()`, tail-calls the grow `_Insert_n` lane
         * FUN_0074F8E0 (cited on `insert(pos,count,value)` below) with
         * `count = newSize - size()` otherwise. Was wrongly classified
         * `external_dependency` ("STL template instantiation / codec helper")
         * -- `Moho::CSimConVarInstanceBase` is an engine type
         * (`moho/sim/CSimConVarInstanceBase.h`), not external. Reached from
         * two real call sites, both already recovered: `Sim.cpp:8161`
         * (`mSimVars.resize(GetSimConVarIndexCounter(), nullptr)`, the
         * `CSimConVarBase::mIndex`-driven grow-to-index path) and
         * `Sim.cpp:8297` (`mSimVars.resize(index + 1u, nullptr)`, the
         * same grow-by-index pattern in a sibling registration function).)
         *
         * Address: 0x0074D190 (FUN_0074D190, `msvc8::vector<Moho::
         * SSTIArmyConstantData>::resize` for `SSyncData::mNewGrids`
         * (`SimDriver.h`) -- `if (size() < newSize) { insert(end(),
         * newSize-size(), T()); }`, tail-calling this instantiation's
         * `insert(pos,count,value)` grow core (`FUN_0074E770`, cited
         * below) with a default-constructed fill. Was wrongly classified
         * `external_dependency` ("External library: std::vector_
         * SSTIArmyConstantData::reserve") -- same mis-tag family as the
         * sibling `mArmyUpdates`/`SSTIArmyVariableData` fix earlier this
         * session (`FUN_0074D2B0`); `SSTIArmyConstantData` is this
         * project's own engine type (`moho/sim/SSTIArmyConstantData.h`),
         * not external. Reached from `Sim.cpp:8498`'s
         * `outSyncData->mNewGrids.resize(armyCount)` call by name, already
         * recovered.)
         *
         * Address: 0x0074D2B0 (FUN_0074D2B0, `msvc8::vector<Moho::
         * SSTIArmyVariableData>::resize` for `SSyncData::mArmyUpdates`
         * (`SimDriver.h`), the 352-byte (`0x160`) sibling of the
         * `SSTIArmyConstantData` instantiation directly above -- same
         * two-branch shape: `if (size() < newSize) { insert(end(),
         * newSize-size(), T()); }` tail-calling this instantiation's
         * `insert(pos,count,value)` grow core (`FUN_0074EB00`, cited
         * below), `else if (newSize < size()) { erase(begin()+newSize,
         * end()); }` tail-calling this instantiation's `erase(iterator,
         * iterator)` shrink core (`FUN_0074EAB0`, cited below). Reached
         * from `Sim.cpp:8467`'s `outSyncData->mArmyUpdates.resize(
         * armyCount)` call by name, already recovered. DB-integrity fix:
         * this address was previously cited above on `reserve()` as
         * `msvc8::vector<Moho::SSTIArmyVariableData>::reserve`, "Reached
         * from Sim::Sync's syncData.mArmyUpdates.reserve(sizes.mArmyData)
         * call by name" -- both claims were wrong. `.c`-confirmed this
         * function reads `newSize` against `size()` (not `capacity()`,
         * ruling out `reserve`) and calls the erase-shaped `FUN_0074EAB0`
         * on the `newSize < size()` branch, which `reserve()` never does;
         * the real `reserve(sizes.mArmyData)` call site reaches a
         * different address entirely, `FUN_00560D60` (already correctly
         * cited on `reserve()` above). Moved and corrected here to match
         * its true `resize()` semantics and its true caller.)
         *
         * Address: 0x0092FC60 (FUN_0092FC60, sub_92FC60, IDA-named
         * `std::vector_MapNode::resize`) -- `msvc8::vector<iterator>::
         * resize(n, val)` for `ClusterInternalCache<gpg::HaStar::
         * OccupationData>::mVec` (`OccupationCacheRuntimeMap`,
         * `gpg/core/algorithms/Cluster.cpp`) -- same 4-byte `list<pair<const
         * OccupationCacheKey, Cluster::Data*>>::iterator` element as
         * `insert`'s `FUN_0092F9E0` above. Grows via that
         * `insert(last_, newSize-cur, val)` call; shrinks via the erase
         * lane `FUN_0092EA10` (not part of this pass). Reached from
         * `hash_map<OccupationCacheKey,...>::insert(value)`'s inlined
         * `_Grow()` (`FUN_00930890`, IDA-named
         * `std::hash_map_unk_unk::insert`, sole caller per
         * `_callgraph_index.sqlite`) -- `mVec.resize(2 * windowCount - 1,
         * mList.end())` in `legacy/containers/HashMap.h`'s `_Grow()`,
         * instantiated for this `hash_map`. DB-integrity fix: was
         * `external_dependency` ("STL template instantiation / codec
         * helper - external") -- this is this project's own `msvc8::
         * vector<iterator>` internals for an engine-owned hash_map
         * instantiation, not external code. This is the `OccupationData`
         * counterpart of the `SubclusterData` emission `FUN_00934130`
         * referenced (but not independently cited) on `insert` above.)
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
         * Address: 0x0088A0C0 (FUN_0088A0C0, msvc8::vector<Moho::
         * WaveParameters>::clear for the 136-byte polymorphic element --
         * guards on `first_ != last_`, destroys the live run through the
         * same vtable-slot-0 deleting-destructor loop `destroy_range`/
         * `~vector` use for this type (via `sub_88AD60`, which resolves to
         * `first_`), then rewinds `last_` to `first_`. Reached from
         * `WavePattern::LoadParametersFromLua` (`FUN_00887870`,
         * `moho/terrain/water/WaveSystem.cpp`), which clears any existing
         * `mWaves` contents before repopulating from the `parameters` Lua
         * array -- a no-op on the freshly-default-constructed vector the
         * `WavePattern(LuaObject&)` constructor path always starts from, but
         * present in the binary because the helper is written generically.)
         */
        void clear() noexcept {
            destroy_all();
            last_ = first_;
        }

        /**
         * Address: 0x007BB840 (FUN_007BB840, msvc8::vector<Moho::SNetCommandArg>::_Tidy)
         *
         * What it does:
         * Full teardown while leaving the vector reusable: destroys the live
         * element range, releases the storage block, and clears the
         * `{first_, last_, end_}` triplet. The debug-iterator proxy lane
         * (`myProxy_`) is deliberately left alone, matching the binary. This is
         * the destructor's own body (`~vector() { destroy_all(); deallocate_all(); }`)
         * exposed as a callable member for the ctor-rollback `catch (...) { _Tidy(); throw; }`
         * shape MSVC emits around a partially-built vector -- for
         * `SNetCommandArg` both real callers (`FUN_007BB080`'s copy-ctor
         * unwind and `FUN_007BB71D`'s count/value-ctor unwind) reach this one
         * shared emission.
         *
         * Address: 0x0082DE60 (FUN_0082DE60, msvc8::vector<void*>::tidy --
         * 4-byte trivially-destructible element, so no destroy loop: just
         * `operator delete(first_)` then zeros `{first_, last_, end_}`,
         * leaving `myProxy_` untouched. This is the EH-unwind cleanup for
         * the `assign(9, sentinel)` MapD emission FUN_0082FB80 -- its
         * `catch (...) { tidy(); throw; }` funclet calls this address when
         * the fill after `operator new(9 * 4)` throws.)
         */
        void tidy() noexcept {
            destroy_all();
            deallocate_all();
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
         * Address: 0x0053FC90 (FUN_0053FC90, msvc8::vector<Moho::SEjectRequest>::push_back
         * for the 8-byte `{const CClientBase* mRequester, int mAfterBeat}` element —
         * fast path checks capacity then tail-calls the shared grow-core
         * (FUN_00540330) on overflow. Emitted via
         * mEjectRequests.push_back(SEjectRequest(requester, afterBeat)) in
         * Moho::CClientBase::AddOrUpdateEjectRequest (CClientBase.cpp))
         * Address: 0x0078A330 (FUN_0078A330, msvc8::vector<moho::CMauiControl*>::
         * insert(end(),1,value) grow-core (IDA's own type library names the
         * element `std::vector_CMauiControl`, i.e. this exact instantiation) —
         * the capacity-full path of `mRenderedChildren.push_back(controlCursor)`
         * in RebuildRenderedChildrenLane (UiRuntimeTypes.cpp), reached from
         * Moho::CMauiControl::Render (0x00786FA0))
         * Address: 0x0057E880 (FUN_0057E880, msvc8::vector<ScalarAndIntVectorLane>::
         * push_back for the 0x14-byte `{int mScalar; vector<int> mValues}`
         * element — `(a1[2]-a1[1])/20` and `(a1[3]-a1[1])/20` at 0x0057E895/
         * 0x0057E8A8 are the size/capacity element counts for this 20-byte
         * stride; fast path copies the zero-initialized row in place via
         * `sub_583210`, capacity-full path tail-calls the insert(end(),1,value)
         * grow lane `sub_57F9F0`. Emitted via `grid.push_back(ScalarAndIntVectorLane{})`
         * in CAiBrain::ProcessAttackVectors (CAiBrain.cpp), once per heightfield
         * grid row, building the per-row enemy-occupancy bitset array)
         *
         * Address: 0x00859F70 (FUN_00859F70 — 0x10-byte element, the
         * formation-preview ghost pair held by `gFormationPreviews` in
         * `moho/sim/CWldSession.cpp`; identified by the `sar ecx, 4` /
         * `sar esi, 4` pair that turns both the size and the capacity byte
         * spans into element counts, and by the two out-of-line halves it
         * calls — FUN_0085A920 for the in-place fast path and FUN_0085A0E0
         * for the grow path)
         *
         * Address: 0x0064E1B0 (FUN_0064E1B0, msvc8::vector<moho::SDebugDecal>::
         * push_back for the 52-byte element (`4EC4EC4Fh`/`sar 4` stride) --
         * fast path via the `uninit_fill_n` emission FUN_0064F9A0 (cited
         * above on `uninit_fill_n`), grow path tail-calls the single-value
         * `insert` grow-core FUN_0064E3B0 (cited below on `insert`).
         * Source-level invocation: `canvas->decals.push_back(decal)` in
         * `RDebugGrid.cpp`/`RDebugRadar.cpp`, the two direct binary callers
         * at 0x0064F336/0x0064F67C.)
         *
         * Address: 0x00889C90 (FUN_00889C90, msvc8::vector<Moho::WaveParameters>::
         * push_back for the 136-byte (`0x88`) polymorphic element -- the
         * `78787879h`/`sar 6` magic-multiply pair is the divide-by-136 size/
         * capacity computation, done twice (current size, then capacity).
         * Fast path (`size < capacity`) copy-constructs the pushed value
         * directly at `myLast` via the `uninit_fill_n` emission FUN_0088B090
         * (cited below on `uninit_fill_n`; its own copy is
         * `WaveParameters`'s compiler-generated copy constructor,
         * FUN_0088AB00) and advances `myLast` by `0x88`. Capacity-full path
         * tail-calls the single-value `insert(pos, value)` overload
         * (FUN_0088A050, cited below on `insert`), whose grow core is
         * FUN_0088A400. Source-level invocation:
         * `WavePattern::LoadParametersFromLua`'s `mWaves.push_back(...)`
         * (moho/terrain/water/WaveSystem.cpp), the per-entry append while
         * loading a `WavePattern`'s `parameters` array from Lua.)
         *
         * Address: 0x007EFFA0 (FUN_007EFFA0, msvc8::vector<moho::
         * SRangeRenderProfile>::push_back for the 136-byte (`0x88`) element --
         * same `78787879h`/`sar 6` divide-by-136 magic-multiply pair as the
         * `WaveParameters` instantiation immediately above (coincidental shape
         * match from the identical 136-byte stride -- confirmed as a distinct
         * type via the per-element copy body cited below, which touches
         * `mExtractorName`/`mCategoryFilter`/three packed ring-color lanes,
         * not `WaveParameters`'s layout). Fast path (`size() < capacity()`)
         * copy-constructs the pushed value directly at `last_` via the
         * `uninit_fill_n` emission FUN_007F38D0 (cited below on
         * `uninit_fill_n`) and advances `last_` by `0x88`. Capacity-full path
         * tail-calls the single-value `insert(pos, value)` overload
         * FUN_007F0790 (cited below on `insert`), whose grow core is
         * FUN_007F1490. This instantiation's only binary caller is
         * `Moho::RangeRenderer::MoveCategories` (FUN_007EE950,
         * `moho/render/RangeRenderer.cpp`, already recovered), which invokes
         * it as `mVisibleProfiles.push_back(...)` by name while rebuilding
         * the visible-profile list from category-name keys.)
         *
         * Address: 0x007409D0 (FUN_007409D0, msvc8::vector<msvc8::string>::
         * push_back dispatcher for the 16-byte `msvc8::string` element —
         * `__thiscall` with the element count in `ecx` (always 1 at every
         * confirmed call site) rather than a genuine `this`. Checked-grow via
         * `FUN_00741270` (validates count, throws via `FUN_00741630` past
         * `0xFFFFFFF`, allocates through `FUN_00741BE0`-style storage,
         * matching `allocate_slots_checked`); on success, constructs the
         * element(s) in place via `FUN_00741FC0`, then advances `last_` by
         * `count * 16`. `FUN_00741FC0`'s decompiled body looks `__noreturn`
         * (a destroy-loop into `CxxThrowException`) but raw `.asm` at the
         * call site (0x00740A1E) confirms execution continues normally after
         * it on the fast path -- that shape is `FUN_00741FC0`'s own
         * exception-cleanup tail, not its whole behavior, and is not
         * reachable from the normal push_back flow. `FUN_00740A60` is called
         * only from `sub_7409D0`'s own SEH funclet (a disjoint code chunk at
         * 0x00740A41, wired through `SEH_7409D0`/`___CxxFrameHandler3_0`) to
         * destroy a partially-constructed range on exception -- compiler-
         * generated unwind scaffolding with no source-level call, per RULE
         * ONE. Emitted via `columns[0].push_back(msvc8::string(""))`, the
         * first of many `msvc8::vector<msvc8::string> columns[8]` appends in
         * `Moho::CSimDriver::DrawNetworkStats` (SimDriver.cpp:2493) --
         * confirmed by address ordering: this dispatcher's only call site is
         * at 0x0073E084, immediately before the 0x0073E098 `columns[0]`
         * push cited at that line.)
         * Address: 0x0082BCB0 (FUN_0082BCB0, msvc8::vector<UICommandGraph::
         * CommandGraphEdge*>::push_back for the 4-byte pointer element --
         * checked-capacity fast append, else tail-calls the grow path
         * FUN_0082E950. Emitted via `bucket.push_back(edge)` in
         * `LinkCommandGraphEdge` (0x00826960, CWldSession.cpp:14703,
         * already recovered), which pushes the new edge into the owning
         * `CommandGraphTreeBucket::mEdges` vector.)
         * Address: 0x006868C0 (FUN_006868C0, msvc8::vector<Moho::
         * CEntityDbBoundedPropQueueNode>::push_back for the 20-byte
         * `{priority, boundedTick, WeakPtr<Prop> ownerLink, handleId}`
         * element -- checked-capacity fast append (constructs in place at
         * `last_`), else tail-calls the grow-and-insert path FUN_00687720.
         * Emitted via `heap.push_back(...)` in
         * `CEntityDbBoundedPropQueueRuntime::Insert` (EntityDb.h/.cpp),
         * the `gpg::PriorityQueue<SPropPriorityInfo, WeakPtr<Prop>>::Insert`
         * member reached from `Moho::EntityDB::AddBoundedProp`.)
         * Address: 0x009302E0 (FUN_009302E0, msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::push_back for the 12-byte
         * `{mAccumulatedCost, mPackedNodeCoordinate, mTraversalCost}` element
         * -- checked-capacity fast append, else tail-calls the single-value
         * `insert(pos, value)` overload FUN_00930000, whose own grow core is
         * the `_Insert_n` emission FUN_0092F630 (cited below on `insert`).
         * Emitted via `outEdgeLanes.push_back(lane)` in
         * `ExpandClusterSearchFrontierEdges` (Cluster.cpp), the per-boundary-
         * edge scratch vector `gpg::HaStar::ClusterBuild`'s open-frontier
         * search (`ProcessClusterSearchOpenFrontier`, FUN_00930D60) refills
         * every time it expands a node. The prior per-type
         * `AppendClusterSearchEdgeTraversalLane` wrapper this token was
         * attributed to was a `RULE ONE`-violating reach-in copy of exactly
         * this member -- collapsed onto this citation instead of kept as a
         * forked free function.)
         * Address: 0x00930190 (FUN_00930190, `std::vector_Ha5::push_back` per
         * IDA's own signature recognition -- `msvc8::vector<gpg::HaStar::
         * ClusterSearchOpenHeapEntryRuntime>::push_back` for the 12-byte
         * `{mCost, mNode, mHandle}` open-heap entry element. Checked-capacity
         * fast append, else tail-calls `insert(pos, value)` FUN_0092FCD0,
         * whose grow core is the `_Insert_n` emission FUN_0092F240 (cited
         * below on `insert` -- structurally identical to FUN_0092F630 above,
         * a separate instantiation for a different 12-byte element, not an
         * ICF twin: distinct `function_sha256`, distinct private copies of
         * every sub-helper). Emitted via `openHeap.mHeap.push_back(entry)` in
         * `PushClusterSearchOpenNode` (FUN_00930820, Cluster.cpp), the open-
         * heap insertion helper `RelaxClusterSearchNeighbor`/
         * `ProcessClusterSearchOpenFrontier` call while opening a search
         * node.)
         * Address: 0x00686E80 (FUN_00686E80, `msvc8::vector<std::int32_t>::
         * push_back` for the handle-to-heap-index reverse map
         * (`ClusterSearchOpenHeapRuntime::mHandleToHeapIndex`, Cluster.cpp)
         * -- checked-capacity fast append, else tail-calls `insert(pos,
         * value)` FUN_00687B40, whose grow core is the `_Insert_n` emission
         * FUN_004451A0 (cited below on `insert`). Emitted via
         * `openHeap.mHandleToHeapIndex.push_back(heapIndex)` in
         * `AcquireOrReuseClusterSearchOpenHandle` (FUN_00930440,
         * Cluster.cpp) when the released-handle free list is empty.)
         * Address: 0x0074C060 (FUN_0074C060, `std::vector_SDesyncInfo::
         * push_back` per IDA's own signature recognition --
         * `msvc8::vector<moho::SDesyncInfo>::push_back` for the 0x28-byte
         * `{int32_t beat; int32_t army; gpg::MD5Digest hash1; gpg::MD5Digest
         * hash2}` element (`Sim::mDesyncs`, `Sim.h`). Checked-capacity fast
         * append constructs the pushed value at `_Mylast` through the
         * `uninit_fill_n` core FUN_00753A90 (`n=1`, cited below on
         * `uninit_fill_n`) then advances `_Mylast`, else tail-calls
         * `insert(pos, value)` FUN_0074DA00 (cited below on `insert`), whose
         * grow core is the count=1-specialized `_Insert_n` emission
         * FUN_0074F060 (cited alongside it). Emitted via
         * `mDesyncs.push_back(desync)` in `Sim::VerifyChecksum`
         * (FUN_007487C0, already recovered, `Sim.cpp`) -- the only lane this
         * element type is ever appended through. DB-integrity fix: was
         * mis-tagged `external_dependency` ("External library:
         * std::vector_SDesyncInfo::push_back") -- despite the IDA-inferred
         * `std::vector_...` name looking library-shaped, this is this
         * project's own `msvc8::vector<T>` internals for an engine-owned
         * element type declared in `moho/sim/SDesyncInfo.h`; nothing here is
         * external.)
         * Address: 0x008F1760 (FUN_008F1760, sub_8F1760) --
         * `msvc8::vector<gpg::gal::HeadSampleOption>::push_back` for
         * `Head::mStrs` (`Head.hpp`, 0x24/36-byte element -- `{sampleType,
         * sampleQuality, msvc8::string label}`). The `.c` decompile renders
         * the fast/slow split as an unconditional fall-through into
         * `insert(pos,value)` regardless of branch, which would double-
         * construct -- confirmed against the raw `.asm` instead: the fast
         * path (`size()<capacity()`) ends in its own `retn 4` right after
         * updating `last_`, so it never reaches the slow-path call; this is
         * an ordinary two-way branch, matching this member exactly. Fast
         * path calls `sub_8EF7E0` (`uninit_fill_n`, cited below) then
         * `last_ += 1`; slow path tail-calls `insert(last_, value)`
         * (`FUN_008F1310`, cited below). Emitted via `head.mStrs.push_back(
         * option);` in `DeviceD3D9::BuildDeviceCapabilities`
         * (`FUN_008F2080`, `D3D9Interfaces.cpp`, already recovered) while
         * enumerating multisample options.)
         * Address: 0x0064E120 (FUN_0064E120, sub_64E120) --
         * `msvc8::vector<moho::SDebugScreenText>::push_back` for
         * `CDebugCanvas::screenText` (`CDebugCanvas.h`, 0x48-byte element).
         * Same two-way split as this member's other instantiations:
         * `size()<capacity()` fast path constructs at `_Mylast` through the
         * `uninit_fill_n` core `FUN_0064F910` (`n=1`, cited below on
         * `uninit_fill_n`) then advances `_Mylast` by 0x48 in place; the
         * capacity-exhausted path tail-jumps into the single-element
         * `insert(end(), value)` wrapper `FUN_0064E2F0` (cited above on
         * `insert`), whose grow core is the count=1-specialized `_Insert_n`
         * emission `FUN_0064E490` (cited below on `insert(pos,count,
         * value)`). DB-integrity fix: was mis-tagged `recovered` citing
         * "Cited on the canonical template" -- the address did not appear
         * anywhere in `src/sdk` at all; this is the real recovery.
         * Caller-evidence note: this token's own only caller,
         * `FUN_0064CC70` (`sub_64CC70`, `call sub_64E120` at 0x0064CCB5,
         * confirmed via `FUN_0064E120.xrefs.txt`), builds a `SDebugScreenText`
         * record from an oriented-label call and pushes it here -- but
         * `FUN_0064CC70` itself has zero incoming xrefs of any kind (code,
         * data, or vtable) after an exhaustive search: its own
         * `.xrefs.txt`/`.meta.json` are empty, the callgraph index's lone
         * `call_edges` row into it (from `FUN_0064E490`) is contradicted by
         * `FUN_0064E490`'s own disassembly (no `call sub_64CC70` appears
         * anywhere in it -- a phantom edge, most likely seeded from the same
         * fabricated `depends_on` list this DB-integrity pass is correcting),
         * and neither `RDebugGrid.cpp`'s `DrawGridCellRecursive` nor
         * `RDebugRadar.cpp`'s `TraverseRadarCellsRecursive`/`DrawReconGrid`
         * (the two already-recovered leaf renderers that plausibly would
         * emit an oriented text label) currently call anything
         * `SDebugScreenText`-shaped. `FUN_0064CC70` and its record-builder
         * `FUN_0064CB90` are therefore left `wip` (not `recovered`, not
         * `blocked`) pending discovery of their own real trigger site; this
         * mirrors the "trivial calling-convention forwarders... have no
         * discoverable callers of their own... recorded as such rather than
         * guessed" precedent already on this file's `uninit_copy_n` member
         * above. This `push_back` instantiation's own evidence (a real,
         * direct, `.asm`-confirmed call from `FUN_0064CC70`) stands
         * regardless of that upstream gap.)
         * Address: 0x005C6E70 (FUN_005C6E70, msvc8::vector<Moho::
         * SPerArmyReconInfo>::push_back for the 52-byte element) -- same
         * two-way split as this member's other instantiations: the
         * `size()<capacity()` fast path constructs the pushed value at
         * `_Mylast` through the `uninit_fill_n` core `FUN_005CC2D0` (`n=1`,
         * cited on `uninit_fill_n` below) then advances `_Mylast` by 52 in
         * place; the capacity-exhausted path tail-calls the single-append
         * adapter `FUN_005C86B0` (its own `Address:` line immediately
         * below), matching this member's `insert(last_, value)` else-branch.
         * Reached from `LoadVectorSPerArmyReconInfo` (`FUN_005C5700`,
         * `ArchiveSerialization.cpp`) as `loaded.push_back(element)` inside
         * the per-element read loop -- confirmed against the `.c`:
         * `sub_5C6E70((int)&obj, &v9)` follows each `ReadArchive::Read` call.
         * The decompiled render drops the third (`ebx`) argument to the
         * nested `uninit_fill_n`/`_Insert_n` calls in both this function and
         * its adapter (a known IDA pseudo-c quirk for custom-convention
         * calls, already documented elsewhere in this file, e.g. the
         * `HeadSampleOption` `push_back` entry above) -- read against the
         * raw `.asm`, both branches match this member exactly. DB-integrity
         * fix: was fake-recovered (batch r14/codex-needs-evidence, zero real
         * src/sdk citation for this token or its caller `FUN_005C3EF0`).
         * Address: 0x005C86B0 (FUN_005C86B0, single-append adapter) --
         * register-shuffling thunk that forwards into this instantiation's
         * `_Insert_n` (`FUN_005C6F90`, cited above) as `_Insert_n(value,
         * vec, pos, count=1u)`; the same adapter `_Insert_n`'s own citation
         * already names as "the single-append adapter FUN_005C86B0" reached
         * "from resize (FUN_005C5460)" -- this is its other reach, from
         * `push_back`'s capacity-exhausted branch.
         * Address: 0x007182A0 (FUN_007182A0, msvc8::vector<Moho::SThreat>::
         * push_back for the 0x38-byte element, `CInfluenceMap.h`'s
         * `threats` member). Same two-way split: `size()<capacity()` fast
         * path constructs at `_Mylast` through `func_VectorCpy_SThreat`
         * (`FUN_0071E760`, already recovered as `CopySThreatValueRange`,
         * `CInfluenceMap.h:111`, `n=1`) then advances `_Mylast` by 0x38 in
         * place (`.c`-confirmed: `func_VectorCpy_SThreat(finish,1,entry);
         * v2->_Mylast=finish+1;`); the capacity-exhausted path tail-calls
         * the single-element `insert(end(), value)` wrapper `FUN_007198E0`
         * (cited on `insert` below) with `pos=v2->_Mylast`. Confirmed
         * `.c`-exact match against this member's own `if
         * (size()<capacity()) { construct-in-place } else { insert(end(),
         * value); }` shape. DB-integrity fix: was mis-tagged
         * `external_dependency` ("STL template instantiation / codec
         * helper - external") with no citation anywhere in `src/sdk` --
         * `Moho::SThreat` is an engine type (`CInfluenceMap.h`) and this
         * caller, `Moho::CInfluenceMap`'s threat-accumulation path
         * (`FUN_00716140`, `CInfluenceMap.cpp`, already `recovered`), is
         * real engine code, not third-party library code.
         * Address: 0x00953610 (FUN_00953610, msvc8::vector<gpg::ReadArchive::
         * TrackedPointerInfo>::push_back for the 0x14-byte element,
         * `ReadArchive.h`'s `mTrackedPtrs` member). Same two-way split:
         * `size()<capacity()` fast path calls `sub_950EA0` (this element's
         * `uninit_fill_n`, `n=1`) then advances `_Mylast` by 0x14 in place
         * (`.c`-confirmed: `sub_950EA0(finish,1,a2); this->_Mylast=
         * finish+1;`); the capacity-exhausted path tail-calls the
         * single-element `insert(end(), value)` wrapper `FUN_00952DD0`
         * (cited above on `insert`) with `pos=this->_Mylast`. Confirmed
         * `.c`-exact match against this member's own two-branch shape.
         * DB-integrity fix: was mis-tagged `external_dependency` ("STL
         * template instantiation / codec helper - external") with no
         * citation -- `gpg::ReadArchive::TrackedPointerInfo` is an engine
         * type (`ArchiveSerialization.h:72`); both real binary callers
         * (`FUN_00953720`, `FUN_00953B30`) are already `recovered`.
         *
         * Address: 0x0074C160 (FUN_0074C160, `msvc8::vector<moho::
         * SExtraUnitData>::push_back` for the 0x20-byte element -- `Moho::
         * Sim::mSyncSerializeGroup2` (`Sim.h`, `+0x0A28`). `.asm`-confirmed
         * exact match of this member's two-way split: `size()<capacity()`
         * (`(mLast-mFirst)>>5` vs `(mEnd-mFirst)>>5`) fast path calls this
         * instantiation's `uninit_fill_n` (`FUN_00753AF0`, cited below, with
         * `n=1`) and advances `mLast` by `0x20` in place; the capacity-
         * exhausted path tail-calls `insert(end(), value)` (`FUN_0074F3E0`,
         * cited below on `insert`). Reached from `Sim::AdvanceBeat`
         * (`FUN_00749F40`, already recovered, `Sim.cpp`) via
         * `mSyncSerializeGroup2.push_back(SExtraUnitData())` in the
         * sync-filter extra-data packing pass -- `AdvanceBeat`'s own call
         * chain (a chunk at `0x0074A378`) calls this instantiation's
         * `insert` and `uninit_fill_n` bodies directly, confirmed via
         * `_callgraph_index.sqlite` `call_edges`. Migrated off a hand-rolled
         * `msvc8::vector<T>` reimplementation
         * (`gpg/core/containers/FastVectorInsertLanes.cpp`'s
         * `InlineQwordVectorWithTag*` cluster, a RULE ONE violation --
         * `moho::SExtraUnitData` and `msvc8::vector<moho::SExtraUnitData>
         * mSyncSerializeGroup2` were already correctly typed in
         * `Unit.h`/`Sim.h`, so the free-function cluster was pure duplicate
         * debt over this template.)
         *
         * Address: 0x0077A0A0 (FUN_0077A0A0, `msvc8::vector<Moho::
         * SDecalInfo>::push_back` for the 0x90-byte element,
         * `Moho::CDecalBuffer::mVisibleDecals`) -- `.asm`-confirmed (IDA's
         * decompiled `.c` renders the fast-path and slow-path branches as
         * if sequential/unconditional; the raw `.asm` shows they are
         * mutually exclusive with an early `retn` ending the fast path --
         * do not trust the `.c` view for this token). Fast path
         * (`size() < capacity()`): `uninit_fill_n(last_, 1u, value)` via
         * direct call to `sub_77E720` (cited below), then `++last_`. Slow
         * path: tail-calls `insert(last_, value)` via `sub_77ACC0` (cited
         * above). Reached from `AppendVisibleDecal` (same address,
         * already recovered, `CDecalBuffer.cpp`) as
         * `visibleDecals.push_back(decalInfo)`, called from
         * `Moho::CDecalBuffer::CleanupTick` (0x00779710, already
         * recovered) once per handle transitioning into focus-army
         * visibility.
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
            // VC8 splits this in two and the binary keeps both halves out of
            // line: when a slot is already spare it fills in place, otherwise
            // it defers the whole grow-and-relocate to `insert(end(), value)`.
            // Writing it as one `ensure_grow_for` + placement-new would be
            // behaviourally identical but would stop the compiler emitting the
            // single-element `insert` the binary calls, which is why the shape
            // is preserved here rather than simplified.
            if (size() < capacity()) {
                uninit_fill_n(last_, 1u, value);
                ++last_;
            } else {
                (void)insert(last_, value);
            }
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
         *
         * Address: 0x00859FE0 (FUN_00859FE0 — 0x10-byte element, the
         * formation-preview ghost pair; rewinds `last_` by one element and
         * runs the pair's destructor. `CWldSession::RenderMeshPreviews` calls
         * it when the renderer refuses the mesh instance it just appended.)
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
         * Address: 0x0082DBA0 (FUN_0082DBA0, the HashListNode88 draw-node table's
         * `mBuckets.assign(9, mListHead)` emission, UICommandGraph::PrepareForRebuild)
         * Address: 0x009303F0 (FUN_009303F0, sub_9303F0) -- `msvc8::
         * vector<iterator>::assign(count, value)` for `ClusterInternalCache<
         * gpg::HaStar::OccupationData>::mVec` (`OccupationCacheRuntimeMap`,
         * `gpg/core/algorithms/Cluster.cpp`) -- same 4-byte `iterator`
         * element as `insert`'s `FUN_0092F9E0` above. Builds `localValue`
         * from the by-ref value param exactly like this member's own
         * `const T localValue(value)`, then unconditionally calls
         * `insert(first_, count, localValue)` (`FUN_0092F9E0`) -- the
         * binary's `if (first_ != last_) last_ = first_` is the compiled
         * `clear()` (`destroy_all(); last_ = first_;`, a no-op destroy pass
         * for this trivially-destructible element) with a redundant-store
         * guard the compiler added around the unconditional pointer write,
         * not a divergence from this member's unconditional `clear()` call.
         * Reached from `hash_map<OccupationCacheKey,...>`'s default
         * constructor (`FUN_00930810`, a 1-statement thiscall thunk into
         * this token, cited as `skip`) and from `clear()` (`FUN_00930B40`,
         * IDA-named `std::hash_map_unk_unk::clear`) -- both call sites are
         * `_Init()`'s `mVec.assign(Traits::min_buckets + 1, mList.end())`
         * (`legacy/containers/HashMap.h`), matching the already-proven
         * `assign(9, sentinel)` bucket-vector-init idiom documented above
         * for the UICommandGraph/HashListNode88 tables. `_Init()` previously
         * read `mVec.clear(); mVec.resize(...)` as two separate calls --
         * behaviourally identical, but updated to a single `assign` call to
         * match this fused compiled shape and the proven idiom.)
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
         * Address: 0x0052BEE0 (FUN_0052BEE0, `msvc8::vector<
         * Moho::RRuleGameRulesLuaExportBinding>::erase(iterator)`'s
         * per-slot shift-assign step for the 16-byte element,
         * `RRuleGameRulesImpl::mMaps` -- reached only from
         * `RRuleGameRulesImpl::CancelExport` (`FUN_0052AA20`), which keeps
         * this method's own shift LOOP inlined into its own body (calling
         * `FUN_0052BEE0` once per shifted slot) rather than as a separate
         * out-of-line `erase` symbol; `*(a2+8) -= 16` after the loop is
         * this method's own `--last_`. Per slot the shift-assign is
         * `RRuleGameRulesLuaExportBinding`'s implicit `operator=`
         * (`FUN_00536DA0`, cited in full on that struct's declaration,
         * RRuleGameRules.h), and the trailing vacated-slot teardown is
         * `FUN_00536DF0` (the range-destroy loop `skip`-classified there,
         * called with a one-element range) -- matching this method's own
         * assign-then-decrement-then-destroy-last-slot shape exactly, just
         * with the loop body and the tail-destroy step kept as separate
         * out-of-line calls instead of being inlined together. Previously
         * modeled as a bespoke `EraseExportBinding` free function
         * hand-rolling the same shift loop against
         * `RRuleGameRulesLuaExportBindingArray`'s raw fields -- removed
         * once `mMaps` became a real `msvc8::vector<T>`; `CancelExport` now
         * calls this method by name (`mMaps.erase(binding)`).)
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
         *
         * Address: 0x0085A130 (FUN_0085A130 — 0x10-byte element, the
         * formation-preview ghost pair. Shifts the tail down one slot at a
         * time through FUN_0085A9F0 (`copy_or_move_assign`), destroys the
         * retired span through FUN_0085A1D0 (`destroy_range`), then rebases
         * `last_`. `CWldSession::RenderMeshPreviews` and `~CWldSession` both
         * reach it as the whole-range `clear`.)
         * Address: 0x00719E80 (FUN_00719E80, `std::vector_InfluenceGrid::
         * CleanUpGrid` per IDA's own inferred name — msvc8::vector<Moho::
         * InfluenceGrid>::erase(iterator,iterator) for the 140-byte element.
         * `count==0` early return, tail-shift down one slot at a time (the
         * per-element assign shape shared with `AssignInfluenceGridValue` /
         * `CopyInfluenceGridRange`, `moho/sim/CInfluenceMap.cpp`, 0x0071ED10 /
         * 0x0071E7B0), destroys the vacated tail through `InfluenceGrid`'s own
         * destructor (equivalent to the sibling `DestroyInfluenceGridRange`
         * free function used elsewhere in that file, 0x0071EA00), rebases
         * `last_`. Five real callers confirmed directly from each caller's own
         * disassembly (not just the callgraph index): `Moho::CInfluenceMap`'s
         * parameterized constructor (0x00716140, defensive pre-clear on the
         * still-empty `mMapEntries` before `resize`), `~CInfluenceMap`
         * (0x007163A0, whole-range teardown before the vector's own storage is
         * freed), `msvc8::vector<InfluenceGrid>::operator=` (0x0071E030,
         * already cited above), and `ResizeInfluenceGridVectorWithFill`'s
         * shrink branch (0x0071B860, `moho/sim/CInfluenceMap.cpp` 0x0071B860
         * citation, `storage.resize(requestedCount)` with no fill value). A
         * sixth address, 0x007188B0, is a byte-distinct but behaviorally
         * redundant thiscall-shaped forwarding wrapper around this same
         * erase(begin(),end()) call with zero callers of its own anywhere in
         * the shipped binary (verified via `call_edges`, `incoming_xrefs`,
         * `data_refs`, `vtable_writers`, and the `reachable` closure, all
         * empty) — classified `skip`, not cited here.)
         * Address: 0x008F6790 (FUN_008F6790, `msvc8::vector<DXGI_MODE_DESC>::
         * erase(iterator,iterator)` for the 0x1C-byte element -- tail-shift-
         * down loop (`qmemcpy` per 28-byte slot, shifting `[last,
         * this->last_)` down to start at `first`), rebases `last_`, returns
         * the post-erase iterator through a hidden out-param (2007 MSVC's ABI
         * for this `thiscall`, not something the modern `T*` return needs to
         * replicate). Reached from this specialization's own `operator=`
         * (`FUN_008F6DD0`, cited above on `operator=`) calling `erase(begin(),
         * end())` on `this` to clear it when the assignment source is empty --
         * the returned iterator is discarded, the same self-clear-via-
         * `erase(begin(),end())` idiom as the `InfluenceGrid` instantiation
         * above.)
         * Address: 0x007D7E00 (FUN_007D7E00, `msvc8::vector<moho::
         * ClutterSurfaceElement>::erase(iterator,iterator)` for the 16-byte
         * polymorphic-teardown element -- byte-for-byte this member's shape:
         * `count==0` early return, tail-shift via `FUN_007D94B0` (cited on
         * `ClutterSurfaceElement::operator=`, `moho/render/Clutter.h` --
         * copies the 3 payload fields and deliberately skips `vtable`, the
         * per-slot-invariant field), `destroy_range(last_-count,last_)`
         * through each element's own vtable-slot-0 dispatch (cited on
         * `ClutterSurfaceElement::~ClutterSurfaceElement`/`DestroyInPlace`,
         * same header), then `last_ -= count`. Two real call sites, both
         * erase-to-end (`tail==0`, so `FUN_007D94B0`'s shift loop never
         * actually executes at either): `Moho::Clutter::Shutdown`
         * (`FUN_007D62C0`, `moho/render/Clutter.cpp`) erasing
         * `[begin(),end())` of every `mSurfaces[i].mSeeds` once per loop
         * iteration -- i.e. `clear()`, cited there directly -- and a second,
         * unnamed 22-byte register-convention fragment at 0x007D7920
         * (padding-delimited both sides, `a1` passed in `eax` rather than on
         * the stack, same `erase(vec->first_, vec->last_)` shape; its own
         * caller was not found this pass). Before this pass,
         * `ClutterSurfaceElement` had no user-declared destructor or
         * `operator=`, so this member's `is_trivially_destructible_v`/
         * `is_trivially_copyable_v` guards took the no-op/memmove branch for
         * it instead of the per-element one the binary actually emits --
         * this template needed no changes; the fix is the element type's own
         * special members, `moho/render/Clutter.h`/`.cpp`.)
         *
         * Address: 0x0074E720 (FUN_0074E720, msvc8::vector<Moho::
         * SSTIArmyConstantData>::erase(iterator,iterator) for the 0x80
         * (128)-byte element -- byte-for-byte this member's shape:
         * tail-shift via per-element copy-assign (the non-trivially-
         * copyable branch, `*writeCursor = *sourceCursor`),
         * `destroy_range(last_-count, last_)` through `SSTIArmyConstantData::
         * ~SSTIArmyConstantData` on the vacated tail, then `last_ -= count`,
         * returning `first` through the VC8 hidden-return-slot ABI (2007
         * MSVC's convention for this `thiscall`, not something the modern
         * `T*` return needs to replicate -- same shape already documented on
         * the `DXGI_MODE_DESC` entry above). Sole caller is `resize`'s
         * shrink branch, `FUN_0074D190` (cited above on `resize`) --
         * `SSyncData::mNewGrids.resize(armyCount)`, already recovered and
         * wired by name at `Sim.cpp:8456`. Formerly modeled as a standalone
         * `LegacyArmyConstantDataVectorSlot` reach-in struct plus a
         * `CompactLegacyArmyConstantDataVectorTail` free function in
         * `moho/sim/SimDriver.cpp` with no source-level caller of its own --
         * collapsed into this template instantiation, RULE ONE.
         * Address: 0x0074EAB0 (FUN_0074EAB0, msvc8::vector<Moho::
         * SSTIArmyVariableData>::erase(iterator,iterator) for the 0x160
         * (352)-byte element -- the same shape as the sibling
         * `SSTIArmyConstantData` instantiation directly above: per-element
         * copy-assign tail shift, `destroy_range` through
         * `SSTIArmyVariableData::~SSTIArmyVariableData` on the vacated tail,
         * `last_ -= count`, hidden-return-slot ABI. Sole caller is
         * `resize`'s shrink branch, `FUN_0074D2B0` (cited above on
         * `resize`, corrected from a prior mis-citation under `reserve()`)
         * -- `SSyncData::mArmyUpdates.resize(armyCount)`, already recovered
         * and wired by name at `Sim.cpp:8467`. Formerly modeled as a
         * standalone `LegacyArmyVariableDataVectorSlot` reach-in struct plus
         * a `CompactLegacyArmyVariableDataVectorTail` free function in
         * `moho/sim/SimDriver.cpp` with no source-level caller of its own --
         * collapsed into this template instantiation, RULE ONE.
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
         * Address: 0x00653E80 (FUN_00653E80, msvc8::vector<moho::SDebugWorldText>::
         * in-place tail-shift-by-move-assign loop for the 48-byte non-trivial
         * element -- the `for (i = tail-count; i>0; --i) insertAt[count+i-1] =
         * std::move(insertAt[i-1])` branch below, walking backward so overlapping
         * source/destination ranges never clobber an unread element (position/
         * style/depth as raw field copies, `text` reassigned via `assign`). Reached
         * via the thin dispatcher FUN_00653A20 from the `_Insert_n` grow lane
         * FUN_00653380, already cited below).
         * Address: 0x008DD050 (FUN_008DD050, msvc8::vector<gpg::RType*>::_Insert_n
         * grow lane for the global reflection TypeVec; the recovered caller
         * gpg::RType::RegisterType invokes insert(end(), 1, this) by name so this
         * per-T symbol is emitted).
         * Address: 0x006E24D0 (FUN_006E24D0, msvc8::vector<Moho::CmdId>::_Insert_n
         * scalar-int32 grow lane; emitted via AppendPendingReleasedCommandId
         * push_back (Sim.cpp:5045)).
         * Address: 0x00692930 (FUN_00692930, msvc8::vector<Moho::SyncCameraShakeRequest>::_Insert_n
         * grow lane; emitted via mSyncCamShake.push_back (Entity.cpp:879)).
         * Address: 0x006928E0 (FUN_006928E0, sibling emission in the same
         * SyncCameraShakeRequest _Insert_n family: computes the destination
         * slot `base + 28*index` for the 28-byte element and forwards to the
         * per-element field-copy loop FUN_00693200, i.e. the tail-shift/copy
         * sub-step this grow lane calls into).
         * Address: 0x00940D40 (FUN_00940D40, msvc8::vector<gpg::gal::AdapterModeD3D9>::_Insert_n
         * 16-byte-element grow lane; emitted via PushBackAdapterModeD3D9 modes.push_back
         * (D3D9Interfaces.cpp:3258)).
         * Address: 0x00882BA0 (FUN_00882BA0, msvc8::vector<msvc8::string>::_Insert_n
         * grow-and-fill lane; emitted via ResizeLegacyStringVectorExact
         * outStrings.resize(n, fillValue) (CSaveGameRequestImpl.cpp:125)).
         * Address: 0x00883820 (FUN_00883820, this instantiation's forward
         * fill-via-assign sub-step -- walks `[dst, dstEnd)` calling
         * `std::string::assign` on each already-constructed slot, the
         * gap-fill half of this member's in-place branch for a non-trivial
         * element. Reached from `FUN_00882BA0` above.)
         * Address: 0x00883840 (FUN_00883840, this instantiation's backward
         * tail-shift-by-assign sub-step -- decrements both cursors then
         * `std::string::assign`s, the `copy_backward`-shaped shift half of
         * this member's in-place branch. Reached from `FUN_00882BA0`
         * above.)
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
         * Address: 0x0071A1F0 (FUN_0071A1F0, the `uninit_copy_n` sibling of the
         * `SPositionThreat` `_Insert_n` above: relocates the existing
         * `[begin, insertPos)` run into the freshly-grown buffer with a
         * 16-byte-stride (`shl eax,4`) element-count loop that forwards to the
         * shared FPU-based 4-float block copy at FUN_0071E8E0, returning
         * `dest + count*16` as the post-copy cursor.)
         * Address: 0x0071E8E0 (FUN_0071E8E0, the shared FPU-based 4-float
         * block copy described above -- a plain forward per-element 16-byte
         * copy loop, called from FUN_0071A1F0's `uninit_copy_n` sibling)
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
         * Address: 0x00540330 (FUN_00540330, msvc8::vector<Moho::SEjectRequest>::_Insert_n
         * grow lane for the 8-byte `{const CClientBase* mRequester, int mAfterBeat}`
         * element (`sar 3` stride, max_size 0x1FFFFFFF = 0xFFFFFFFF/8, overflow
         * throw through FUN_00540580). `_Count` is folded to the constant 1 — the
         * value arrives by pointer and is copied two dwords at a time with no
         * destroy pass, so the element is trivially copyable, matching the
         * `SUpgradeNotifyPair` sibling above. In-place growth shifts the tail
         * through FUN_00540BD0/FUN_00540C20/FUN_00540E80 and returns the iterator
         * via FUN_00540C00; the realloc path allocates through the checked
         * 8-byte lane FUN_00540C40. Reached from push_back's capacity-full path
         * (FUN_0053FC90, already cited above). Emitted via
         * mEjectRequests.push_back(SEjectRequest(requester, afterBeat)) in
         * Moho::CClientBase::AddOrUpdateEjectRequest (CClientBase.cpp))
         * Address: 0x00653380 (FUN_00653380, msvc8::vector<moho::SDebugWorldText>::_Insert_n
         * grow lane for the 0x30-byte (48) non-trivial element (`{Wm3::Vec3f
         * position; msvc8::string text; int32_t style; uint32_t depth;}`,
         * stride divide by 48, max_size 0x5555555 = 0xFFFFFFFF/48, overflow
         * throw through FUN_00653860). `_Count` is folded to the constant 1 --
         * both binary callers are single-element lanes. The reallocation
         * path's by-ref value is copy-constructed into a local `_Tmp` (zeroed
         * to empty SSO state then `text.assign(...)`) before the old range
         * moves, so a reallocation cannot invalidate it; tail-shift and
         * prefix/suffix range mechanics route through FUN_006539E0/
         * FUN_00653A20/FUN_00653AD0/FUN_00653F40/FUN_00653330, and allocation
         * through the checked 48-byte lane FUN_00653A80 (already cited in
         * CheckedArrayAllocationLanes.cpp). Reached from the single-element
         * `insert(iterator, const T&)` overload FUN_006532C0, already cited
         * above, under `CDebugCanvas::AddWorldText`'s `worldText.push_back(text)`
         * (Sim.cpp) -- called from Moho::RDebugWeapons::Tick.)
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
         * Address: 0x007F3500 (FUN_007F3500, sibling emission in the same
         * SRangeExtractionPayload `_Insert_n` count=1 in-place-growth family: the
         * calling-convention adapter that MSVC8 split out for the "move the single
         * trailing element into the newly uninitialized slot past `mLast`" step.
         * Repackages its four stack args (dest, srcFirst, srcLast, ...) into the
         * order FUN_007F3EF0's forward-copy primitive expects and tail-calls it;
         * no independent logic of its own. Reached only from the in-place growth
         * path of FUN_007F1D50 (cited above), which is itself only reachable
         * through push_back — same load-bearing caller chain.)
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
         * reflected vector<float> SerLoad lane. Its in-place tail-shift step is
         * FUN_005260D0, the memmove_s-based dword-range relocate for this
         * 4-byte element.)
         * Address: 0x005260D0 (FUN_005260D0, the in-place tail-shift relocate
         * described immediately above -- `memmove_s(dst, n*4, src, n*4)` for
         * the 4-byte `float` element, reached from `_Insert_n` FUN_00524780.)
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
         * Address: 0x006F88D0 (FUN_006F88D0, msvc8::vector<CUnitCommand*>::
         * _Insert_n -- same 4-byte-pointer shape, max_size 0x3FFFFFFF.
         * Reached from `cfunc_CoordinateAttacksL`'s `commands.push_back(command)`
         * in CCommandLuaFunctionRegistrations.cpp.)
         * Address: 0x0066A860 (FUN_0066A860, msvc8::vector<moho::WCurveEditorPanel*>::
         * _Insert_n -- same 4-byte-pointer shape, max_size 0x3FFFFFFF checked via
         * `cur == max_size` folded for `count == 1` (throw lane FUN_0066AA70,
         * already cited as the VC8 length_error closure in
         * CrtRuntimeHelpers.cpp). The in-place shift sub-path (`pos != end()`)
         * moves the single trailing element past the old end and shifts
         * `[pos, oldLast)` up by one slot through two calls to the generic
         * dword-memmove helper (FUN_0066AE50 / FUN_0066AE90, both already
         * cited as sibling emissions of `MoveDwordRangeAndReturnEnd` /
         * `MoveDwordRangeToEnd` in Vector.cpp), then fills the vacated slot
         * with a raw single-dword store (count folded to 1, no fill-helper
         * call needed for one element). The in-place append sub-path
         * (`pos == end()`) and the reallocation path both construct the new
         * element through FUN_0066A460 (`uninit_fill_n`,
         * LegacyContainerFillLanes.cpp); the realloc buffer comes from the
         * checked allocator FUN_0066AEC0 (CheckedArrayAllocationLanes.{h,cpp}).
         * 1.5x growth clamp (`0x3FFFFFFF - (cap>>1) >= cap`) matches
         * `recommended_capacity` exactly.
         * Reached from two confirmed call sites: `msvc8::vector<T*>::push_back`'s
         * own capacity-full path (FUN_0066A150, `sub_66A860(this, *(_Mylast))` at
         * 0x0066A18C -- push_back itself has no further caller the exhaustive
         * byte scan can find, so it is a dead-but-correct sibling instantiation)
         * and directly from `Moho::WEmitterWx::WEmitterWx` (0x00666EBE, inside
         * FUN_00663900, already cited in WEmitterWx.cpp) -- the compiled ctor
         * inlines push_back's capacity check and calls straight through to this
         * grow lane on `mCurvePanels.push_back(curvePanel)`'s capacity-full turn,
         * one of 5 iterations building the curve-editor notebook tabs. A third
         * code xref at 0x0066A3C7 sits in an anonymous, IDA-unclassified chunk
         * this pass could not trace to a named owner.)
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
         * Address: 0x0067D320 (FUN_0067D320, msvc8::vector<Moho::SEntityVariableUpdateEntry>::_Insert_n
         * grow-core for the same 0xD8-byte (216) element -- max_size guard
         * `0xFFFFFFFF/216 = 19884107` overflow throw, 1.5x growth clamped to
         * `size+1`, checked allocation, tail-shift via FUN_0067F9A0/FUN_0067F9E0,
         * and the single-slot gap fill through the already-cited FUN_00680BD0.
         * Reached from `Entity.cpp`'s sync-update insert path when
         * `mEntityUpdates.push_back(...)`'s capacity-full branch grows the
         * vector instead of filling in place.)
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
        /**
         * Address: 0x0067C750 (FUN_0067C750,
         * msvc8::vector<Moho::SEntityVariableUpdateEntry>::insert(iterator,
         * const T&) for the 0xD8-byte element -- recovers the insertion index
         * with the 4BDA12F7h/`sar 6` divide-by-0xD8 magic pair *before* the
         * insert, tail-calls the `_Insert_n` lane at 0x0067D320 with a count
         * of one, then rebuilds the iterator as `first_ + off * 0xD8` because
         * the insert may have reallocated. Reached from the grow half of
         * `push_back` at 0x0067B780.)
         * Address: 0x006532C0 (FUN_006532C0,
         * msvc8::vector<moho::SDebugWorldText>::insert(iterator, const T&) for
         * the 0x30-byte element -- recovers the insertion index via
         * `(pos - mFirst) / 48` *before* the insert, tail-calls the
         * `_Insert_n` lane at 0x00653380 with a count of one, then rebuilds
         * the iterator as `mFirst + off * 48` because the insert may have
         * reallocated. Reached from the grow half of `push_back`, itself
         * reached from `CDebugCanvas::AddWorldText`'s `worldText.push_back(text)`
         * (Sim.cpp).)
         * Address: 0x0057EDB0 (FUN_0057EDB0,
         * msvc8::vector<moho::SAiAttackVectorDebug>::insert(iterator, const T&)
         * for the 0x18-byte element -- recovers the insertion index via
         * `(pos - mFirst) / 24` *before* the insert, tail-calls the `_Insert_n`
         * lane at 0x00580150 (already `skip`-classified as this template's
         * generic body) with a count of one, then rebuilds the iterator as
         * `mFirst + off * 24` because the insert may have reallocated. Reached
         * from the grow half of `push_back` (FUN_0057D820, already cited above
         * on `push_back`) when `mAttackVectors` is at capacity -- emitted via
         * `CAiBrain`'s `mAttackVectors.push_back(...)` call sites (CAiBrain.cpp),
         * the only lane this element type is appended through.)
         * Address: 0x00592460 (FUN_00592460, `msvc8::vector<T>::insert(iterator,
         * const T&)` for a 12-byte three-float element (`imul` by `2AAAAAABh`
         * then `sar 1` is the divide-by-3 dword-stride calc). The reallocation
         * branch reads the caller-supplied value's three dwords into a stack-
         * local before touching storage (matching this method's `const T
         * localValue(value)` copy-out) and, on the empty/full-buffer path,
         * routes the prefix-copy and single-value-fill through the
         * `uninit_move_n`/`uninit_fill_n` per-T emissions FUN_005940F0 and
         * FUN_00592030 (both cited on those methods below); the in-place
         * tail-shift path calls the same two templates' non-reallocating
         * siblings, FUN_00595F10 and FUN_00594A20, directly. Reachable from a
         * static initializer (`ctor_static`/`__xc_a`, depth 6 via its own
         * caller FUN_00591F40) -- the owning `vector<T>` field has not been
         * pinned to a named engine type beyond "12-byte, three float lanes",
         * consistent with this file's practice of citing structurally-proven
         * but not fully name-identified instantiations (cf. the "unidentified
         * map<int32_t,T>" family in RbTree.h).)
         *
         * Address: 0x0064E3B0 (FUN_0064E3B0, `msvc8::vector<moho::SDebugDecal>::
         * insert(iterator, const T&)` for the 52-byte element -- captures
         * `off = (pos - first_) / 52`, tail-calls the `_Insert_n` grow core
         * FUN_0064E770 with `count = 1`, rebuilds the returned iterator as
         * `first_ + off * 52` (`imul esi, 34h`). Reached from `push_back`'s
         * grow path, FUN_0064E1B0, cited above.)
         * Address: 0x0064E770 (FUN_0064E770, the `_Insert_n` grow core this
         * `insert` tail-calls -- `max_size` guard `0x4EC4EC4`
         * (`0xFFFFFFFF/52`), throw lane FUN_0064EEE0 (cited on
         * `throw_too_long` below), 1.5x growth falling back to `size()+1`
         * through the size thunk FUN_004521B0, checked 52-byte allocation
         * FUN_0064F8C0, memberwise `_Tmp` copy since `SDebugDecal` is
         * trivially copyable (no ctor/dtor call in the shipped body).)
         *
         * Address: 0x0088A050 (FUN_0088A050, `msvc8::vector<Moho::
         * WaveParameters>::insert(iterator, const T&)` for the 136-byte
         * polymorphic element -- push_back's capacity-full path
         * (FUN_00889C90, cited above) tail-calls this with `pos = myLast`.
         * Computes the current size and (when non-empty) the requested
         * insertion offset via the same `78787879h`/`sar 6` divide-by-136
         * pair `push_back` uses, then tail-calls the `_Insert_n` grow core
         * FUN_0088A400 with the resolved offset/position. `vectorThis`
         * (`edi`) stays live across both calls -- the shape IDA renders as a
         * bare `sub_88A400(a1, a3)` with the intermediate size arithmetic
         * elided is a decompiler artifact; the actual disassembly carries the
         * full offset computation.)
         * Address: 0x0088A400 (FUN_0088A400, the `_Insert_n` grow core this
         * `insert` tail-calls for the same 136-byte polymorphic element --
         * reallocates, copy-constructs the head/tail ranges through
         * `uninit_copy_n`/the class's copy constructor (FUN_0088AB00), places
         * the inserted value, and releases the old storage, matching this
         * method's own reallocation-branch shape. The old range is destroyed
         * by FUN_0088A3E0 (`msvc8::vector<Moho::WaveParameters>::
         * destroy_range`, cited below) before the buffer is freed -- called
         * 3x: once on the success path (0x0088A5A5, destroying the old
         * buffer's live range immediately before `operator delete`), twice
         * more in the head/tail copy-construction exception-cleanup funclets
         * (0x0088A5E2, 0x0088A687), destroying the partially-constructed new
         * buffer before rethrowing. IDA's own decompile of this function
         * (`FUN_0088A400.c`) omits all three calls entirely -- the same
         * "bad/positive sp value" decompiler failure already documented for
         * the sibling `AdapterD3D9`/`FUN_008F1890` pair (`destroy_range`,
         * cited below) -- and mis-marks the function `__noreturn`, even
         * though the primary path returns normally through `retn 8`;
         * confirmed only against the raw `.asm`.)
         *
         * Address: 0x007F0790 (FUN_007F0790, `msvc8::vector<moho::
         * SRangeRenderProfile>::insert(iterator, const T&)` for the 136-byte
         * element -- `push_back`'s capacity-full path (FUN_007EFFA0, cited
         * above) tail-calls this with `pos = last_`. Captures
         * `offset = (size() == 0) ? 0 : pos - first_` before touching
         * storage, tail-calls the `_Insert_n` grow core FUN_007F1490 passing
         * `(value, vectorThis, pos)`, then rebuilds the returned iterator as
         * `first_ + offset` since a capacity-full call reallocates and
         * invalidates `pos`. This function's only binary caller is
         * FUN_007EFFA0 (`push_back`'s capacity-full path, cited above),
         * itself reached only from `Moho::RangeRenderer::MoveCategories`'s
         * `mVisibleProfiles.push_back(...)` call.)
         * Address: 0x007F1490 (FUN_007F1490, the `_Insert_n` grow core this
         * `insert` tail-calls for the same 136-byte element -- copies the
         * inserted value into a local guard temporary first (the standard
         * self-aliasing-safe insert idiom, safe for `v.insert(v.begin(),
         * v[i])`) through the element's own copy operation (FUN_007F0ED0,
         * cited in `RangeRenderer.cpp` as `RebindAndCopyRangeRenderProfile`),
         * computes size/capacity via the same `78787879h`/`sar 6`
         * divide-by-136 pair, grows via this method's own
         * `recommended_capacity` shape (1.5x, `(capacity>>1)+capacity`,
         * falling back to `size()+1` -- the fallback's `size()` call is
         * FUN_007EFF80, the `(_Mylast-_Myfirst)/136` element-count shape),
         * allocates through the checked `allocate_slots_checked` emission
         * FUN_007F3490 (`bad_alloc` guard is `0xFFFFFFFF/count < 136`, then
         * `operator new(136*count)`), relocates the live range, places the
         * guarded value, and releases the old block -- matching this
         * method's own reallocation-branch shape and the sibling
         * `WaveParameters` grow core above.)
         *
         * Address: 0x007BB780 (FUN_007BB780, msvc8::vector<Moho::
         * SNetCommandArg>::insert(iterator, const T&) for the 36-byte
         * `{EType mType; int32_t mNum; msvc8::string mStr}` element --
         * captures `off = (pos - first_) / 36` before touching storage
         * (mirrored here as `offset`), tail-calls the `_Insert_n` grow core
         * FUN_007BBD60 with the fixed `count = 1` (no explicit count
         * parameter -- both this wrapper and the core it calls are
         * count=1-specialized emissions, not the general N-count body),
         * then rebuilds the returned iterator as `first_ + offset` since a
         * capacity-full call reallocates and invalidates `pos`. Reached
         * from push_back's capacity-full path, FUN_007BB120 (cited above on
         * `push_back` -- `moho::cfunc_GpgNetSendL`'s three
         * `args.push_back(SNetCommandArg(...))` call sites,
         * CGpgNetInterface.cpp).)
         *
         * Address: 0x008EFA50 (FUN_008EFA50, msvc8::vector<gpg::gal::
         * HeadAdapterMode>::insert(iterator, const T&) for the 12-byte
         * `{width; height; refreshRate}` element -- same offset-capture/
         * tail-call/iterator-rebuild shape as the two entries directly
         * above, offset computed as `(pos - first_) / 12`, tail-calls the
         * `_Insert_n` grow core `FUN_008EF010` with `count = 1`. Reached
         * from `push_back`'s capacity-full path via `AppendHeadAdapterMode`
         * (D3D9Interfaces.cpp, `adapterModes.push_back(mode); return
         * &adapterModes.back();`).)
         *
         * Address: 0x0082E950 (FUN_0082E950, msvc8::vector<UICommandGraph::
         * CommandGraphEdge*>::insert for the 4-byte pointer element -- the
         * full grow-core implementation this instantiation's push_back
         * (`FUN_0082BCB0`, cited above) tail-calls on its capacity-full
         * path: `max_size` guard folds to `0x3FFFFFFF` (`>>2` pointer
         * stride), 1.5x growth (`(size>>1)+size`, falling back to
         * `size()+1` on overflow), in-place tail-shift-then-fill when
         * capacity already covers the request, full reallocate-and-
         * relocate via `memmove_s` otherwise. Reached from
         * `LinkCommandGraphEdge`'s `bucket.push_back(edge)`
         * (`CWldSession.cpp:14703`, already recovered) when the bucket's
         * `mEdges` vector is at capacity.)
         *
         * Address: 0x00930000 (FUN_00930000, `msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::insert(iterator, const T&)`
         * for the 12-byte edge-traversal-lane element -- offset captured up
         * front (`(pos-first_)/12`), tail-calls the `_Insert_n` grow core
         * `FUN_0092F630` with `count = 1`, rebuilds the returned iterator as
         * `first_ + offset`. Reached from this element's `push_back`
         * (`FUN_009302E0`, cited above) capacity-full path.)
         * Address: 0x0092FCD0 (FUN_0092FCD0, `msvc8::vector<gpg::HaStar::
         * ClusterSearchOpenHeapEntryRuntime>::insert(iterator, const T&)` for
         * the 12-byte open-heap-entry element -- same offset-capture/tail-
         * call/iterator-rebuild shape as the edge-lane instantiation
         * immediately above, tail-calling its own private `_Insert_n` grow
         * core `FUN_0092F240` with `count = 1`. Reached from this element's
         * `push_back` (`FUN_00930190`, cited above) capacity-full path.)
         * Address: 0x00687B40 (FUN_00687B40, `msvc8::vector<std::int32_t>::
         * insert(iterator, const T&)` for the handle-to-heap-index reverse
         * map (`ClusterSearchOpenHeapRuntime::mHandleToHeapIndex`,
         * Cluster.cpp) -- offset captured as `(pos-first_)>>2`, tail-calls
         * the `_Insert_n` grow core `FUN_004451A0` with `count = 1`. Reached
         * from this element's `push_back` (`FUN_00686E80`, cited above)
         * capacity-full path.)
         * Address: 0x0084F200 (FUN_0084F200, `msvc8::vector<wxWindowBase*>::
         * insert(iterator, const T&)` for
         * `SuspendInputWindowEventHandlersAndFlushQueue`'s per-window saved-
         * handler vector (`UiRuntimeTypes.cpp`) -- like `FUN_0082E950` above,
         * this is a fused single-element implementation (no separate
         * count-based `_Insert_n` core call): reads `size()`/`capacity()`
         * directly, and on the capacity-available path uses
         * `uninit_move_n` (`FUN_0084F940`, cited above on that member) to
         * relocate the current last element into the freshly grown slot,
         * then a raw 4-byte-broadcast loop to shift/write the remainder --
         * on the capacity-exhausted path, `recommended_capacity`-shaped 1.5x
         * growth, `allocate_slots_checked` (`FUN_0084FA10`), and two
         * `memmove_s` head/tail relocates inline (not through
         * `uninit_move_n`, since this is the *reallocating* branch). Reached
         * from `moho::PushEventHandler`'s (WxRuntimeTypes.cpp)
         * `savedHandlers.push_back(handler)` capacity-full path via
         * `FUN_0084E520`/`FUN_0084EAB7`, and from
         * `SuspendInputWindowEventHandlersAndFlushQueue`
         * (`FUN_0084DA80`) directly. RULE ONE compiler/template emission,
         * not hand-written source -- the programmer-written source line
         * that emits it already exists at the instantiating call site, so
         * this token stays `skip`.)
         *
         * Address: 0x00627340 (FUN_00627340, sub_627340) --
         * `msvc8::vector<Moho::SPickUpInfo>::insert(iterator, const T&)`
         * for the 12-byte intrusive-weak `{WeakPtr<Unit>, float}` element
         * (`SPickUpInfoVectorReflection.cpp`'s `SPickUpInfoVector`). Offset
         * captured up front via the divide-by-3 reciprocal idiom
         * (`0x2AAAAAAB`, matching `(pos-first_)` already measured in
         * 4-byte/dword units here rather than raw bytes), tail-calls the
         * `_Insert_n` grow core `FUN_00627800` (cited below on the
         * count-form `insert`) with `count = 1` (`push 1` immediately
         * before the call, confirmed against the `.asm`), rebuilds the
         * returned iterator as `first_ + offset*3` dwords afterwards.
         * IDA's decompiler mis-infers this body `__noreturn` (it cannot
         * see past the tail call into `_Insert_n`'s own control flow) --
         * it unconditionally returns, it does not throw. Reached from this
         * element's `push_back` (`FUN_00626E10`,
         * `PushBackSPickUpInfoWithRelink`, `SPickUpInfoVectorReflection.cpp`,
         * already recovered) capacity-full path, exactly like the sibling
         * `push_back`/`insert(pos,value)` pairs cited throughout this file.
         * Previously mis-tracked `skip` as a fabricated "__noreturn
         * 1-statement tail-call typed throw shim" (confidence 0.35 on that
         * note); the `.asm` shows ~100 bytes of real offset/count
         * arithmetic and a normal `retn`, not a throw.
         *
         * Address: 0x007336C0 (FUN_007336C0, sub_7336C0) --
         * `msvc8::vector<PlatoonUnitSearchEntry>::insert(iterator, const T&)`
         * for the 8-byte `{Unit*, float}` element (`CPlatoon.cpp`'s
         * `AppendPlatoonUnitSearchEntry`/`cfunc_CPlatoonFormPlatoonL`
         * nearest-first candidate scratch vector). `max_size` folds to
         * 0x1FFFFFFF (`0xFFFFFFFF / 8`, throw lane `FUN_00733910`). Unlike
         * this member's usual "capture offset, tail-call the count-form
         * with `count=1`" shape, this emission is fully fused in place --
         * like `FUN_0084F200` above -- with no separate `_Insert_n(pos, 1,
         * value)` call: the in-place branch's `tail > 0` sub-case moves
         * the current last element into the freshly grown slot through
         * the calling-convention bridge `FUN_00733A80` (cited below on
         * `uninit_move_n`) then shifts the remainder via `FUN_00733AD0`
         * (not yet individually recovered -- its existing citation in
         * `CPlatoon.cpp` as `CopyPlatoonPriorityEntryRangeBackward` names
         * the wrong element type, a `PlatoonPriorityEntry`/
         * `PlatoonUnitSearchEntry` shape collision this pass did not
         * resolve); the `tail == 0` (append) sub-case calls the same
         * bridge with a zero-length range (a structural no-op) and
         * constructs the new value in place via `FUN_00733C40` (not yet
         * recovered). The reallocation branch grows 1.5x, allocates via
         * `FUN_00733AF0`, and relocates the head/tail spans through two
         * more calls into `FUN_00734440` (the same core `FUN_00733A80`
         * bridges into). Reached from this element's `push_back`
         * (`FUN_00733480`/`AppendPlatoonUnitSearchEntry`, `CPlatoon.cpp`,
         * already recovered) capacity-full path, itself reached from
         * `cfunc_CPlatoonFormPlatoonL`'s (`FUN_0072D8F0`, already
         * recovered) nearest-first candidate filter -- previously that
         * filter used a locally-duplicated `CandidateDistance` struct and
         * a real `std::vector` instead of `PlatoonUnitSearchEntry`/
         * `msvc8::vector`, which meant `AppendPlatoonUnitSearchEntry` was
         * an orphan `[[maybe_unused]]` helper with the wrong container
         * type entirely; both fixed in the same pass as this citation.
         * Previously `blocked` on `needs_ida`; stays `skip` per the
         * established fused-emission precedent (`FUN_0084F200`), now with
         * concrete caller evidence instead of an unsupported claim.
         *
         * Address: 0x008F1310 (FUN_008F1310, sub_8F1310) -- `msvc8::
         * vector<gpg::gal::HeadSampleOption>::insert(pos, value)` for
         * `Head::mStrs` (same instantiation as `push_back`'s `FUN_008F1760`
         * above, 0x24/36-byte element). Field-for-field match once the
         * vector's real 4-field debug-proxy layout is used (`this[1]`=
         * `first_`, matching this member's own `myProxy_`/`first_`/`last_`/
         * `end_` layout): `offset = (size()==0) ? 0 : (pos-first_)`,
         * tail-calls the count overload with `count=1` (`sub_8F05C0`,
         * cited on `insert(pos,count,value)` below), returns `first_+
         * offset` -- exactly this member's shape, including the `size()==0`
         * null-`pos` guard. Reached from `push_back`'s slow (no-spare-
         * capacity) path with `pos=last_`/`end()`.)
         *
         * Address: 0x00411EA0 (FUN_00411EA0, sub_411EA0) -- `msvc8::
         * vector<msvc8::string>::insert(pos, value)` for the 28-byte
         * `msvc8::string` element. Same "capture offset, tail-call the
         * count overload with `count=1` (`sub_412000`, cited on
         * `insert(pos,count,value)` below), rebuild the iterator from the
         * captured offset" shape as `FUN_008F1310` above, field for field.
         * Reached from `boost::algorithm::split`'s per-token insert loop
         * (`FUN_007CEFB0`, `iter_split`'s naive single-pass path -- see the
         * `vector(InputIt,InputIt)` constructor's citation above for why
         * this instantiation takes that path instead of a bulk copy) inside
         * `func_GetIgnoreNames`/`BuildLobbyIgnoreNameList`
         * (`CLobby.cpp`, `0x007CBC80`).
         *
         * Address: 0x0074DA00 (FUN_0074DA00, `msvc8::vector<moho::
         * SDesyncInfo>::insert(iterator, const T&)` for the 0x28-byte
         * element (`Sim::mDesyncs`) -- captures `offset = (_Myfirst ==
         * nullptr) ? 0 : (pos - _Myfirst)/40` before touching storage (the
         * null-`_Myfirst` guard matches this member's own `size()==0` check
         * field for field), tail-calls the count=1-specialized `_Insert_n`
         * core FUN_0074F060 with `(vectorThis, pos, value)` -- no explicit
         * count parameter, both this wrapper and the core it calls are
         * count=1-specialized emissions, not the general N-count body
         * (same precedent as `FUN_007BB780`/`FUN_007BBD60` above) -- then
         * rebuilds the returned iterator as `_Myfirst + offset*40` since the
         * insert may have reallocated. Reached from `push_back`'s
         * capacity-full path (FUN_0074C060, cited above on `push_back`)
         * with `pos = _Mylast`/`end()`, itself reached only from
         * `Sim::VerifyChecksum`'s `mDesyncs.push_back(desync)` (already
         * recovered, `Sim.cpp`) -- the only lane this element type is ever
         * inserted through.)
         * Address: 0x0074F060 (FUN_0074F060, the count=1-specialized
         * `_Insert_n` core this `insert` tail-calls for the same
         * `SDesyncInfo` instantiation -- copies the inserted value into a
         * local 40-byte stack temporary first (the standard
         * self-aliasing-safe insert idiom, matching this method's own
         * `const T localValue(value)` copy-out), `max_size` guard folds to
         * `0x6666666` (`0xFFFFFFFF/40`), throwing via the already-recovered
         * `throw_too_long` helper FUN_0074F320 (`CrtRuntimeHelpers.cpp`) on
         * overflow. Capacity-available branch splits on whether `pos` is
         * the current end: the at-end sub-branch -- the only one this
         * instantiation's real caller ever reaches, since `push_back`
         * always passes `pos=_Mylast` -- constructs the new value at
         * `_Mylast` through the `uninit_fill_n` advance-returning adapter
         * FUN_0074DAC0 (cited below on `uninit_fill_n`) and advances
         * `_Mylast` by 40; the sibling not-at-end sub-branch (compiled as
         * part of this shared emission but never reached by any caller in
         * this binary -- `mDesyncs` is only ever mutated through
         * `push_back`) shifts the current last element and the remaining
         * tail through FUN_00751AF0/FUN_00751B30, already `recovered` as
         * the generic by-stride `CopyForward40ByteTailRangeAdapter`/
         * `CopyBackward40ByteLaneSourceFirstNullScratchAdapterB` in
         * `gpg/core/containers/FastVectorInsertLanes.cpp`. Both
         * capacity-available sub-branches converge on a shared finishing
         * call, FUN_00753D60 (grouped with FUN_00756990 below as the same
         * `CopyForward40ByteLaneSourceFirst` shape in that same file),
         * which performs the gap-fill assignment the not-at-end branch
         * still needs and is a harmless same-value rewrite on the at-end
         * branch already constructed via FUN_0074DAC0. The reallocation
         * branch grows through the by-stride size helper FUN_0074D9E0
         * (`Count40ByteElementVectorLanes`, `Vector.cpp`, this method's own
         * `size()` reuse) with a 1.5x/`size()+1` fallback, allocates
         * through the checked 40-byte allocator FUN_00751B60
         * (`AllocateChecked40ByteElements`, `Vector.cpp`, this method's own
         * `allocate_slots_checked`), and relocates the pre-/post-insertion
         * spans through two calls into the shared forward-copy lane
         * FUN_00756990. FUN_00751AF0/FUN_00751B30/FUN_00751B60/
         * FUN_00756990/FUN_00753D60/FUN_0074D9E0 are pre-existing
         * RULE-ONE-flagged generic by-stride emissions (not per-element-type),
         * already `recovered` and shared with unrelated 40-byte vector
         * instantiations elsewhere in the engine -- cited here by address
         * for completeness, not re-derived or renamed.)
         *
         * Address: 0x006882E0 (FUN_006882E0, `msvc8::vector<moho::
         * CEntityDbBoundedPropQueueNode>::insert(iterator, const T&)` for
         * the 20-byte element -- `moho/entity/EntityDb.cpp`'s bounded-prop
         * priority-queue backing store). Max_size check
         * `0xFFFFFFFF/20==214748364` throwing through `FUN_006885F0`
         * (`_Xlength_error`, `VTABLE_CONFIRMED` via `vtable_writers` ->
         * `length_error@std`), 1.5x growth, allocates through
         * `FUN_00688E80` (already recovered, checked 20-byte allocator),
         * relocates the pre-/post-insertion spans through `FUN_00689D70`
         * (cited on `WeakPtr.h`'s `CopyPrefixedWeakPtrDwordPayloadRange
         * ForwardCore` -- `CEntityDbBoundedPropQueueNode`'s binary layout
         * is field-for-field the same 20-byte prefix+`WeakPtr`+payload
         * shape that generic helper already models: `mPriority`/
         * `mBoundedTick`/`mOwnerLink`(`WeakPtr<Prop>`)/`mHandleId` at the
         * same four offsets as `prefix0`/`prefix1`/`weak`/`payload`; see
         * the `Duplicate layout contract` note on that citation), called
         * twice in the reallocation branch (copy-before-insertion-point,
         * copy-after) matching `_Insert_n`'s `uninit_copy` pair shape. A
         * local stack temp of the inserted value self-registers into an
         * SEH cleanup list before the copy (`*a1[2] = &v19`-style
         * intrusive-list splice, matching an EH-unwind funclet at
         * 0x00686120 doing the identical unlink walk -- compiler-emitted
         * glue, not an independently callable function). Reached from
         * `FUN_006868C0` (already recovered, `msvc8::vector<
         * CEntityDbBoundedPropQueueNode>::push_back`, `EntityDb.cpp`) via
         * `FUN_00687720` (already `skip`-tagged, a 1-line typed-throw
         * shim), itself reached from `FUN_006859F0` (already recovered).
         * Address: 0x00688DF0 (FUN_00688DF0, the single-element-range
         * calling-convention wrapper this method's shift-insert and
         * append-at-end paths both call into `FUN_00689D70` through --
         * `.asm`-confirmed call sites at 0x688529 (shift-insert,
         * `sub_688DF0(v16-20, v16)`) and 0x68859B (append-at-end,
         * `sub_688DF0(arg4, arg4+20)`).)
         * Address: 0x0064E2F0 (FUN_0064E2F0, sub_64E2F0) --
         * `msvc8::vector<moho::SDebugScreenText>::insert(iterator, const
         * T&)` for the 0x48-byte element (`CDebugCanvas::screenText`).
         * `.asm`-confirmed shape: `EDI@this` (register), stack args
         * `(outIterator, pos)`, `ECX@value` (register, forwarded from this
         * wrapper's own incoming `ECX`) -- captures `offset = (_Myfirst ==
         * nullptr || size() == 0) ? 0 : (pos - _Myfirst)/0x48` before
         * touching storage (the null/empty guard matches this member's own
         * `size() == 0u` check field for field), tail-calls the count=1
         * `_Insert_n` core `FUN_0064E490` with `(this, pos)` and `value`
         * still in `ECX`, then rebuilds `*outIterator = _Myfirst + offset*
         * 0x48` using the *new* `_Myfirst` (post-reallocation) -- the same
         * "capture offset up front, rebuild after" idiom as this method's
         * own body. Direct caller (`.asm`-confirmed, `call sub_64E2F0` at
         * 0x0064E19E): `FUN_0064E120` (`push_back`, cited above), on its
         * capacity-exhausted path with `pos = _Mylast`. DB-integrity fix:
         * was mis-tagged `recovered` citing "Cited on the canonical
         * template" -- the address did not appear anywhere in `src/sdk`;
         * this is the real recovery.)
         *
         * Address: 0x005C60A0 (FUN_005C60A0, msvc8::vector<Moho::
         * CAiReconDBImpl::SNewBlip>::insert(pos,value) for the 12-byte
         * element) -- same "capture offset up front, tail-call the count=1
         * core, rebuild the iterator from the offset afterwards" shape:
         * computes `offset = (a3-v4)/12` before the call (the `size()==0`
         * guard is implicit -- `v4` being null makes the division moot),
         * tail-calls the count-based core `FUN_005C7B10` (cited below), then
         * rebuilds `*outIterator = _Myfirst + 12*offset` from the
         * post-reallocation `_Myfirst`. Direct caller (`.asm`-confirmed):
         * `AppendPendingNewBlip` (`FUN_005C4CA0`, `CAiReconDBImpl.cpp`,
         * cited above on `uninit_fill_n`)'s `pending.push_back(SNewBlip{...})`
         * on its capacity-exhausted path (`push_back`'s own `else { insert(
         * last_, value); }` branch). DB-integrity fix: was wrongly `skip`
         * ("drift-audit-demoted... behavior absorbed into owning subsystem
         * sources" -- no such absorption exists; zero real citation
         * anywhere in `src/sdk` before this pass, and this shape is a
         * distinct, real, uncollapsed emission, not something any other
         * recovered function already models).
         *
         * Address: 0x007198E0 (FUN_007198E0, msvc8::vector<Moho::SThreat>::
         * insert(pos,value) for the 0x38-byte element) -- same
         * "capture offset up front, tail-call the count=1 core, rebuild the
         * iterator from the offset afterwards" shape: `.c`-confirmed
         * `v6 = a3 - v5` (offset, guarded by `v5 && (_Mylast-_Myfirst)/56`
         * mirroring `size()==0`) computed before the call, tail-calls the
         * count=1 `_Insert_n` core `FUN_0071AF90` (`msvc8::vector<
         * moho::SThreat>::_Insert_n`, cited above on `resize`/`insert(pos,
         * count,value)`), then rebuilds `*a2 = _Myfirst + 56*v6` from the
         * post-reallocation `_Myfirst`. Direct caller (`.c`-confirmed,
         * `sub_7198E0((int)v2,a2,&v6,v2->_Mylast,entry)`):
         * `msvc8::vector<Moho::SThreat>::push_back` (`FUN_007182A0`, cited
         * above) on its capacity-exhausted path, matching this member's own
         * `else { insert(last_, value); }` branch exactly. That push_back is
         * reached from `Moho::CInfluenceMap`'s threat-accumulation path
         * (`FUN_00716140`, `CInfluenceMap.cpp`, already `recovered`) and
         * from `FUN_0071A6F0` (also `recovered`). DB-integrity fix: was
         * `blocked` with no citation anywhere in `src/sdk`; `Moho::SThreat`
         * is an engine type, not third-party library code.
         *
         * Address: 0x00952DD0 (FUN_00952DD0, msvc8::vector<gpg::ReadArchive::
         * TrackedPointerInfo>::insert(pos,value) for the 0x14-byte element,
         * `ReadArchive.h`'s `mTrackedPtrs` member) -- same "capture offset
         * up front, tail-call the count=1 core, rebuild the iterator from
         * the offset afterwards" shape: `.c`-confirmed `v6 = (a3-v5)/20`
         * (offset, guarded by `v5 && (_Myend-v5)/20` mirroring `size()==0`)
         * computed before the call, tail-calls the count=1 `_Insert_n` core
         * `FUN_00952770` (already `skip`-tagged as this instantiation's
         * `_Insert_n`, cited above on `allocate_slots_checked` alongside
         * this same element's `reserve`/`_Insert_n` siblings), then
         * rebuilds `*a2 = _Myfirst + 20*v6` from the post-reallocation
         * `_Myfirst`. Direct caller (`.c`-confirmed, `sub_952DD0(this,&a2,
         * (int)this->_Mylast,(int)a2)`): `msvc8::vector<TrackedPointerInfo>
         * ::push_back` (`FUN_00953610`, cited below) on its
         * capacity-exhausted path, matching this member's own `else {
         * insert(last_, value); }` branch exactly. That push_back is
         * reached from `FUN_00953720`/`FUN_00953B30` (both `recovered`,
         * `ArchiveSerialization.cpp`/`ReadArchive.cpp`). DB-integrity fix:
         * was `blocked` with no citation anywhere in `src/sdk`;
         * `gpg::ReadArchive::TrackedPointerInfo` is an engine type
         * (`ArchiveSerialization.h:72`), not third-party library code.
         *
         * Address: 0x0077ACC0 (FUN_0077ACC0, `msvc8::vector<Moho::
         * SDecalInfo>::insert(pos,value)` for the 0x90-byte element,
         * `Moho::CDecalBuffer::mVisibleDecals`) -- same "capture offset up
         * front, tail-call the count=1 core, rebuild the iterator from the
         * offset afterwards" shape: `.asm`-confirmed `esi = (ebx-[edi+4])/
         * 144` (offset, guarded by `[edi+4] && ...` mirroring `size()==0`)
         * computed before the call, tail-calls the count=1 core
         * `sub_77B990` (cited below on the 3-arg `insert`). Direct caller
         * (`.asm`-confirmed, `sub_77A0A0(this=eax, value=ecx)` at
         * 0x0077A121): `msvc8::vector<SDecalInfo>::push_back` (`sub_77A0A0`,
         * cited below) on its capacity-exhausted branch, matching this
         * member's own `else { insert(last_, value); }` branch exactly.
         * DB-integrity fix: was `skip`-tagged ("Bulk: __noreturn
         * 1-statement tail-call typed throw shim") -- wrong on both counts:
         * IDA's decompiler mis-tags this `__noreturn` (it has a normal
         * `retn` epilogue reached through its tail-call), and its `.c`
         * pseudocode genuinely is one statement (`sub_77B990(a4,a1,a3);`)
         * but that statement is a real tail-call into a ~700-byte `insert`
         * core, not a throw shim -- the "1-statement" heuristic a bulk
         * pass used to classify this as dead conflated brevity with
         * triviality. Corrected to `recovered` in this pass.
         *
         * What it does:
         * The VC8 single-element `insert`. The offset is captured up front and
         * the iterator rebuilt from it afterwards, which is the only way the
         * returned iterator survives a reallocation. The `size() == 0` guard
         * mirrors the binary: on an empty vector `pos` may be null, so the
         * difference is never taken.
         */
        iterator insert(const_iterator pos, const T& value) {
            const std::size_t offset =
                (size() == 0u) ? 0u : static_cast<std::size_t>(pos - first_);
            (void)insert(pos, static_cast<std::size_t>(1), value);
            return first_ + offset;
        }

        /**
         * Address: 0x008523C0 (FUN_008523C0, the `_Insert_n` core for a
         * 12-byte three-dword element -- the `lea edx, [edi+edi*2]` and
         * `add esi, 0Ch` pair are the stride, and it carries the full VC8
         * shape: one `operator new`, two `operator delete` (the grow path's
         * old-block free and the throw path's cleanup), and the
         * `_CxxThrowException` that is `_Xlen`. Its first read is a `movss`
         * of the fill value, so the element is float-typed at the source
         * level even though the copy moves dwords.
         *
         * Reached from the recovered insert-and-rebase lane at 0x00852350,
         * which captures the index, inserts, then rebuilds the cursor -- the
         * single-element `insert` shape recovered onto this template in
         * f3e3858c.)
         * Address: 0x00933950 (FUN_00933950, the `_Insert_n` core for
         * `msvc8::vector<iterator>` -- the HaStar cluster-cache bucket
         * vector (Cluster.cpp's `InsertOccupationCacheEntry`/
         * `InsertSubclusterCacheEntry` block). Carries the same 0x3FFFFFFF
         * `max_size` overflow guard and grow/shift/throw-cleanup shape as
         * the other instantiations here. Reached from `resize(n, end())`
         * (0x00934130, cited above) via `_Grow`.)
         * Address: 0x0082DE90 (FUN_0082DE90, `msvc8::vector<void*>::
         * _Insert_n` for a 4-byte pointer element on one of
         * `Moho::UICommandGraph`'s hash-bucket vectors -- same 4-byte-
         * pointer shape as the sibling UICommandGraph instantiation
         * FUN_0082F210 above (`max_size` 0x3FFFFFFF, `0x3FFFFFFF - size <
         * count` overflow guard, 1.5x growth `(cap>>1)+cap`), but a
         * distinct address/call chain: reached from `resize` FUN_0082CBA0
         * (itself `msvc8::vector<void*>::resize(n, val)`, calling this as
         * its grow half), which is in turn called from
         * `InsertOrFindHashListNode` FUN_0082B5E0 -- the sibling of the
         * `HashListNode10`/`HashListNode2C` insert helper CWldSession.cpp's
         * `AddCommandQueueToCommandGraph` notes already document
         * (0x0082C750/0x0082C950/0x0082C480/0x0082B5E0), so this is
         * `UICommandGraph`'s *other* hash table's bucket array growing on a
         * one-bucket rehash. The in-place tail-shift branch calls the
         * register-shape adapter FUN_00831640; both the in-place and
         * reallocation branches call the range-copy body FUN_00832B80
         * directly for the head/tail relocation (all cited on
         * `uninit_copy_n` above).)
         * Address: 0x00768090 (FUN_00768090, `msvc8::vector<T>::insert` for
         * `hash_map<Key,T,Traits>::iterator` -- a 4-byte pointer-wrapper
         * element (`max_size` folds to `0x3FFFFFFF`, matching the 4-byte-
         * pointer family cited elsewhere on this method). This is `mVec`'s
         * grow lane in `legacy/containers/HashMap.h`'s `hash_map` (the
         * `PathQueue::ImplBase` node-table instantiation): `_Init()`'s
         * `mVec.clear(); mVec.resize(Traits::min_buckets + 1, mList.end())`
         * calls this template's own `resize(n, value)` -> `insert(last_, n,
         * value)` path on first construction, when `mVec` is still empty and
         * the resize forces a full reallocation. `_Init()` itself is
         * `FUN_00767C70` (already recovered/address-annotated,
         * `legacy/containers/HashMap.h` + `moho/path/PathTables.cpp`), which
         * is this function's direct, confirmed caller (`call sub_768090` at
         * its own body). The other two call sites, FUN_00767EC0 (`skip`,
         * one-instruction tail-call thunk) and FUN_00769B90
         * (`external_dependency`), are not needed to satisfy this
         * instantiation's caller evidence.)
         * Address: 0x0052DBE0 (FUN_0052DBE0, `msvc8::vector<T>::insert` for a
         * 16-byte element (`max_size` folds to `0x0FFFFFFF`, `sar
         * reg,4`/`shl reg,4` stride) in the `RRuleGameRulesImpl` area --
         * confirmed reachable at depth 1 from
         * `??_7RRuleGameRulesImpl@Moho@@6B@` and, by direct disassembly,
         * called from `RRuleGameRulesImpl::ExportToLuaState`
         * (`FUN_00529F70`, recovered/address-annotated at
         * `moho/sim/RRuleGameRules.cpp:2005`) at `call sub_52DBE0`,
         * 0x0052A31D -- the currently-committed `ExportToLuaState` body is a
         * partial reconstruction that does not yet show this specific
         * insert; the call is present in the shipped binary regardless. The
         * in-place (capacity-already-sufficient) branch's tail-shift-assign
         * step for this element is FUN_005334B0 -> its wrapped body
         * FUN_00537420 (cited on this method's in-place branch below --
         * corrected from a prior pass on that citation, which mis-attributed
         * it to this method's reallocation branch and mis-described it as
         * `uninit_move_n`; verified against 0x0052DBE0's own `.asm`, which
         * calls `FUN_005334B0` only from the `loc_52DDA0`-rooted block that
         * contains no `operator new` call, unlike the preceding reallocation
         * block at 0x0052DCB2-0x0052DCC8). The reallocation branch instead
         * relocates elements through FUN_00537860 (unrecovered, out of
         * scope here).
         *
         * A third direct callee, FUN_00536F10, is confirmed the same
         * RRuleGameRulesLuaExportBinding-family shape as FUN_00536DA0/
         * FUN_00537420 (its own body calls the identical sub_52D9C0
         * erase-destination-tree + sub_530EE0 clone-source-tree pair,
         * both already cited on that struct's assignment operator) but
         * wraps that logic in an explicit range loop (`do { ...; } while
         * (cursor != end)`) rather than being a single-element body
         * itself -- an assignment-per-element LOOP, not the assignment
         * operator proper. Exactly which of insert's branches emits this
         * specific loop shape (vs. the already-mapped FUN_005334B0/
         * FUN_00537420 tail-shift and FUN_00537860 relocate) was not
         * disambiguated from register-level reconstruction alone;
         * recorded here rather than left unattributed. FUN_005334A0 is a
         * thin calling-convention bridge into it (`LOBYTE(this)=0;
         * return sub_536F10(this,this,this);`, the same adapter idiom
         * used throughout this cluster).)
         * Address: 0x00868040 (FUN_00868040, `msvc8::vector<
         * Moho::WeakEntitySetUserEntity>::insert(end(), count, value)` core for
         * the 12-byte selection-priority bucket vector -- `max_size` folds to
         * `357913941` (`0xFFFFFFFF/12`, checked against `count` before
         * growing), reallocation growth is `(size>>1)+size` clamped to the
         * needed size (this method's `recommended_capacity`), the new buffer
         * is filled by copying the live range with the `uninit_copy_n`
         * instantiation FUN_00868FD0 and the new tail with the `uninit_fill_n`
         * instantiation FUN_00868DB0 (cited below); the in-place (capacity
         * already sufficient) branch shifts the tail with the `uninit_move_n`
         * instantiation FUN_00868920 and fills the vacated gap through the
         * advance-returning `_Ufill` adapter FUN_00868580 (cited on
         * `uninit_fill_n` below), matching this method's own two-branch shape
         * exactly. Reached from the two-argument `resize` overload above
         * (FUN_00867B90) when growing.)
         * Address: 0x007030C0 (FUN_007030C0,
         * msvc8::vector<SEntitySetTemplateUnit>::insert(end(), count, value)
         * core for the 0x28-byte element -- copies `value` into a local
         * first (VC8's aliasing-safe idiom; the copy itself is the
         * `uninit_fill_n`-shaped emission FUN_007046F0, called twice from
         * inside this function, once per branch), checks `max_size` via the
         * `0xFFFFFFFF/40` fold and calls `throw_too_long` (FUN_00703410) on
         * overflow, allocates through `allocate_slots_checked`
         * (FUN_00704750), and moves the pre-gap/post-gap ranges into the new
         * buffer through the `uninit_move_n` emissions FUN_00706900 /
         * FUN_00705980 (reached via the thin trampolines FUN_007046C0 /
         * FUN_00703B90), whose own EH-unwind cleanup destroys the
         * already-constructed prefix through the `~SEntitySetTemplateUnit`
         * emission FUN_00705B30 (cited on the destructor, ArmyUnitSet.h).
         * Reached from `resize`'s two-argument overload above (FUN_00702450)
         * when growing `CArmyImpl::UnitCategorySets`.)
         *
         * Address: 0x007BBD60 (FUN_007BBD60, msvc8::vector<Moho::
         * SNetCommandArg>::_Insert_n grow/insert core for the 36-byte
         * element, count=1-specialized (no `count` parameter -- every
         * arithmetic step in the body is folded for exactly one inserted
         * element). Reached only through the single-element wrapper
         * FUN_007BB780 (cited above on the single-value `insert`
         * overload), which is itself push_back's capacity-full tail-call
         * target (FUN_007BB120, `moho::cfunc_GpgNetSendL`'s
         * `args.push_back(...)` sites, CGpgNetInterface.cpp). Builds a
         * local copy of `value` on the stack first (VC8's aliasing-safety
         * idiom, matching this method's own `const T localValue(value)`),
         * then:
         *   - `_Xlen`/`max_size` guard: divides by 36 via the
         *     `38E38E39h`/`sar 3` magic pair, throws through
         *     `throw_too_long`'s FUN_007BC060 (cited below) when
         *     `0xFFFFFFFF/36 (=119304647) - size < 1`;
         *   - capacity check `capacity >= size+1`; if true, takes the
         *     in-place branch (below); if false, takes the reallocation
         *     branch: 1.5x growth (`(cap>>1)+cap`) falling back to
         *     `size()+1` through the `size()` accessor FUN_007BB0E0
         *     (cited as `GetCommandArgCount`, CGpgNetInterface.cpp) when
         *     1.5x is still insufficient, allocates through the checked
         *     36-byte lane FUN_007BCD70 (`AllocateCheckedElementBlock`,
         *     the runtime-width `_Allocate` sibling cited on
         *     `allocate_slots_checked` below, Vector.cpp), relocates
         *     `[first,pos)` and `[pos,last)` into the new buffer via two
         *     calls to the `uninit_move_n` realization FUN_007BED70 (cited
         *     below), constructs the inserted value between them via the
         *     `uninit_fill_n` realization FUN_007BD810 (cited below as
         *     `CopyAssignCommandArgRangeWithRollback`, CGpgNetInterface.cpp),
         *     destroys the old range through `destroy_range`'s FUN_007BD8F0
         *     (cited above on `destroy_range`), and frees the old block;
         *   - in-place branch (capacity already sufficient): when
         *     `pos == last_` (count_after == 0, true append-with-spare-
         *     capacity), constructs the new element directly at `last_`
         *     through the `uninit_fill_n` trampoline FUN_007BB880 ->
         *     FUN_007BD810 (both cited below); when `pos != last_` (true
         *     middle-insert), relocates the current last live element into
         *     the new one-past-end slot through the single-element
         *     `uninit_move_n` adapter FUN_007BCD00 (cited below), shifts
         *     the remaining `[pos, last_-1)` run one slot right via the
         *     in-place tail-shift-by-move-assign loop FUN_007BCD40 (cited
         *     below), then writes `value` into the vacated `pos` slot
         *     through the fill helper FUN_007BD950 (cited as
         *     `FillCommandArgRangeFromPrototype`, CGpgNetInterface.cpp) --
         *     the append case reaches the same tail-shift/fill calls with a
         *     degenerate empty range (`pos == last_` collapses both to
         *     no-ops), so no separate append-only body exists in the
         *     binary.)
         * Address: 0x007BCD40 (FUN_007BCD40, msvc8::vector<Moho::
         * SNetCommandArg>::insert(pos, count, value)'s in-place
         * tail-shift-by-move-assign loop for the 36-byte element -- a thin
         * register-shape adapter (no logic of its own beyond reshuffling
         * `(oldLast-36, oldLast)` onto the stack) that tail-calls the real
         * backward-copy loop FUN_007BDF00 (cited below). Called once from
         * FUN_007BBD60's middle-insert branch, cited above.)
         * Address: 0x007BDF00 (FUN_007BDF00, the `copy_backward`-shaped
         * per-element move-assign loop FUN_007BCD40 forwards into -- walks
         * `[pos, oldLast-36)` backward (decrementing both cursors by 36
         * each step, so it starts with the element just before the one
         * already relocated by `uninit_move_n`/FUN_007BCD00 above, and
         * never re-touches an unread source slot), assigning `mType`/
         * `mNum` as raw dwords and `mStr` through `std::string::assign`
         * per slot. This is the tail-shift half of `insert`'s in-place
         * branch: it assigns into *already-constructed* destination slots
         * -- unlike `uninit_move_n` (FUN_007BED70/FUN_007BCD00, which
         * construct into fresh memory) -- matching this method's own
         * `for (i = tail-count; i>0; --i) insertAt[count+i-1] =
         * std::move(insertAt[i-1])` branch for a non-trivial element, the
         * same shape already documented for FUN_00653E80/SDebugWorldText
         * above.)
         * Address: 0x00855DF0 (FUN_00855DF0, msvc8::vector<boost::
         * shared_ptr<moho::MeshInstance>>::insert(pos, count, value) core
         * for the 8-byte shared_ptr `(px, pn)` pair element -- `max_size`
         * folds to `0x1FFFFFFF` (`0xFFFFFFFF/8`), matching this method's
         * own fold for an 8-byte element. IDA's own decompile of this
         * address is flagged "positive sp value ... may be wrong", so this
         * citation rests on the parts independently confirmed from each
         * callee's own (clean) decompile rather than on FUN_00855DF0's
         * exact argument wiring: `localValue` is built on the stack first
         * exactly like this method's own `const T localValue(value)` (the
         * `_InterlockedExchangeAdd(pn+1, 1)` bump on construction is
         * `boost::detail::sp_counted_base::add_ref_copy`, the closing
         * `_InterlockedExchangeAdd(pn+1, -1)` / vtable-dispose /
         * weak-release chain at the end is that type's `release()`/
         * `weak_release()`, the same pattern already documented at
         * 0x004229B0); the `0x1FFFFFFF - cur < count` guard throws through
         * this element's own `throw_too_long` lane FUN_00856100 (cited
         * below); the in-place branch relocates the tail through this
         * method's own `uninit_move_n` instantiation FUN_00857A90 (reached
         * via the thiscall bridge FUN_008571F0, cited below) and either
         * tail-shifts the remainder by per-element copy-assign through
         * FUN_00857880 (reached via the thin cdecl bridge FUN_00857230) or,
         * when the gap is bigger than the live tail, constructs the
         * trailing slots fresh through this method's own `uninit_fill_n`
         * instantiation FUN_008575A0 (cited below); the fill step in the
         * Address: 0x0076A890 (FUN_0076A890, `msvc8::vector<hash_map<Key,T,
         * Traits>::iterator>::uninit_fill_n` for the 4-byte pointer-wrapper
         * element -- the same `PathQueue::ImplBase` node-table instantiation
         * cited on `insert` as `FUN_00768090`. Fills `count` copies of the
         * plain-dword iterator value into fresh slots. Reached from this
         * instantiation's `insert`, `FUN_00768090`, itself reached from
         * `_Init()`'s `mVec.resize(Traits::min_buckets + 1, mList.end())`
         * (`FUN_00767C70`, cited above on `insert`).)
         * Address: 0x008326C0 (FUN_008326C0, `msvc8::vector<void*>::
         * uninit_fill_n` for UICommandGraph's hash-bucket vector, same
         * 4-byte pointer / same-shape emission as `FUN_0076A890` above.
         * Reached from this instantiation's `_Insert_n`, `FUN_0082DE90`
         * (cited above on `insert`).)
         * Address: 0x00832710 (FUN_00832710, `msvc8::vector<void*>::
         * uninit_fill_n` for UICommandGraph's MapC hash-bucket table, same
         * shape as the two addresses immediately above. Reached from this
         * instantiation's `assign(9, sentinel)`, `FUN_0082F680` (cited
         * above on `assign`), the same call chain as the MapC
         * `deallocate_all` sibling `FUN_0082DBF0` cited on that member.)
         * Address: 0x007E6460 (FUN_007E6460, `msvc8::vector<Wm3::Vector3f>::
         * uninit_fill_n` for the 12-byte three-float element -- the same
         * instantiation as the `_Insert_n` core `FUN_008523C0` cited on
         * `insert` above (`WavePattern`-adjacent `insert-and-rebase` lane).
         * Reached from `push_back`'s own fast path (`FUN_008522A0`, cited
         * above on `push_back` -- confirmed as this token's real direct
         * caller via the callgraph, filling this member's "no grow-core
         * citation found" gap noted there), from `_Insert_n`'s
         * gap-construct branches, and from `FUN_007E3730`'s
         * `vector(size_type)`/`vector(size_type,const T&)` allocate-then-
         * fill body (cited above on the count-only constructor) -- the
         * broadcast-fill core is shared by every code path that constructs
         * or grows this instantiation with a repeated value, regardless of
         * which higher-level operation triggers it.)
         *
         * tail-shift sub-branch is a per-element copy-assign broadcast of
         * `localValue`, FUN_008576A0 -- both FUN_00857880 and FUN_008576A0
         * assign into *already-constructed* slots (add-ref the incoming
         * pointer, release the outgoing one), matching this method's own
         * `insertAt[...] = localValue`/`= std::move(...)` loops for a
         * non-trivial element, the same construct-vs-assign split already
         * documented for the SNetCommandArg entry above; the reallocation
         * branch grows 1.5x (`(cap>>1)+cap`) clamped to the needed size,
         * allocates through this method's own `allocate_slots_checked`
         * instantiation FUN_00857260 (cited below), and tears the old
         * buffer down through this method's own `destroy_range`
         * instantiation FUN_00857630 (cited below) before `operator
         * delete`. Reached from `push_back`'s capacity-full tail-call
         * (`insert(last_, value)` -> this method's own single-value
         * overload above -> this method with `count=1`) for
         * `moho::CUIWorldViewBuildDragRuntimeView::mMeshes`
         * (UiRuntimeTypes.h:890) -- confirmed directly from
         * `PushBackMeshInstanceSharedPtrVector`'s (FUN_00855040,
         * UiRuntimeTypes.cpp, already recovered) own raw decompile, which
         * tail-calls `sub_855DF0((int)a2, a2[2], 1u, a1)` on its
         * capacity-full path.)
         *
         * Address: 0x007FB8D0 (FUN_007FB8D0, thin argument-reordering
         * bridge into FUN_007FBFE0) -- `msvc8::vector<moho::
         * WRenViewportWorldViewParamRuntime>::insert(pos, count, value)`'s
         * in-place tail-shift-by-assign sub-step for the 20-byte element
         * (`{IRenderWorldView* view; int head; int depth; boost::
         * shared_ptr<TerrainCommon> terrain}`, the same instantiation
         * cited on `uninit_move_n` below as `FUN_007FC2F0`) -- backward
         * walk, raw dword copy for view/head/depth, `terrain`'s control
         * block add-ref/release juggling on assign, matching this method's
         * own non-trivial-element tail-shift-by-move-assign loop. Reached
         * from `InsertWorldViewParamAt` (`FUN_007FB060`, WxRuntimeTypes.cpp)
         * when the insertion position isn't at `end()` and spare capacity
         * already covers the request -- the in-place branch this
         * instantiation's `uninit_move_n` citation below did not yet
         * cover (that one documents the reallocation branch only).
         * Address: 0x0074F8E0 (FUN_0074F8E0, IDA types the vector correctly
         * as `std::vector_CSimConVarInstanceBase` -- `msvc8::vector<Moho::
         * CSimConVarInstanceBase*>::insert(pos, count, value)` for the
         * 4-byte pointer element, trivially copyable: the in-place branch
         * uses `sub_751D30`/`memset32` for the tail-shift and gap-fill
         * (matching this method's `memmove`+broadcast-`localValue` shape
         * for `is_trivially_copyable_v<T>`), the reallocation branch
         * allocates via `sub_751DA0` (matching `allocate_slots_checked`)
         * and copies via `memmove_s` (matching `uninit_move_n` for a
         * trivial element). Was `blocked` ("needs deeper owner/xref
         * closure") -- its only caller, `FUN_0074DDD0` (now cited on
         * `resize` above as the `mSimVars.resize(n, nullptr)` grow path),
         * was independently wrongly `external_dependency`; both corrected
         * together. `sub_751D30`/`sub_751D70`/`sub_751DA0` (the in-place
         * shift / destroy-tail / allocate sub-helpers this instantiation
         * calls) are not individually cited yet -- follow-up.)
         * Address: 0x00751D30 (FUN_00751D30, this `CSimConVarInstanceBase*`
         * instantiation's in-place tail-shift sub-step -- `count =
         * (rangeEnd-rangeBegin)>>2` (4-byte pointer stride), `memmove_s(
         * dest, count*4, rangeBegin, count*4)` when `count != 0`, returns
         * `dest + count*4` (the new range end). Reached from `FUN_0074F8E0`
         * above's in-place branch (tail-shift-by-memmove for the trivially-
         * copyable pointer element). DB previously mis-attributed this
         * token to `CrtRuntimeHelpers.cpp` with no real citation there (same
         * "DB-integrity bulk fix 2026-08-24... plausible-sounding
         * boilerplate" contamination documented for several other tokens
         * this session); corrected to `recovered` here, resolving the
         * "not individually cited yet" follow-up noted just above.)
         * Address: 0x008F7770 (FUN_008F7770, `msvc8::vector<AdapterModeD3D10>::
         * insert(pos, count, value)` / `_Insert_n` core for the 0x74-byte
         * (116) non-trivial `AdapterModeD3D10` element -- `AdapterD3D10::
         * modes_` (`+0x12C`). Full three-branch VC8 shape matching this
         * method body statement-for-statement: copies `value` into a local
         * stack temporary first (`sub_8F6D20` on `&localValue.modes_`,
         * guarding against `value` aliasing into `this` across a
         * reallocation/shift, exactly this method's `const T
         * localValue(value);`), computes `cur = size()`, checks `max_size()
         * - cur < count` throwing through `FUN_008F6900` (`this method's
         * `throw_too_long()` guard); growth branch (`cur+count >
         * capacity()`): `recommended_capacity` via `FUN_008F5D90` (already
         * recovered), allocate via `FUN_008F6040`
         * (`allocate_struct116_slots_checked`, already recovered),
         * `uninit_move_n`/`uninit_copy_n` the pre-insertion-point elements
         * via `FUN_008F7390` (cited below on `uninit_copy_n`), `uninit_fill_n`
         * `count` copies of `localValue` at the gap via `FUN_008F74A0`
         * (through the thiscall bridge `FUN_008F7630`, cited there), then
         * `uninit_move_n`/`uninit_copy_n` the post-insertion-point tail via a
         * second `FUN_008F7390` call (through the thiscall bridge
         * `FUN_008F7700`, cited on `uninit_copy_n`), destroys and frees the
         * old buffer via `FUN_008F7550`/`FUN_008F7670` (already recovered);
         * in-place branches (capacity available, no reallocation): the
         * tail-large-enough-to-shift-whole case uses the `copy_backward`-
         * shaped tail-shift-by-assignment loop `FUN_008F70A0` (through the
         * `__cdecl` bridge `FUN_008F7470`, already correctly `skip`-tagged
         * as a thin tail-call thunk) to relocate already-constructed
         * elements via `operator=` (`FUN_008F6DD0`, cited above on
         * `operator=`) for each element's `modes_` sub-object, then
         * overwrites the vacated gap with `localValue` via the
         * `std::fill`-shaped assign loop `FUN_008F72D0` (also `operator=`
         * via `FUN_008F6DD0` per slot); the tail-smaller-than-gap case
         * `uninit_move_n`s the tail into fresh slots past `last_` (again
         * `FUN_008F7390`/`FUN_008F7700`), `uninit_fill_n`s the newly-exposed
         * trailing gap slots (`FUN_008F74A0`/`FUN_008F7630`), and assign-fills
         * the head-of-gap slots that overlap already-constructed storage via
         * `FUN_008F72D0` again. Reached via the `__stdcall` calling-
         * convention bridge `FUN_008F7B80` (`sub_8F7770(a2, 1, a3);`, no
         * logic of its own) from `AppendAdapterModeEntry`'s
         * `modes.push_back(entry)` (D3D10Interfaces.cpp, already committed)
         * -- `push_back`'s capacity-exceeded path is `insert(end(), 1,
         * value)`, matching this token's `count=1` invocation shape
         * (`FUN_008F7C50`'s own fast path calls `FUN_008F74A0` directly when
         * capacity allows; this token is the slow/grow path taken when it
         * does not). DB previously listed this token `blocked` ("released
         * after triage - either too large for single-session recovery,
         * callers themselves blocked, or recovery would conflict with
         * existing high-level abstractions") -- stale: `FUN_008F7C50` is
         * `recovered`, and none of this token's real callees conflict with
         * this template; corrected to `recovered` here.
         * Address: 0x008F72D0 (FUN_008F72D0, this instantiation's
         * `std::fill`-shaped gap-overwrite sub-step -- loops `[a1,a2)`
         * writing the single repeated `*a3` value into each already-
         * constructed slot via `operator=` (`FUN_008F6DD0` on the `modes_`
         * sub-object at each element's `+0x64`). Reached from `FUN_008F7770`
         * above (both in-place branches) and from the orphan bridge
         * `FUN_008F7460` (`// attributes: thunk`, zero traced callers of its
         * own -- likely reached from the still-unrecovered outer
         * `msvc8::vector<AdapterModeD3D10>::operator=`'s own assign-over
         * step, matching the correction on `operator=` above, but not
         * proven). DB previously listed this token `blocked` ("mixed
         * POD+subobject copy lane requires dependent type recovery (callee
         * FUN_008F6DD0)") -- stale: `FUN_008F6DD0` is `recovered`; corrected
         * to `recovered` here.
         * Address: 0x008F70A0 (FUN_008F70A0, this instantiation's
         * `copy_backward`-shaped tail-shift-by-assignment sub-step -- walks
         * `[a1,a2)` backward writing into a descending `a3` cursor,
         * `operator=` (`FUN_008F6DD0`) per element's `modes_` sub-object,
         * safe for the overlapping-range shift `_Insert_n`'s in-place branch
         * needs. Reached through the `__cdecl` calling-convention bridge
         * `FUN_008F7470` (`return sub_8F70A0(a1,a2,a3);`, already correctly
         * `skip`-tagged, no logic of its own) from `FUN_008F7770` above.
         * `FUN_008F7320` (`jmp sub_8F70A0`, already `skip`-tagged as a
         * tail-call thunk) is a second, still-uncalled-from-anywhere-traced
         * bridge to this same token -- likely reached from the same
         * still-unrecovered outer `operator=`/`erase`/`resize` family as
         * `FUN_008F7460` above, not proven. DB previously listed this token
         * `blocked` ("unresolved owner layout and callee FUN_008F6DD0") --
         * stale: layout is `AdapterModeD3D10` (`AdapterD3D10.hpp`, already
         * recovered) and `FUN_008F6DD0` is `recovered`; corrected to
         * `recovered` here.)
         * Address: 0x008EFCD0 (FUN_008EFCD0, the same
         * `copy_backward`-shaped tail-shift-by-assignment sub-step as
         * `FUN_008F70A0` above, for the 112-byte `gpg::gal::AdapterD3D9`
         * element: reverse pointer-walk (`v3 -= 112; v4 -= 112;` per
         * iteration, copying from high addresses down to `a1`) assigning
         * the two leading `uint32_t` id lanes directly, three
         * `std::string::assign` calls for `driver`/`deviceName`/
         * `description` (real `std::string::assign` per IDA, matching
         * `msvc8::string`'s VC8-ABI-compatible layout), then this element
         * type's own `operator=` (`FUN_008EF870`,
         * `msvc8::vector<AdapterModeD3D9>::operator=`, cited above) for the
         * `modes` member at `+0x60`/`+96` -- together the compiler-
         * synthesized memberwise `AdapterD3D9::operator=`. Bridged through
         * the thin forwarder `FUN_008F0380` (`return sub_8EFCD0(a1,a2,a3);`,
         * no logic of its own) from the `_Insert_n`-shaped grow/shift lane
         * `FUN_008F1890` (that function's own decompile carries IDA's
         * "bad/positive sp value" unreliability warning -- its precise
         * argument wiring was not relied on here, only the `call
         * sub_8F0380` instruction, which is a plain, register-independent
         * fact). Source trigger:
         * `AsDeviceD3D9Runtime(device).adapters.push_back(adapter);`
         * (D3D9Interfaces.cpp) instantiates this template member; see the
         * note on `operator=` above for the dumpbin-verified confirmation
         * that this inline loop -- not the separate `copy_or_move_assign`
         * helper -- is what actually gets compiled for `T = AdapterD3D9`.)
         *
         * Address: 0x0092F630 (FUN_0092F630, `msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::insert(iterator, size_type,
         * const T&)` for the 12-byte edge-traversal-lane element -- the
         * `_Insert_n` core `push_back`'s capacity-full path reaches with
         * `count=1` (via the single-value `insert` at `FUN_00930000`, cited
         * above). Carries the full VC8 shape byte-for-byte matching this
         * member's own control flow: `max_size` guard folds to `357913941`
         * (`0xFFFFFFFF/12`, throw lane `FUN_0092EFF0`, cited below on
         * `throw_too_long`); in-place branch (capacity already covers
         * `size()+count`) tail-shifts via the copy-alias `FUN_0092ED60` ->
         * `FUN_0092D7D0` (cited below on `uninit_move_n`) then
         * `FUN_0092DC80` (reverse/backward element-wise copy -- this
         * instantiation is not recognized as the STL's "trivial scalar"
         * fast-copy candidate despite being POD, so the binary emits an
         * explicit backward-walking per-element loop here rather than a
         * `memmove`; this member's own `if constexpr
         * (is_trivially_copyable_v<T>)` branch reaches `std::memmove`
         * instead for this same element -- both produce byte-identical
         * results for a 3-field POD with no aliasing hazard, so this is a
         * different-instructions/same-behavior case, not a divergence to
         * fix per RULE ONE) or `FUN_92D0A0` (plain fill, cited below on
         * `uninit_fill_n`); reallocation branch (the only branch this
         * element's `push_back` call path ever actually exercises, since
         * `push_back` only forwards to `insert` once capacity is already
         * exhausted) computes `recommended_capacity` inline
         * (`(cap>>1)+cap`, folding to `count+capacity()` on the `grown <
         * need` fallback -- exactly this member's own `recommended_capacity`
         * shape below), allocates via `FUN_0092C080` (cited below on
         * `allocate_slots_checked`), head/tail-relocates the live range via
         * two calls to `FUN_0092D7D0` (`uninit_move_n`), fills the gap via
         * the advance-returning `FUN_0092E920` -> `FUN_0092DF10` adapter
         * (cited below on `uninit_fill_n`), frees the old block and rebases
         * `{first_,last_,end_}`. Emitted via `outEdgeLanes.push_back(lane)`
         * in `ExpandClusterSearchFrontierEdges` (Cluster.cpp) once
         * `edgeLanes` is at capacity.)
         * Address: 0x0092F240 (FUN_0092F240, `msvc8::vector<gpg::HaStar::
         * ClusterSearchOpenHeapEntryRuntime>::insert(iterator, size_type,
         * const T&)` for the 12-byte open-heap-entry element -- structurally
         * identical to `FUN_0092F630` immediately above (same `357913941`
         * max_size constant, same 1.5x growth, same in-place/reallocate
         * branch shape), but a distinct instantiation with its own private
         * sub-helpers throughout (`FUN_0092F060` throw, `FUN_0092C0E0`
         * allocate, `FUN_0092C280` capacity, `FUN_0092D840`/`FUN_0092EEB0`
         * move-copy, `FUN_0092DFC0` backward-copy, `FUN_0092D580` plain
         * fill, `FUN_0092EB70` fill-advance adapter -- all cited below on
         * their respective shared members) -- confirmed a separate
         * emission, not an ICF twin: distinct `function_sha256`, every
         * sub-call target differs. Reached from this element's `push_back`
         * (`FUN_00930190`, cited above) capacity-full path via
         * `FUN_0092FCD0` (cited above on the single-value `insert`
         * overload).)
         * Address: 0x004451A0 (FUN_004451A0, `msvc8::vector<std::int32_t>::
         * insert(iterator, size_type, const T&)` for the handle-to-heap-
         * index reverse map (`ClusterSearchOpenHeapRuntime::
         * mHandleToHeapIndex`, Cluster.cpp) -- same shape again for the
         * 4-byte element: `max_size` folds to `0x3FFFFFFF`, 1.5x growth,
         * throw lane `FUN_00444270` (cited below on `throw_too_long`),
         * allocate `FUN_00445B80` (cited below on `allocate_slots_checked`).
         * Unlike the two 12-byte instantiations above, this element *is*
         * recognized as the STL's trivial-scalar fast-copy candidate, so
         * every copy/shift step (`FUN_00445F20`, called three times for the
         * in-place tail-shift, the reallocation head-relocate, and the
         * reallocation tail-relocate) is a direct `memmove_s` wrapper rather
         * than a per-element loop -- exactly this member's own `if
         * constexpr (is_trivially_copyable_v<T>) { std::memmove(...); }`
         * fast path. The fill step `FUN_00445430` (cited below on
         * `uninit_fill_n`) already returns the advanced pointer directly, no
         * separate adapter needed for a 4-byte element. Reached from this
         * element's `push_back` (`FUN_00686E80`, cited above) capacity-full
         * path via `FUN_00687B40`.)
         * Address: 0x00936FF0 (FUN_00936FF0, `msvc8::vector<gpg::
         * ThreadCtxEntry*>::insert(iterator, size_type, const T&)` --
         * `gpg::ThreadState::mEntries`, `Logging.h`. Same 4-byte-pointer
         * shape again: `max_size` folds to `0x3FFFFFFF`, 1.5x growth
         * (`v10 = (v7 >> 1) + v7`, confirmed against the `.asm`), throw lane
         * `FUN_00936DB0`, allocate `FUN_00935B20`, copy/relocate step
         * `FUN_00936990` (cited above on `uninit_move_n`, called three
         * times: twice for the in-place tail-shift, once per half for the
         * reallocation branch), fill step `FUN_00936B00` (cited below on
         * `uninit_fill_n`). Reached from `gpg::PushThreadContext`'s
         * `tls->mEntries.push_back(entry)` (`Logging.cpp`) capacity-full
         * path. Previously mass-mis-attributed to `CrtRuntimeHelpers.cpp`
         * by the 2026-08-24 DB-integrity bulk pass (address not present in
         * that file); marked `skip` in `recovered_progress.json` rather
         * than `recovered` since `push_back(entry)` above is the
         * programmer-written source line this address's whole family
         * compiles to, matching every other `push_back`-reached `insert`
         * instantiation in this member -- but it had no source-side
         * citation at all before this pass, unlike its siblings.)
         *
         * Address: 0x00627800 (FUN_00627800, sub_627800) --
         * `msvc8::vector<Moho::SPickUpInfo>::insert(iterator, size_type,
         * const T&)` (`_Insert_n`) for the 12-byte intrusive-weak
         * `{WeakPtr<Unit>, float}` element (`SPickUpInfoVectorReflection.cpp`'s
         * `SPickUpInfoVector`). `max_size` folds to 357913941
         * (`0xFFFFFFFF / 12`, throw lane `FUN_00627B20`). In-place branch
         * (`capacity() >= size()+count`): the `tail >= count` sub-branch
         * (not exercised by this instantiation's only confirmed caller,
         * since `push_back` always inserts at `end()` where `tail == 0`)
         * shifts via `FUN_00628200`/`FUN_00628230`; the `tail < count`
         * sub-branch -- the one `push_back`'s `count=1`-at-`end()` call
         * always takes -- moves the (empty) tail via `FUN_00628200` then
         * fills the new element through the `_Ufill` adapter `FUN_006274B0`
         * (cited below on `uninit_fill_n`), matching this member's
         * `uninit_move_n(insertAt, tail, insertAt+count); uninit_fill_n(
         * insertAt+tail, count-tail, localValue);` pair for `tail == 0`.
         * Reallocation branch: 1.5x growth (`v10 = (v5>>1)+v5`, folding to
         * `count + FUN_00627310` -- this instantiation's own
         * `recommended_capacity`-shaped grow query -- when 1.5x undershoots
         * `size()+count`), allocates via `FUN_00628260`, fills the new
         * element(s) through `FUN_00629F40`/`FUN_00628AE0`, relocates the
         * live range and frees the old block via `FUN_00628AB0` +
         * `operator delete`. Every element move/copy/destroy step in both
         * branches drives `SPickUpInfo`'s non-trivial copy-ctor/dtor to
         * relink the intrusive `WeakPtr<Unit>` owner chain -- none of this
         * instantiation's sub-helpers are the STL's trivial-scalar
         * fast-copy path. Reached from this element's `insert(pos, value)`
         * single-value overload (`FUN_00627340`, cited above) with
         * `count = 1`, itself reached from `push_back`
         * (`FUN_00626E10`/`PushBackSPickUpInfoWithRelink`,
         * `SPickUpInfoVectorReflection.cpp`, already recovered)
         * capacity-full path. Previously `blocked`
         * ("needs_recovered_caller" -- its only feasible source-level
         * callers were `[[maybe_unused]]` orphans); both
         * `PushBackSPickUpInfoWithRelink` and `gpg::RVectorType_SPickUpInfo::
         * SetCount`/`SerLoad` are non-orphan recovered source as of this
         * pass, resolving that blocker per its own documented unblock
         * criteria (`decomp/recovery/reports/FUN_00627800.md`).
         *
         * Address: 0x00537C60 (FUN_00537C60, sub_537C60) --
         * `msvc8::vector<const char*>::insert(iterator, size_type, const T&)`
         * (`_Insert_n`) for the 4-byte pointer element (`CAniSkel.cpp`'s
         * `FillSScmBoneNamePointers` scratch vector). `max_size` folds to
         * 0x3FFFFFFF (`0xFFFFFFFF / 4`, throw lane `FUN_00537EF0`). This is
         * the STL trivial-scalar fast-copy shape (like `FUN_004451A0`
         * above): the in-place branch's tail-shift step is the range-form
         * `uninit_move_n` adapter `FUN_00538040` (cited above), the fill
         * step is a direct `memset32(dst, value, count)` broadcast (no
         * per-element loop, no separate `uninit_fill_n` callee -- `value`
         * is a single 4-byte word here), and the reallocation branch grows
         * 1.5x, allocates via `FUN_005380D0`, and relocates head/tail
         * through two more `memmove_s` calls inline rather than through
         * this member's own helpers. `sub_538080` (called once, in the
         * in-place branch's `tail >= count` sub-branch) is not yet
         * individually recovered. Reached from `resize`'s emission for
         * this instantiation (`FUN_00537B40`, cited below) with `pos =
         * last_`, `count = newSize - size()` -- the only call pattern this
         * instantiation is exercised with, which is why its `tail >= count`
         * sub-branch (only reachable for a mid-range insert) is dead in
         * practice. Previously `blocked` ("requires deeper evidence/
         * caller-context before recovery"); this pass supplies the full
         * instantiation and caller evidence.
         *
         * Address: 0x008A9100 (FUN_008A9100, sub_8A9100) --
         * `msvc8::vector<moho::TerrainEnvironmentLookupPair>::insert(
         * iterator, size_type, const T&)` (`_Insert_n`) for the 56-byte
         * `pair<msvc8::string, msvc8::string>` element
         * (`moho::TerrainEnvironmentLookupPairs`, `CWldMap.cpp`'s
         * `AppendEnvironmentLookupPair`/`IWldTerrainRes::EnumerateEnvLookup`
         * output vector). `max_size` folds to 76695844
         * (`0xFFFFFFFF / 56`, throw lane `FUN_008A95C0`). Copies the
         * inserted value into a local first (`FUN_004D4970`, the pair
         * copy-ctor -- an aliased-element-survives-reallocation guard,
         * matching this member's own `const T localValue(value);` comment
         * above). In-place branch: `tail > 0` sub-case moves the last
         * element (`FUN_008A9B70`), shifts the remaining tail
         * (`FUN_008A9BB0`), assigns the new value into the vacated slot
         * (`FUN_008A9FA0`); `tail == 0` (append) sub-case calls the same
         * move helper with a zero-length range then assigns the value
         * directly. Reallocation branch: 1.5x growth
         * (`recommended_capacity`-shaped, `FUN_008A8A60`), allocates via
         * `allocate_slots_checked` (`FUN_008A9BF0`, cited above), moves
         * the head and tail spans via two calls to `FUN_008AA180`
         * (`uninit_move_n`-shaped for this non-trivial element), destroys
         * and frees the old block (`FUN_008A9F10` + `operator delete`).
         * None of `FUN_004D4970`/`FUN_008A9B70`/`FUN_008A9BB0`/
         * `FUN_008A9FA0`/`FUN_008A8A60`/`FUN_008AA180`/`FUN_008A9F10` are
         * yet individually recovered -- all are this instantiation's own
         * `msvc8::string`-pair construct/destroy/relocate helpers, matched
         * by shape and call position, not fabricated. Reached from this
         * element's single-value `insert(pos, value)` overload
         * (`FUN_008A8A90`, `skip`'d as a RULE ONE offset-capture/
         * tail-call-with-`count=1` wrapper) with `count = 1`, itself
         * reached from `push_back`
         * (`FUN_008A8310`/`AppendEnvironmentLookupPair`, `CWldMap.cpp`,
         * already recovered) capacity-full path, itself reached from
         * `IWldTerrainRes::EnumerateEnvLookup` (`FUN_008A1500`, already
         * recovered). Previously `blocked` on `owner_layout` pending
         * "deeper dependency closure/owner-layout evidence"; this pass
         * supplies the instantiation identity and the full caller chain
         * back to already-recovered source. Its own seven listed callees
         * remain open (callee-side health low) -- each is this
         * instantiation's own non-trivial-element construct/destroy/
         * relocate helper, not a blocker on this citation, and each is a
         * legitimate next target for a dedicated `pair<string,string>`
         * follow-up pass.
         *
         * Address: 0x008F05C0 (FUN_008F05C0, sub_8F05C0) -- `msvc8::
         * vector<gpg::gal::HeadSampleOption>::insert(pos, count, value)`,
         * the count-based core `FUN_008F1310` (cited above on `insert(pos,
         * value)`) tail-calls with `count=1`. IDA's own decompile carries a
         * "positive sp value... may be wrong" disclaimer; verified against
         * this member's real shape regardless: stages a local copy of
         * `value` first (raw dword pair for `sampleType`/`sampleQuality`
         * plus a `std::string::assign` for `label` -- exactly this
         * member's `const T localValue(value);` self-aliasing guard, see
         * that line's own comment), the `119304647`(=`0xFFFFFFFF/36`)
         * `max_size` overflow guard, the `(cap>>1)+cap` 1.5x growth
         * formula, and a reallocate-or-shift split matching this member's
         * two branches field for field. Reached only from `FUN_008F1310`
         * with `count` hardcoded to 1; the general multi-count path is
         * template-instantiated but not separately exercised through any
         * currently-traced caller -- same "compiled, not separately
         * runtime-exercised" shape as this file's other single-caller
         * count-overload citations.)
         *
         * Address: 0x00412000 (FUN_00412000, sub_412000) -- `msvc8::
         * vector<msvc8::string>::insert(pos, count, value)` for the 28-byte
         * `msvc8::string` element, the count-based core `FUN_00411EA0`
         * (cited above on `insert(pos, value)`) tail-calls with `count=1`.
         * Stages `const T localValue(value);` first via
         * `std::string::assign` (this member's self-aliasing guard, see
         * that line's own comment), the `153391689` (`=0xFFFFFFFF/28`)
         * `max_size` overflow guard, the `(cap>>1)+cap` 1.5x growth
         * formula, and the in-place-shift-vs-reallocate split matching
         * this member's two branches field for field. Only ever reached
         * with `count` hardcoded to 1 from `FUN_00411EA0`, same
         * "compiled, not separately runtime-exercised" shape as this
         * file's other single-caller count-overload citations.
         *
         * Address: 0x008F1890 (FUN_008F1890, sub_8F1890) -- `msvc8::
         * vector<gpg::gal::AdapterD3D9>::insert(pos, count, value)` for
         * `DeviceD3D9Runtime::adapters` (`D3D9Interfaces.cpp`, 112-byte
         * polymorphic element). IDA's own decompile carries a "bad/positive
         * sp value... may be wrong" disclaimer and its visible `.c` body
         * does not show the reallocation-path cleanup calls at all --
         * confirmed against the raw `.asm` instead: stages a local copy of
         * `value` via this element's copy-ctor (`FUN_008EFF80`, already
         * recovered as `AdapterD3D9::AdapterD3D9(const AdapterD3D9&)`),
         * the `38347922`(=`0xFFFFFFFF/112`) `max_size` overflow guard, the
         * `(cap>>1)+cap` 1.5x growth formula, and on the reallocation path
         * calls this instantiation's own `destroy_range` (`FUN_008EA5C0`,
         * cited above) 3x on the old buffer's live range before freeing it
         * with `operator delete`, matching this member's shape field for
         * field. This member itself is `DeviceD3D9::BuildDeviceCapabilities`'s
         * (`FUN_008F2080`, already recovered, `D3D9Interfaces.cpp`)
         * `runtime.adapters`-population path, growing the adapter list
         * during device-capability enumeration.
         *
         * Address: 0x005C6580 (FUN_005C6580, sub_5C6580) -- `insert(pos,
         * count, value)` for `Moho::SCreateUnitParams` (`SimDriver.h`,
         * 0x1C-byte element: `SCreateEntityParams` 3-dword header, tag
         * byte@+0x0C, raw pointer@+0x10, `_InterlockedExchangeAdd`-bumped
         * `boost::shared_ptr<Stats<StatItem>>` control-block pointer@+0x14,
         * trailing byte@+0x18) -- one of `uninit_copy_n`'s (`FUN_005CDEF0`
         * above) five previously-unidentified candidate callers
         * (`0x005C6580`/`0x005C9D60`/`0x005CBCA0`/`0x005CD0E0`/`0x005CD9E0`),
         * confirmed by field-for-field match against the local-copy
         * staging this member performs (`const T localValue(value)`'s
         * real emission here: copies the 3-dword header + tag into a local
         * buffer, `_InterlockedExchangeAdd`-bumps the refcount block if
         * non-null, matching this member's self-aliasing guard exactly),
         * and independently confirmed by this element's real owner:
         * `SSyncData::mNewUnits` (`SimDriver.h`, `msvc8::vector<
         * SCreateUnitParams>`) -- its reallocation branch calls this
         * template's own `destroy_range` (`FUN_005CC280`, cited below on
         * that member) 3x on the old/partial buffers, matching this
         * instantiation's 3 confirmed calls into that same address exactly.
         * IDA's own decompile carries a "bad/positive sp value... may be
         * wrong" disclaimer. Calls this instantiation's own `_Ufill`/tail-
         * shift helpers (`sub_5C9D60`/`sub_5C9DA0`/`sub_5CBCC0`) and the
         * `153391689`(=`0xFFFFFFFF/28`) `max_size` overflow guard, matching
         * this member's shape. Reached from `mNewUnits.push_back(params)`
         * (`QueueCreateUnitParams`, `SimDriver.cpp`, already recovered) on
         * its capacity-exhausted path (`push_back`'s generic `else
         * insert(last_, value)` branch, `insert(pos,value)` tail-calling
         * this count-based core with `count=1`, the same "MSVC8's
         * push_back is insert(end(),1,value) when full" shape already
         * established throughout this file). The other four candidate
         * addresses from the `uninit_copy_n` citation are still
         * unidentified thin calling-convention bridges into that same
         * member (see the citation there); this entry resolves the element
         * type for the whole cluster, not just this one address.
         *
         * Address: 0x0074EB00 (FUN_0074EB00, sub_74EB00) -- `msvc8::
         * vector<Moho::SSTIArmyVariableData>::insert(pos, count, value)`
         * for the 352-byte element, `SSyncData::mArmyUpdates` (same
         * instantiation as `reserve`'s `FUN_0074D2B0` above). Stages a
         * local copy of `value` via this element's copy ctor
         * (`Moho::SSTIArmyVariableData::SSTIArmyVariableData`, already
         * recovered), the max_size overflow guard (the divisor constant
         * folds onto a decompiler-mislabeled `LuaObject::j_Dtr_9` symbol --
         * a coincidental address overlap, not a real reference to
         * `LuaObject`, matching `0xFFFFFFFF/352`), the `(cap>>1)+cap` 1.5x
         * growth formula via `FUN_560E90`, allocation via `FUN_562700`,
         * and calls this instantiation's own uninit-copy/shift helpers
         * (`FUN_757430`/`FUN_7519D0`) on the reallocation and in-place
         * paths respectively. IDA's own decompile carries a spurious
         * `__noreturn` tag -- the function returns normally in every
         * observed path; matches this member's shape once the mislabeled
         * symbol and `__noreturn` tag are set aside. Sole caller is
         * `reserve`'s `FUN_0074D2B0` above. DB-integrity fix: was
         * `blocked` with no specific note.
         *
         * Address: 0x0074E770 (FUN_0074E770, sub_74E770) -- `msvc8::
         * vector<Moho::SSTIArmyConstantData>::insert(pos, count, value)`
         * for `SSyncData::mNewGrids` (128-byte element, `>>7` stride
         * divide matches `sizeof(SSTIArmyConstantData)==0x80` exactly).
         * Stages a local copy via this element's ctor
         * (`Moho::SSTIArmyConstantData::SSTIArmyConstantData`), the
         * max_size overflow guard, `(cap>>1)+cap` 1.5x growth, allocate
         * via `sub_751950`, and calls this instantiation's own uninit-
         * copy/shift helpers (`sub_757390`/`sub_7518D0`) on the
         * reallocation and in-place paths respectively -- same shape as
         * the sibling `SSTIArmyVariableData` instantiation above. IDA's
         * own decompile carries a spurious `__noreturn` tag; the function
         * returns normally. Sole caller is `resize`'s `FUN_0074D190`
         * above.
         *
         * Address: 0x0092F9E0 (FUN_0092F9E0, sub_92F9E0) -- `msvc8::
         * vector<iterator>::insert(pos, count, value)` for `msvc8::hash_map<
         * OccupationCacheKey, gpg::HaStar::Cluster::Data*, hash_compare<
         * OccupationCacheKey, OccupationKeyOrder>>::mVec`
         * (`OccupationCacheRuntimeMap`, `ClusterInternalCache<gpg::HaStar::
         * OccupationData>::mVec`, `gpg/core/algorithms/Cluster.cpp`) -- the
         * bucket-index vector whose element is `msvc8::list<std::pair<const
         * OccupationCacheKey, Cluster::Data*>>::iterator`, a single 4-byte
         * `_Nodeptr` wrapper (this file's own `list<T>::iterator`), matching
         * the `0x3FFFFFFF` (`0xFFFFFFFF/4`) `max_size` fold this body
         * carries. Carries this method's full two-branch shape: `sub_92F0D0`
         * is `throw_too_long` (cited below), `sub_92C1E0` is
         * `allocate_slots_checked` (cited below, `sizeof(T)==4` group), the
         * in-place branches' `sub_92ED90` and the reallocation branch's
         * `sub_92D810` are this instantiation's `uninit_move_n` (cited
         * below -- `sub_92D810` is already `skip`, an ICF twin of
         * `FUN_008D8190`; `sub_92ED90` is the calling-convention entry the
         * in-place branches call, itself tail-calling that same primitive),
         * and `sub_92EA50`/`sub_92DF90` are this instantiation's
         * `uninit_fill_n` (cited below as the advance-returning `_Ufill`
         * adapter -- `sub_92DF90` is already `skip`, an ICF twin of
         * `FUN_008EA0D0`). The in-place branch's backward tail-shift
         * (`sub_92DCB0`) and gap-fill-assign (`sub_92D130`) loops match this
         * method's own `std::memmove` (trivially-copyable branch) and
         * `insertAt[i] = localValue` lines directly -- no separate template
         * member, the same treatment as the `SSTIArmyVariableData` entry's
         * "own uninit-copy/shift helpers" above. DB-integrity fix: `sub_92D130`
         * (`FUN_0092D130`) was duplicated as a standalone `FillDwordRangeByEnd
         * LaneE` orphan free function in `moho/containers/
         * LegacyContainerFillLanesB.cpp` (anonymous-namespace, no
         * source-level caller); removed from there since this member's own
         * `insertAt[i] = localValue` loop is the complete recovery.
         *
         * Reached from `resize(n, val)`'s grow branch (`FUN_0092FC60`,
         * IDA-named `std::vector_MapNode::resize`, cited below on
         * `resize`), itself called from `hash_map<OccupationCacheKey,...>::
         * insert(value)` (`FUN_00930890`, IDA-named
         * `std::hash_map_unk_unk::insert`, `_Grow()` inlined) when the load
         * factor is exceeded -- the source-level trigger is
         * `ClusterInternalCache<OccupationData>::Fetch`'s
         * `mVec.insert(OccupationCacheRuntimeMap::value_type(key,
         * built.mData))`, `Cluster.cpp:3687`, already recovered. Also
         * reached from `assign(count, value)`'s `insert(first_, count,
         * localValue)` call (`FUN_009303F0`, cited below on `assign`),
         * itself reached from `_Init()`'s `mVec.assign(Traits::min_buckets +
         * 1, mList.end())` (`legacy/containers/HashMap.h`) via both the
         * default constructor (`FUN_00930810`, thunk) and `clear()`
         * (`FUN_00930B40`, IDA-named `std::hash_map_unk_unk::clear`).
         * `FUN_00933950`/`0x00934130` cited above are this template's
         * sibling emission for `SubclusterCacheRuntimeMap`
         * (`ClusterInternalCache<SubclusterData>::mVec`) -- a distinct C++
         * `iterator` type (different `Key` in `list<pair<const Key,T>>`)
         * with the identical 4-byte-trivial shape, not ICF-folded across
         * because the two are separate instantiations.)
         *
         * Address: 0x0064E490 (FUN_0064E490, sub_64E490) -- the count=1
         * `_Insert_n` core `msvc8::vector<moho::SDebugScreenText>::insert`
         * (0x48-byte element, `CDebugCanvas::screenText`). `.asm`-confirmed
         * calling shape: `this@arg_0` (stack), `pos@arg_4` (stack),
         * `value@ECX` (register, unused directly -- forwarded straight into
         * the entry-point copy below). Body:
         *   - `sub_64EC50(EDI=value, ESI=&localTemp)` first, copy-
         *     constructing `value` into a stack-local `SDebugScreenText`
         *     (this member's own `const T localValue(value)` aliasing-safety
         *     idiom -- `sub_64EC50` is this element's compiler-generated
         *     copy ctor, cited on `SDebugScreenText.h`).
         *   - `max_size()` guard folds to `0x38E38E3` (`0xFFFFFFFF/0x48`);
         *     throws through `throw_too_long`'s `FUN_0064EE20` (cited below)
         *     on overflow.
         *   - Growth branch (`capacity() < size()+1`): 1.5x
         *     `recommended_capacity` (`(cap>>1)+cap`, clamped to `size()+1`
         *     via the out-of-line `size()` thunk `FUN_00452160` /
         *     `GetDebugScreenTextCount`, `CDebugCanvas.h`), allocates
         *     through `allocate_slots_checked`'s `FUN_0064F860` (cited
         *     below), then relocates `[_Myfirst, pos)` into the new buffer
         *     through `uninit_move_n`'s `FUN_00650160` (`ECX=srcBegin,
         *     stack=(srcEnd=pos, dstBegin=newBuf)`, cited below), releases
         *     the old buffer if the SSO-adjacent local exceeds inline
         *     capacity, and rebinds `_Myfirst/_Mylast/_Myend` to the new
         *     block sized via the `lea reg,[base+idx*8]`/`*9` stride-0x48
         *     folds at 0x0064E64B-0x0064E65E.
         *   - Tail-shift branch (`tail = (_Mylast-pos)/0x48`): `tail==0`
         *     (append -- the only sub-branch `CDebugCanvas::screenText`'s
         *     confirmed caller chain ever reaches, see `push_back`
         *     `FUN_0064E120` above) constructs the new element at `_Mylast`
         *     from `localTemp` through the advance-returning `_Ufill`
         *     adapter `FUN_0064E360` (`count=1`, cited below on
         *     `uninit_fill_n`) and advances `_Mylast` by 0x48; `tail>=1`
         *     (mid-vector insert -- compiled as part of this shared
         *     emission but never reached by any caller in this binary,
         *     matching the documented `SDesyncInfo`/other-instantiation
         *     precedent above) shifts the tail backward one slot through
         *     the calling-convention adapter `FUN_0064F760` into
         *     `CopyDebugScreenTextRangeBackward` (`FUN_0064FFB0`,
         *     `Vector.cpp`, already recovered) and fills the vacated slot
         *     from `localTemp` via `FUN_0064E360` again.
         *   - The reallocation branch's own head-copy call
         *     (`sub_650160(ECX=_Myfirst, arg_0=pos, arg_4=newBuf)`) and the
         *     append-branch's degenerate `sub_64F720(pos, pos+0x48)` call
         *     (an empty-range no-op present only because this is the
         *     shared general-position emission) are both this member's
         *     `uninit_move_n`/its adapter, cited below.
         * Direct caller (`.asm`-confirmed, `call sub_64E490` at
         * 0x0064E33A): `FUN_0064E2F0` (`insert(iterator,const T&)`, cited
         * above), with `count` folded to 1. DB-integrity fix: was
         * mis-tagged `recovered` citing "Cited on the canonical template"
         * -- `grep -n "64E490" src/sdk/legacy/containers/Vector.h` found
         * nothing; this is the real recovery. The claimed dependency
         * `FUN_0064CC70` in the stale note's `depends_on` list does **not**
         * appear anywhere in this function's `.asm` (no `call sub_64CC70`)
         * and is not part of this instantiation's real call graph -- see
         * the caller-evidence note on `push_back` `FUN_0064E120` above for
         * where that address actually fits (two hops further up, and
         * itself still uncalled).
         *
         * Address: 0x007D8620 (FUN_007D8620, sub_7D8620,
         * msvc8::vector<moho::ClutterSurfaceElement>::insert for the 16-byte
         * element with `count` folded to 1) -- `Moho::Clutter::Surface::
         * mSeeds` (`Clutter.h`). Max_size guard against 0xFFFFFFF
         * (`0xFFFFFFFF/16`, throw lane `FUN_007D88B0`); fast path
         * (`capacity > size`): tail-shift branch moves the current last
         * element into the new slot via the count=1 `uninit_move_n`
         * specialization `FUN_007D95C0`, shifts the remaining tail right one
         * slot via `FUN_007D9620` (cited below), then assigns the gap via
         * the count=1 assign-fill specialization `FUN_007D95F0`; at-end
         * branch (no tail) constructs directly through the `FUN_007D7F00`/
         * `FUN_007D9970` adapter pair (cited above on `uninit_fill_n`).
         * Reallocation path: checked-allocate via `FUN_007D9660`
         * (`gpg/core/containers/CheckedArrayAllocationLanes.cpp`, already
         * recovered as this instantiation's `allocate_slots_checked`),
         * head-copy and tail-copy through the general range form
         * `FUN_007D9B40` (`uninit_move_n`, called twice -- head then tail;
         * pre-existing citation in `moho/sim/SimRecoveryRuntime.cpp` as
         * `CopyClutterSeedRangeRuntime` uses a generic `ClutterSeedRuntime`
         * reach-in lane rather than the typed element -- flagged as
         * existing RULE ONE debt, not collapsed in this pass), gap-fill via
         * `FUN_007D9970`, old-buffer teardown via `FUN_007D8600`
         * (`msvc8::vector<moho::ClutterSurfaceElement>::destroy_range`,
         * cited below -- called 3x: once on the success path destroying the
         * old buffer's live range immediately before `operator delete`,
         * twice more in the head/tail copy-construction exception-cleanup
         * funclets destroying the partially-constructed new buffer before
         * rethrowing; formerly modeled as a standalone free function in
         * `moho/containers/LegacyContainerFillLanes.cpp` with no
         * source-level caller anywhere in `src/sdk/**` -- collapsed into
         * this template's own generic `destroy_range<T>`, which already
         * resolves to `ClutterSurfaceElement`'s own destructor). Reached
         * from `AppendSurfaceSeed`'s (`Clutter.cpp`)
         * `mSeeds.insert(mSeeds.end(), seed)` call on the capacity-exhausted
         * path. DB-integrity fix: was fake-recovered (batch r14, zero real
         * src/sdk citation).
         *
         * Address: 0x007D9620 (FUN_007D9620, sub_7D9620) -- the non-
         * trivially-copyable tail-shift-by-one-slot loop this member's fast
         * path takes when a live tail follows the insertion point:
         * `for (i=tail-1; i>0; --i) insertAt[i] = std::move(insertAt[i-1]);`
         * per-field copy (vtable/selectionWeight/uniformScale/meshBlueprint)
         * since `ClutterSurfaceElement` has no move-aware type to dispatch
         * to. DB-integrity fix: was blocked (owner_layout) citing a stale
         * `CLobby.cpp` lead from earlier research that does not match this
         * function's real body at all -- this and `FUN_007D8620` are
         * `Moho::Clutter::Surface`'s seed vector, not lobby/networking code.
         *
         * Address: 0x005C7B10 (FUN_005C7B10, msvc8::vector<Moho::
         * CAiReconDBImpl::SNewBlip>::insert for the 12-byte element with
         * `count` folded to 1) -- `CAiReconDBImpl.cpp`'s `pending` staging
         * vector. Max_size guard against 357913941 (`0xFFFFFFFF/12`, throw
         * lane `FUN_005C7DA0`); fast path: tail-shift branch moves the
         * current last element via the count=1 `uninit_move_n` adapter
         * `FUN_005CA0A0` (cited below), shifts the remaining tail right one
         * slot via the backward per-element loop `FUN_005CA0F0`, then
         * assigns the gap via `FUN_005CA0D0`; at-end branch (no tail)
         * constructs directly through the already-cited `FUN_005C6190`/
         * `FUN_005CBC70` `uninit_fill_n` adapter pair. Reallocation path:
         * checked-allocate via `FUN_005CA120` (`allocate_slots_checked`),
         * head-copy and tail-copy through the general range form
         * `FUN_005CE090` (`uninit_move_n`, called twice -- head then tail --
         * also the target `FUN_005CA0A0`'s adapter forwards into for its
         * count=1 case), gap-fill via the already-cited `FUN_005CBC70`.
         * Reached from `insert(pos,value)`'s (`FUN_005C60A0`, cited above)
         * capacity-exhausted forward, which is itself reached from
         * `AppendPendingNewBlip`'s (`FUN_005C4CA0`, already recovered,
         * `CAiReconDBImpl.cpp`) `pending.push_back(SNewBlip{...})` on its
         * own capacity-exhausted branch. DB-integrity fix: was left `wip`
         * pending this element-type identification (its own note already
         * confirmed the 12-byte/max_size shape); real caller and sibling
         * `uninit_fill_n` emissions were independently recovered by another
         * pass on `AppendPendingNewBlip` -- this closes the loop.
         *
         * Address: 0x005CA0A0 (FUN_005CA0A0, single-element uninit_move_n
         * adapter) -- register-shuffling thunk that forwards into this
         * instantiation's general range form `FUN_005CE090` as
         * `uninit_move_n(dest, src, src+1)` (count=1, expressed as a
         * one-element range rather than a count parameter). Reached from
         * `insert`'s (`FUN_005C7B10`) fast-path tail-shift branch to move
         * the current last element into the newly-opened slot beyond the
         * old end. DB-integrity fix: was blocked citing a stale `CLobby.cpp`
         * lead -- real home is `CAiReconDBImpl.cpp`'s `SNewBlip` vector.
         *
         * Address: 0x0074F3E0 (FUN_0074F3E0, `msvc8::vector<moho::
         * SExtraUnitData>::insert` core for the 0x20-byte element, `count`
         * folded to 1 -- `Moho::Sim::mSyncSerializeGroup2`). Reached
         * directly from `Sim::AdvanceBeat` (`FUN_00749F40`, already
         * recovered) and from this instantiation's own `push_back`
         * (`FUN_0074C160`, cited above). Reallocation branch calls
         * `allocate_slots_checked` (`FUN_00751C40`, cited below) and
         * `throw_too_long` (`FUN_0074F680`, cited below on that member) for
         * the `max_size() - cur < count` guard; in-place branch's
         * tail-shift-assign sub-step (element is not trivially copyable --
         * `pairs` is `gpg::core::FastVectorN<SExtraUnitDataPair,1>`, so the
         * compiler kept the reverse per-element assign loop out of line
         * rather than inlining a memmove) is `FUN_00755A00`/`FUN_00751C10`/
         * `FUN_00753E70` (three call-shape variants of the same backward
         * `std::_Copy_backward`-style assign loop this method's `tail >=
         * count` branch performs); the gap-fill-assign sub-step (`insertAt[i]
         * = localValue` loop) is `FUN_00751BF0`. Migrated off
         * `gpg/core/containers/FastVectorInsertLanes.cpp`'s
         * `InsertInlineQwordVectorWithTagSlowPath`/
         * `CopyAssignInlineQwordVectorWithTagRangeBackward`/
         * `FillAssignInlineQwordVectorWithTagRange` -- a RULE ONE
         * hand-rolled `msvc8::vector<T>` reimplementation, see `push_back`
         * above for the full evidence chain.
         *
         * Address: 0x0077B990 (FUN_0077B990, `msvc8::vector<Moho::
         * SDecalInfo>::insert` core for the 0x90-byte element, `count`
         * folded to 1 -- `Moho::CDecalBuffer::mVisibleDecals`,
         * `CDecalBuffer.h`) -- `.asm`-confirmed (IDA's decompiler mis-tags
         * this function `__noreturn`; it has a normal `retn 8` epilogue,
         * the same decompiler failure already seen and worked around on
         * this element's `insert(pos,value)` wrapper below and its
         * `push_back` root, both cited here). Max_size guard against
         * 0x1C71C71B (`0xFFFFFFFF/144`, throw lane `sub_74EEA0`).
         * Reallocation path (the only one exercised by this element's real
         * caller, below): growth is 1.5x floored at `cur+count` via
         * `sub_77ACA0` (already recovered, `CDecalTypes.cpp`,
         * `msvc8::vector<SDecalInfo>::size()`-shaped used-count helper),
         * checked-allocate via `sub_751A50` (already recovered,
         * `Vector.cpp`, this element's `allocate_slots_checked`
         * instantiation), head-copy and tail-copy through the general
         * range form `sub_77F560` (already recovered/cited below on
         * `uninit_copy_n`, called twice -- head then tail), gap-fill
         * (`count`=1) via `sub_77E720` (`uninit_fill_n`, cited below),
         * old-buffer teardown via `sub_742090` (`destroy_range`, cited
         * above, called once on the success path immediately before
         * `operator delete`, twice more in the head/tail
         * copy-construction exception-cleanup funclets via the
         * `sub_741420` thiscall adapter -- also cited above -- destroying
         * the partially-constructed new buffer before rethrowing). In-place
         * branch (unreached by this element's only known caller, since
         * `push_back`'s slow path only calls `insert` once capacity is
         * already exhausted, but still real, compiled, address-bearing
         * code): tail-shift via `sub_77DA50` (`uninit_move_n` adapter,
         * cited below) then gap-fill via `sub_77AD30` (`uninit_fill_n`
         * adapter, cited below). Reached from `insert(pos,value)`'s
         * (`sub_77ACC0`, cited above on that overload) tail-call, itself
         * reached from `push_back`'s (`sub_77A0A0`, cited above)
         * capacity-exhausted branch -- `Moho::CDecalBuffer::CleanupTick`'s
         * (0x00779710, already recovered) `AppendVisibleDecal(mVisibleDecals,
         * handle->mInfo)` -> `visibleDecals.push_back(decalInfo)`.
         * DB-integrity fix: was `blocked` ("stale codex-main in_progress
         * claim cleanup") citing three dependencies that were themselves
         * either already recovered (`sub_741420`, `sub_742090`) or
         * similarly mis-tagged (`sub_77AD30` was `blocked` citing this
         * very function as its own unresolved dependency -- a cycle;
         * `sub_77DA50` was already correctly `recovered` in this file;
         * `sub_77E720` was already correctly `recovered` but uncited --
         * all four corrected in this same pass.)
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
         *
         * Address: 0x006DEB80 (FUN_006DEB80,
         * msvc8::vector<Moho::EntityCategorySet>::destroy_range -- for this
         * element the destructor's whole job is releasing the bit-word
         * fastvector, so the body rebinds each lane's words back to inline
         * storage, freeing the heap block where one is active.)
         * Address: 0x006DC5E0 (FUN_006DC5E0, register-shape adapter for FUN_006DEB80)
         * Address: 0x0085A1D0 (FUN_0085A1D0 — 0x10-byte element, the
         * formation-preview ghost pair; walks the span forward calling the
         * pair's destructor, FUN_00859E90, on each slot)
         * Address: 0x00884260 (FUN_00884260, msvc8::vector<Moho::
         * SSavedGameArmyInfo>::destroy_range -- 28-byte element,
         * SSavedGameArmyInfo's entire content is one msvc8::string
         * (mPlayerName), so the loop is exactly `~msvc8::string()`'s SSO
         * capacity-check-then-free shape at stride 28. Reached implicitly
         * from `SSavedGameHeader::~SSavedGameHeader()`'s compiler-generated
         * `mArmyInfo` member teardown, SSavedGameHeader.cpp.)
         * Address: 0x007BD8F0 (FUN_007BD8F0, msvc8::vector<Moho::
         * SNetCommandArg>::destroy_range -- 36-byte element, forward `~T()`
         * sweep releasing each element's `mStr` payload; `SNetCommandArg`'s
         * explicit destructor is what makes this generic loop non-trivial for
         * that element, matching the binary. Used by `_Tidy`
         * (`vector<T>::tidy()`, FUN_007BB840) and by `clear()`.)
         * Address: 0x007BBD40 (FUN_007BBD40, register-shape thiscall adapter
         * for FUN_007BD8F0, taking `(rangeEnd, rangeBegin)` in swapped
         * argument order.)
         * Address: 0x007FBBA0 (FUN_007FBBA0, msvc8::vector<moho::
         * WRenViewportWorldViewParamRuntime>::destroy_range -- the same
         * 20-byte `{IRenderWorldView* view; int head; int depth;
         * boost::shared_ptr<TerrainCommon> terrain}` element as this
         * method's `uninit_move_n` sibling FUN_007FC2F0 below (stride 0x14
         * confirmed). Per slot, `terrain`'s destructor releases the control
         * block at `+0x10` through `sp_counted_base::release()` (interlocked
         * decrement of `use_count` at `pi+4`, vtable `dispose()` dispatch
         * when it hits zero, then the same pattern on `weak_count` at `pi+8`
         * with `destroy()` -- the exact release() shape documented in
         * BoostWrappers.h, address 0x004229B0); `view`/`head`/`depth` are
         * trivially destructible and need no per-slot work. `view` and
         * `terrain.px` are not released here -- only the control block, since
         * `view` is a non-owning raw pointer and `terrain.px` needs no
         * separate teardown once its control block is dropped. Reached from
         * six recovered `WRenViewport` call sites in WxRuntimeTypes.cpp (the
         * ctor 0x007F66A0, dtor 0x007F6900, `RenderPreviewImage` 0x007F7400,
         * the `CD3DDevice::Paint`-reached override 0x007F7B30,
         * `RemoveWorldView` 0x007FA090, and `InsertWorldViewParamAt`
         * 0x007FB060's capacity-full erase/clear path) -- not edited here,
         * WxRuntimeTypes.cpp is under active concurrent edit this pass.)
         * Address: 0x008A9F10 (FUN_008A9F10, msvc8::vector<Moho::
         * TerrainEnvironmentLookupPair>::destroy_range -- 56-byte element
         * (`std::pair<msvc8::string, msvc8::string>`); the forward sweep
         * inlines both strings' SSO capacity-check-then-free teardown per
         * slot (capacity>=0x10 -> `operator delete` the heap buffer) instead
         * of calling a named pair destructor, matching `std::pair`'s
         * memberwise-destroy semantics. Used by `erase(first, last)`
         * (`EraseTerrainEnvironmentLookupPairRange`, CWldMap.cpp) after the
         * `std::copy` shift cited above on `0x008A9DC0`, to tear down the
         * vacated tail.)
         * Address: 0x008FA890 (FUN_008FA890, msvc8::vector<gpg::gal::
         * AdapterD3D10>::destroy_range for the 0x13C-byte polymorphic
         * element -- a vtbl-slot-0 virtual dtor loop, `flag=0` (destroy in
         * place, no `operator delete` per element since the buffer itself
         * is freed by the caller). Reached from the `_Insert_n` grow lane
         * FUN_00900630, cited above on `insert`, which destroys the old
         * range after relocating into the reallocated buffer.)
         * Address: 0x008EA5F0 (FUN_008EA5F0, msvc8::vector<gpg::gal::
         * AdapterModeD3D9>::destroy_range for the 16-byte polymorphic
         * element (`gpg::gal::AdapterModeD3D9` -- confirmed via its own
         * vtable symbol referenced in the caller) -- the same vtbl-slot-0
         * virtual dtor loop shape as the `AdapterD3D10` entry above,
         * `flag=0`. Reached from the `_Insert_n` grow lane FUN_00940D40
         * (cited above on `insert`, `PushBackAdapterModeD3D9`
         * modes.push_back, D3D9Interfaces.cpp:3258), which destroys the old
         * range after relocating into the reallocated buffer.)
         * Address: 0x00857630 (FUN_00857630, `msvc8::vector<boost::
         * shared_ptr<moho::MeshInstance>>::destroy_range` for the 8-byte
         * shared_ptr `(px, pn)` pair element -- forward `[first,last)` walk
         * releasing each slot's `pn` (the `sp_counted_base::release()`
         * chain already documented at 0x004229B0), no `operator delete`
         * per slot since the buffer itself is freed separately by the
         * caller. Reached from `_Insert_n` FUN_00855DF0 (cited above on
         * `insert`), `mMeshes`'s reallocation branch, to tear down the old
         * buffer's live range after relocating into the new one.)
         * Address: 0x008EA5C0 (FUN_008EA5C0, sub_8EA5C0) -- `msvc8::
         * vector<gpg::gal::AdapterD3D9>::destroy_range` for the 112-byte
         * polymorphic element (`AdapterD3D9` has a real vtable and virtual
         * destructor, `Scalar-deleting wrapper: 0x008F0040`, already cited
         * in `AdapterD3D9.hpp`) -- the same vtbl-slot-0 virtual-dtor loop
         * shape as the sibling `AdapterModeD3D9`/`AdapterModeD3D10` entries
         * above (`FUN_00857630`/`FUN_008EA5F0`), `flag=0`. IDA types the
         * loop variable as a triple-indirected function-pointer, so its
         * decompiled `+= 28` is 28 POINTER units (112 bytes), matching this
         * element's real size, not a 28-byte stride. Reached 3x from
         * `insert(pos,count,value)`'s emission for this instantiation
         * (`FUN_008F1890`, cited below), all in the reallocation path's
         * cleanup of the old buffer after relocating into the new one --
         * the `.c` decompile for `FUN_008F1890` doesn't show these calls at
         * all (its own "bad/positive sp value" disclaimer), only the raw
         * `.asm` does; confirmed against that directly.)
         * Address: 0x007D8600 (FUN_007D8600, `msvc8::vector<moho::
         * ClutterSurfaceElement>::destroy_range` for the 16-byte element --
         * the same vtbl-slot-0 dispatch loop shape as the sibling
         * `AdapterModeD3D9` entry above, `flag=0`, but through
         * `ClutterSurfaceElement`'s own hand-rolled `ClutterSurfaceElementVTable`
         * (a raw one-slot function-pointer struct, not a real C++ `virtual`)
         * rather than a compiler-generated vtable -- see `DestroyInPlace()`
         * (`Clutter.h`), which documents this exact `vtable->destroy(this, 0)`
         * dispatch and already cites three other inlined call sites of the
         * same one-element operation; `ClutterSurfaceElement`'s explicit
         * destructor (declared exactly to be that same `DestroyInPlace()`
         * body) is what routes this generic `destroy_range<T>` instantiation
         * through it. Reached from `insert`'s (`FUN_007D8620`, cited above)
         * reallocation branch, called 3x: once destroying the old buffer's
         * live range immediately before `operator delete` frees it
         * (0x007D87A7), twice more in the head/tail copy-construction
         * exception-cleanup funclets (0x007D87EC, 0x007D885C), destroying
         * the partially-constructed new buffer before rethrowing.
         * `Moho::Clutter::Surface::mSeeds`'s reallocation teardown step.
         * Formerly modeled as a standalone free function in
         * `moho/containers/LegacyContainerFillLanes.cpp`
         * (`DestroyVirtualRange16`, over a raw `VirtualDtor16RuntimeView`)
         * with no source-level caller anywhere in `src/sdk/**` -- collapsed
         * into this template instantiation, RULE ONE.)
         * Address: 0x0088A3E0 (FUN_0088A3E0, `msvc8::vector<Moho::
         * WaveParameters>::destroy_range` for the 136-byte (`0x88`)
         * polymorphic element -- the same vtbl-slot-0 virtual-dtor loop
         * shape as the sibling `AdapterD3D10`/`AdapterModeD3D9`/`AdapterD3D9`
         * entries above, `flag=0`, dispatching through `WaveParameters`'s
         * own single-slot vtable (its real, compiler-generated `virtual
         * ~WaveParameters()`, vtable-slot-0 scalar deleting destructor
         * FUN_00886D80, already cited in `WaveSystem.h`; independently
         * confirmed via RTTI -- `dumps/rtti_dump_all.hpp`'s
         * `Moho::WaveParameters` vftable has exactly one slot,
         * `sub_886D80`). Reached from `_Insert_n`'s (`FUN_0088A400`, cited
         * above on `insert`) reallocation branch, called 3x: once
         * destroying the old buffer's live range immediately before
         * `operator delete` frees it (0x0088A5A5), twice more in the
         * head/tail copy-construction exception-cleanup funclets
         * (0x0088A5E2, 0x0088A687), destroying the partially-constructed new
         * buffer before rethrowing -- the same "bad/positive sp value"
         * decompiler failure as the sibling `AdapterD3D9`/`FUN_008F1890`
         * entry above hides all three calls from `FUN_0088A400`'s own `.c`
         * decompile; only the raw `.asm` shows them.
         * `WavePattern::mWaves`'s reallocation teardown step. Formerly
         * modeled as a standalone free function in
         * `moho/containers/LegacyContainerFillLanes.cpp`
         * (`DestroyVirtualRange136`, over a raw `VirtualDtor136RuntimeView`)
         * with no source-level caller anywhere in `src/sdk/**` -- collapsed
         * into this template instantiation, RULE ONE.)
         * Address: 0x005CC280 (FUN_005CC280, `msvc8::vector<Moho::
         * SCreateUnitParams>::destroy_range` for the 28-byte (`0x1C`)
         * element -- `SCreateUnitParams : SCreateEntityParams`
         * (`SimDriver.h`): base `SCreateEntityParams`'s 3 dwords
         * (`mEntityId`/`mBlueprint`/`mTickCreated`) are trivially
         * destructible and produce no code; the loop body reduces to
         * exactly `mConstDat.mStatsRoot` (`boost::shared_ptr<Stats<
         * StatItem>>`, `SCreateUnitConstantData` +0x04, i.e. this element
         * +0x10)'s `~shared_ptr()` -- interlocked-decrement `use_count_` at
         * control+4, vtable-slot-1 `dispose()` when it hits zero, then the
         * same pattern on `weak_count_` at control+8 with vtable-slot-2
         * `destroy()`, the same `sp_counted_base::release()` shape
         * documented at `0x004229B0` (`BoostWrappers.h`) -- a distinct
         * per-callsite emission at this address. `mConstDat.mBuildStateTag`
         * (element +0x0C) and `mConstDat.mFake` (element +0x18) are trivial
         * bytes either side of the control-block pointer (element +0x14)
         * and need no teardown. This is the same 0x1C-byte "WeakPtr-shaped
         * element" this file's `insert(pos, count, value)`/`uninit_copy_n`/
         * `copy_or_move_assign` members previously carried as unidentified
         * (`FUN_005C6580`/`FUN_005CDEF0`/`FUN_005CD100`, cited above/below)
         * -- resolved by this address's own real callers. `Moho::
         * SSyncData::~SSyncData()` (0x0073FC70, `SimDriver.cpp`, already
         * recovered) calls this address directly on `mNewUnits`'s live
         * range (decompiled with named fields: `a1->mNewUnits._Myfirst`/
         * `_Mylast` at `SSyncData+0x13C`/`+0x140`, i.e. the vector head
         * `msvc8::vector<SCreateUnitParams> mNewUnits` at `SSyncData+0x138`,
         * `SimDriver.h`) before freeing the buffer -- once on the normal
         * path (0x007400F3) and once more from an SEH-unwind funclet
         * reached only if an earlier member's teardown throws
         * (0x007403D0, `loc_7403C0`; the dispatch trampoline at 0x00BA42B0
         * computes `esi = this+0x138` -- exactly `mNewUnits` -- before
         * jumping there, and the funclet reads the begin/end pair at
         * `esi+4`/`esi+8`, matching `msvc8::vector<T>`'s own `_Myfirst`/
         * `_Mylast` slots -- compiler-generated exception-safety glue, not
         * a distinct source line). The other 3 confirmed call sites are
         * `insert(pos,count,value)`'s (`FUN_005C6580`, cited above) own
         * reallocation branch -- this method's `destroy_n`/`destroy_range`
         * old- and partial-buffer teardown calls above, all inlined at this
         * address -- reached from `mNewUnits.push_back(params)`
         * (`QueueCreateUnitParams`, `SimDriver.cpp`, already recovered) on
         * its capacity-exhausted path. A further 3 raw call sites
         * (0x005C85C9, 0x005CA1C9, 0x00740BD0) sit in address ranges IDA
         * does not attribute to any function (no `.meta.json`/owner; each
         * immediately follows an unrelated tiny leaf, e.g. the `max_size`
         * constant-return body at 0x005C85B0) -- not independently cited
         * here pending that attribution. Formerly modeled as a standalone
         * `Stride28SharedOwnerElementRuntimeView`/
         * `ReleaseSharedOwnerRangeStride28` pair in
         * `moho/containers/LegacyContainerFillLanes.cpp` with no
         * source-level caller anywhere in `src/sdk/**` -- collapsed into
         * this template instantiation, RULE ONE.)
         *
         * Address: 0x00742170 (FUN_00742170, `msvc8::vector<moho::
         * SExtraUnitData>::destroy_range` for the 0x20-byte element,
         * `Sim::mSyncSerializeGroup2`) -- `.c`-confirmed: loops `[first,
         * last)` on a 32-byte stride, and for each element whose `pairs`
         * sub-vector has left its inline slot (`elem.pairs.start_ !=
         * elem.pairs.originalVec_`) frees the heap block and restores the
         * saved inline-capacity header, otherwise just rebases `end_` --
         * the exact `gpg::core::ResetStorageToInline<SExtraUnitDataPair,1>`
         * shape (cited on that free function in `FastVector.h`) inlined
         * per-element rather than called out to a separate symbol. Reached
         * from `operator=` (`FUN_007530C0`, cited below) on its
         * capacity-reused and full-reallocation paths.
         *
         * Address: 0x00742090 (FUN_00742090, `msvc8::vector<Moho::
         * SDecalInfo>::destroy_range` for the 0x90-byte element) --
         * `.c`-confirmed: loops `[first,last)` resetting the trailing
         * `mType` string (freeing its heap buffer when `myRes >= 0x10`)
         * then tearing down `mTexName1`/`mTexName2` via `.tidy(true,0)`,
         * per element -- the same behavior `SDecalInfo::~SDecalInfo()`
         * (0x00742360, already recovered, `CDecalTypes.h`) documents, with
         * that destructor's body inlined into the range loop rather than
         * called out per-element (the standard MSVC `_Destroy_range`
         * codegen choice for a simple, non-virtual, non-throwing
         * destructor). `.xrefs.txt`-confirmed 10 real callers, all
         * accounted for as of this pass:
         *   - 0x0073FF4B, 0x007404E0: `Moho::SSyncData::~SSyncData`
         *     (normal-path and EH-unwind-funclet copies of the same
         *     `mAddDecals` teardown; `SSyncData::mAddDecals` is `msvc8::
         *     vector<SDecalInfo>`, `SimDriver.h`, so this is that member's
         *     own automatic destructor reaching this instantiation).
         *   - 0x007792FF (owner 0x00779270, `Moho::CDecalBuffer::
         *     ~CDecalBuffer`, already recovered, `CDecalBuffer.cpp`): same
         *     shape -- `mVisibleDecals` (`msvc8::vector<SDecalInfo>`,
         *     `CDecalBuffer.h` +0x0CCC) is declared before
         *     `mPendingHideObjectIds` and destroyed automatically by the
         *     compiler-generated member teardown; no explicit call needed
         *     in the recovered destructor body.
         *   - 0x0077BB44 (owner 0x0077B990, `insert(const_iterator,
         *     std::size_t, const T&)` below, this element's instantiation):
         *     destroys the old `[first_,last_)` run immediately before
         *     `operator delete`-ing the old buffer on the reallocation
         *     path, cited in full on that method's own entry below.
         *   - 0x00740D60 (owner 0x00740D50,
         *     `DestroySDecalInfoRangeOwnerRuntime`, already recovered,
         *     `moho/sim/SimRecoveryRuntime.cpp`): a
         *     `RangeOwnerRuntime<SDecalInfo>`-shaped reset-and-free helper.
         *     `.xrefs.txt`/`_callgraph_index.sqlite` show its only caller is
         *     `sub_77E040`'s SEH-unwind funclet (0x0077E0E3) -- and
         *     `sub_77E040` (0x0077E040) itself has zero callers anywhere:
         *     empty in the callgraph index, zero direct `call`/`jmp rel32`
         *     hits across the whole `.text` section (scan validated by
         *     confirming it finds all 10 real callers of this member
         *     exactly), and zero occurrences of its address as a raw
         *     `DWORD` anywhere in the PE image (rules out a vtable slot or
         *     a function-pointer table entry too). Already `skip`-tagged
         *     ("prior pass already exhaustively byte-verified ZERO
         *     references of any kind") before this pass; independently
         *     re-verified here with the same method. `DestroySDecalInfoRangeOwnerRuntime`
         *     is therefore reachable from this instantiation but not
         *     (currently) from any live binary caller -- pre-existing
         *     state, left as-is rather than inventing a caller for it.
         *   - 0x0074142A (owner 0x00741420, thiscall-convention adapter for
         *     this same body -- `ecx`=last, one stack arg=first, reordered
         *     into this member's `a1@<eax>`=first/`a2`=last calling
         *     convention): reached from `operator=`'s (0x0077E100, cited
         *     below) reallocation branch as its old-buffer `_Tidy`-shaped
         *     teardown step, and again from this element's own `insert`
         *     (0x0077B990 below) on two EH-unwind cleanup funclets that
         *     destroy a partially-filled new buffer before rethrowing.
         *     Formerly modeled as an orphaned `[[maybe_unused]]`
         *     `DestroySDecalInfoRangeThiscallAdapter` free function in
         *     `moho/render/CDecalTypes.cpp` with no source-level caller
         *     anywhere in `src/sdk/**` -- the same "mis-cited standalone
         *     body" bug already fixed once in this file for this exact
         *     element's `uninit_copy_n` adapter (`FUN_0077DA50`, cited
         *     below: "previously mis-cited as having its canonical body in
         *     CDecalTypes.cpp") -- collapsed into this citation, RULE ONE.
         *   - 0x00741B1A (owner `<none>` per IDA): a real, coherent
         *     18-byte thunk at 0x00741B10-0x00741B22 (`push ecx; mov
         *     eax,[esp]; push eax; mov eax,[esp+0Ch]; push ecx; call
         *     sub_742090; add esp,0Ch; ret`, 16-byte-aligned between two
         *     other IDA-unattributed sibling thunks at 0x00741AF0 and
         *     0x00741B30) that marshals `(ecx=last, stack-arg=first)` into
         *     this member's `(eax=first, stack-arg=last)` convention --
         *     not misclassified padding (real `int3` filler brackets it on
         *     both sides at the expected 16-byte alignment boundaries).
         *     Exhaustively searched for a caller: empty in
         *     `_callgraph_index.sqlite` (`incoming_xrefs`/`data_refs`/
         *     `call_edges` all empty for 0x00741B00-0x00741B30), zero
         *     direct `call`/`jmp rel32` hits across the whole `.text`
         *     section (same scan, validated against this member's own 10
         *     known callers, which it finds exactly), and zero occurrences
         *     of 0x00741B10 as a raw `DWORD` anywhere in the complete PE
         *     image (rules out a vtable slot, a jump table, or a
         *     function-pointer table entry). Not given a source-level home
         *     in `src/sdk/**` pending real caller evidence -- recorded
         *     here rather than guessed at.
         *   - 0x0077E17B (owner 0x0077E100, `operator=(const vector&)`,
         *     cited below, this element's instantiation): the
         *     "source is longer but fits in capacity" branch's
         *     excess-tail teardown -- `sub_77E8E0`
         *     (`CopyAssignSDecalInfoRangeForward`, `CDecalTypes.cpp`)
         *     assign-copies over the retained prefix and returns one past
         *     the last assigned slot, and this call destroys `[thatSlot,
         *     oldLast)`, the remainder left over when the source is
         *     shorter than the previous destination length.
         *   - 0x0077E2F1 (owner 0x0077E2D0, `clear()`, cited above this
         *     member): destroys the live `[first_,last_)` run before
         *     rebasing `last_` to `first_`.
         *   - 0x0077E32B (owner 0x0077E300): a real, coherent
         *     15-instruction function (`.c`-confirmed: `if (a3 != a4) {
         *     v4 = sub_77E8E0(a3); sub_742090(v4, *(a1+8)); *(a1+8) = v4;
         *     } *a2 = a3; return a2;` -- another assign/erase-shaped
         *     forwarding lane for this element) with the same
         *     "zero callers anywhere" profile as `sub_77E040` above: empty
         *     in the callgraph index, zero direct call/jmp hits in
         *     `.text`, zero raw-`DWORD` occurrences anywhere in the PE
         *     image. Was mis-tagged `external_dependency` ("all-external
         *     callees") despite calling this engine-internal member and
         *     `sub_77E8E0` (also engine, `CDecalTypes.cpp`) -- corrected to
         *     `skip` (real engine code, but genuinely unreferenced, same
         *     bucket as `sub_77E040` above) as part of this pass.
         * Formerly modeled as a standalone
         * `DestroyLegacyDecalInfoRangeForSyncPayload` free function in
         * `moho/sim/SimDriver.cpp` (its only source-level caller was a
         * hand-written `SSyncData::~SSyncData()` teardown walk that has
         * since been replaced by real owning `msvc8::vector<T>`/smart-
         * pointer members and their own automatic destructors) --
         * collapsed into this template instantiation, RULE ONE.
         *
         * Address: 0x00741F70 (FUN_00741F70, this member instantiated for
         * `T = msvc8::vector<msvc8::string>` -- a 0x10-byte element that is
         * itself a `msvc8::vector<msvc8::string>`) -- walks `[first,last)`
         * and for each inner vector: destroys its live strings through
         * `destroy_range<msvc8::string>` (`FUN_0040D540`, cited immediately
         * below) then frees the inner buffer -- i.e. each element's own
         * `~vector()` inlined into the outer range loop rather than called
         * out per-element, the same "standard MSVC `_Destroy_range` codegen
         * choice for a simple, non-virtual, non-throwing destructor"
         * already documented on the `SDecalInfo` entry above. Two real call
         * sites, both from `Moho::CSimDriver::DrawNetworkStats`
         * (`SimDriver.cpp`, already recovered): once for the 8-slot
         * `columns` table (`msvc8::vector<msvc8::vector<msvc8::string>>
         * columns(kNumColumns)`) and once for the single-element range
         * destroying `summary` (`msvc8::vector<msvc8::string> summary`) at
         * scope exit. Formerly modeled as a standalone
         * `LegacyStringVectorSlot` reach-in struct plus
         * `DestroyLegacyStringVectorRange`/`DestroyLegacyStringPayloadRange`
         * free functions in `moho/sim/SimDriver.cpp`, with
         * `DrawNetworkStats` itself built on real `std::vector<std::
         * vector<msvc8::string>>` locals instead of the binary-matching
         * `msvc8::vector` type, so neither address had a live source-level
         * invocation -- collapsed into this template instantiation and
         * `DrawNetworkStats`'s `columns`/`summary` locals retyped to
         * `msvc8::vector`, RULE ONE.
         * Address: 0x0040D540 (FUN_0040D540, `func_DestroyStringsRange`,
         * this member instantiated for `T = msvc8::string`) -- the single
         * most widely reused instantiation of this template in the whole
         * binary (85 distinct callers per `_callgraph_index.sqlite`); tears
         * down each string via the same `.tidy(true,0)`-equivalent teardown
         * as every other `msvc8::string` range-destroy already documented
         * in this file (e.g. the `SDecalInfo::mTexName1`/`mTexName2` entry
         * above). Not independently audited caller-by-caller this pass; two
         * concrete, already-recovered examples directly relevant here are
         * `DrawNetworkStats` above (destroying each inner `msvc8::string`
         * of `columns`/`summary`) and `Moho::SSyncData::~SSyncData`
         * (`SimDriver.cpp`, calls `FUN_0040D540` directly per
         * `_callgraph_index.sqlite` -- its own `mPrintField`
         * (`msvc8::vector<msvc8::string>`) member teardown, `SSyncData`'s
         * only vector-of-string field). A byte-distinct sibling emission,
         * `FUN_0040D5B0` (same IDA-inferred name), is already cited
         * independently in `REntityBlueprintTypeInfo.cpp`/
         * `LaunchInfoBase.cpp`.
         */
    public:
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

    private:
        /**
         * Address: 0x0084C250 (FUN_0084C250, sub_84C250) -- a plain, no-refcount
         * 12-byte-element `uninit_copy_n` (3-dword-stride copy loop, no
         * `_InterlockedExchangeAdd`/refcount bump, unlike the
         * `SPendingPoseCopy` specialization below -- a trivially-copyable
         * POD element, not a `shared_ptr`-holding one). Owning `T` identified
         * 2026-08-25: `CCommandLuaFunctionRegistrations.cpp`'s local
         * `DockCandidate` struct (`{UserUnit* platform; float distSq;
         * std::int32_t freeCapacity;}`, exactly 12 bytes, declared inside
         * `cfunc_IssueDockCommandL`'s anonymous namespace) -- this is the
         * SAME `std::vector<DockCandidate>` whose `std::sort`/`std::rotate`
         * internals were cited on `front()` and elsewhere this session
         * (`FUN_0084A890`/`FUN_0084B3F0`/`FUN_0084B0F0`/`FUN_0084C330`, all
         * `external_dependency`, MSVC8 STL-internal). Reached via
         * `FUN_0084B8B0` (`sub_84B8B0`, a thin 2-arg calling-convention
         * adapter that zeroes a truncated flag byte before tail-calling this
         * body) from `sub_849250`, a `vector<T>::insert`-growth emission
         * whose allocator (`FUN_0084A560`) is `gpg::core::legacy::
         * AllocateChecked12ByteLane` (`CheckedArrayAllocationLanes.h`).
         * `FUN_0084B8B0` was previously mis-cited in `CWorldParticles.cpp`
         * as a `TrailRuntimeView` (80+-byte, ref-counted-texture-pointer)
         * range-copy bridge -- disproven by this body's real shape (plain
         * 3-dword copy, no texture/refcount handling at all) and corrected
         * there; `CWorldParticles.cpp`'s real `TrailRuntimeView` copy bridge
         * is `FUN_004A0310` alone, cited on the same member.
         *
         * `FUN_00849250` (`push_back`'s capacity-exceeded growth path,
         * 1.5x geometric growth floored to `size()+1`, max_size guard
         * `0xFFFFFFFF/12`, allocate via `FUN_0084A560`, uninit-copy the head
         * via two direct calls to this member, in-place-construct the new
         * value via `FUN_0084AF60`) is itself reached from the
         * position-preserving wrapper `FUN_00848CB0` (converts insert
         * position to an index before the call, since reallocation moves
         * the buffer), reached in turn from the `push_back` capacity
         * dispatcher `FUN_00848820` (in-place fast path calling
         * `FUN_0084AF60` directly vs. `_Insert_n`-growth slow path), reached
         * from `cfunc_IssueDockCommandL` (`FUN_00840A70`, already recovered,
         * `CCommandLuaFunctionRegistrations.cpp`) as
         * `candidates.push_back(DockCandidate{platform, distSq,
         * freeCapacity})` and `nearbyPlatforms.push_back(candidate)` -- the
         * same two `std::vector<DockCandidate>` locals the sort/rotate
         * citations above already trace back to this exact function.
         * `FUN_0084A4E0` is the in-place (capacity-available) fast path's
         * own thin `uninit_fill_n`-shaped single-value construct call
         * (`sub_84A4E0(dst, dst+12)` bracketing one already-placed value),
         * distinct from `FUN_0084B8B0`'s role in the growth path above but
         * calling this same `uninit_copy_n` body.)
         *
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
         * Address: 0x0077F560 (FUN_0077F560, the shared canonical body that
         * both FUN_0077E7B0's and FUN_0077E910's adapters tail-call into --
         * the actual 62-instruction range-copy-construct-with-rollback-on-throw
         * loop for this specialization. Also reached, through the same shape-
         * adapter pattern, from FUN_0077DA50, FUN_0077F310, and FUN_0077F3D0,
         * and directly from FUN_0077B990)
         * Address: 0x0077DA50 (FUN_0077DA50, fastcall-shape adapter for
         * FUN_0077F560 -- a linker-emitted calling-convention trampoline
         * previously mis-cited as having its canonical body in
         * CDecalTypes.cpp; the real canonical body is FUN_0077F560, above)
         * Address: 0x0077F310 (FUN_0077F310, register-shape adapter for FUN_0077F560)
         * Address: 0x0077F3D0 (FUN_0077F3D0, register-shape adapter for FUN_0077F560)
         * Address: 0x0077F4C0 (FUN_0077F4C0, a second, independently-emitted
         * `uninit_copy_n` body for this same specialization -- the same
         * range-copy/rollback-on-throw shape as FUN_0077F560, under a
         * slightly different local-frame layout and parameter-passing
         * convention. Reached through its own pair of shape adapters,
         * FUN_0077E8B0 and FUN_0077F370)
         * Address: 0x0077E8B0 (FUN_0077E8B0, fastcall-shape adapter for FUN_0077F4C0)
         * Address: 0x0077F370 (FUN_0077F370, register-shape adapter for FUN_0077F4C0)
         * Address: 0x00563430 (FUN_00563430,
         * msvc8::vector<Moho::SUnitVariableUpdateEntry>::uninit_copy_n -- the
         * range form, with the destroy-what-was-built rollback on throw)
         * Address: 0x00562B70 (FUN_00562B70, register-shape adapter for FUN_00563430)
         * Address: 0x00563070 (FUN_00563070, register-shape adapter for FUN_00563430)
         * Address: 0x00563250 (FUN_00563250, register-shape adapter for FUN_00563430)
         * Address: 0x00562680 (FUN_00562680, register-shape adapter for FUN_00563430)
         * Address: 0x005CBB20 (FUN_005CBB20, the counted form of the same)
         * Address: 0x005C9AD0 (FUN_005C9AD0, register-shape adapter for FUN_005CBB20)
         * Address: 0x005CDF60 (FUN_005CDF60, a second, independently-emitted
         * `uninit_copy_n` body for this same specialization -- byte-for-byte
         * the same range-copy/rollback-on-throw shape as FUN_00563430 (per-slot
         * copy through the nested `SSTIUnitVariableData` copy ctor at
         * `sub_560680`, plus the trailing dword at record+0x230), just under a
         * different parameter-passing convention. Called directly, twice, from
         * `_Insert_n`'s reallocation path (FUN_005C68E0) to copy the pre-gap
         * head range into the freshly allocated buffer)
         * Address: 0x005C9DD0 (FUN_005C9DD0, thin forwarder to FUN_005CDF60 --
         * also called directly from FUN_005C68E0, for the post-gap tail range)
         * Address: 0x005CD1C0 (FUN_005CD1C0, compiler-emitted EH cleanup
         * funclet: `call FUN_005CDF60(a1,a2)` then falls into the unwind
         * continuation. Zero code/data xrefs in the IDA export -- funclets are
         * entered through the `__CxxFrameHandler3` unwind table, not a `call`
         * instruction, matching FUN_005C68E0's own EH state variable (`v25` in
         * its decompile) around this same reallocation region. No source line
         * produced this; it is the compiler's own lowering of the `try`/`catch`
         * inside `uninit_copy_n` above, for this call site)
         * Address: 0x005CBDB0 (FUN_005CBDB0, sibling EH cleanup funclet of
         * FUN_005CD1C0 -- identical shape, zero xrefs, same mechanism)
         * Address: 0x005CDA00 (FUN_005CDA00, sibling EH cleanup funclet of
         * FUN_005CD1C0 -- identical shape, zero xrefs, same mechanism)
         * Address: 0x005CDAE0 (FUN_005CDAE0, msvc8::vector<Moho::SPerArmyReconInfo>::
         * uninit_copy_n for the 52-byte element -- the `_Insert_n` reallocation
         * path's head/tail range copies, FUN_005C6F90. `FUN_005CC4E0` is the
         * same thin calling-convention bridge shape documented on
         * `DumpUnitsCountEntry`'s uninit_copy_n above -- zeroes the low byte
         * of its `this`-shaped third argument and forwards `(a3, this,
         * this)` on to `sub_5CDAE0`.)
         * Address: 0x005C9EC0 (FUN_005C9EC0, the same specialisation emitted a
         * second time for FUN_005C6F90's in-place-insert branch, where it
         * copy-constructs the relocated tail past the old `mLast`)
         *
         * `FUN_005CDAB0` (sub_5CDAB0) is a *third*, byte-distinct (not
         * sha256-identical, so not a strict ICF twin) but structurally and
         * behaviorally identical non-folded emission of this exact
         * specialisation: `if (dst) sub_5C84D0(dst, src); dst += 0x34;
         * src += 0x34;` per element, `.asm`-confirmed (`add esi,34h` /
         * `add edi,34h` at 0x005CDACE/0x005CDAD1), calling the same
         * per-element copy ctor `FUN_005C84D0` (`Moho::SPerArmyReconInfo::
         * SPerArmyReconInfo`, cited on this template's ctor above). Its
         * only three code xrefs (`_callgraph_index.sqlite`
         * `incoming_xrefs`, cross-checked against `data_refs` and
         * `vtable_writers` -- all empty for all three) are `FUN_005CC4B0`
         * and `FUN_005CD370`, thin "hardcode one bool arg false, forward
         * the rest" calling-convention bridges with zero callers of their
         * own, and `FUN_005CA8D0` -- which, fully decoded from its own
         * `.asm` since Hex-Rays' decompile of it drops an argument (the
         * allocation call's real arguments), is itself a genuine, distinct
         * engine function: `msvc8::vector<Moho::SPerArmyReconInfo>::
         * vector(const vector& other)`, this template's own copy
         * constructor -- `allocate_slots_checked` (`FUN_005C5530`, which
         * internally calls the already-cited allocator `FUN_005C9F40` and
         * throw lane `FUN_005C7290`) for exactly `other.size()` slots,
         * matching this ctor's `if (n) { reserve(n); ...}` body below,
         * then `uninit_copy_n` via `FUN_005CDAB0`. `FUN_005CA8D0` has the
         * same zero-xrefs profile (`incoming_xrefs`/`data_refs`/
         * `vtable_writers` all empty, absent from the seeded-root
         * `reachable` closure) -- `ReconBlip::mReconDat` is this
         * specialisation's only instantiating field in the whole binary
         * and it is never value-copied (`ReconBlip` has no copy
         * constructor; `IAiReconDB`/`CAiReconDBImpl` have no `Clone`-style
         * virtual either), so this copy constructor is real,
         * correctly-typed, compiler-emitted code the shipped build
         * apparently never calls at runtime. This is the same situation
         * already documented on `FUN_008F7020`/`FUN_008F7110` above (on
         * `vector(const vector&)`): a structurally-confirmed instantiation
         * with an exhaustively-searched-empty caller set. Matching that
         * precedent, `FUN_005CDAB0`/`FUN_005CD370`/`FUN_005CA8D0` are
         * `skip`-classified (not `recovered` -- the source-level-
         * invocation rule has no caller to wire to; not `blocked` -- RULE
         * TWO) rather than forcing a citation neither (1)-(4) of the
         * callsite-verification rule supports. `FUN_005CA8D0`'s DB entry
         * pre-dated this pass as `external_dependency`/"no engine
         * references", which was wrong for the reason CLAUDE.md's "Engine
         * code is not external" rule describes; corrected to `skip` here,
         * this note being the accurate record of what it actually is.
         *
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
         * Address: 0x00868FD0 (FUN_00868FD0, `msvc8::vector<
         * Moho::WeakEntitySetUserEntity>::uninit_copy_n` for the 12-byte
         * selection-priority bucket element -- copy-constructs the live
         * range into the freshly grown buffer via the element's own copy
         * constructor (`sub_822210`, `WeakEntitySetUserEntity`'s copy ctor
         * in WeakEntitySet.h), with the same construct/rollback-on-throw
         * shape as `uninit_fill_n`'s sibling emission for this type
         * (`sub_868E50` destroys the constructed prefix on a mid-loop
         * throw). Reached from the `insert`/`_Insert_n` core FUN_00868040's
         * reallocation branch (cited above on `insert`), which copies the
         * live range through this before filling the new tail with
         * FUN_00868DB0.)
         * Address: 0x006E0400 (FUN_006E0400,
         * msvc8::vector<Moho::EntityCategorySet>::uninit_copy_n for the
         * 0x28-byte element -- copy-constructs each `BVSet`, writing the
         * universe handle and the bit-set first-word index, rebinding the
         * embedded `fastvector_n<unsigned int, 2>` to its inline storage and
         * copying the source words through `gpg::fastvector_uint::cpy`
         * (0x004028E0). On a partial range it tears the in-flight slots down
         * and rethrows, which is the strong guarantee this member already
         * provides.)
         * Address: 0x008D9FA0 (FUN_008D9FA0, msvc8::vector<gpg::REnumType::
         * ROptionValue>::uninit_copy_n for the 8-byte trivially-copyable
         * `{int mValue; const char* mName}` element -- a range-form
         * dword-pair copy loop (`[first,last) -> dst`, `+= 2` stride,
         * returns the advanced `dst`). Reached from the `_Insert_n` grow
         * lane FUN_008DCB70 (cited above on `insert`), which relocates the
         * existing option slots into the reallocated buffer for
         * `gpg::AppendEnumOptionValue`'s `options.insert(options.end(), 1,
         * value)` on the capacity-full path)
         * Address: 0x00832B80 (FUN_00832B80, `msvc8::vector<void*>::
         * uninit_copy_n` for a 4-byte pointer element on
         * `Moho::UICommandGraph`'s hash-bucket vector(s) -- `cmp ecx,edx /
         * jz done / test eax,eax / jz skip-store / mov esi,[ecx] / mov
         * [eax],esi / add ecx,4 / add eax,4 / loop`, i.e. `[first@ecx,
         * last@edx) -> dst@eax`, one dword per iteration, `dst` advanced
         * even when null. The `test eax,eax` null-tolerance is the same
         * defensive-null shape already noted on FUN_00549BC0 above; it never
         * observably fires from a real `_Insert_n` call (count > 0 implies a
         * non-null freshly-allocated or in-place destination). Reached from
         * the `_Insert_n` grow lane FUN_0082DE90 (cited below on `insert`)
         * both directly (head/tail range copies on the reallocation path)
         * and through four calling-convention adapters that reshuffle a
         * stack-passed `(first, last)` pair plus a passed-through `edx`
         * `dst` into this body's `eax`/`edx`/`ecx` form:
         *   - 0x00831640, 0x008323F0, 0x00832850 -- byte-identical register-
         *     shape adapters (differing only in their own return-cleanup:
         *     `retn 8` for the first, plain `retn` for the other two),
         *     reached from `_Insert_n`'s in-place tail-shift branch with an
         *     empty source range (`first == last`) at the shift's boundary.
         *   - 0x00832AB0 -- a `__thiscall`-shaped register/stack-shape
         *     adapter with the same dead-code register-save-then-discard
         *     preamble as the other three, called with all three logical
         *     arguments collapsed to the same value (degenerate empty-range
         *     no-op call).
         * All four adapters are unreachable except through `_Insert_n`'s
         * degenerate-range branches, so they carry no independent behaviour
         * beyond forwarding into this body.)
         * Address: 0x00831640 (FUN_00831640, first of the four adapters described above)
         * Address: 0x008323F0 (FUN_008323F0, second of the four adapters described above)
         * Address: 0x00832850 (FUN_00832850, third of the four adapters described above)
         * Address: 0x00832AB0 (FUN_00832AB0, fourth of the four adapters described above)
         *
         * Address: 0x00658490 (FUN_00658490, `uninit_copy_n` for a 4-byte
         * element that is a single refcounted-handle slot (`refCountBlockPtr`
         * only, no paired raw pointer): per slot, the block pointer is copied
         * verbatim from `[src]` to `[dst]` and, when non-null, its refcount
         * word at `blockPtr+4` is atomically incremented (`lock xadd`) --
         * the same `boost::shared_ptr`/`weak_ptr` control-block bump seen on
         * the 8-byte and 16-byte instantiations elsewhere in this method,
         * but for a bare single-pointer handle array rather than a full
         * `{rawPtr, block}` pair. Reached via WinMain (depth 18); sole caller
         * FUN_00658090 is not recovered source yet, matching this method's
         * established practice of citing algorithm-shape-confirmed
         * instantiations ahead of their caller (cf. FUN_0085AB80 below, none
         * of whose five candidate callers are recovered either). Owning
         * element type and class not yet identified.)
         * Address: 0x0085AB80 (FUN_0085AB80, `uninit_copy_n` for a 16-byte
         * element containing two independent shared/weak-pointer-style
         * handles (`{rawPtr, refCountBlockPtr}` pairs at +0x00 and +0x08):
         * per slot, both handle pairs are copied verbatim, and whichever
         * `refCountBlockPtr` is non-null gets its refcount word (at
         * `blockPtr+4`) atomically incremented (`lock xadd`), matching
         * `boost::shared_ptr`/`weak_ptr`'s copy-construct semantics without
         * calling a named copy-ctor per element. Reached via
         * `Moho::CUIWorldView`'s vtable; owning element type not yet fully
         * identified. Of the five candidate callers (0x0085A2D0,
         * 0x0085A7E0, 0x0085A970, 0x0085AAB0, 0x0085AB60), 0x0085A7E0 is
         * now confirmed: `FUN_0085A7E0` is a thin calling-convention
         * adapter (`LOBYTE(this)=0; return sub_85AB80(a3,this);`,
         * matching this file's `FUN_007CBF90`-style adapter pattern),
         * called from `FUN_0085A2D0` (this instantiation's `_Insert_n`-
         * shaped orchestrator: max_size check against `0x0FFFFFFF ==
         * 0xFFFFFFFF/16 - 1`, two call sites -- the grow-in-place
         * tail-shift path and the insert-at-end path). `FUN_0085A2D0`
         * itself is real but not yet independently recovered (honestly
         * `blocked` pending a dedicated evidence pass, not contamination);
         * the other four candidates remain unconfirmed.)
         *
         * Address: 0x007CED40 (FUN_007CED40, `msvc8::vector<Moho::
         * CDiscoveryService::DiscoveredGameRecord, false>::uninit_copy_n`
         * for the element -- a plain 16-byte POD (protocol/address/port/
         * padding/reply-timestamp, no pointers), matching
         * `Moho::CDiscoveryService.h`'s own
         * `static_assert(sizeof(DiscoveredGameRecord) == 0x10)`. Verbatim
         * 4-dword-per-slot copy, no refcount/special handling. `mGames` is
         * the `HasDebugProxy=false` instantiation (see `vector`'s class doc
         * above) -- its ctor/dtor/EH-funclet evidence shows no reserved
         * proxy slot, a genuine 12-byte narrower shape than this template's
         * 16-byte default. Reached from `AddDiscoveredGame`'s (0x007C87E0,
         * `CDiscoveryService.cpp`) growth-reallocation path -- which is
         * this method's own `insert(last_, value)` slow path, since
         * `AddDiscoveredGame`'s entire real body is `mGames.push_back(newRecord)`
         * -- via its thin calling-convention adapter `FUN_007CBF90`
         * (truncates a flag byte before tail-calling this body).
         * `FUN_007C9CD0`, the sibling `_Insert`-shaped emission for the
         * same 16-byte element, is already `skip` (RULE ONE compiler/
         * template emission, its source-level call site is
         * `AddDiscoveredGame` itself, i.e. this method's `insert` call).
         *
         * Address: 0x005CDEF0 (FUN_005CDEF0, `uninit_copy_n` for `Moho::
         * SCreateUnitParams`'s 0x1C-byte element, `SimDriver.h`) --
         * containing a leading 3-dword header (`SCreateEntityParams`'s
         * `mEntityId`/`mBlueprint`/`mTickCreated`), a 1-byte tag at +0x0C
         * (`mConstDat.mBuildStateTag`), a raw pointer at +0x10
         * (`mConstDat.mStatsRoot.px`), and a `boost::shared_ptr<Stats<
         * StatItem>>`-style `{rawPtr@+0x10, refCountBlockPtr@+0x14}` handle
         * pair whose block pointer is atomically refcount-bumped
         * (`lock xadd [block+4], 1`) when non-null, followed by a trailing
         * byte at +0x18 (`mConstDat.mFake`): per slot, the three header
         * dwords, the tag byte, both handle-pair words and the trailing
         * byte are all copied verbatim; the `test eax,eax` dst-null guard
         * wraps only the copy body (same defensive-null shape as
         * FUN_00549BC0/FUN_00832B80 above) while all four cursors still
         * advance by the 0x1C stride every iteration. Owning element type
         * identified via this instantiation's `destroy_range` sibling
         * (`FUN_005CC280`, cited on that member below): its real caller,
         * `SSyncData::~SSyncData()` (`SimDriver.cpp`, already recovered),
         * decompiles with named fields directly onto `mNewUnits`
         * (`msvc8::vector<SCreateUnitParams>`, `SimDriver.h`), and this
         * element's layout matches `SCreateUnitParams` field-for-field
         * (base `SCreateEntityParams` header, `mConstDat.mBuildStateTag`/
         * `mStatsRoot`/`mFake` at the exact tag/pointer-pair/trailing-byte
         * offsets above). One of the five candidate callers is
         * `0x005C6580`, this instantiation's own `insert(pos, count,
         * value)` (cited below on that member) -- confirmed by
         * field-for-field match of its local-copy staging against this
         * element's exact layout. The other four are all thin
         * calling-convention bridges: `0x005C9D60`/`0x005CBCA0`/
         * `0x005CD0E0`/`0x005CD9E0` each tail-call straight into this
         * member (`sub_5CDEF0`) with register/stack argument reshuffling
         * and nothing else -- e.g. `sub_5CBCA0(edx@a1, a2, a3) { return
         * sub_5CDEF0(a3, a2, a1); }`. `0x005C9DA0` is the one exception: it
         * bridges to a DIFFERENT address, `FUN_005CD100` (this element's
         * `copy_or_move_assign` emission, cited there, not this plain-copy
         * one) -- `insert(pos, count, value)`'s `FUN_005C6580` above calls
         * both this member and `copy_or_move_assign` for different parts
         * of its shift/fill logic, and each has its own bridge.)
         *
         * Address: 0x00832BC0 (FUN_00832BC0, `msvc8::vector<void*>::
         * uninit_copy_n` for a 4-byte pointer element -- `[first@ecx,
         * last@edx) -> dst@eax`, same shape as `FUN_00832B80` above, a
         * distinct instantiation for `Moho::UICommandGraph`'s "MapC"
         * hash-bucket vector. Reached from the `_Insert_n` grow lane
         * `FUN_0082F210` (`msvc8::vector<void*>::_Insert_n` for `MapC`), and
         * from `assign(9, sentinel)`'s insert step (`FUN_0082F680`, the
         * MapC `assign` emission cited above) via the thin calling-
         * convention bridge `FUN_00831860` -- `LOBYTE(this)=0; return
         * sub_832BC0(a3, this);`, same adapter shape as the bridges cited
         * elsewhere in this file.)
         * Address: 0x006829B0 (FUN_006829B0, `msvc8::vector<moho::Entity*>::
         * uninit_copy_n` for the 4-byte pointer element -- `[first,last) ->
         * dst`, stack-passed range form. Reached from `moho::
         * LoadEntityPointerVector`'s `reserve(count)` path (`FUN_0067D9B0`,
         * already recovered above), which uninit-copies the live range into
         * the freshly reallocated buffer.)
         * Address: 0x005E2160 (FUN_005E2160, `msvc8::vector<
         * Moho::CAcquireTargetTask*>::uninit_copy_n` for the 4-byte pointer
         * element -- byte-identical shape to FUN_006829B0 above, a separate
         * instantiation. Reached from `gpg::RVectorType_CAcquireTargetTask_P::
         * SerLoad`'s `reserve(count)` path (`FUN_005DD400`, already recovered
         * above).)
         * Address: 0x00642F30 (FUN_00642F30, `gpg::RVectorType_bool`'s
         * backing `msvc8::vector<uint32_t>::uninit_copy_n` for the 4-byte
         * word element -- same shape again. Reached from `gpg::
         * RVectorType_bool::reserve_word_capacity` (`FUN_006421C0`, already
         * recovered, `ManipulatorStartupRegistrations.cpp`).)
         * Address: 0x00720220 (FUN_00720220, `msvc8::vector<
         * moho::SPositionThreat>::uninit_copy_n` for the 0x10-byte
         * (4-float) element -- `[first@edx,last@ecx) -> dst@eax`, per-slot
         * 4-dword copy. Reached from the `_Insert_n` grow lane
         * `FUN_0071BEE0` (already recovered above), which relocates the
         * live range into the reallocated buffer for
         * `InfluenceGrid::mThreats` (CInfluenceMap.cpp).)
         * Address: 0x00760810 (FUN_00760810, `msvc8::vector<
         * Moho::Sim::DumpUnitsCountEntry>::uninit_copy_n` for the 8-byte
         * `{const RUnitBlueprint* blueprint; int count}` element --
         * `[first@edx,last@ecx) -> dst@eax`, per-slot dword-pair copy.
         * Reached from the `_Insert_n` grow lane `FUN_0075F810` (already
         * recovered above), `Sim::DumpUnits`'s `counts.push_back({blueprint,
         * 1})` capacity-full path. `FUN_0075FCF0` is a thin calling-
         * convention bridge in front of this same address -- zeroes the
         * low byte of its `this`-shaped third argument and forwards
         * `(a3, this, this)` on to `sub_760810`, adapting `FUN_0075F810`'s
         * call-site register layout to this member's `[edx,ecx)->eax`
         * convention; same logical operation, no separate behavior.)
         * Address: 0x0076B6B0 (FUN_0076B6B0, `msvc8::vector<gpg::
         * AStarOpenHeap<TCell>::Entry>::uninit_copy_n` for the 12-byte
         * `{float mPriority; node_type* mNode; std::int32_t mHandle;}`
         * element (`gpg/core/algorithms/AStarSearch.h`) -- `[first@edx,
         * last@ecx) -> dst@eax`, per-slot 3-dword copy. Reached from the
         * `_Insert_n`/push_back grow core `FUN_00769F60` (already recovered
         * above, on `push_back`), `AStarOpenHeap::Push`'s
         * `mEntries.push_back(entry)` capacity-full path. `FUN_0076AA80` is
         * the same thin calling-convention bridge shape as `FUN_0075FCF0`
         * above -- zeroes the low byte of its `this`-shaped third argument
         * and forwards `(a3, this, this)` on to `sub_76B6B0`.)
         * Address: 0x006DFFF0 (FUN_006DFFF0, `msvc8::vector<Moho::
         * EntityCategorySet>::uninit_copy_n` for the 40-byte element --
         * per-slot copies the two raw dwords at `+0x00`/`+0x08`, then
         * re-establishes the embedded `gpg::fastvector_uint`'s inline-SBO
         * self-pointers at `+0x10..+0x1C` before deep-copying its bitset
         * payload via the already-cited `gpg::fastvector_uint::cpy`
         * (`FUN_004028E0`, `FastVector.h`) -- exactly `EntityCategorySet`'s
         * own copy-construct shape, not a raw memberwise copy. Reached
         * from this instantiation's copy constructor (`FUN_006DE100`,
         * cited above on `vector(const vector&)`), `CPlatoon::
         * FindPrioritizedUnit`'s `priorityList = squad->mCats`.)
         * Address: 0x008F6470 (FUN_008F6470, `msvc8::vector<DXGI_MODE_DESC>::
         * uninit_copy_n` for the 0x1C-byte (28, `DXGI_MODE_DESC`) POD element
         * -- `[first@a1,last@a2) -> dst@a3`, per-slot `qmemcpy(dst, first,
         * 0x1C)`, returns the advanced `dst` cursor. No placement-new/destroy
         * pass since the element is trivially copyable -- this is exactly the
         * shape the `is_trivially_copyable_v<T>` branch above collapses to a
         * single `memcpy` call for; the original binary loops per-element
         * instead (period-accurate VC8 STL: `_Uninit_copy` had no bulk-memmove
         * fast path for scalar/POD ranges), same divergence already accepted
         * for e.g. `FUN_00720220` above. Two calling-convention bridges
         * forward here with no logic of their own: `FUN_008F65F0` (`__cdecl`,
         * `return sub_8F6470(a1,a2,a3);`) and `FUN_008F6690` (`__stdcall`,
         * same tail call) -- neither needs its own citation. Byte-identical
         * (`function_sha256`) to `FUN_008F64D0`, the ICF-twin instantiation
         * reached from this specialization's own `operator=`
         * (`FUN_008F6DD0`, cited above on `operator=`) for its two
         * grow-branch uninitialized-copy steps (the capacity-fits
         * excess-tail fill, and the reallocate-and-copy-everything path);
         * that twin is already recovered as `CopyForward28ByteLaneSourceFirst`
         * in `gpg/core/containers/FastVectorInsertLanes.cpp`. Reached from
         * this instantiation's copy constructor (`FUN_008F6D20`, cited above
         * on `vector(const vector&)`), `AdapterD3D10::AdapterD3D10(const
         * AdapterD3D10&)`'s `modes_(other.modes_)` member-init
         * (D3D10Interfaces.cpp) deep-copying `AdapterModeD3D10::modes_`.)
         * Address: 0x008F7390 (FUN_008F7390, `msvc8::vector<AdapterModeD3D10>::
         * uninit_copy_n` for the 0x74-byte (116) non-trivial
         * `AdapterModeD3D10` element -- matches this member's non-trivial
         * branch shape exactly: loop constructing one `AdapterModeD3D10` per
         * slot (`qmemcpy` of the POD `format_`/`output_`/`outputDesc_`
         * prefix plus a nested `sub_8F6D20` copy-construct of the
         * `modes_` sub-object at `+0x64`), with an SEH catch funclet that
         * destroys the already-constructed `[dst,dst+i)` prefix via
         * `FUN_008F7360` (already `skip`-tagged: "MSVC-emitted member-vector
         * storage release", the same `begin->modes_ =
         * decltype(begin->modes_){}` operation `DestroyAdapterModeRuntimeRange`
         * -- cited on `FUN_008F7550` -- performs per element, just compiled
         * as a standalone per-call address here) and rethrows via
         * `_CxxThrowException`; Hex-Rays renders the try-body loop and the
         * disjoint catch funclet as one linear `__noreturn` listing since
         * the SEH catch handler is laid out immediately after its guarded
         * try region with no explicit branch between them -- the loop's
         * normal-completion path (all elements copied, no throw) falls
         * through to an ordinary return that the misapplied `__noreturn` tag
         * suppresses from the decompile, not an unconditional
         * destroy-then-rethrow. Reached directly from `FUN_008F7770` above
         * (both the growth branch's pre-insertion-point relocate and, via
         * the thiscall calling-convention bridge `FUN_008F7700` -- `sub_8F7390(a2,
         * a3, a4, this);`, no logic of its own -- the post-insertion-point
         * tail relocate and the in-place tail-smaller-than-gap branch); also
         * reached through four further thin calling-convention bridges with
         * no logic of their own -- `FUN_008F7590` (`__cdecl`), `FUN_008F7610`
         * (`__cdecl`), `FUN_008F7690` (`__cdecl`), and `FUN_008FF020`
         * (`__thiscall`) -- from sibling `msvc8::vector<AdapterModeD3D10>`
         * methods (`reserve`/`resize`/`assign`-family grow paths) not yet
         * individually recovered; none of the five bridges need a separate
         * citation. DB previously listed this token `skip` ("Compiler-
         * generated VC8 uninitialized range-copy/EH cleanup helper... no
         * standalone SDK body") -- directionally correct (this is exactly
         * the shape this template member already generalizes) but the wrong
         * terminal status: the sibling instantiation `FUN_0071A1F0`
         * (`msvc8::vector<SPositionThreat>::uninit_copy_n`, cited elsewhere
         * in this member) sets the precedent of `recovered` with its own
         * `Address:` line for this exact class of token; corrected to
         * `recovered` here for consistency.
         * Address: 0x008FE940 (FUN_008FE940, a second, separately-compiled
         * COMDAT instantiation of the same `msvc8::vector<AdapterModeD3D10>::
         * uninit_copy_n` body as `FUN_008F7390` above -- byte-for-byte the
         * same algorithm (construct-with-rollback loop, `sub_8F6D20` for the
         * `modes_` sub-object) but not an ICF twin
         * (`function_sha256` differs: its rollback destroy call is
         * `FUN_008F6970` at a `+116`-byte-stride cursor instead of
         * `FUN_008F7360` at a `+29`-dword-stride one -- same operation,
         * different codegen). Reached directly from `FUN_008FF220` above
         * (`vector(const vector&)`'s whole-range uninitialized copy into the
         * freshly-allocated buffer -- unambiguous copy-construct semantics,
         * `other` is left untouched) and through two thin calling-convention
         * bridges with no logic of their own -- `FUN_008FEFD0` (`__cdecl`)
         * and `FUN_008FF050` (`__stdcall`) -- from sibling
         * `msvc8::vector<AdapterModeD3D10>` methods not yet individually
         * recovered; neither bridge needs a separate citation. `FUN_008F6970`
         * (its rollback destroy callee) DB previously listed
         * `external_dependency` ("all-external-callees thunk... no Moho/gpg
         * engine references") -- wrong for the same reason `FUN_008F6D20`
         * was: it is the `AdapterModeD3D10`-element-typed sibling of
         * `FUN_008F7360` (already correctly `skip`-tagged), not third-party
         * runtime; corrected to `skip` here with a matching note. DB
         * previously listed `FUN_008FE940` itself `external_dependency` for
         * the same wrong reason; corrected to `recovered` here.
         *
         * Address: 0x00832BE0 (FUN_00832BE0, `msvc8::vector<UICommandGraph::
         * HashListNode2C*>::uninit_copy_n` for the 4-byte pointer element --
         * `for (; a3 != a2; ++result) { if (result) *result = *a3; ++a3; }`,
         * a per-element pointer-assignment loop that is byte-for-byte
         * equivalent to this member's `memcpy(dst, src, n*4)` trivially-
         * copyable path (same `HashListNode2C*` instantiation `resize`
         * above already cites via its `_Insert_n` lane FUN_0082F7A0, `skip`'d
         * as a RULE ONE compiler/template emission). Reached from
         * `_Insert_n`'s reallocation copy-the-old-range step for this
         * instantiation (`FUN_0082F7A0`) and, via a thin calling-convention
         * bridge with no logic of its own, from sibling `HashListNode2C*`
         * emissions not yet individually recovered.
         * Address: 0x00831910 (FUN_00831910, the calling-convention bridge
         * described immediately above -- `int __thiscall sub_831910(this,
         * a2, a3) { LOBYTE(this) = 0; return sub_832BE0(a3, this, this); }`,
         * pure register-shuffle into FUN_00832BE0 with no logic of its own.)
         *
         * Address: 0x005CE060 (FUN_005CE060, sub_5CE060) --
         * `msvc8::vector<Moho::ReconBlip*>::uninit_copy_n` for the 4-byte
         * pointer element (`Moho::CAiReconDBImpl::mBblips`/`mTempBlips`,
         * `CAiReconDBImpl.h`) -- `for (; a2 != a3; ++result) { if (result)
         * *result = *a2; ++a2; }`, byte-for-byte confirmed against the `.asm`,
         * the same per-element pointer-assignment loop family as
         * `FUN_00832BE0` above (the `if (result)` null guard is the same
         * defensive "compiler cannot prove the freshly-allocated destination
         * is non-null" pattern already documented on `uninit_move_n`'s
         * `FUN_007FC2F0` entry, not a real runtime branch). Reached from
         * `reserve`'s emission for this instantiation (`FUN_005C7680`, cited
         * above) as its live-range copy-into-the-new-buffer step. Has 24 ICF
         * twins (canonical `FUN_0054F6B0`); this address's own instantiation
         * identity is independently confirmed via its sole real caller
         * (`FUN_005C7680`) rather than inferred from the twin group -- of its
         * five raw code xrefs, four (`FUN_005C9FA0`/`FUN_005CBF80`/
         * `FUN_005CD2C0`/`FUN_005CDA50`) are themselves confirmed zero-caller
         * dead fragments (`call_edges` has no incoming edge for any of the
         * four), leaving `FUN_005C7680` as the only live path. Previously
         * mis-tracked `blocked` citing `CrtRuntimeHelpers.cpp` boilerplate
         * the address never appeared in.
         *
         * Address: 0x007574E0 (FUN_007574E0, sub_7574E0) --
         * `msvc8::vector<Moho::SimArmy*>::uninit_copy_n` for the 4-byte
         * pointer element -- `for (; a2 != a3; ++result) { if (result)
         * *result = *a2; ++a2; }`, the same per-element pointer-assignment
         * loop family as `FUN_005CE060`/`FUN_00832BE0` above, has 24 ICF
         * twins. Reached from `reserve(n)`'s emission for this
         * instantiation (`FUN_0074F720`, corrected below from a wrong
         * `external_dependency` tag -- reachability root is
         * `??_7?$RVectorType@PAVSimArmy@Moho@@@gpg@@6B@`): `if (a2 >
         * 0x3FFFFFFF) throw; ...grow via sub_704530/operator new...;
         * sub_7574E0(v8,v7)` to copy the old range into the new buffer,
         * matching this member's reallocation-copy role exactly.
         * `FUN_0074F720`'s own caller, `FUN_0074E240`, is already
         * `recovered` in `gpg/core/reflection/Reflection.cpp` as the
         * `RVectorType<Moho::SimArmy*>` foundation exemplar. Four trivial
         * calling-convention forwarders into this token (`FUN_00751C90`,
         * `FUN_00753EA0`, `FUN_00755A30`, `FUN_00756710`) exist but have no
         * discoverable callers of their own in the indexed binary; recorded
         * as such rather than guessed.
         * Address: 0x0074F720 (FUN_0074F720, sub_74F720) --
         * `msvc8::vector<Moho::SimArmy*>::reserve(std::size_t)` for the
         * same instantiation, described immediately above.
         *
         * Address: 0x008528E0 (FUN_008528E0, sub_8528E0) --
         * `msvc8::vector<Wm3::Vector3f>::uninit_copy_n` for the 12-byte
         * (3-float) element -- `for (; a3 != a2; result += 3) { if
         * (result) { copy 3 floats } a3 += 3; }`, the 12-byte-stride
         * sibling of this member's generic copy loop. Reached from
         * `_Insert_n`'s emission for this instantiation (`FUN_008523C0`,
         * already `skip`-tagged as a RULE ONE compiler/template emission,
         * resting on the already-recovered `allocate_triple_dword_slots_
         * checked`, `FUN_007E5650`). Four sibling thunks passing a
         * degenerate empty range (`FUN_008526D0`/`FUN_00852780`/
         * `FUN_00852830`/`FUN_00852880`) are already `skip`-tagged with
         * matching reasoning, except `FUN_00852830` which was still
         * sitting in stale fabricated-`blocked` state; corrected to `skip`
         * here alongside its three siblings for consistency.
         *
         * Address: 0x005444B0 (FUN_005444B0, sub_5444B0) --
         * `msvc8::vector<moho::ArmyLaunchInfo>::uninit_copy_n` calling-
         * convention bridge for the 0x20-byte (`BVIntSet`-embedding)
         * element: `sub_5444B0(a1,a2,a3,a4) { return sub_5454A0(a4,a2); }`
         * drops two dead register args and forwards `(dst, src)` into the
         * per-element body at 0x005454A0. `moho::ArmyLaunchInfo`
         * (moho/misc/LaunchInfoBase.h) declares only a default constructor,
         * so its copy constructor is compiler-synthesized -- memberwise over
         * the single `mUnitSources` (`moho::BVIntSet`) field -- and
         * `BVIntSet::BVIntSet(const BVIntSet&)` (moho/containers/
         * BVIntSet.cpp) already performs exactly the sequence the binary's
         * per-element body open-codes (`mFirstWordIndex` copy, then
         * `mWords.ResetFrom(other.mWords)`). Reached from
         * `moho::CopyAssignArmyLaunchInfoVector`'s grow lane
         * (moho/misc/LaunchInfoBase.cpp) via `destination = source;`, which
         * is this member's real source-level instantiation site for
         * `T = moho::ArmyLaunchInfo`.
         * Address: 0x005454A0 (FUN_005454A0, sub_5454A0) -- the per-element
         * body itself: placement-constructs each destination slot from the
         * matching source slot via `ArmyLaunchInfo`'s (compiler-synthesized)
         * copy constructor, with construct/destroy-on-throw rollback
         * matching this member's own generic `try`/`catch` shape above.
         * Address: 0x00544C60 / 0x00545090 / 0x00545580 (FUN_00544C60,
         * FUN_00545090, FUN_00545580) -- three more register/EH-shape
         * calling conventions into the same 0x005454A0 body, one per caller
         * site's register allocation.
         * Address: 0x005457A0 / 0x00545880 (FUN_005457A0, FUN_00545880) --
         * two more forwarding lanes into 0x005454A0.
         * Address: 0x00545200 / 0x005445E0 / 0x00544E60 / 0x00545550
         * (FUN_00545200, FUN_005445E0, FUN_00544E60, FUN_00545550) -- four
         * further register-shape thunks over the two lanes immediately
         * above, completing this specialization's calling-convention bridge
         * family (thirteen addresses in total, including 0x005444B0 and
         * 0x005454A0 above).
         * Address: 0x00545620 / 0x00545270 (FUN_00545620, FUN_00545270) --
         * a related single-element `BVIntSet` rebind-and-copy lane and its
         * thin adapter, same 0x20-byte element; behaviourally redundant
         * with `copy_or_move_assign`'s per-element `dst[i] = src[i]`
         * (`ArmyLaunchInfo::operator=`, compiler-synthesized ->
         * `BVIntSet::operator=`) for the same specialization. No
         * discoverable caller of its own in the indexed binary; recorded
         * as such rather than guessed.
         * This whole family previously lived in moho/misc/LaunchInfoBase.cpp
         * as thirteen hand-written per-type functions
         * (`CopyConstructArmyLaunchInfoRangeRollback` and its Adapter/Thunk/
         * RegisterAdapter siblings, plus `CopyArmyLaunchInfoUnitSources
         * RebindAndCopy`/Adapter) that manually reached into `BVIntSet`'s
         * fields instead of calling its own copy constructor/assignment
         * operator -- the exact RULE ONE per-type reach-in shape, and all
         * thirteen were `[[maybe_unused]]` orphans with zero real callers.
         * Collapsed into this citation; the hand-rolled bodies are removed.
         *
         * Address: 0x005CE020 (FUN_005CE020, msvc8::vector<Moho::
         * SPerArmyReconInfo>::uninit_copy_n for the 52-byte element) --
         * another separate compiled copy of this method for the same
         * instantiation, reached from `reserve`'s (`FUN_005C6D10`, cited
         * above) inlined growth path rather than `_Insert_n`'s (which
         * already cites its own pair, `FUN_005CDAE0`/`FUN_005C9EC0`, above).
         * Forward range-copy loop over `[src, srcEnd)` into `dst`, advancing
         * both by 52 bytes per element and copy-constructing each slot
         * through `FUN_005C84D0` (`SPerArmyReconInfo`'s copy ctor, cited
         * elsewhere in this file); returns the one-past-the-end dst pointer.
         * Matches this method's non-trivial-T loop exactly.
         *
         * Address: 0x00756A00 (FUN_00756A00, `msvc8::vector<moho::
         * SExtraUnitData>::uninit_copy_n` primary emission for the 0x20-byte
         * element, `Sim::mSyncSerializeGroup2`) -- range-form loop over
         * `[sourceBegin, sourceEnd)`, placement-new copy-constructing each
         * slot (default-init the `pairs` sub-vector to inline then assign
         * source's content, copy the `unitEntityId` tag word -- the shape a
         * compiler-generated `SExtraUnitData(const SExtraUnitData&)` member-
         * wise copy ctor produces for `FastVectorN<SExtraUnitDataPair,1>
         * pairs; EntId unitEntityId; int32 syncAuxWord1C;`, notably NOT
         * copying `syncAuxWord1C` -- consistent with `Unit.h`'s existing
         * note that field is "not written by `Sim::AdvanceBeat`"), with
         * destroy-on-exception rollback of the already-constructed prefix.
         * Reached from `vector(const vector&)` (`FUN_00753020`, cited
         * above).
         * Address: 0x007549A0 (FUN_007549A0, register-shape sibling of
         * `FUN_00756A00`, same body)
         * Address: 0x00755DB0 (FUN_00755DB0, second register-shape sibling
         * of `FUN_00756A00`, same body)
         * Address: 0x00756AB0 (FUN_00756AB0, thin wrapper that forwards
         * into `FUN_00756A00` unchanged -- reached from `insert`'s
         * (`FUN_0074F3E0`, cited above) in-place tail-shift branch to
         * construct-copy the trailing element past the old end, `count=1`)
         * Address: 0x00751BC0 (FUN_00751BC0, register-shape sibling of
         * `FUN_00756AB0`)
         * Address: 0x00753E00 (FUN_00753E00, second register-shape sibling
         * of `FUN_00756AB0`)
         * Address: 0x00754A00 (FUN_00754A00, third register-shape sibling of
         * `FUN_00756AB0`)
         * Address: 0x007559D0 (FUN_007559D0, fourth register-shape sibling
         * of `FUN_00756AB0`)
         * Address: 0x00755E10 (FUN_00755E10, fifth register-shape sibling of
         * `FUN_00756AB0`)
         * Address: 0x007506F0 (FUN_007506F0, single-element (`n=1`) T-copy-
         * construct adapter -- default-inits the destination's `pairs` to
         * inline then assigns source's `pairs` content, tag copied
         * separately by the caller. Reached from `insert`'s slow path
         * (`FUN_0074F3E0`, cited above) to construct the local "inserted
         * value" scratch copy.)
         * Address: 0x00755EF0 (FUN_00755EF0, sibling single-element
         * T-copy-construct adapter that additionally copies the
         * `unitEntityId` tag itself rather than leaving that to the caller
         * -- calls `FUN_007506F0` above then copies the tag word. Reached
         * from an adjacent, IDA-untokenized register-shape shim (a call
         * site in the `0x00754BC0` area with no `functions`-table entry of
         * its own); no further caller found beyond that shim.)
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
         * Address: 0x00653AD0 (FUN_00653AD0, msvc8::vector<moho::SDebugWorldText>::
         * uninit_fill_n for the 48-byte non-trivial element -- a count-driven loop
         * that copy-constructs `count` copies of the same source value into `dst`
         * (position/style/depth as raw field copies, `text` zeroed to empty SSO
         * state then `assign`ed), with a trailing EH cleanup loop that destroys the
         * already-constructed prefix and rethrows on a `catch(...)`. Reached via the
         * thin dispatcher FUN_00653330 from the `_Insert_n` grow lane FUN_00653380,
         * already cited above)
         * Address: 0x0075FEF0 (FUN_0075FEF0, msvc8::vector<Moho::Sim::
         * DumpUnitsCountEntry>::uninit_fill_n for the 8-byte trivially-copyable
         * element -- a count-driven dword-pair fill loop, reached from both
         * `Moho::Sim::DumpUnits` (0x0075EE50) and its `push_back` grow lane
         * (0x0075F1A0, cited on `push_back` above))
         * Address: 0x008DA380 (FUN_008DA380, msvc8::vector<gpg::REnumType::
         * ROptionValue>::uninit_fill_n for the 8-byte trivially-copyable
         * `{int mValue; const char* mName}` element -- the same count-driven
         * dword-pair fill loop, called with n=1 from `push_back`'s in-place
         * fast path FUN_008DF290 (cited on `AppendEnumOptionValue`,
         * Reflection.cpp) when the vector still has spare capacity)
         * Address: 0x007046F0 (FUN_007046F0,
         * msvc8::vector<SEntitySetTemplateUnit>::uninit_fill_n for the
         * 0x28-byte element -- a count-driven loop over `[dst, dstEnd)`
         * that, per slot, calls `gpg::fastvector_Entity::AddAll(slot.mVec,
         * value.mVec)` against the SAME fixed `value` source every
         * iteration (confirmed in the .asm: the source register is loaded
         * once before the loop and never advances) -- this type's own
         * "fill with N copies" idiom is a merge-into-an-already-constructed
         * slot rather than a placement-new copy ctor. Called twice from
         * `insert(pos, count, value)`'s `_Insert_n` core FUN_007030C0, once
         * per branch (in-place gap fill and reallocation gap fill), matching
         * this template's own two `uninit_fill_n` call sites exactly.)
         * Address: 0x00680940 (FUN_00680940, msvc8::vector<moho::SCreateEntityParams>::
         * uninit_fill_n for the 12-byte trivially-copyable element -- a count-driven
         * dword-triple fill loop, reached from QueueCreateEntityParams's
         * `mNewEntities.push_back(params)` in Entity.cpp via its push_back grow
         * lane FUN_0067B6F0)
         * Address: 0x0067C730 (FUN_0067C730, the advance-returning `_Ufill`
         * adapter around FUN_00680940 for the same `SCreateEntityParams`
         * instantiation: fills then returns `dst + count*0xC`. Called from
         * the capacity-full `_Insert_n` grow path FUN_0067D090, still open;
         * not needed to satisfy this instantiation's own caller evidence,
         * which is the `mNewEntities.push_back(params)` source line above)
         * Address: 0x008EA090 (FUN_008EA090, msvc8::vector<gpg::gal::HeadAdapterMode>::
         * uninit_fill_n for the 12-byte trivially-copyable element (width/height/
         * refreshRate dwords) -- the same count-driven dword-triple fill loop,
         * called with n=1 from push_back's in-place fast path FUN_008EFDD0 (cited
         * on `AppendHeadAdapterMode`, D3D9Interfaces.cpp) when the vector still has
         * spare capacity)
         * Address: 0x0076AAB0 (FUN_0076AAB0, msvc8::vector<gpg::AStarOpenHeap<TCell>::
         * Entry>::uninit_fill_n for the 12-byte `{float mPriority; AStarNode<TCell>*
         * mNode; std::int32_t mHandle}` element -- a dst/dstEnd-bounded dword-triple
         * fill loop (compares `result != dstEnd` each iteration instead of a
         * decrementing count -- the same n=1 semantics expressed in end-pointer
         * form) that writes the single inserted entry's fields into the vacated
         * gap. Called from the `insert(pos, 1, value)` core FUN_00769F60 (already
         * `recovered`, cited on `push_back` above) once its `copy_backward` sibling
         * FUN_0076AAD0 (cited below on `copy_or_move_assign`) has shifted the live
         * tail right by one slot. Source-level invocation: `mEntries.push_back(entry)`
         * in `gpg::AStarOpenHeap<TCell>::Push`, `AStarSearch.h`)
         * Address: 0x007B1830 (FUN_007B1830, msvc8::vector<moho::GeomCamera3>::
         * uninit_fill_n for the 0x2C8 (712)-byte non-trivial element -- an
         * SEH-framed count-driven loop that copy-constructs `count` copies of the
         * by-ref prototype via `func_CpyCamera` (the element's field-copy body,
         * recovered as `CopyGeomCameraStatePreservingFlags` in GeomCamera3.cpp),
         * advancing the destination cursor by `0x2C8` per slot; the exception
         * handler destroys the already-constructed prefix `[dst, cursor)` via
         * `Moho::GeomCamera3::~GeomCamera3` and rethrows the in-flight exception
         * (`CxxThrowException(0,0)`) -- `CGeomSolid3`'s heap-backed frustum-plane
         * storage inside the element means the per-slot copy genuinely can throw,
         * so this rollback is load-bearing, not defensive boilerplate. Reached
         * with n=1 from `push_back`'s in-place fast path at `Moho::GeomCamera3
         * *__cdecl` helper FUN_007AEB10 (recovered as
         * `AppendGeomCameraViewAndReturnEnd`, GeomCamera3.cpp) when the vector
         * still has spare capacity -- confirmed from `FUN_007AEB10.asm`, whose
         * fast-path block constructs the element then returns directly at
         * `0x007AEB8B`, never falling into the capacity-full `_Insert_n` growth
         * call at `0x007AEB8E` (the linear decompiler pseudocode misrepresents
         * these as one unconditional tail call; the two `jz`/`jnb` branches to
         * `loc_7AEB8E` prove they are mutually exclusive). The other three xrefs
         * (FUN_007AF4C0, FUN_007B0010, FUN_007B1100) are call sites inside the
         * `_Insert_n` growth core for this element -- not needed to satisfy
         * THIS instantiation's caller evidence, but see the next entry, which
         * cites FUN_007B0010 itself. Source-level invocation:
         * `cameras.push_back(camera)` in `AppendGeomCameraViewAndReturnEnd`)
         *
         * Address: 0x007B0010 (FUN_007B0010, msvc8::vector<moho::GeomCamera3>::
         * insert(pos, value)'s `_Insert_n` growth core for the same 0x2C8
         * (712)-byte element -- max_size guard (`0xFFFFFFFF/712`, throw lane
         * FUN_007AF4C0, already cited as a typed throw shim above), 1.5x
         * growth (`(cap>>1)+cap`) floored to `size()+1` via `size()` itself
         * (`std::vector_GeomCamera3::size`, inlined), allocation through the
         * checked 712-byte lane `sub_7419E0`, construct-the-inserted-value
         * via `sub_7425B0`, tail relocation/destroy-old-buffer via
         * `sub_7B1290`/`sub_7B12E0`/`sub_7B12C0`. Reached from the
         * `insert(pos,val)` wrapper `FUN_007AF450` (already `skip`'d as a
         * RULE ONE compiler/template emission -- its own note already
         * identifies this address as the canonical template home). Its
         * sibling throw-shim `FUN_007B1100` (already `skip`'d) pairs with
         * this instantiation's own `_Buy` allocation lane the same way
         * `FUN_007AF4C0` does above.)
         *
         * Address: 0x0064F9A0 (FUN_0064F9A0, msvc8::vector<moho::SDebugDecal>::
         * uninit_fill_n for the 52-byte element -- broadcast-copies the same
         * by-ref prototype `count` times via 12 `fld`/`fstp` float moves (the
         * four corner Vector3s) plus one dword `mov` (the packed colour),
         * source pointer never advanced, no EH cleanup since the element is
         * trivially copyable. Reached from the `_Insert_n` grow lane
         * FUN_0064E770 (still open; not needed to satisfy this instantiation's
         * own caller evidence) via its advance-returning `_Ufill` adapter
         * FUN_0064E420. Source-level invocation: `canvas->decals.push_back(decal)`
         * in RDebugGrid.cpp / RDebugRadar.cpp)
         * Address: 0x0064E420 (FUN_0064E420, the advance-returning `_Ufill`
         * adapter around FUN_0064F9A0: fills then returns `dst + count`)
         *
         * Address: 0x006501F0 (FUN_006501F0, `uninit_copy_n`/relocation-copy
         * step for the same `msvc8::vector<moho::SDebugDecal>` 52-byte
         * (13-dword) element -- per-slot memberwise copy (13 `mov`-per-dword
         * steps, no ctor/dtor call, matching the trivially-copyable element
         * confirmed on FUN_0064F9A0 above), stride advances all four tracked
         * pointers (`result`/`v3`/`v4`/`v5`) every iteration but only
         * performs the actual dword stores when `result` is non-null -- a
         * defensive null-destination guard the compiler emitted for this
         * call site rather than the usual unconditional copy shape. Called
         * from the `_Insert_n` grow core FUN_0064E770 (still open, cited
         * above and on `insert`/`_Insert_n`; recovered as the caller of this
         * token regardless -- see the evidence note on FUN_0064F9A0) to
         * relocate the live decal range into the freshly grown buffer, via
         * the thin calling-convention bridge `FUN_0064F790` -- `LOBYTE(this)
         * =0; return sub_6501F0(a3, this, this);`, same adapter shape cited
         * elsewhere in this file.)
         *
         * Address: 0x00592030 (FUN_00592030, `uninit_fill_n` for the same
         * 12-byte three-float element as `insert(iterator, const T&)`'s
         * FUN_00592460 above -- broadcast-copies a stack-local prototype
         * (populated from the caller's `value` argument before storage is
         * touched) via three `mov`-per-dword steps, dest stride `+0x0C`.
         * Reached from FUN_00592460's reallocation branch with count folded
         * to the single-element case; the non-reallocating in-place path
         * calls the ICF-identical sibling FUN_00594A20 directly for the same
         * fill. See FUN_00592460's citation on `insert(iterator, const T&)`
         * above for the caller chain and reachability evidence.)
         * Address: 0x00594A20 (FUN_00594A20, the ICF-identical sibling named
         * immediately above -- own decompile confirmed byte-for-byte the
         * same three-`mov`-per-dword broadcast-fill shape, reached from
         * `FUN_00592460`'s in-place (non-reallocating) branch instead of
         * the reallocation branch `FUN_00592030` covers.)
         * Address: 0x005EAA10 (FUN_005EAA10, `uninit_fill_n` for the 20-byte
         * `moho::SAttachPoint` element (`CAiTransportImpl.h`,
         * `sizeof(SAttachPoint) == 0x14`) -- broadcast-copies a stack-local
         * prototype (one dword id/bone field plus four floats) via
         * `mov`+`fld`/`fstp` steps, dest stride `+0x14`, source pointer never
         * advanced. Reached from FUN_005EB320's reallocation branch --
         * FUN_005EB320's own body invokes the IDA-recognised
         * `std::vector<SAttachPoint>::size`/`::_Buy` helpers directly,
         * independently confirming the element type -- which is itself an
         * `msvc8::vector<SAttachPoint>::insert(iterator, count, value)`
         * emission reachable from `WinMain` at depth 24. This is a distinct
         * insert-at-position call chain from the already-recovered
         * `RVectorType_SAttachPoint::SerLoad` (0x005EA260,
         * `IAiTransport.cpp`), which only appends via `push_back`.)
         *
         * Address: 0x00868DB0 (FUN_00868DB0, `msvc8::vector<
         * Moho::WeakEntitySetUserEntity>::uninit_fill_n` for the 12-byte
         * selection-priority bucket element -- the non-trivial-element shape
         * this method's `try`/`catch` guards: copy-constructs `n` copies of
         * `value` at `dst` through the element's own copy constructor
         * (`sub_822210`, matching `WeakEntitySetUserEntity`'s copy constructor
         * in WeakEntitySet.h, which clones the source tree via `find`/
         * `Iterator_inc`/`InsertSelectionEntity`), and on a mid-loop throw
         * destroys the already-constructed prefix `[dst, dst+i)` one element at
         * a time (`sub_868E50`, matching this type's destructor) before
         * rethrowing via `CxxThrowException` -- byte-for-byte the same
         * construct/rollback shape `destroy_n` below implements generically.
         * Reached from the `insert`/`_Insert_n` core FUN_00868040 (both
         * branches: the reallocation tail-fill directly, and the in-place gap
         * fill through the advance-returning `_Ufill` adapter FUN_00868580,
         * `int __usercall sub_868580(dest, value, count) { uninit_fill_n(dest,
         * count, value); return dest + 12*count; }`) cited above on `insert`.)
         * Address: 0x00868580 (FUN_00868580, the advance-returning `_Ufill`
         * adapter described immediately above, around `uninit_fill_n` for
         * this same `WeakEntitySetUserEntity` specialization.)
         *
         * Address: 0x00583180 (FUN_00583180, `msvc8::vector<
         * SAiAttackVectorDebug>::uninit_fill_n` for the 24-byte (6-float)
         * element -- broadcasts the single source struct into `count` slots,
         * counting down from the incoming count in `eax`. Reached from
         * `push_back`'s (`FUN_0057D820`, already recovered above)
         * capacity-full path, whose `insert(end(), 1, value)` fallback calls
         * this with `n=1`.)
         * Address: 0x0057EEF0 (FUN_0057EEF0, the advance-returning `_Ufill`
         * adapter around FUN_00583180 for this same `SAiAttackVectorDebug`
         * specialization -- `int __userpurge sub_57EEF0(dest@ecx, gapPtr@edi,
         * count@esi, value) { uninit_fill_n(value, count, gapPtr); return
         * gapPtr + 24*count; }`, matching the `_Ufill` adapter shape already
         * documented on FUN_00868580 above. Reached from the `_Insert_n`
         * emission for this same 24-byte element (FUN_00580150, `skip`'d as
         * a RULE ONE compiler/template emission already modeled generically
         * by `insert`/`_Insert_n` below) to fill the vacated gap and advance
         * past it.)
         * Address: 0x007E9700 (FUN_007E9700, `msvc8::vector<
         * Moho::MeshRenderer's palette entry type>::uninit_fill_n` for the
         * 0x10-byte (4-float) element -- broadcasts the caller's zeroed
         * source struct into `[dst, dstEnd)`. Reached from `sub_7E9280`
         * (already recovered, `Mesh.cpp`), which "appends `count`
         * value-initialized (zeroed) entries to the palette buffer".)
         *
         * Address: 0x0088AB00 (FUN_0088AB00, `Moho::WaveParameters`'s
         * compiler-generated copy constructor, invoked by the uninit_fill_n
         * and _Insert_n emissions below wherever a `WaveParameters` value is
         * copy-constructed into fresh storage)
         * Address: 0x0088B090 (FUN_0088B090, `msvc8::vector<Moho::
         * WaveParameters>::uninit_fill_n` for the 136-byte polymorphic
         * element -- copy-constructs `n` copies of `value` at `dst` through
         * the class's own compiler-generated copy constructor (FUN_0088AB00),
         * and on a mid-loop throw destroys the already-constructed prefix
         * through the vtable-slot-0 deleting destructor (`(**it)(it, 0)`,
         * the same mechanism `destroy_range` above documents for this type)
         * before rethrowing. Reached from `push_back`'s fast path
         * (FUN_00889C90, cited above, `n=1`).)
         *
         * Address: 0x007F38D0 (FUN_007F38D0, `msvc8::vector<moho::
         * SRangeRenderProfile>::uninit_fill_n` for the 136-byte element --
         * copy-constructs `n` copies of the same source value at `dst`
         * through the element's own copy operation (FUN_007F0ED0, cited in
         * `RangeRenderer.cpp` as `RebindAndCopyRangeRenderProfile`), dest
         * stride `+0x88`, and on a mid-loop throw destroys the
         * already-constructed prefix one element at a time (FUN_007EE860,
         * cited in `RangeRenderer.cpp` as
         * `ResetRangeRenderProfileTransientState`) before rethrowing via
         * `CxxThrowException` -- the same construct/rollback shape this
         * method implements generically. Reached from `push_back`'s fast
         * path (FUN_007EFFA0, cited above, `n=1`).)
         *
         * Address: 0x007BD810 (FUN_007BD810, msvc8::vector<Moho::
         * SNetCommandArg>::uninit_fill_n for the 36-byte element --
         * recovered as the free function
         * `CopyAssignCommandArgRangeWithRollback(prototype, count,
         * destination)` in CGpgNetInterface.cpp: loops `count` times
         * constructing one copy of `prototype` per slot through the same
         * per-element helper FUN_007BE4B0 this method's `uninit_move_n`
         * sibling uses (cited above), destroying the already-written
         * prefix through FUN_007BDBB0 on exception. Called directly from
         * push_back's fast (capacity-available) path FUN_007BB120 with
         * `count = 1` (cited above on `push_back`), and from `_Insert_n`'s
         * reallocation branch FUN_007BBD60 (cited above on `insert`) to
         * construct the inserted value between the relocated
         * prefix/suffix ranges.)
         * Address: 0x007BB880 (FUN_007BB880, register-shape trampoline
         * into FUN_007BD810 above -- reshuffles a caller's `(prototype,
         * count, dest)` triplet from a mix of its own stack arg and the
         * caller's live `esi`/`edi` registers onto FUN_007BD810's own
         * calling convention. Called once from `_Insert_n`'s in-place
         * append branch, FUN_007BBD60 (cited above on `insert`), with
         * `count = 1` to construct the new back element when
         * `pos == last_`.)
         * Address: 0x008575A0 (FUN_008575A0, `msvc8::vector<boost::
         * shared_ptr<moho::MeshInstance>>::uninit_fill_n` for the 8-byte
         * shared_ptr `(px, pn)` pair element -- `(count@edx, dst@ecx,
         * srcValue@esi)` loop broadcasting the same `(px, pn)` pair into
         * `count` fresh slots, `_InterlockedExchangeAdd(pn+4,1)` add-ref
         * per non-null copy. Reached from `_Insert_n` FUN_00855DF0 (cited
         * above on `insert`), `mMeshes`'s in-place tail-smaller-than-gap
         * branch (constructs the trailing gap slots that have no live tail
         * element to relocate over them).)
         *
         * Address: 0x007CCEB0 (FUN_007CCEB0, `msvc8::vector<Moho::
         * CDiscoveryService::DiscoveredGameRecord, false>::uninit_fill_n`
         * for the 16-byte plain-POD element (protocol/address/port/padding/
         * reply-timestamp, no pointers) -- `(dst@eax, srcValue@edx,
         * count@ecx)` loop: `*dst = *srcValue` (unrolled 4-dword copy) then
         * `dst += 4`, `srcValue` never advanced, once per remaining count;
         * the `if (dst)` null guard wraps only the copy body, matching the
         * same defensive-null shape already documented on FUN_00549BC0 and
         * FUN_00832B80 above. Reached with `count = 1` from `AddDiscoveredGame`'s
         * (0x007C87E0, `CDiscoveryService.cpp`) capacity-available fast path
         * -- this method's own `if (size() < capacity()) { uninit_fill_n(last_,
         * 1u, value); ++last_; }` branch -- which is `AddDiscoveredGame`'s
         * entire real body, `mGames.push_back(newRecord)`. Previously
         * mis-recovered as a bespoke free function `FillStride4DwordLaneRuntimeA`
         * in `SimRecoveryRuntime.cpp` (a `*Lane*`-named per-instantiation
         * reimplementation, the exact RULE ONE anti-pattern this method
         * exists to replace) with zero source-level callers of its own;
         * removed in favor of this citation when `CDiscoveryService::mGames`
         * was migrated onto this template.)
         * Address: 0x008F74A0 (FUN_008F74A0, `msvc8::vector<AdapterModeD3D10>::
         * uninit_fill_n` for the 0x74-byte (116) non-trivial
         * `AdapterModeD3D10` element -- matches this member's shape exactly:
         * `while (a2 [count]) { construct one AdapterModeD3D10 copy of *a3
         * at a1; --a2; a1 += 116; }`, per-element construct is the same
         * `qmemcpy` POD-prefix-plus-`sub_8F6D20`-for-`modes_` shape as the
         * `uninit_copy_n` instantiations above, with the same disjoint-SEH-
         * catch-funclet-rendered-as-linear-`__noreturn` decompile artifact
         * documented there (destroys `[a1_start,a1)` via `FUN_008F7360` on
         * exception, then rethrows -- not an unconditional
         * destroy-then-rethrow on the normal-completion path). Reached
         * directly from `FUN_008F7C50` (`AppendAdapterModeEntry`'s
         * `msvc8::vector<AdapterModeD3D10>::push_back` capacity-available
         * fast path -- `size() < capacity()` -> construct the one new
         * element directly at `last_`, this method's own `if (size() <
         * capacity()) { uninit_fill_n(last_, 1u, value); ++last_; }` branch
         * -- `FUN_008F7C50` is already `recovered`, D3D10Interfaces.cpp) and
         * through the thiscall calling-convention bridge `FUN_008F7630`
         * (`sub_8F74A0(a2, a3, a4, this);`, no logic of its own) from
         * `FUN_008F7770` above (both the growth branch's fill-the-gap step
         * and the in-place tail-smaller-than-gap branch's trailing-gap
         * fill). DB previously listed this token `external_dependency`
         * ("all-external-callees thunk... no Moho/gpg engine references")
         * -- wrong for the same reason `FUN_008F6D20`/`FUN_008F69A0` were:
         * its only real callee besides the destroy/throw helpers is
         * `sub_8F6D20`, an engine-instantiated `DXGI_MODE_DESC` vector
         * internal, not third-party runtime; corrected to `recovered` here.)
         *
         * Address: 0x005CBC70 (FUN_005CBC70, `msvc8::vector<Moho::
         * CAiReconDBImpl::SNewBlip>::uninit_fill_n` for the 12-byte
         * trivially-copyable element (`Unit* sourceUnit; uint8_t fake; enum
         * detectedFlags;`) -- `(dst@eax, srcValue@edx, count@ecx)` loop:
         * `*dst = *srcValue` (3-dword copy) then `dst += 3`, `srcValue`
         * never advanced, once per remaining count; the `if (dst)` null
         * guard wraps only the copy body, the same defensive-null shape as
         * the 16-byte `CDiscoveredGameRecord` instantiation above. Reached
         * with `count = 1` from `AppendPendingNewBlip`'s (0x005C4CA0,
         * `CAiReconDBImpl.cpp`) capacity-available fast path -- this
         * method's own `if (size() < capacity()) { uninit_fill_n(last_, 1u,
         * value); ++last_; }` branch -- which is `AppendPendingNewBlip`'s
         * entire real body, `pending.push_back(SNewBlip{...})`.
         * DB-integrity fix: `pending`'s declared type (`AppendPendingNewBlip`/
         * `GenerateNewBlips`/`UpdateBlips`, `CAiReconDBImpl.h`/`.cpp`) had
         * drifted to real `std::vector<SNewBlip>`, which would not emit this
         * symbol on rebuild; retyped to `msvc8::vector<SNewBlip>` to match.)
         * Address: 0x005C6190 (FUN_005C6190, sub_5C6190) -- this
         * instantiation's own `_Ufill` advance-returning adapter: `sub_5CBC70
         * (dst@edi, srcValue@edx, count@esi); return &dst[3*count];`, the
         * same "wrap the core fill loop, return `dst + n*sizeof(T)`" shape
         * as `FUN_0092E920`/`FUN_0092EB70`/`FUN_006274B0` elsewhere in this
         * file, wrapping the already-cited `uninit_fill_n` above with a
         * variable `count` (not hardcoded to 1 the way `AppendPendingNewBlip`'s
         * fast path uses it) -- matches `insert(pos, count, value)`'s
         * reallocation-path tail-fill sub-branch for this instantiation.
         * Stale in_progress claim (crt2-batch-3, 24h+, abandoned) reclaimed;
         * its traced caller's own `recovered` status is itself unsupported
         * (no citation anywhere in `src/sdk`) so cited here strictly against
         * this member's own confirmed shape and the already-verified callee,
         * not against that specific caller.)
         *
         * Address: 0x0092D0A0 (FUN_0092D0A0, `msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::uninit_fill_n` for the
         * 12-byte element -- same per-element 3-dword defensive-null-guarded
         * copy loop shape as `FUN_005CBC70` above. Used directly by the
         * `_Insert_n` in-place branch's "tail >= count" sub-branch (fills the
         * vacated gap after the tail has been moved). Reached from the
         * `_Insert_n` grow core `FUN_0092F630`, cited above on `insert`.)
         * Address: 0x0092DF10 (FUN_0092DF10, a second, byte-distinct emission
         * of the identical fill loop for the same `ClusterSearchEdgeTraversal
         * LaneRuntime` instantiation -- not folded with `FUN_0092D0A0` above
         * despite matching source/shape, reached only through the advance-
         * returning adapter `FUN_0092E920` (`sub_92DF10(a1,a2,a3); return a1
         * + 12*a2;`, this member's own "`_Ufill`" shape), which the
         * `_Insert_n` in-place branch's "tail < count" sub-branch calls to
         * fill the trailing-gap section. Both `FUN_0092D0A0` and
         * `FUN_0092DF10` model this one member; recovered together.)
         * Address: 0x0092D580 (FUN_0092D580, the sibling `msvc8::vector<gpg::
         * HaStar::ClusterSearchOpenHeapEntryRuntime>::uninit_fill_n` for the
         * 12-byte open-heap-entry element -- same shape as `FUN_0092D0A0`
         * above, reached directly by the `_Insert_n` in-place branch's
         * "tail >= count" sub-branch. Reached from the `_Insert_n` grow core
         * `FUN_0092F240`, cited above on `insert`.)
         * Address: 0x0092E010 (FUN_0092E010, the open-heap-entry sibling's
         * own second byte-distinct fill-loop emission -- same relationship
         * to `FUN_0092D580` as `FUN_0092DF10` has to `FUN_0092D0A0` above,
         * reached only through this instantiation's own advance-returning
         * adapter `FUN_0092EB70` (`sub_92E010(a1,a2,a3); return a1+12*a2;`)
         * from the `_Insert_n` in-place branch's "tail < count" sub-branch.)
         * Address: 0x00445430 (FUN_00445430, `msvc8::vector<std::int32_t>::
         * uninit_fill_n` for the handle-to-heap-index reverse map
         * (`ClusterSearchOpenHeapRuntime::mHandleToHeapIndex`, Cluster.cpp)
         * -- `for (i=count; i; ++dst,--i) *dst = *value; return dst;`, the
         * 4-byte-element analogue of the two 12-byte loops above, already
         * returning the advanced pointer directly with no separate adapter
         * needed. Reached from the `_Insert_n` grow core `FUN_004451A0`,
         * cited above on `insert`.)
         * Address: 0x006274B0 (FUN_006274B0, sub_6274B0) -- the `_Ufill`
         * advance-returning adapter for `msvc8::vector<Moho::SPickUpInfo>`'s
         * fill loop, for the 12-byte intrusive-weak `{WeakPtr<Unit>, float}`
         * element (`SPickUpInfoVectorReflection.cpp`'s `SPickUpInfoVector`)
         * -- `sub_628AE0(a1,a2,a3); return a1 + 12*a2;`, the same
         * "wrap the core fill loop, return `dst + n*sizeof(T)`" shape as
         * `FUN_0092E920`/`FUN_0092EB70` above, confirmed against the `.asm`
         * (3 instructions of setup, one `call`, one `lea`, `retn`). The
         * wrapped core loop (`FUN_00628200`/`FUN_00628230`, this
         * instantiation's own `WeakPtr<Unit>`-relinking element constructor,
         * not yet individually recovered) is passed through unchanged.
         * Reached from the `_Insert_n` grow core `FUN_00627800`'s (cited
         * above on `insert`) `tail < count` sub-branch -- the one
         * `push_back`'s `count=1`-at-`end()` insert always takes, since
         * `tail == last_ - insertAt == 0` there. Previously mis-tracked
         * `blocked` citing `CrtRuntimeHelpers.cpp` boilerplate the address
         * never appeared in.
         *
         * Address: 0x008EF7E0 (FUN_008EF7E0, sub_8EF7E0) -- `msvc8::
         * vector<gpg::gal::HeadSampleOption>::uninit_fill_n` for `Head::
         * mStrs` (same instantiation as `push_back`'s `FUN_008F1760`
         * above). DB-integrity fix: was mis-tagged `external_dependency`
         * ("all-external-callees thunk... no engine references") -- its
         * two callees `FUN_00437900`/`FUN_00437D70` (cited below) are this
         * project's own `HeadSampleOption` construct/destroy helpers, not
         * external runtime. IDA's own decompile carries the same "positive
         * sp value... may be wrong" disclaimer as `FUN_008F05C0` above, and
         * renders the SEH cleanup funclet as a bogus `while(1)` fallthrough
         * that never returns -- the raw `.asm` shows the true shape: `test
         * esi,esi; jbe` straight to a normal `retn` once the fill loop
         * (`n` iterations of `FUN_00437D70` at `+0x24`/36-byte stride)
         * completes, matching this member's `for(;i<n;++i) new(dst+i)
         * T(value)` exactly. The destroy-and-rethrow block (`FUN_00437900`
         * per element, then `CxxThrowException`) is only reached via SEH
         * unwind, matching this member's `catch(...){ destroy_n(dst,i);
         * throw; }`. Reached from `push_back`'s fast (spare-capacity)
         * path with `n=1`.
         *
         * Address: 0x00437D70 (FUN_00437D70, sub_437D70) -- this
         * instantiation's own out-of-line emission of `HeadSampleOption`'s
         * copy constructor, as invoked from `uninit_fill_n`'s placement-new
         * (`::new (dst+i) T(value)`) rather than a direct `T(other)`
         * expression -- a distinct compiled emission of the SAME logical
         * ctor already recovered under its "named" mangled symbol
         * `FUN_004369B0` (`Device.cpp`, `HeadSampleOption::HeadSampleOption
         * (const HeadSampleOption&)`), confirmed field-for-field identical:
         * raw dword copy of `sampleType`(+0x00)/`sampleQuality`(+0x04),
         * `label`(+0x08) reset to empty-SSO state then `std::string::
         * assign`ed from `other.label`. DB-integrity fix: was mis-tagged
         * `external_dependency` ("template/helper instantiation artifact")
         * -- it is this project's own `HeadSampleOption`, not a generic/
         * external type. No new source needed: this address is the
         * compiler's own out-of-line copy of the already-recovered ctor
         * body, reached through this member's placement-new rather than a
         * separate hand-written call.
         *
         * Address: 0x00437900 (FUN_00437900, sub_437900) -- this
         * instantiation's own destroy helper for `HeadSampleOption::label`
         * (SSO-aware `msvc8::string` teardown: `if (_Myres>=0x10) operator
         * delete(_Bx._Ptr);` then reset to empty state), invoked from
         * `destroy_n`'s per-element loop on this member's SEH cleanup
         * path. `HeadSampleOption` declares no explicit destructor in
         * `Head.hpp` -- this is the compiler-emitted implicit destructor's
         * out-of-line body for the `label` sub-object, not hand-written
         * source (CLAUDE.md's "member destructors are compiler-emitted, not
         * hand-written" applies directly). DB-integrity fix: was mis-tagged
         * `external_dependency` ("STL/wxWidgets string dtor... external
         * runtime") -- `label` is this project's own `msvc8::string`
         * member, and this teardown is only reachable during unwind of
         * this project's own `uninit_fill_n<HeadSampleOption>`.
         *
         * Address: 0x008F0090 (FUN_008F0090, sub_8F0090) -- `msvc8::
         * vector<gpg::gal::AdapterD3D9>::uninit_fill_n` for
         * `DeviceD3D9Runtime::adapters` (`D3D9Interfaces.cpp`, 112-byte
         * polymorphic element, same instantiation as `insert(pos,count,
         * value)`'s `FUN_008F1890` and `destroy_range`'s `FUN_008EA5C0`
         * above). `for (i=dst; i!=dstEnd; i+=112) { copy 2 dwords; assign
         * 3 embedded msvc8::strings; call sub_8EF870 on the modes
         * sub-vector; }` -- per-slot copy-construct via this element's own
         * copy ctor sub-pieces rather than a single ctor call (matches
         * `FUN_008EFF80`'s own field layout exactly: 2 leading dwords,
         * 3 string members, `modes` vector at +0x60). `FUN_008EF870` is
         * already `recovered` (`msvc8::vector<AdapterModeD3D9>::
         * operator=`). Previously `blocked` citing "caller integration
         * lane FUN_008F1890" as unresolved -- that token is now recovered
         * (cited above on `insert`), clearing the stated blocker.
         *
         * Address: 0x00753A90 (FUN_00753A90, `msvc8::vector<moho::
         * SDesyncInfo>::uninit_fill_n` for the 0x28-byte element
         * (`Sim::mDesyncs`, `Sim.h`) -- `(count@eax, dst@edx, srcValue@ecx)`
         * loop: `*dst = *srcValue` (unrolled 10-dword copy) then `dst +=
         * 10` (0x28-byte stride), `srcValue` never advanced, once per
         * remaining count; the `test edx,edx`/`if (dst)` null guard wraps
         * only the copy body while `dst` still advances every iteration
         * regardless, matching the same defensive-null shape already
         * documented on FUN_00549BC0/FUN_00832B80/FUN_007CCEB0 above (the
         * destination is freshly-allocated or in-place storage the compiler
         * cannot prove non-null). Reached with `count=1` from `push_back`'s
         * (FUN_0074C060, cited above on `push_back`) capacity-available
         * fast path -- this method's own `if (size() < capacity()) {
         * uninit_fill_n(last_, 1u, value); ++last_; }` branch -- which is
         * `Sim::VerifyChecksum`'s entire `mDesyncs.push_back(desync)` call
         * (already recovered, `Sim.cpp`), and with `count=1` again from the
         * `_Insert_n` core FUN_0074F060's at-end sub-branch (cited above on
         * `insert`) via the advance-returning adapter FUN_0074DAC0
         * immediately below. DB-integrity fix: was `blocked` citing
         * `src/sdk/moho/misc/CrtRuntimeHelpers.cpp` boilerplate that does
         * not contain this address at all (systematic DB-integrity
         * contamination pattern); this is this project's own
         * `msvc8::vector<T>` internals for an engine-owned element type,
         * not CRT code.)
         * Address: 0x0074DAC0 (FUN_0074DAC0, the advance-returning `_Ufill`
         * adapter around FUN_00753A90 above, for this same `SDesyncInfo`
         * specialization -- `int __userpurge sub_74DAC0(dest@edi, count@esi,
         * srcValue) { uninit_fill_n(dest, count, srcValue); return dest +
         * 40*count; }`, matching the `_Ufill` adapter shape already
         * documented on FUN_00868580 above. Called once from the
         * `_Insert_n` core FUN_0074F060's at-end sub-branch (cited above on
         * `insert`) to construct the newly-appended element and obtain the
         * advanced end pointer. DB-integrity fix: was mis-tagged
         * `external_dependency` ("All-external-callees thunk... no
         * Moho/gpg engine references") -- its only callee is FUN_00753A90,
         * this project's own `uninit_fill_n` core for this same
         * engine-owned `moho::SDesyncInfo` element, not third-party
         * runtime.)
         *
         * Address: 0x0092EA50 (FUN_0092EA50, sub_92EA50) -- the
         * advance-returning `_Ufill` adapter for this instantiation's
         * `uninit_fill_n` (`ClusterInternalCache<gpg::HaStar::
         * OccupationData>::mVec`, `OccupationCacheRuntimeMap`, 4-byte
         * `iterator` element -- same instantiation as `insert`'s
         * `FUN_0092F9E0` above): `int __stdcall sub_92EA50(dest, count,
         * srcValue) { sub_92DF90(dest, count, srcValue); return dest +
         * 4*count; }`, matching the `_Ufill` adapter shape already
         * documented on `FUN_00868580`/`FUN_0074DAC0` above. Its callee
         * `FUN_0092DF90` is already `skip`, an ICF twin of `FUN_008EA0D0`
         * (the D3D9 dword-fill dispatch helper this 4-byte-trivial fill
         * loop folds onto). Called once from `FUN_0092F9E0`'s tail<count
         * branch to construct the trailing gap (`uninit_fill_n(oldLast,
         * count-tail, localValue)`) and once from its reallocation branch
         * to construct the inserted run in the fresh buffer.)
         *
         * Address: 0x00753A90 (FUN_00753A90, sub_753A90) --
         * `msvc8::vector<Moho::SDesyncInfo>::uninit_fill_n` for the 40-byte
         * (`SDesyncInfo.h`, `static_assert(sizeof==0x28)`) element:
         * `eax=count, edx=dest, ecx=source_value_ptr` fills `count` copies
         * of one value into consecutive slots, source pointer never
         * advances -- textbook `uninit_fill_n`, not a range copy. Real
         * caller `FUN_0074C060` is IDA-named `std::vector_SDesyncInfo::
         * push_back` (corrected below from a wrong `external_dependency`
         * tag -- `std::` here just names the STL *template*, `SDesyncInfo`
         * is the engine value type used by `Moho::Sim::mDesyncs`/
         * `SimDriver.h`); real caller chain is `Moho::Sim::VerifyChecksum`
         * (desync detection). `FUN_0074DAC0` (the `_Ufill` adapter cited
         * above) forwards into this token too; corrected alongside it from
         * the same wrong `external_dependency` tag.
         *
         * Address: 0x0064F910 (FUN_0064F910, sub_64F910) --
         * `msvc8::vector<moho::SDebugScreenText>::uninit_fill_n` for the
         * 0x48-byte element (`CDebugCanvas::screenText`). Count-driven loop
         * (`count` register-carried) that, per slot, copy-constructs
         * `value` through this element's compiler-generated copy ctor
         * `FUN_0064EC50` (cited on `SDebugScreenText.h`) and advances the
         * destination by 0x48; the guard-list bookkeeping local
         * (`v5[3]`/`v5[4]` in the decompile) is the VC8 SEH cleanup-scope
         * idiom that destroys the already-constructed prefix through the
         * element dtor `FUN_00453710` (already `skip`-tagged) and rethrows
         * via `_CxxThrowException` on an exception mid-loop -- IDA's own
         * `__noreturn` tag on this function (and its adapter below) is
         * spurious, matching the documented pattern elsewhere in this file:
         * both return normally on every path actually exercised by their
         * callers. Called with `count=1` from `push_back`'s
         * (`FUN_0064E120`, cited above) capacity-available fast path and
         * from `_Insert_n`'s (`FUN_0064E490`, cited above on
         * `insert(pos,count,value)`) reallocation-branch fill step. DB-
         * integrity fix: was `recovered` citing "Cited on the canonical
         * template" with no such citation anywhere in `src/sdk`; this is
         * the real recovery.
         * Address: 0x0064E360 (FUN_0064E360, sub_64E360) -- the
         * advance-returning `_Ufill` adapter around `FUN_0064F910` above,
         * for the same `SDebugScreenText` specialization: forwards its
         * `EDI`-carried destination straight into `FUN_0064F910`, matching
         * the `_Ufill` adapter shape already documented on
         * `FUN_0074DAC0`/`FUN_0092EA50` above. Called once from `_Insert_n`
         * `FUN_0064E490`'s at-end sub-branch (`count=1`) to construct the
         * newly-appended element from the aliasing-safe local copy and
         * obtain the advanced end pointer. DB-integrity fix: was
         * mis-tagged `skip` ("`__noreturn` 1-statement tail-call typed
         * throw shim") -- its only callee, `FUN_0064F910`, is this
         * project's own `uninit_fill_n` core, not a throw lane; the
         * `__noreturn` tag both functions carry is the same spurious-tag
         * artifact called out above, not evidence of throw-only behavior.
         *
         * Address: 0x007D9970 (FUN_007D9970, sub_7D9970) --
         * `msvc8::vector<moho::ClutterSurfaceElement>::uninit_fill_n` for the
         * 16-byte element (`Moho::Clutter::Surface::mSeeds`, `Clutter.h`).
         * Count-driven loop (`a3` register-carried) that per slot resets the
         * element's vtable to `Moho::Clutter::Seed::`vftable'` and copies
         * `selectionWeight`/`uniformScale`/`meshBlueprint` from the fixed
         * `a2` source (never advances -- textbook fill, not a range copy),
         * advancing the destination by 16. Called from `insert(pos,count,
         * value)`'s (`FUN_007D8620`, cited below) reallocation-branch fill
         * step, and via the `FUN_007D7F00` adapter immediately below from
         * that same instantiation's fast-path at-end append. Previously
         * recovered under the name `CopyClutterSeedRange` in Clutter.cpp (a
         * bespoke per-type free function -- moved here per RULE ONE now that
         * this pass touches the same instantiation's `insert`).
         * Address: 0x007D7F00 (FUN_007D7F00, sub_7D7F00) -- the
         * advance-returning `_Ufill` adapter around `FUN_007D9970` above,
         * for the same `ClutterSurfaceElement` specialization: forwards its
         * carried destination straight into `FUN_007D9970` with `count=1`
         * and returns the advanced destination pointer, matching the
         * `_Ufill` adapter shape already documented on `FUN_0064E360`/
         * `FUN_0074DAC0`/`FUN_0092EA50` above. Called once from `insert`'s
         * (`FUN_007D8620`) fast-path at-end sub-branch (no tail to shift) to
         * construct the newly-inserted element and obtain the advanced end
         * pointer. Previously recovered under the name
         * `CopyClutterSeedValueRange` in Clutter.cpp -- moved here alongside
         * its `uninit_fill_n` core for the same reason.
         *
         * The following addresses are `uninit_fill_n` instantiations for
         * 4-byte trivially-copyable element types (mostly pointers, two
         * `int32_t`s) -- every one compiles to the same `for(i=0;i<n;++i)
         * dst[i]=value` store loop regardless of `T`'s identity, which is
         * why MSVC8 emitted them as separate per-instantiation bodies but
         * they read as near-identical `.c` exports. Previously duplicated in
         * `LegacyContainerFillLanes.cpp` as 16 lettered
         * `FillDwordSpanCountedLane*`/3 `FillDwordSpanByEndLane*` thin
         * wrappers over a shared generic `FillDwordSpanByCount`/
         * `FillDwordSpanByEnd` implementation (itself byte-identical to this
         * method's body) -- a RULE ONE violation once each wrapper's real
         * `_Insert_n`/`push_back` caller and element `T` were identified via
         * `_callgraph_index.sqlite` `call_edges`; retired in favor of citing
         * each address here directly. A follow-up sweep (full-population
         * caller scan) resolved six more of the file's previously-
         * unidentified lettered lanes -- `B` (0x0057F860), `F` (0x006522F0),
         * `N` (0x007DA1D0), `Q` (0x0084EAD0), `R` (0x008558E0), and `S`
         * (0x00869C80), all cited below -- plus `J` (0x00701FA0), cited
         * inline on `detail::LegacyVectorDwordInsertN` in Vector.cpp instead
         * since that instantiation's fill step is already expressed as part
         * of that helper's own in-place/reallocation arms. `FillDwordSpanByCount`/
         * `FillDwordSpanByEnd` are kept alive only for lane `X` (0x008B2FD0),
         * the sole lettered lane still without a confirmed element `T`: its
         * grow-path caller `FUN_008B31B0` has two genuine, non-padding call
         * sites (0x008B29CA, 0x008B2F47, hand-verified against the raw PE
         * bytes) that IDA's own function analysis never boxed into named
         * functions, so the owning engine call site cannot yet be cited by
         * name.
         * The `ByEnd`-lettered three below were expressed over a
         * `[begin,end)` pointer pair rather than a count at their call
         * sites; same `uninit_fill_n` semantics, alternate compiled form.
         *
         * Address: 0x00535620 (FUN_00535620, `msvc8::vector<Moho::
         * RBlueprint*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from this instantiation's `_Insert_n` grow lane
         * `FUN_00535D60` (cited above), whose `_Count` is folded to the
         * constant 1; emitted via `rules.mBlueprintsByOrdinal.push_back(...)`
         * in `moho::AppendBlueprintOrdinal`, Sim.cpp:14253.)
         * Address: 0x0057F860 (FUN_0057F860, `msvc8::vector<Moho::
         * Unit*>::uninit_fill_n` for the 4-byte pointer element. Reached
         * from this instantiation's `insert(pos,value)` grow/shift helper
         * `FUN_005809A0` (uncited -- compiler emission, no separate source;
         * the general single-element insert-at-position body `push_back`
         * tail-calls into on its grow path), itself reached from `msvc8::
         * vector<Unit*>::push_back`'s `FUN_0057E6A0` (cited above) via
         * `storedCargo.push_back(storedUnit)` in `Sim::TransferUnit`
         * (Sim.cpp:11097) and `stdCandidates.push_back(unit)` in
         * `moho::FindAvailableFactory` (CAiBrain.cpp). Previously duplicated
         * here as lettered lane `B`, `FillDwordSpanCountedLaneB`; removed
         * from `LegacyContainerFillLanes.cpp` in favor of this citation.)
         * Address: 0x005C5F90 (FUN_005C5F90, `msvc8::vector<moho::
         * ReconBlip*>::uninit_fill_n` for the 4-byte pointer element, filled
         * with a `nullptr` placeholder. Reached from the already-recovered
         * `GrowBlipPointerVector` (CAiReconDBImpl.cpp:964), which invokes
         * `values.resize(values.size()+appendCount, nullptr)` by name --
         * this address is `resize`'s own grow-and-fill step for this `T`.)
         * Address: 0x005DC940 (FUN_005DC940, `msvc8::vector<Moho::
         * UnitWeapon*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from this instantiation's `_Insert_n` grow lane
         * `FUN_005DD120` (cited above, `CAiAttackerImpl::mWeapons`); emitted
         * via `view->mWeapons.push_back(weapon)` in
         * `CAiAttackerImpl::CreateWeapon`, CAiAttackerImpl.cpp:973.)
         * Address: 0x005DCAE0 (FUN_005DCAE0, `msvc8::vector<moho::
         * CAcquireTargetTask*>::uninit_fill_n` for the 4-byte pointer
         * element. Reached from this instantiation's `_Insert_n` grow lane
         * `FUN_005DD570` (cited above); emitted via the recovered helper
         * `InsertNCopiesCAcquireTargetTaskPtrVector`'s
         * `storage.insert(begin()+offset, count, value)`, IAiAttacker.cpp.)
         * Address: 0x006522F0 (FUN_006522F0, `msvc8::vector<const
         * RDebugOverlayClass*>::uninit_fill_n` for the 4-byte pointer
         * element. Reached from this instantiation's `insert(pos,value)`
         * grow/shift helper `FUN_00652380` (uncited -- compiler emission,
         * no separate source), itself reached from `push_back`'s grow path
         * -- the per-T canonical-template-helper binding
         * `PushBackDebugOverlayClassPtrVector`'s `destination.push_back(
         * value)` (Sim.cpp), called from `CollectPrefixDebugOverlayTypes`'s
         * `PushBackDebugOverlayClassPtrVector(outMatches, overlayClass)`.
         * Previously duplicated here as lettered lane `F`,
         * `FillDwordSpanCountedLaneF`; removed from
         * `LegacyContainerFillLanes.cpp` in favor of this citation.)
         * Address: 0x0066A460 (FUN_0066A460, `msvc8::vector<moho::
         * WCurveEditorPanel*>::uninit_fill_n` for the 4-byte pointer
         * element -- already named on this instantiation's `push_back`
         * entry above (`FUN_0066A860`) as "constructs the new element
         * through FUN_0066A460 (uninit_fill_n)"; cited here directly too.
         * Reached from `msvc8::vector<T*>::push_back`'s capacity-full path
         * and directly from `Moho::WEmitterWx::WEmitterWx`'s
         * `mCurvePanels.push_back(curvePanel)`, WEmitterWx.cpp.)
         * Address: 0x0067CB80 (FUN_0067CB80, `msvc8::vector<Moho::
         * Entity*>::uninit_fill_n` for the 4-byte pointer element
         * (`Moho::Entity::mAttachedEntities` @+0x17C). Reached from this
         * instantiation's `_Insert_n` grow lane `FUN_0067DB40` (cited
         * above); emitted via the recovered helper
         * `InsertNCopiesEntityPtrVector`'s `storage.insert(begin()+offset,
         * count, value)` (Entity.cpp), and via `AppendAttachedEntity` on
         * `Moho::Entity::AttachTo`'s (FUN_00679550) capacity-full path.)
         * Address: 0x006F87A0 (FUN_006F87A0, `msvc8::vector<
         * CUnitCommand*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from this instantiation's `_Insert_n` grow lane
         * `FUN_006F88D0` (cited above); emitted via
         * `cfunc_CoordinateAttacksL`'s `commands.push_back(command)`,
         * CCommandLuaFunctionRegistrations.cpp.)
         * Address: 0x0078A2A0 (FUN_0078A2A0, `msvc8::vector<moho::
         * CMauiControl*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from this instantiation's `insert(end(),1,value)` grow-core
         * `FUN_0078A330` (cited above); emitted via `RebuildRenderedChildrenLane`'s
         * `mRenderedChildren.push_back(controlCursor)` (UiRuntimeTypes.cpp),
         * reached from `Moho::CMauiControl::Render` (0x00786FA0).)
         * Address: 0x007AF3B0 (FUN_007AF3B0, `msvc8::vector<Moho::
         * CameraImpl*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from the recovered `InsertNCopiesCameraImplPtrVector`
         * (EngineVectorHelpers.cpp:74, `msvc8::vector<CameraImpl*>::
         * _Insert_n` per-T binding for `FUN_007AFD10`), which forwards to
         * `storage.insert(pos, count, fillValue)` by name.)
         * Address: 0x007AF620 (FUN_007AF620, `msvc8::vector<Moho::
         * RCamCamera*>::uninit_fill_n` for the same 4-byte pointer element
         * as the entry immediately above (`RCamCamera` is the public alias
         * of `CameraImpl`) -- a second, distinct `_Insert_n` emission for
         * this `T` reached via a different call shape. Reached from this
         * instantiation's `_Insert_n` grow lane `FUN_007B0340` (cited above,
         * folded to `_Count=1`); emitted via `Moho::CAM_GetAllRCamCameras`'s
         * (FUN_007AADE0, RCamManager.cpp) `result.push_back(cam)`.)
         * Address: 0x007DA1D0 (FUN_007DA1D0, `msvc8::vector<
         * MeshInstance*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from this instantiation's `insert(pos,value)` grow/shift
         * helper `FUN_007DA270` (uncited -- compiler emission, no separate
         * source), reached in turn from `msvc8::vector<MeshInstance*>::
         * push_back`'s `FUN_007D9FC0` grow path via `bucket->push_back(
         * instance)` inside `Moho::MeshRenderer::Batch` (0x007DFA00,
         * Mesh.cpp), which appends into the per-`MeshBatchKey`
         * `MeshBatchInstanceVector` bucket. Previously duplicated here as
         * lettered lane `N`, `FillDwordSpanCountedLaneN`; removed from
         * `LegacyContainerFillLanes.cpp` in favor of this citation.)
         * Address: 0x007E31E0 (FUN_007E31E0, `msvc8::vector<Moho::
         * MeshLOD*>::uninit_fill_n` for the 4-byte pointer element. Reached
         * from this instantiation's `push_back` `FUN_007E3850` (cited
         * above); emitted via `Mesh::CreateLOD`'s `lods.push_back(lod)`.)
         * Address: 0x0082D250 (FUN_0082D250, `msvc8::vector<
         * UICommandGraph::CommandGraphEdge*>::uninit_fill_n` for the 4-byte
         * pointer element. Reached from this instantiation's `insert`
         * grow-core `FUN_0082E950` (cited above); emitted via
         * `LinkCommandGraphEdge`'s `bucket.push_back(edge)`
         * (CWldSession.cpp:14703) when the bucket's `mEdges` vector is at
         * capacity.)
         * Address: 0x0084EAD0 (FUN_0084EAD0, `msvc8::vector<
         * wxWindowBase*>::uninit_fill_n` for the 4-byte pointer element --
         * the per-window saved pushed-event-handler inner vector built by
         * `moho::SuspendInputWindowEventHandlersAndFlushQueue`
         * (UiRuntimeTypes.cpp, `Address: 0x0084DA80`). Reached from this
         * instantiation's `insert(pos,value)` grow/shift helper
         * `FUN_0084F200` (uncited -- compiler emission, no separate
         * source), itself reached from `push_back`'s grow path via
         * `suspended[index].push_back(inputWindow->PopEventHandler(false))`
         * -- every call takes the grow path since each per-window inner
         * vector starts default-constructed at capacity 0. Previously
         * duplicated here as lettered lane `Q`, `FillDwordSpanCountedLaneQ`;
         * removed from `LegacyContainerFillLanes.cpp` in favor of this
         * citation.)
         * Address: 0x008558E0 (FUN_008558E0, `msvc8::vector<
         * std::uint32_t>::uninit_fill_n` for the 4-byte dword element.
         * Reached from this instantiation's `insert(pos,count,value)`
         * grow/shift helper `FUN_008561D0` (uncited -- compiler emission,
         * no separate source), itself reached from `AppendDwordLaneRuntime`
         * (`Address: 0x00855150`, SimRecoveryRuntime.cpp) appending one
         * dword lane to a reflection-runtime `LegacyVectorStorageRuntime<
         * std::uint32_t>` on its capacity-exhausted path. Note:
         * `AppendDwordLaneRuntime`'s current `ReserveTrivialVector` helper
         * grows to exactly the requested size rather than this
         * instantiation's real 1.5x `_Insert_n` growth policy -- a
         * pre-existing simplification in that already-recovered caller, not
         * introduced by this citation and not something this citation
         * depends on being fixed. Previously duplicated here as lettered
         * lane `R`, `FillDwordSpanCountedLaneR`; removed from
         * `LegacyContainerFillLanes.cpp` in favor of this citation.)
         * Address: 0x00869C80 (FUN_00869C80, `msvc8::vector<Moho::
         * IWldTeardownCallback*>::uninit_fill_n` for the 4-byte pointer
         * element (`WldTeardownCallbackVector`, CWldSession.h). Reached
         * from this instantiation's `insert(pos,value)` grow/shift helper
         * `FUN_00869D30` (uncited -- compiler emission, no separate
         * source), itself reached from `push_back`'s grow path via
         * `WLD_AddOnTeardownCallback`'s `callbacks->push_back(callback)`
         * (CWldSession.cpp). Previously duplicated here as lettered lane
         * `S`, `FillDwordSpanCountedLaneS`; removed from
         * `LegacyContainerFillLanes.cpp` in favor of this citation.)
         * Address: 0x00879A80 (FUN_00879A80, `msvc8::vector<Moho::
         * CWldTerrainDecal*>::uninit_fill_n` for the 4-byte pointer element
         * (`Moho::CDecalManager::mDecals` @+0x10). Reached from this
         * instantiation's `_Insert_n` grow lane `FUN_0087A830` (cited
         * above); emitted via the recovered helper
         * `InsertNCopiesCWldTerrainDecalPtrVector` (CWldSplat.cpp) and via
         * `AppendDecal` on `CDecalManager::LoadDecal`/`NewSplat`'s
         * capacity-full path.)
         * Address: 0x00879ED0 (FUN_00879ED0, `msvc8::vector<Moho::
         * CDecalGroup*>::uninit_fill_n` for the 4-byte pointer element
         * (`Moho::CDecalManager::mDecalGroups`). Reached from this
         * instantiation's `_Insert_n` grow lane `FUN_0087B1C0` (cited above
         * on `uninit_move_n`).)
         * Address: 0x0087A310 (FUN_0087A310, `msvc8::vector<Moho::
         * CWldSplat*>::uninit_fill_n` for the 4-byte pointer element
         * (`Moho::CDecalManager::mSplats` @+0x48). Reached from this
         * instantiation's `_Insert_n` grow lane `FUN_0087BB40` (cited
         * above); emitted via the recovered helper
         * `InsertNCopiesCWldSplatPtrVector` (CWldSplat.cpp) and via
         * `AppendSplat` on `CDecalManager::NewSplat`'s capacity-full path.)
         * Address: 0x0088A2E0 (FUN_0088A2E0, `msvc8::vector<Moho::
         * WaveGenerator*>::uninit_fill_n` for the 4-byte pointer element.
         * Reached from this instantiation's `_Insert_n` grow lane
         * `FUN_0088A7B0` (cited above on `uninit_move_n`), WaveSystem.cpp.)
         * Address: 0x008D9D50 (FUN_008D9D50, `msvc8::vector<gpg::
         * RType*>::uninit_fill_n` for the 4-byte pointer element, expressed
         * over a `[begin,end)` pointer pair rather than a count at this call
         * site. Reached from this instantiation's `_Insert_n` grow lane
         * `FUN_008DD050` (cited above, the global reflection `TypeVec`);
         * emitted via `gpg::RType::RegisterType`'s `insert(end(), 1, this)`.)
         * Address: 0x008E9260 (FUN_008E9260, `msvc8::vector<
         * std::int32_t>::uninit_fill_n` for `gpg::gal::Head::validFormats2`
         * @+0x60, expressed over a `[begin,end)` pointer pair. Reached from
         * this instantiation's `_Insert_n` grow lane `FUN_008EF2B0` (cited
         * above); emitted via `gpg::gal::DeviceD3D9::BuildDeviceCapabilities`'s
         * `validFormats2.insert(end(),1,token)`, D3D9Interfaces.cpp.)
         * Address: 0x008E9280 (FUN_008E9280, `msvc8::vector<
         * std::int32_t>::uninit_fill_n` for `gpg::gal::Head::validFormats1`
         * @+0x70, the sibling of the entry immediately above. Reached from
         * this instantiation's `_Insert_n` grow lane `FUN_008EF500` (cited
         * above); emitted via the same `BuildDeviceCapabilities`'s
         * `validFormats1.insert(end(),1,token)`.)
         *
         * Address: 0x008E9230 (FUN_008E9230, `msvc8::vector<gpg::gal::
         * HeadAdapterMode>::uninit_fill_n` for the 12-byte `{width; height;
         * refreshRate}` element -- `[begin,end)` pointer-pair fill loop
         * (3-dword copy per iteration, no defensive null guard; verified
         * against the `.asm`). Reached from the `_Insert_n` grow core
         * `FUN_008EF010` (named within `FUN_008EFA50`'s citation above as
         * the tail-called, count=1 reallocation half of `insert(iterator,
         * const T&)`), itself reached from `push_back`'s capacity-full path
         * via `AppendHeadAdapterMode` (D3D9Interfaces.cpp). DB-integrity fix:
         * was duplicated as a standalone `FillDwordTripleRangeLaneA` free
         * function in `moho/containers/LegacyContainerFillLanesB.cpp`
         * (orphan -- anonymous-namespace, no source-level caller); removed
         * from there in favor of this citation.)
         * Address: 0x009324E0 (FUN_009324E0, `msvc8::vector<iterator>::
         * uninit_fill_n` for the 4-byte `_Nodeptr`-wrapper element -- the
         * HaStar cluster-cache bucket vector instantiation sibling to
         * `FUN_0092F9E0`'s `OccupationCacheRuntimeMap` above, this one for
         * `FUN_00933950` (cited above on `insert`). `[begin,end)`
         * pointer-pair fill loop, verified against the `.asm`; reached from
         * that `_Insert_n` core's in-place gap-fill branch. DB-integrity fix:
         * was duplicated as `FillDwordRangeByEndLaneG` in
         * `LegacyContainerFillLanesB.cpp` (orphan); removed from there.)
         * Address: 0x00936050 (FUN_00936050, `msvc8::vector<gpg::
         * ThreadCtxEntry*>::uninit_fill_n` for the 4-byte pointer element
         * (`gpg::ThreadState::mEntries`, `Logging.h`/`Logging.cpp`) --
         * `[begin,end)` pointer-pair fill loop, verified against the `.asm`;
         * the in-place branch's direct gap-fill call. Reached from the
         * `_Insert_n` core `FUN_00936FF0` (cited above on `insert`; itself
         * `skip` since `tls->mEntries.push_back(entry)` in
         * `gpg::PushThreadContext` is the whole family's programmer-written
         * source line).)
         * Address: 0x00936B00 (FUN_00936B00, the same `msvc8::vector<gpg::
         * ThreadCtxEntry*>::uninit_fill_n` instantiation's second,
         * byte-distinct emission -- `(dst, count, value)` counted-fill form
         * matching this member's own signature directly (`retn 0Ch`, three
         * stack args popped; verified against the `.asm`), used by
         * `FUN_00936FF0`'s reallocation-branch tail fill. Both
         * `FUN_00936050` and `FUN_00936B00` model this one member; recovered
         * together. DB-integrity fix: both were duplicated as
         * `FillDwordRangeByEndLaneH`/`FillDwordCountedLaneAA` in
         * `LegacyContainerFillLanesB.cpp` (orphans, never reached from that
         * file's own source); removed from there in favor of this citation.)
         * Address: 0x008F9A50 (FUN_008F9A50, `msvc8::vector<void*>::
         * uninit_fill_n` for the D3D10 backend swap-chain vector (`_Insert_n`
         * core `FUN_008FE010`, cited above on `insert`) -- `[begin,end)`
         * pointer-pair fill loop, verified against the `.asm`; the in-place
         * branch's direct gap-fill call.)
         * Address: 0x008FA970 (FUN_008FA970, the same D3D10 swap-chain
         * `msvc8::vector<void*>::uninit_fill_n` instantiation's counted-fill
         * sibling emission -- `(dst, count, value)` form, verified against
         * the `.asm`; same relationship to `FUN_008F9A50` as `FUN_00936B00`
         * has to `FUN_00936050` above. Reached from `FUN_008FE010`'s
         * reallocation-branch tail fill. DB-integrity fix: both were
         * duplicated as `FillDwordRangeByEndLaneD`/`FillDwordCountedLaneZ` in
         * `LegacyContainerFillLanesB.cpp` (orphans); removed from there in
         * favor of this citation.)
         * Address: 0x0094FE90 (FUN_0094FE90, `msvc8::vector<gpg::
         * TypeHandle>::uninit_fill_n` for the 8-byte `{type,version}`
         * element -- `[begin,end)` pointer-pair fill loop (2-dword copy per
         * iteration, no defensive null guard; verified against the `.asm`),
         * the missing fill step for the `_Insert_n` core `FUN_00951F30`
         * (cited above on `insert`) -- that entry's tail-shift is always
         * empty since `gpg::AppendTypeHandle` only ever inserts at `mLast`,
         * so this fill call is the entire visible effect of the grow path
         * once the allocate/tail-shift steps (`FUN_0094F1B0`/`FUN_00950670`,
         * cited there) are done. DB-integrity fix: was duplicated as
         * `FillDwordPairRangeLaneA` in `LegacyContainerFillLanesB.cpp`
         * (orphan); removed from there in favor of this citation.)
         *
         * Address: 0x00753AF0 (FUN_00753AF0, `msvc8::vector<moho::
         * SExtraUnitData>::uninit_fill_n` for the 0x20-byte element,
         * `Sim::mSyncSerializeGroup2`) -- placement-new copy-construct loop
         * with destroy-on-exception rollback, matching this member exactly.
         * Reached directly from `push_back` (`FUN_0074C160`, `n=1`) and
         * `insert` (`FUN_0074F3E0`, cited above), both independently reached
         * from `Sim::AdvanceBeat`.
         * Address: 0x0074DBF0 (FUN_0074DBF0, register-shape adapter --
         * forwards into `FUN_00753AF0` above)
         * Address: 0x00751800 (FUN_00751800, sibling register-shape
         * adapter, same forward)
         *
         * Address: 0x0077E720 (FUN_0077E720, `msvc8::vector<Moho::
         * SDecalInfo>::uninit_fill_n` for the 0x90-byte element,
         * `Moho::CDecalBuffer::mVisibleDecals`) -- `.c`-confirmed:
         * placement-new copy-construct loop (`SDecalInfo::SDecalInfo(dst,
         * value)` copy ctor per slot) with destroy-on-exception rollback
         * (destroys `[dst0, dst)` through `SDecalInfo::~SDecalInfo`,
         * 0x00742360, then rethrows via `_CxxThrowException`), matching
         * this member exactly. Reached directly from `push_back`
         * (`sub_77A0A0`, cited above, `n=1`) fast path, and from `insert`
         * (`sub_77B990`, cited above) reallocation-path gap-fill (`n=1`
         * there too -- both call sites fold `count` to the literal 1 this
         * element's only real caller ever uses).
         * Address: 0x0077AD30 (FUN_0077AD30, thiscall-shape adapter --
         * `.c`-confirmed one-statement tail-call, `LOBYTE(a1)=0;
         * sub_77E720(a2,a3,a1);`, forwarding into `FUN_0077E720` above with
         * a zeroed low byte on the reused register slot). Reached from
         * `insert`'s (`sub_77B990`, cited above) in-place branch gap-fill
         * step. DB-integrity fix: was `blocked` ("noreturn wrapper depends
         * on unresolved FUN_0077E720") -- `FUN_0077E720` was not actually
         * unresolved (see above); the dependency was already satisfied,
         * just uncited. Corrected to `recovered` in this pass.
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
         * Address: 0x00653F40 (FUN_00653F40, msvc8::vector<moho::SDebugWorldText>::
         * uninit_move_n for the 48-byte non-trivial element -- forward per-element
         * copy-construct loop over `[src, srcEnd)` into `dst` (position/style/depth
         * as raw field copies, `text` zeroed to empty SSO state then `assign`ed --
         * MSVC8 has no real move ctor for this type, so "move" degrades to copy,
         * matching `move_if_noexcept` on a non-nothrow-movable T), with a trailing
         * EH cleanup loop that destroys the already-constructed prefix and rethrows.
         * Reached via the thin dispatcher FUN_006539E0 from the `_Insert_n` grow
         * lane FUN_00653380, already cited above)
         * Address: 0x007FC2F0 (FUN_007FC2F0, msvc8::vector<moho::WRenViewportWorldViewParamRuntime>::
         * uninit_move_n for the 20-byte `{IRenderWorldView* view; int head; int depth;
         * boost::shared_ptr<TerrainCommon> terrain}` element -- range-form loop over
         * `[src, srcEnd)`, raw dword copy for view/head/depth/`terrain.px`, then
         * `terrain.pn` (the `sp_counted_base*` control block) copied and, when
         * non-null, refcount-bumped via `_InterlockedExchangeAdd` on the block's
         * `use_count_` at +4 -- Boost 1.34.1's vendored `shared_ptr` has no move
         * ctor, so `move_if_noexcept` degrades to copy here exactly as for
         * SDebugWorldText above, matching the binary's copy-with-refcount-bump shape
         * (same family as the SPendingPoseCopy/`shared_ptr<CAniPose>` uninit_copy_n
         * entry above). The `if (result)` null guard sits *inside* the loop for the
         * same reason as FUN_00549BC0's ResourceDeposit lane: the destination is
         * freshly-allocated storage the compiler cannot prove non-null. Reached from
         * `InsertWorldViewParamAt` (0x007FB060, WxRuntimeTypes.cpp)'s
         * `worldViews->push_back(entry)` capacity-full path, whose `insert(end(),1,
         * value)` full-reallocation branch moves the whole existing range with
         * `uninit_move_n(first_, cur, newBuf)`, via the thin argument-
         * reordering dispatcher `FUN_007FB890` (`return sub_7FC2F0(a3, a2,
         * a1);`) that `InsertWorldViewParamAt`'s own real body calls
         * directly.)
         * Address: 0x00813E40 (FUN_00813E40, msvc8::vector<boost::shared_ptr<
         * moho::ShoreCell>>::uninit_move_n register-shuffle wrapper for the
         * 8-byte `{ShoreCell* px; sp_counted_base* pn}` element -- same
         * pattern as FUN_005940F0 below: takes `first`/`dest` on the stack
         * (this member's two args are `first` and `first+elementSize`, i.e.
         * a single-element range) and forwards `(dest=eax, first=ecx,
         * last=esi)` into the range-copy body FUN_00814480 (`this`
         * unrecovered in this pass), whose loop copies `px`/`pn` per element
         * and, when `pn` is non-null, refcount-bumps the control block via
         * `lock xadd [pn+4]` -- Boost 1.34.1's vendored `shared_ptr` has no
         * move ctor, so `move_if_noexcept` degrades to copy here exactly as
         * for the `shared_ptr<TerrainCommon>` entry above. Called twice from
         * the `_Insert_n` grow lane FUN_00813900 (cited on `insert(pos,
         * count, value)` above): once for the tail>=count branch's
         * `uninit_move_n(oldLast-count, count, oldLast)` step (moving the
         * single trailing element past the old end, `last` supplied by the
         * caller's inherited `esi`), and once for the tail<count branch's
         * `uninit_move_n(insertAt, tail, insertAt+count)` step, which is a
         * no-op here since `tail==0` (both call sites land at `pos==end()`
         * in this instantiation, verified against FUN_00813900's own
         * `.asm`). Reached from `AppendShoreCellRef` (Shoreline.cpp)'s
         * `shorelineCells.push_back(cell)` on the capacity-full path.)
         * Address: 0x00885070 (FUN_00885070, msvc8::vector<msvc8::string>::
         * uninit_move_n for the 0x1C-byte `msvc8::string` element -- range-form
         * loop that default-tidies each destination slot in place
         * (`_Myres=15, _Mysize=0, _Bx._Buf[0]=0`, i.e. `msvc8::string`'s
         * `_Tidy`) and then calls `std::string::assign(dst, *src, 0, npos)`,
         * exactly `msvc8::string`'s own copy constructor inlined into the
         * loop body; a trailing SEH funclet (unreachable from the normal
         * control-flow graph, dispatched only on unwind) destroys the
         * already-constructed prefix via `sub_8846B0`
         * (`msvc8::string::tidy(true,0)`, already recovered in String.cpp)
         * and rethrows. This is the `_Insert_n` reallocation path's element
         * relocation step -- called twice from within `msvc8::vector<
         * msvc8::string>::_Insert_n` (FUN_00882BA0, at 0x00882CFE for the
         * head span `[first_, first_+offset)` and 0x00882D49 for the tail
         * span, which is always empty here because `resize(n, fillValue)`
         * inserts at `end()`), and twice more via the register-shape
         * adapter FUN_008837F0 (0x00882E1F / 0x00882EA6, also inside
         * FUN_00882BA0 -- the compiler folded the fast-path tail-shift's two
         * mutually exclusive branches into one shared local thunk). Reached
         * from `ResizeLegacyStringVectorExact`'s `outStrings.resize(n,
         * fillValue)` (CSaveGameRequestImpl.cpp:125). Sibling emission of
         * the already-recovered `wxUninitializedCopyMsvc8StringRange`
         * (FUN_00884FD0, WxRuntimeTypes.cpp), which is the same algorithm
         * instantiated at the vector-clone/copy-construction call site
         * instead of `_Insert_n`'s relocation step -- the two emissions are
         * not byte-identical (different register allocation from being
         * compiled as part of different enclosing functions) so `/OPT:ICF`
         * left them as separate symbols.
         * Address: 0x008837F0 (FUN_008837F0, the register-shape adapter into
         * FUN_00885070 described immediately above, reached from within
         * FUN_00882BA0 at both 0x00882E1F and 0x00882EA6.)
         *
         * Address: 0x005940F0 (FUN_005940F0, `uninit_move_n` for the same
         * 12-byte three-float element as `insert(iterator, const T&)`'s
         * FUN_00592460 above (`[first_, first_+offset)` -> `newBuf` prefix
         * copy). Register-shuffle wrapper: takes `first`/`dest` on the stack
         * and `last` passed through unmodified from its own caller's `edx`
         * (the reallocation branch computes the prefix length there before
         * the call), then forwards `(dest=eax, first=ecx, last=edx)` into
         * the range-copy body FUN_00595F10 -- a plain trivially-copyable
         * forward loop, `while (first != last) { copy 12 bytes; first +=
         * 0xC; dest += 0xC; }`. The local dword written and read back before
         * the call is dead in this instantiation (its low byte would be a
         * `bool` argument in the tree/node family this wrapper shape also
         * appears in, but the range-copy callee here never reads the stack
         * arg it is packaged with). Reached from FUN_00592460's reallocation
         * branch; see that citation above for the full caller chain.)
         * Address: 0x00537420 (FUN_00537420, `msvc8::vector<
         * Moho::RRuleGameRulesLuaExportBinding>::insert(pos, count,
         * value)`'s in-place tail-SHIFT-ASSIGN loop for the 16-byte
         * `RRuleGameRulesLuaExportBinding` element (`RRuleGameRules.h`) --
         * this is *not* `uninit_move_n`. It is this method's own
         * `tail >= count` branch's second step above: `for (i = tail -
         * count; i > 0; --i) insertAt[count + i - 1] =
         * std::move(insertAt[i - 1]);`, backward per-element ASSIGNMENT
         * over an already-live range, not construction into raw storage
         * (proven by the callee shapes below, which erase real,
         * currently-live tree content at the destination before
         * overwriting it -- erasing uninitialised memory would crash).
         * Reached from `FUN_0052DBE0` (`insert(pos, count, value)`, cited
         * above) at 0x0052DE2B via the register-shape wrapper
         * `FUN_005334B0` (cited immediately below) -- from the in-place,
         * capacity-already-sufficient branch (no `operator new` between
         * `loc_52DDA0` and this call), *not* the reallocation branch as a
         * prior pass on this citation mis-stated; the reallocation branch
         * relocates elements through `FUN_00537860` instead (unrecovered,
         * out of scope here).
         *
         * Per destination slot the loop performs a raw dword copy of
         * `mRootState` (offset +0x00, trivially copyable) followed by
         * `mPendingBlueprintOrdinals`'s (`msvc8::set<uint32_t>`, offset
         * +0x04) implicit `operator=`, inlined here rather than called as
         * a standalone function -- the `cmp edi,ebx` / `jz` guarding the
         * two callee calls is `rb_tree::operator=`'s own `if (this !=
         * &other)` self-assignment check (`operator=`, RbTree.h), compiled
         * per-slot because the compiler cannot prove `&dest.tree !=
         * &src.tree` at compile time; it is only taken (calls skipped) in
         * the degenerate `insertAt == oldLast` case. When it fires:
         *   - `sub_52D9C0` (0x0052D9C0) is the *same* shared `erase_range`
         *     body already cited on that member (RbTree.h) -- here erasing
         *     the DESTINATION slot's own currently-live tree
         *     (`erase_range(leftmost(), header())`, always the whole-tree
         *     fast path) before it is overwritten. This is the load-
         *     bearing evidence that the destination is live, already-
         *     constructed data being reassigned, not uninitialised memory
         *     being constructed into -- a prior pass on this citation
         *     misread this call as a "copy-construct helper", which is not
         *     what `erase_range` does anywhere else in this codebase.
         *   - `sub_530EE0` (0x00530EE0) is `copy_from`'s emission for this
         *     same instantiation (cited on that member, RbTree.h) -- deep-
         *     clones the source slot's tree into the now-empty destination
         *     and re-seats `header()->left`/`header()->right`. A prior
         *     pass on this citation called it "a destroy call on the
         *     source slot"; its own `.asm` has no `operator delete`/free of
         *     any kind and instead walks live node pointers and calls two
         *     more real engine helpers (`sub_531B30`, cited on `copy_from`,
         *     RbTree.h) -- it is a copy, not a destroy, and it reads from
         *     the source side while writing the destination side.
         *
         * Net effect matches `insertAt[count+i-1] = insertAt[i-1]` exactly:
         * each destination slot's own prior tree is torn down and replaced
         * by a structural clone of the source slot's tree, once per slot,
         * walking backward from `oldLast` toward `insertAt` (the same
         * direction this method's own `tail >= count` branch shifts in, for
         * the same reason: overlapping source/destination ranges within one
         * live buffer). Also reached, unverified in this pass, from
         * `FUN_00536F70` at 0x00536F90 -- a second, sibling call site on
         * the same body not further investigated here.)
         * Address: 0x005334B0 (FUN_005334B0, the register-shape wrapper
         * into `FUN_00537420` described immediately above -- repackages the
         * same three range pointers from its own incoming stack arguments
         * into `FUN_00537420`'s eax/stack calling convention, no logic of
         * its own beyond that (same pattern as this file's other
         * register-shape adapters, e.g. `FUN_008837F0` and `FUN_005940F0`
         * above). Sole caller is `FUN_0052DBE0` at 0x0052DE2B, from the
         * in-place tail-shift branch described above.)
         *
         * Address: 0x00706900 (FUN_00706900,
         * msvc8::vector<SEntitySetTemplateUnit>::uninit_move_n for the
         * 0x28-byte element, forward-direction shape -- per slot,
         * default-constructs the destination node in place (self-referential
         * list-link pointers, inline-storage fastvector header) then calls
         * `gpg::fastvector_Entity::AddAll(dst.mVec, src.mVec)` to copy the
         * payload, with both cursors advancing together by 0x28; a trailing
         * `while(1) { destroy already-built prefix via FUN_00705B30;
         * rethrow; }` funclet is the EH-unwind cleanup on a mid-range throw.
         * Reached via the thin trampoline FUN_007046C0.)
         * Address: 0x00705980 (FUN_00705980, a second, independently-emitted
         * copy of the same `uninit_move_n` shape for the same element --
         * identical default-construct + `AddAll` + EH-unwind-destroy body,
         * just a countdown loop (`while(v4) { ...; --v4; }`) instead of a
         * `while(cursor != end)` forward loop. Reached via the thin
         * trampoline FUN_00703B90.)
         * Address: 0x007046C0 (FUN_007046C0, thin argument-reordering
         * trampoline into FUN_00706900)
         * Address: 0x00703B90 (FUN_00703B90, thin argument-reordering
         * trampoline into FUN_00705980)
         * Both pairs are called from `insert(pos, count, value)`'s
         * reallocation branch (FUN_007030C0) to move the pre-gap and
         * post-gap live ranges into the freshly allocated buffer, growing
         * `CArmyImpl::UnitCategorySets`.
         *
         * Address: 0x00536FF0 (FUN_00536FF0, `msvc8::vector<
         * Moho::RBlueprint*>::uninit_move_n` for the trivially-relocatable
         * 4-byte pointer element -- `memmove_s(dst, n*4, src, n*4)` range
         * form, `[Source,a3) -> Destination`. Reached from the `_Insert_n`
         * grow lane `FUN_00535D60` (already recovered above).)
         * Address: 0x0087D320 (FUN_0087D320, `msvc8::vector<
         * Moho::CDecalGroup*>::uninit_move_n` for the same 4-byte pointer
         * shape. Reached from the `_Insert_n` grow lane `FUN_0087B1C0`
         * (already recovered above), `Moho::CDecalManager::mDecalGroups`.)
         * Address: 0x0087D3F0 (FUN_0087D3F0, `msvc8::vector<
         * Moho::CWldSplat*>::uninit_move_n` for the same 4-byte pointer
         * shape. Reached from the `_Insert_n` grow lane `FUN_0087BB40`
         * (already recovered above), `Moho::CDecalManager::mSplats`.)
         * Address: 0x0088AEE0 (FUN_0088AEE0, `msvc8::vector<
         * Moho::WaveGenerator*>::uninit_move_n` for the same 4-byte pointer
         * shape. Reached from the `_Insert_n` grow lane `FUN_0088A7B0`
         * (already recovered above), `WaveSystem.cpp`.)
         * Address: 0x008DB240 (FUN_008DB240, `msvc8::vector<gpg::RType*>::
         * uninit_move_n` for the same 4-byte pointer shape. Reached from the
         * `_Insert_n` grow lane `FUN_008DD050` (already recovered above),
         * the global reflection TypeVec.)
         * Address: 0x008FA8F0 (FUN_008FA8F0, `msvc8::vector<void*>::
         * uninit_move_n` for the same 4-byte pointer shape, the D3D10
         * backend swap-chain vector. Reached from the `_Insert_n` grow lane
         * `FUN_008FE010` (already recovered above).)
         * Address: 0x00831730 (FUN_00831730, `msvc8::vector<UICommandGraph::
         * CommandGraphEdge*>::uninit_move_n` for the same 4-byte pointer
         * shape, `memmove_s`-based. Reached from this instantiation's
         * `_Insert_n`, `FUN_0082E950` (cited above on `insert`).)
         * Address: 0x00950670 (FUN_00950670, `msvc8::vector<gpg::TypeHandle>::
         * uninit_move_n` for the 8-byte `{type,version}` element -- backward
         * `[src,srcEnd)` walk, raw 8-byte copy. Already named (not
         * previously address-cited) on this instantiation's `_Insert_n`
         * entry above (`FUN_00951F30`) as "the in-place growth path's
         * tail-shift... corresponds to FUN_00950670" -- degenerate/empty
         * in practice since `gpg::AppendTypeHandle`'s sole call site always
         * inserts at `mLast`, but the compiled body is real and reached.)
         * Address: 0x00814480 (FUN_00814480, `msvc8::vector<
         * boost::shared_ptr<moho::ShoreCell>>::uninit_move_n` -- the
         * range-copy body FUN_00813E40's register-shuffle wrapper (cited
         * above) forwards into; per-element `{px,pn}` copy with an
         * `_InterlockedExchangeAdd`-based refcount bump on `pn` when
         * non-null, matching Boost 1.34.1's copy-degrades-move shape already
         * documented for the other `shared_ptr`/`weak_ptr` entries in this
         * method. Reached (via FUN_00813E40) from the `_Insert_n` grow lane
         * `FUN_00813900` (already recovered above), `AppendShoreCellRef`'s
         * (Shoreline.cpp) `shorelineCells.push_back(cell)` capacity-full
         * path.)
         * Address: 0x00857A90 (FUN_00857A90, `msvc8::vector<boost::
         * shared_ptr<moho::MeshInstance>>::uninit_move_n` -- the same
         * per-element `{px,pn}` copy-with-refcount-bump shape as the
         * ShoreCell entry above (forward `[src,srcEnd)` walk, `pn!=0`
         * guards an `_InterlockedExchangeAdd(pn+4,1)` add-ref per slot).
         * Reached via the thiscall bridge FUN_008571F0 (`LOBYTE(this)=0;
         * return sub_857A90(a3,this,this);`, the same register-shape-
         * adapter idiom as this method's other bridges) from `_Insert_n`
         * FUN_00855DF0 (cited above on `insert`), `mMeshes`'s in-place
         * tail-relocate and reallocation head/tail-copy steps.)
         * Address: 0x007BED70 (FUN_007BED70, msvc8::vector<Moho::
         * SNetCommandArg>::uninit_move_n (copy-construct, no real move --
         * see this method's own note below) for the 36-byte element. Loops
         * `[srcBegin@ecx, srcEnd@edx)` (0x24 stride) constructing each
         * destination slot through the per-element helper FUN_007BE4B0
         * (writes `mType`/`mNum` as raw dwords, resets the `mStr` header to
         * empty-SSO state, then calls `std::string::assign` -- exactly this
         * method's placement-new-then-copy-ctor shape, just with the SSO
         * reset inlined instead of a separate ctor call), and on exception
         * destroys the already-constructed prefix through FUN_007BDBB0
         * (this element's `~msvc8::string`-equivalent: frees the heap
         * buffer when `_Myres >= 0x10`, resets to empty SSO) before
         * rethrowing -- matching this method's own
         * `try { ... } catch (...) { destroy_n(dst, i); throw; }` shape.
         * All 4 of FUN_007BE4B0's own xrefs and all 3 of FUN_007BDBB0's are
         * this address family (FUN_007BD810/FUN_007BDBA0/FUN_007BDE40/
         * FUN_007BED70 for the construct step; the matching
         * FUN_007BD810/FUN_007BDE40/FUN_007BED70 rollback blocks for the
         * destroy step) -- CGpgNetInterface.h separately cites FUN_007BE4B0
         * as `SNetCommandArg::operator=` (ICF-plausible: `operator=`'s
         * `reset_and_assign`-then-copy shape folds to the same bytes as a
         * fresh-slot construct for this SSO string type), but that citation
         * has no independent callsite evidence of its own beyond this
         * construct-helper role; treat the range-copy attribution here as
         * the evidence-backed one. Called twice from `_Insert_n`'s
         * reallocation branch, FUN_007BBD60 (cited above on `insert`): once
         * for the `[first,pos)` prefix, once for the `[pos,last)` suffix.
         * Also reached, via the register-shape adapters FUN_007BD930/
         * FUN_007BCD00/FUN_007BEC10, from three call sites this recovery
         * previously mis-attributed to a same-size `SSTICommandSource`
         * copy-with-rollback in SSTICommandSource.cpp
         * (`CopySSTICommandSourceRangeWithRollback` and its three
         * `RegisterContextAdapter` siblings) -- `SSTICommandSource` is also
         * 36 bytes but has a *different* field layout (`mIndex` at +0x00,
         * `mName` string at +0x04, `mTimeouts` at +0x20; see
         * SSTICommandSource.h), so it cannot share this address's compiled
         * body, which explicitly writes two leading dwords (+0x00/+0x04)
         * before touching the string at +0x08 and never touches +0x20 at
         * all -- that shape only matches `SNetCommandArg`
         * (`{EType mType; int32_t mNum; msvc8::string mStr}`,
         * CGpgNetInterface.h). Corrected in SSTICommandSource.cpp alongside
         * this citation.)
         * Address: 0x007BCD00 (FUN_007BCD00, the single-element
         * specialization of the `uninit_move_n` realization above --
         * forwards `(srcBegin=oldLast-36, srcEnd=oldLast, dest=oldLast)`
         * into FUN_007BED70 to relocate exactly the current last live
         * element into the freshly-grown one-past-end slot. Called once
         * from `_Insert_n`'s in-place middle-insert branch, FUN_007BBD60
         * (cited above on `insert`) -- the "construct the vacated back-slot
         * from the old last element" step this method's own
         * `uninit_move_n(oldLast - count, count, oldLast)` call models.
         * Same SSTICommandSource mis-attribution and correction as
         * FUN_007BED70 immediately above.)
         * Address: 0x0092D7D0 (FUN_0092D7D0, `msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::uninit_move_n` for the
         * 12-byte element -- per-element 3-dword copy loop with a defensive
         * `if (result)` null-check per iteration (same "defensive-null"
         * shape documented elsewhere on this member), used both for the
         * reallocation branch's head/tail relocation and, via its alias
         * `FUN_0092ED60` (a plain tail-call, no logic of its own), for the
         * in-place branch's move-the-trailing-elements step. Reached from
         * the `_Insert_n` grow core `FUN_0092F630`, cited above on
         * `insert`.)
         * Address: 0x0092D840 (FUN_0092D840, the sibling `msvc8::vector<gpg::
         * HaStar::ClusterSearchOpenHeapEntryRuntime>::uninit_move_n` for the
         * 12-byte open-heap-entry element -- same per-element defensive-null
         * loop shape, reached both directly and via its alias `FUN_0092EEB0`
         * from the `_Insert_n` grow core `FUN_0092F240`, cited above on
         * `insert`.)
         * Address: 0x00445F20 (FUN_00445F20, `msvc8::vector<std::int32_t>::
         * uninit_move_n` for the handle-to-heap-index reverse map
         * (`ClusterSearchOpenHeapRuntime::mHandleToHeapIndex`, Cluster.cpp)
         * -- this element type *is* the STL's trivial-scalar fast-copy
         * candidate, so the compiled body is a direct `memmove_s` wrapper
         * (`if (count) memmove_s(dst, count*4, src, count*4);`) rather than a
         * per-element loop, matching this member's own `if constexpr
         * (is_trivially_copyable_v<T>) { std::memcpy(...); }` fast path
         * (`memmove_s`/`memcpy` are behaviourally interchangeable here since
         * every call site relocates into non-overlapping freshly-allocated
         * storage). The same symbol also serves the in-place branch's
         * tail-shift step (`std::memmove` in that branch's own `if
         * constexpr` arm) -- one compiled `memmove_s` wrapper backs both
         * call shapes for this element. Reached from the `_Insert_n` grow
         * core `FUN_004451A0`, cited above on `insert`.)
         * Address: 0x0084F940 (FUN_0084F940, `msvc8::vector<wxWindowBase*>::
         * uninit_move_n` for `SuspendInputWindowEventHandlersAndFlushQueue`'s
         * per-window saved-handler vector (`UiRuntimeTypes.cpp`) -- same
         * trivial-scalar shape as `FUN_00445F20` immediately above: `count =
         * (rangeEnd-rangeBegin)>>2`, `memmove_s(dst, count*4, rangeBegin,
         * count*4)` when `count != 0`, returns `dst + count*4`. Reached from
         * the single-value `insert(pos, value)` overload's capacity-available
         * branch, `FUN_0084F200` (cited below on that overload) -- there it
         * serves as the "move the current last element into the freshly
         * grown one-past-end slot" step (`count = 1`), the same role
         * `FUN_007BCD00` documents above for the 36-byte `SNetCommandArg`
         * element. DB previously mis-attributed this token to
         * `CrtRuntimeHelpers.cpp` with no real citation there ("DB-integrity
         * bulk fix 2026-08-24" boilerplate contamination documented for
         * several other tokens this session); corrected to `recovered` here.)
         *
         * Address: 0x00936990 (FUN_00936990, `msvc8::vector<gpg::
         * ThreadCtxEntry*>::uninit_move_n` for the 4-byte pointer element --
         * `gpg::ThreadState::mEntries`, `Logging.h`. `memmove_s(dst, n*4,
         * src, n*4)` range form, `[Source,SourceEnd) -> Destination`,
         * returning `Destination + n` -- confirmed against its own `.c`:
         * `if ((a2-Source)>>2) memmove_s(Destination, 4*((a2-Source)>>2),
         * Source, 4*((a2-Source)>>2)); return &Destination[4*((a2-Source)>>2)];`.
         * Reached from this instantiation's `_Insert_n` (`FUN_00936FF0`,
         * cited above on `insert`) three times: twice for the in-place
         * tail-shift (degenerate/zero-length in practice, since this
         * vector's sole mutator `PushThreadContext`/`mEntries.push_back`
         * always inserts at `end()` -- same "compiled but not separately
         * exercised by the one real call site" shape already documented on
         * this member's other `push_back`-only instantiations), and once
         * (twice, for the pre-gap/post-gap halves) for the reallocation
         * branch's relocate-into-new-buffer step, which real `push_back`
         * growth does exercise. Previously mass-mis-attributed to
         * `CrtRuntimeHelpers.cpp` by the 2026-08-24 DB-integrity bulk pass
         * (address not present in that file); `gpg::ThreadState` was also
         * a hand-rolled `begin`/`end`/`cap` triple with its own doubling
         * (not MSVC8's real ~1.5x) growth helper at the time, corrected to
         * `msvc8::vector<ThreadCtxEntry*>` alongside this citation so the
         * real call site this member documents now actually exists in
         * source (`Logging.cpp`'s `PushThreadContext`).
         *
         * NOTE on why this is `uninit_move_n` and not a true move: proving
         * this address is what pinned down a real divergence in this
         * template. `msvc8::string` declares a `noexcept` move constructor
         * (String.h) added purely for reconstruction-side leak prevention --
         * MSVC8's real `std::basic_string` had no move operations at all in
         * this C++03-era binary (see the comment on that ctor). Before the
         * fix below, `std::move_if_noexcept(src[i])` would have selected
         * that move ctor here and produced a buffer-steal, not the
         * default-tidy-then-assign shape this address actually has. No
         * currently-cited `uninit_move_n` instantiation relies on real move
         * behaviour (shared_ptr and SDebugWorldText above both explicitly
         * degrade to copy already), so forcing copy unconditionally matches
         * every existing citation and fixes this one.
         *
         * Uninitialized move (or copy if non-movable) N elements src->dst.
         * Used by `insert(pos, count, value)` to shift the tail and to
         * populate the reallocated buffer's head/tail spans.
         *
         * MSVC8/C++03 vector growth never moved elements -- there was no
         * move constructor to move with -- so the relocation step always
         * copy-constructed the old element into the new slot and destroyed
         * the old one afterwards. Some element types in this reconstruction
         * have since gained a real (modern, `noexcept`) move constructor for
         * reasons unrelated to binary fidelity (e.g. `msvc8::string`, added
         * to stop leaks from the reconstruction's missing destructor). Using
         * `std::move_if_noexcept` here would let such a type's move ctor
         * silently take over this loop and diverge from the binary, which is
         * exactly what happened at FUN_00885070 above. Always copy-construct
         * instead, matching every emission seen for this member so far.
         *
         * Address: 0x00538040 (FUN_00538040, sub_538040) -- range-form,
         * advance-returning calling-convention variant of this member for
         * `msvc8::vector<const char*>` (4-byte trivially-copyable pointer
         * element; `CAniSkel.cpp`'s `FillSScmBoneNamePointers` scratch
         * vector). Takes `(dst, first, last)` instead of `(src, n, dst)`
         * and returns `dst + (last-first)` instead of `void` -- confirmed
         * against the `.asm`: `n = (last-first)>>2; if (n) memmove_s(dst,
         * 4n, first, 4n); return dst+4n;`, the same trivially-copyable
         * `memmove` fast path this member's `if constexpr
         * (is_trivially_copyable_v<T>)` branch takes, just addressed by a
         * range instead of a count. Reached from `_Insert_n`'s emission for
         * this instantiation (`FUN_00537C60`, cited below on `insert`) as
         * its tail-shift step -- a structural no-op for this instantiation's
         * only live caller (`resize`, which always inserts at `end()`, so
         * `tail == 0`), present because the emission is the general
         * insert-at-any-position shape. Previously mis-tracked `blocked`
         * citing `CrtRuntimeHelpers.cpp` boilerplate the address never
         * appeared in.
         *
         * Address: 0x00733A80 (FUN_00733A80, sub_733A80) -- calling-
         * convention bridge into `FUN_00734440` (this instantiation's real
         * move core, not yet individually recovered) for `msvc8::vector<
         * PlatoonUnitSearchEntry>` (8-byte `{Unit*, float}` element;
         * `CPlatoon.cpp`'s `AppendPlatoonUnitSearchEntry`/
         * `cfunc_CPlatoonFormPlatoonL` nearest-first candidate scratch
         * vector). A pure register/stack reshuffle with no logic of its
         * own -- 15 bytes of setup, one `call FUN_00734440`, `retn 8` --
         * confirmed against the `.asm`. Called twice from `insert(pos,
         * value)`'s emission for this instantiation (`FUN_007336C0`, cited
         * above): once in the in-place branch's `tail > 0` sub-case as
         * `sub_733A80(oldLast-8, oldLast)`, moving the current last
         * element into the freshly grown slot (this member's
         * `uninit_move_n(oldLast-1, 1, oldLast)` shape for `count=1`), and
         * once in the `tail == 0` (append) sub-case as `sub_733A80(pos,
         * pos+8)`, a zero-length structural no-op present only because the
         * emission is the general insert-at-any-position shape. Previously
         * mis-tracked `blocked` citing `CrtRuntimeHelpers.cpp` boilerplate
         * the address never appeared in.
         *
         * Address: 0x0092ED90 (FUN_0092ED90, sub_92ED90) -- the `__stdcall`
         * calling-convention entry `insert`'s in-place branches call for
         * this instantiation's `uninit_move_n` (`ClusterInternalCache<
         * gpg::HaStar::OccupationData>::mVec`, `OccupationCacheRuntimeMap`,
         * 4-byte `iterator` element -- same instantiation as `insert`'s
         * `FUN_0092F9E0` above). Forwards straight into the shared 4-byte-
         * stride forward-copy primitive `FUN_0092D810` (already `skip`, an
         * ICF twin of `FUN_008D8190`) -- a real tail-call reusing that
         * primitive's body, not an ICF fold (the differing `__stdcall`/
         * `__cdecl` prologues keep the two byte-distinct). Called from
         * `FUN_0092F9E0`'s tail>=count branch (`uninit_move_n(oldLast-count,
         * count, oldLast)`) and tail<count branch (`uninit_move_n(insertAt,
         * tail, insertAt+count)`); that same instantiation's reallocation
         * branch calls `FUN_0092D810` directly instead of through this
         * trampoline.)
         *
         * Address: 0x0086A0B0 (FUN_0086A0B0, sub_86A0B0) --
         * `msvc8::vector<T*>::uninit_move_n` for a 4-byte pointer element:
         * `count=(a3-src)>>2; if (count) memmove_s(dst, 4*count, src,
         * 4*count); return dst+4*count;` -- trivially-relocatable-element
         * move via `memmove_s`, matching this member's fast path exactly.
         * Sole caller `FUN_00869D30` is already `skip`-tagged (RULE ONE
         * compiler/template emission, `vector<T*>::_Insert` single-element,
         * stride 4, canonical home `Vector.h`).
         *
         * Address: 0x00650160 (FUN_00650160, sub_650160) --
         * `msvc8::vector<moho::SDebugScreenText>::uninit_move_n` for the
         * 0x48-byte element (`CDebugCanvas::screenText`). `.asm`-confirmed
         * shape: `ECX=srcBegin` (register), stack args
         * `(arg_0=srcEnd, arg_4=dstBegin)`; loops `while (src != srcEnd) {
         * copy-construct *dst from *src via FUN_0064EC50; src+=0x48;
         * dst+=0x48; }`, matching this member's non-trivial-`T` branch
         * exactly (`::new (dst+i) T(src[i])` with `src[i]` an lvalue --
         * VC8/2007 predates move semantics, so this member's "move" of the
         * live range during grow/insert is a true copy through
         * `SDebugScreenText`'s compiler-generated copy ctor `FUN_0064EC50`,
         * cited on `SDebugScreenText.h`). On exception mid-loop, destroys
         * the constructed destination prefix through the element dtor
         * `FUN_00453710` (already `skip`-tagged) and rethrows -- the same
         * EH-cleanup shape as `uninit_fill_n`'s `FUN_0064F910` above.
         * Called directly from `_Insert_n`'s (`FUN_0064E490`, cited above
         * on `insert(pos,count,value)`) reallocation branch to relocate
         * `[_Myfirst, pos)` into the new buffer. DB-integrity fix: was
         * mis-tagged `external_dependency` ("All-external-callees thunk...
         * no Moho/gpg engine references") -- its only non-CRT callee,
         * `FUN_0064EC50`, is this project's own `SDebugScreenText` copy
         * ctor, not third-party runtime.
         * Address: 0x0064F720 (FUN_0064F720, sub_64F720) -- a
         * calling-convention adapter into `FUN_00650160` above, for the
         * same `SDebugScreenText` specialization (`__fastcall`
         * register/stack reshuffle, no logic of its own, matching the
         * adapter idiom already documented throughout this file, e.g.
         * `FUN_00688DF0`/`FUN_0092ED90` above). Called twice from
         * `_Insert_n` `FUN_0064E490`: once in the reallocation branch's
         * tail-relocate step, and once in the at-end sub-branch as a
         * degenerate `sub_64F720(pos, pos+0x48)` empty-range no-op
         * (present only because this is the shared general-position
         * emission -- the same "harmless same-value rewrite on the at-end
         * branch" shape already documented on the `SDesyncInfo`
         * instantiation above). DB-integrity fix: was mis-tagged `skip`
         * ("1-statement tail-call thunk (compiler-emitted ABI shim)") with
         * no element-type identification; corrected to a real,
         * address-cited adapter.
         */
        static void uninit_move_n(T* src, const std::size_t n, T* dst) {
            if constexpr (std::is_trivially_copyable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                std::size_t i = 0;
                try {
                    for (; i < n; ++i) {
                        ::new (static_cast<void*>(dst + i)) T(src[i]);
                    }
                } catch (...) {
                    destroy_n(dst, i);
                    throw;
                }
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
         * Address: 0x005C9E10 (FUN_005C9E10, sibling register-shape adapter for
         * FUN_005CD1F0 -- tail-calls it with the same value in both source
         * cursor slots and both destination cursor slots (`sub_5CD1F0(a2, a2,
         * this, this)`, `this`'s low byte cleared, upper bits preserved as
         * the real pointer), i.e. the degenerate empty-range call this
         * calling convention produces when the shift distance is zero.
         * Reached from the same `_Insert_n` grow core FUN_005C68E0 as
         * FUN_005C9E00.)
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
         * Address: 0x0076AAD0 (FUN_0076AAD0, the `std::copy_backward` lane for
         * `gpg::AStarOpenHeap<TCell>::Entry` (the same 12-byte `{float; AStarNode<TCell>*;
         * std::int32_t}` element as FUN_0076AAB0 above) -- walks two cursors downward
         * together (`dst -= 0x0C; src -= 0x0C;`), copying the trivially-copyable
         * element three dwords at a time. Called from the `insert(pos, 1, value)`
         * core FUN_00769F60 (already `recovered`, cited on `push_back` above) to
         * shift the live tail right by one slot, immediately before its
         * `uninit_fill_n` sibling FUN_0076AAB0 (cited above) writes the newly
         * inserted entry into the vacated gap. Source-level invocation:
         * `mEntries.push_back(entry)` in `gpg::AStarOpenHeap<TCell>::Push`,
         * `AStarSearch.h`)
         * Address: 0x00548C00 (FUN_00548C00, the `std::copy` emission for the
         * 20-byte `Moho::ResourceDeposit` -- the same five-dword stride-0x14
         * loop as FUN_00549BC0 but with all three cursors in registers and
         * **no** null guard, because here the destination is already-live
         * storage. Used by `resize`'s shrink branch (FUN_00547F20, to compute
         * the new `_Mylast`) and three times by `operator=` (FUN_00548ED0) for
         * its assign-over-the-retained-prefix paths.)
         *
         * Assign n elements from src to dst (dst already constructed)
         *
         * Address: 0x006DE9F0 (FUN_006DE9F0, the `std::copy` emission for the
         * 0x28-byte `Moho::EntityCategorySet` -- per-element `BVSet::operator=`,
         * which copies the universe handle and first-word index and forwards the
         * words to `gpg::fastvector_uint::cpy` at 0x004028E0)
         * Address: 0x006DDA60 (FUN_006DDA60, register-shape adapter for FUN_006DE9F0)
         * Address: 0x006DFAD0 (FUN_006DFAD0, the matching `std::copy_backward`
         * emission -- same per-element assign, walked in reverse so an
         * overlapping shift cannot corrupt the tail)
         * Address: 0x006DDC50 (FUN_006DDC50, register-shape adapter for FUN_006DFAD0)
         * Address: 0x006DEBF0 (FUN_006DEBF0, the same assign emitted a third
         * time, bounded by the destination range rather than the source)
         * Address: 0x0085A9F0 (FUN_0085A9F0 — 0x10-byte element, the
         * formation-preview ghost pair; the single-slot shared-handle assign
         * the erase shift-down loop at FUN_0085A130 drives)
         * Address: 0x005CBDE0 (FUN_005CBDE0 — 568-byte (0x238)
         * `Moho::SUnitVariableUpdateEntry`: per-element loop assigning the
         * leading key dword directly, forwarding the `SSTIUnitVariableData`
         * payload at `+0x08` to its own `Assign` member, then the trailing
         * dword at `+0x230` — the non-trivial per-field assign this
         * element's `is_trivially_copy_assignable_v<T>` branch takes.
         * Reached from the `_Insert_n` grow lane FUN_005C68E0, already
         * cited above.)
         * Address: 0x0084F820 (FUN_0084F820 — 16-byte `msvc8::vector<
         * wxWindowBase*>` element (a nested vector, not a POD struct;
         * `wxWindowBase*` is this codebase's stand-in for the real wx
         * `wxEvtHandler*`, see the note on `operator=` above): pointer-walk
         * loop form (`for (; src != srcEnd; dst += 16) dst[0..3] = *src++`,
         * IDA shows the two cursors threaded through registers rather than
         * an index) calling this element type's own `operator=`
         * (`FUN_0084FF80`, cited above on `operator=`) per slot -- the
         * non-trivial branch here because a `vector<T>` element owns a heap
         * buffer and is not `is_trivially_copy_assignable_v`. Reached from
         * the outer `msvc8::vector<msvc8::vector<wxWindowBase*>>`'s
         * grow-relocate path (`FUN_0084EE20`, not yet independently
         * address-annotated) when `moho::
         * SuspendInputWindowEventHandlersAndFlushQueue`'s
         * `suspended.resize(g_UIManager->mInputWindows.size())` call
         * instantiates it (UiRuntimeTypes.cpp).)
         *
         * Address: 0x005CD100 (FUN_005CD100, sub_5CD100) -- backward
         * (`dst -= 28`/`src -= 28`) tail-shift-and-reassign loop for
         * `Moho::SCreateUnitParams`'s 0x1C-byte element (`SimDriver.h`),
         * the same element identified on `uninit_copy_n`'s `FUN_005CDEF0`/
         * `insert(pos,count,value)`'s `FUN_005C6580`/`destroy_range`'s
         * `FUN_005CC280` above (3-dword header, tag byte, raw pointer +
         * `mConstDat.mStatsRoot` refcount-block-pointer handle pair,
         * trailing byte). Unlike the
         * plain-copy `uninit_copy_n` shape, this member does REAL
         * assignment semantics per slot: `_InterlockedExchangeAdd`-bumps
         * the incoming handle's refcount, and if the outgoing slot's own
         * old refcount hits zero on release, dispatches two virtual calls
         * through its vtable (`vtbl[1]`/`vtbl[2]`) before overwriting --
         * matching a `boost::shared_ptr`/`weak_ptr`-style full
         * release-then-reassign, not a blind relocate. Reached from this
         * instantiation's own `sub_5C9DA0` (`(a1,a2,a3) -> sub_5CD100(a1,
         * a3)`), itself reached from `insert(pos,count,value)`'s
         * `FUN_005C6580` above (`insert`'s in-place-shift branch calling
         * `copy_or_move_assign` on the pre-move tail, matching this
         * member's non-trivial branch exactly since the element owns a
         * refcounted handle and is not `is_trivially_copy_assignable_v`).
         *
         * Address: 0x00755DE0 (FUN_00755DE0, `msvc8::vector<moho::
         * SExtraUnitData>::copy_or_move_assign` forward emission for the
         * 0x20-byte element, `Sim::mSyncSerializeGroup2`) -- per-element
         * forward assign loop over already-live destination slots (assigns
         * the `pairs` sub-vector then the `unitEntityId` tag, matching the
         * compiler-generated `SExtraUnitData::operator=` a non-trivially-
         * copy-assignable element takes here). Reached directly from
         * `operator=` (`FUN_007530C0`, cited above, both its
         * source-fits-in-capacity assign-over branch and, via its
         * self-clear delegate `FUN_007536D0`, the empty-source branch),
         * itself confirmed via a real, direct `.xrefs.txt` code xref from
         * `Moho::CWldSession::DoBeat`.
         * Address: 0x007549D0 (FUN_007549D0, register-shape sibling of
         * `FUN_00755DE0` -- reached from `operator=`'s
         * source-longer-than-capacity branch to assign over the retained
         * prefix before uninit-copying the excess tail)
         */
        static void copy_or_move_assign(T* dst, const T* src, const std::size_t n) {
            if constexpr (std::is_trivially_copy_assignable_v<T>) {
                std::memcpy(dst, src, n * sizeof(T));
            } else {
                for (std::size_t i = 0; i < n; ++i) dst[i] = src[i];
            }
        }

    public:
        /**
         * The VC8 `vector<T>::_Grow_to(_Count)` lane.
         *
         * MSVC8 grows by **1.5x** (`capacity() + capacity() / 2`), not by
         * doubling, clamping to 0 on max_size overflow and flooring to the
         * requested count. Every recovered `_Insert_n` body in this binary
         * shows the same `shr reg, 1` + `add` pair -- e.g. `0x005C7043` /
         * `0x005C705C` in `msvc8::vector<Moho::SPerArmyReconInfo>::_Insert_n`
         * (FUN_005C6F90), preceded by the `sub_5C3C70` max_size clamp.
         *
         * Exposed publicly (was private) so per-element-type helpers that
         * can't route through `reallocate_to` directly -- because their `T`
         * needs relocation semantics this template doesn't model, e.g.
         * `moho::EnsureWeakPtrVectorCapacity` for `WeakPtr<T>`'s intrusive
         * owner-chain relink -- can still reuse the real growth formula
         * instead of re-deriving it.
         */
        [[nodiscard]] std::size_t recommended_capacity(const std::size_t need) const noexcept {
            const std::size_t cur = capacity();
            std::size_t grown = (max_size() - cur / 2u < cur) ? 0u : cur + cur / 2u;
            if (grown < need) {
                grown = need;
            }
            return grown;
        }

    private:
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
         * Address: 0x00848BD0 (FUN_00848BD0, msvc8::vector<moho::UserArmy*>::
         * deallocate_all -- exact match: `if(first_) operator delete(first_);
         * first_=last_=end_=nullptr;`. Reached from SnapshotUserArmyVector's
         * `*outSnapshot = source` operator= in Sim.cpp)
         * Address: 0x0082D8D0 (FUN_0082D8D0, msvc8::vector<void*>::
         * deallocate_all for UICommandGraph's MapAB hash-bucket table --
         * same exact shape. `assign(9, sentinel)`'s own `clear()` step only
         * logically empties (keeps capacity); this address's caller
         * (`FUN_0082F110`, `assign`'s MapAB emission, cited above) fully
         * releases the old buffer first so the following `assign` always
         * lands a fresh exact-9-slot allocation, matching `UICommandGraph::
         * PrepareForRebuild`'s reset-then-rebuild semantics.)
         * Address: 0x0082DBF0 (FUN_0082DBF0, the MapC sibling of the above --
         * byte-identical shape, reached from `FUN_0082F680` (`assign`'s
         * MapC emission, cited above) the same way.)
         * Address: 0x0052D590 (FUN_0052D590, `msvc8::vector<
         * Moho::RRuleGameRulesLuaExportBinding>::deallocate_all` for the
         * 16-byte element, `RRuleGameRulesImpl::mMaps` -- byte-identical
         * `if (*(a1+4)) operator delete(*(a1+4)); *(a1+4)=*(a1+8)=*(a1+12)=
         * 0;` shape to `FUN_00848BD0`/`FUN_0082D8D0` above, confirming this
         * element type's buffer is freed with a plain scalar `operator
         * delete` and never `delete[]` -- the load-bearing evidence that
         * the previous hand-rolled `RRuleGameRulesLuaExportBindingArray`
         * model (`new T[N]{}` / `delete[]`, RRuleGameRules.cpp before this
         * migration) was a genuine behavioral divergence, not just a style
         * mismatch: `delete[]`-pairing is only correct when every slot up
         * to capacity is a live constructed object, which this address
         * proves the real binary never has. Zero recorded direct callers in
         * `_callgraph_index.sqlite` (`RRuleGameRulesImpl::~RRuleGameRulesImpl`,
         * `FUN_00529700`, instead shows its per-element destroy loop
         * `FUN_00536DF0` followed by an inlined `operator delete` call at
         * its own call site rather than calling out to this address) --
         * reached transitively once real code destroys/reallocates
         * `mMaps`, which now happens through this member's ordinary
         * `~vector()`/`reserve()` machinery instead of the removed
         * `ReleaseLuaExportBindingArray` free function.)
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
         * Address: 0x00445B80 (FUN_00445B80, `msvc8::vector<std::int32_t>::
         * allocate_slots_checked` for the handle-to-heap-index reverse map
         * `ClusterSearchOpenHeapRuntime::mHandleToHeapIndex` (Cluster.cpp) --
         * reached from the `_Insert_n` grow core `FUN_004451A0`, cited above
         * on `insert`.)
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
         * Address: 0x00857260 (FUN_00857260, `msvc8::vector<boost::
         * shared_ptr<moho::MeshInstance>>::allocate_slots_checked` --
         * `0xFFFFFFFF/count < 8` guard, `operator new(8*count)`. Reached
         * from `_Insert_n` FUN_00855DF0 (cited above on `insert`),
         * `mMeshes`'s reallocation branch.)
         *
         * sizeof(T) == 28 (`count > 0x0F5C28F5` throws):
         * Address: 0x00883870 (FUN_00883870, `msvc8::vector<msvc8::string>`'s
         * checked-allocate lane, reached from the `_Insert_n` reallocation path
         * FUN_00882BA0 already cited above on `_Insert_n` -- `reallocate_to`'s
         * `allocate_slots_checked(newCap)` call for this element. Five call
         * sites converge on it (0x00882610/0x00882920/0x00882BA0/0x00882FAF/
         * 0x00883B30), all within the `msvc8::vector<msvc8::string>`
         * reallocation family around `Moho::LaunchInfoLoad`; 0x00882BA0's own
         * citation traces a real source-level trigger through
         * `ResizeLegacyStringVectorExact`'s `outStrings.resize(n, fillValue)`
         * (CSaveGameRequestImpl.cpp:125).)
         *
         * sizeof(T) == 152 (`count > 0x01B4E81A` throws):
         * Address: 0x0077DD10 (FUN_0077DD10, checked-allocate lane for
         * `msvc8::list<moho::SDecalInfo>`'s internal 0x98-byte node
         * (`_Node{_Next(4), _Prev(4), SDecalInfo(0x90)}` -- `SDecalInfo` is
         * confirmed 0x90 bytes in `CDecalTypes.h`, so 8+0x90=0x98 matches
         * exactly). Reached from the node-buy wrappers FUN_0077D1D0
         * (`_Buynode(next,prev)`, default-constructs the node's `SDecalInfo`
         * value in place -- confirmed from its own disassembly, which default-
         * constructs via `call SDecalInfo::SDecalInfo()` after writing the
         * caller-supplied `prev`/`next` link fields) and FUN_0077D3E0 (`mov
         * ecx,1; jmp FUN_0077DD10`, the with-value `_Buynode` overload's
         * shared allocate step). FUN_0077D1D0 is called directly from
         * `gpg::RListType_SDecalInfo::SerLoad` (0x0077B260, recovered and
         * address-annotated in CDecalTypes.cpp), whose current source
         * (`list->push_back(value)`, calling into this template's own
         * `insert()`/`al.allocate(1)` path) is the source-level trigger for
         * this exact `list<SDecalInfo>` instantiation.)
         * Address: 0x0077D1D0 (FUN_0077D1D0, the `_Buynode(next,prev)`
         * node-buy wrapper described above)
         *
         * sizeof(T) == 12 / 16 / 52 / 60 / 64 / 116 / 388:
         * Address: 0x007E5650 (FUN_007E5650, 12B, e.g. `Wm3::Vector3<float>`)
         * Address: 0x008E87F0 (FUN_008E87F0, 0x10B)
         * Address: 0x0085F930 (FUN_0085F930, 0x34B)
         * Address: 0x005C9F40 (FUN_005C9F40, 0x34B, the
         * `msvc8::vector<Moho::SPerArmyReconInfo>::_Insert_n` reallocation path,
         * FUN_005C6F90)
         * Address: 0x0064F8C0 (FUN_0064F8C0, 0x34B,
         * `msvc8::vector<moho::SDebugDecal>::allocate_slots_checked` --
         * reached from the `_Insert_n` grow core `FUN_0064E770` (still open,
         * cited on `uninit_fill_n`/`uninit_copy_n` above; recovered as the
         * caller of this token regardless, same evidence basis as those two
         * citations), which relocates `canvas->decals` into freshly-grown
         * storage on `push_back`'s capacity-full path)
         * Address: 0x007FB950 (FUN_007FB950, 0x3CB)
         * Address: 0x004C6520 (FUN_004C6520, 64B)
         * Address: 0x008F6040 (FUN_008F6040, 0x74B)
         * Address: 0x00526080 (FUN_00526080, 0x184B, `moho::RUnitBlueprintWeapon`)
         * Address: 0x0092C080 (FUN_0092C080, 12B, `msvc8::vector<gpg::HaStar::
         * ClusterSearchEdgeTraversalLaneRuntime>::allocate_slots_checked` --
         * reached from the `_Insert_n` grow core `FUN_0092F630`, cited above
         * on `insert`.)
         * Address: 0x0092C0E0 (FUN_0092C0E0, 12B, `msvc8::vector<gpg::HaStar::
         * ClusterSearchOpenHeapEntryRuntime>::allocate_slots_checked` --
         * reached from the `_Insert_n` grow core `FUN_0092F240`, cited above
         * on `insert`.)
         *
         * sizeof(T) == 56:
         * Address: 0x0044E650 (FUN_0044E650, allocator for one 56-byte
         * intrusive sentinel/head node used by `CD3DFileBatchTexture.cpp`'s
         * BVSet lanes)
         * Address: 0x00892B00 (FUN_00892B00, second 56-byte-stride emission,
         * same `count > 0xFFFFFFFF/56` guard via the reciprocal-division
         * codegen (`0xFFFFFFFF/count < 0x38`) rather than a folded
         * `0x04924924` immediate -- not ICF-folded with 0x0044E650 because
         * the two TUs picked different register allocations. Callers
         * unclassified (0x00892400/0x008928EF, not their own tracked
         * tokens) plus a `skip`-marked ICF thunk (FUN_008924C0); no
         * concrete `T` identified yet.)
         *
         * sizeof(T) == 0x78:
         * Address: 0x00562850 (FUN_00562850,
         * `msvc8::vector<Moho::SSyncPublishedCommandPacket>::allocate_slots_checked`,
         * reached from the `reserve()` guard FUN_00561160)
         *
         * sizeof(T) == 0x1C (28, `DXGI_MODE_DESC` -- Width/Height/
         * RefreshRate{Num,Denom}/Format/ScanlineOrdering/Scaling):
         * Address: 0x008F5FD0 (FUN_008F5FD0,
         * `msvc8::vector<DXGI_MODE_DESC>::allocate_slots_checked`, reached
         * from the `_Insert_n` grow lane `FUN_008F6A50` (cited on `insert`
         * above), the display-mode-enumeration vector's capacity-full path)
         *
         * sizeof(T) == 0x14 (20, `count > 0xFFFFFFFF/20` throws, zero-count
         * guarded ahead of the reciprocal division to avoid a div-by-zero
         * trap):
         * Address: 0x00A53BD0 (FUN_00A53BD0, sole caller FUN_00A55857 is an
         * untracked code fragment, not a separately recovered function; no
         * concrete `T` identified yet)
         *
         * sizeof(T) == 0x18 (24, same zero-count-guarded reciprocal-division
         * shape as the 0x14 emission above):
         * Address: 0x008D9190 (FUN_008D9190, sole caller FUN_008D9CC7 is an
         * untracked code fragment; no concrete `T` identified yet)
         * Address: 0x0087D570 (FUN_0087D570, alloc_raw callee of one of the
         * two `Moho::CDecalManager` `buy_head` emissions RbTree.h's
         * `buy_head` catalog cites at 0x0087C3B0 -- "owning member names
         * not yet pinned down" there; this completes that citation's
         * `alloc_raw` half.)
         * Address: 0x0087D5F0 (FUN_0087D5F0, byte-identical sibling of
         * FUN_0087D570 -- the `alloc_raw` callee of `buy_head`'s
         * FUN_0087C5F0, the second distinct `CDecalManager` map/set
         * instantiation. Two genuinely distinct addresses, not an ICF
         * twin, matching `buy_head`'s own note that the two callers differ
         * only in which of these two allocators they call.)
         *
         * sizeof(T) == 0x80 (128, `count > 0xFFFFFFFF/128` throws via the
         * reciprocal-division form `0xFFFFFFFF/count < 0x80`):
         * Address: 0x00751950 (FUN_00751950, reachable from `WinMain` at
         * callgraph depth 16; its three callers -- FUN_0074D272,
         * FUN_0074E770 (blocked), FUN_0074EA9F -- are all still open in the
         * CrtRuntimeHelpers.cpp cluster, so no concrete `T` is identified
         * yet)
         *
         * sizeof(T) == 0x28 (40, `Moho::EntitySetTemplate<Moho::Unit>` a.k.a.
         * `SEntitySetTemplateUnit` -- checks `0xFFFFFFFF/40 < count` before
         * `operator new(40*count)`):
         * Address: 0x00704750 (FUN_00704750, msvc8::vector<
         * SEntitySetTemplateUnit>::allocate_slots_checked -- reached from the
         * `_Insert_n` reallocation path FUN_007030C0, which grows
         * `CArmyImpl::UnitCategorySets`)
         *
         * sizeof(T) == 0x20 (32, `count > 0xFFFFFFFF/32` throws):
         * Address: 0x008D6FC0 (FUN_008D6FC0, cross-container reuse -- NOT a
         * vector, a single-node (`count` always 1 at every confirmed call
         * site) allocation for the local `msvc8::rb_tree<moho::Resolution>`
         * dedup tree in `SetupPrimaryAdapterSettings` (`StartupHelpers.cpp`;
         * node layout `{left,parent,right,vtable,width,height,
         * framesPerSecond,color,isNil}` = 0x20 bytes, cited on `buy_head`/
         * `insert_at` in RbTree.h). RbTree.h's own dedicated `alloc_raw()` is
         * parameterless with no overflow guard (always exactly one node at a
         * compile-time-constant size); this address instead reuses this
         * member's checked-count shape with `count=1`, confirmed from its
         * own callers: `FUN_008D6280` (buy-node-with-value) and
         * `FUN_008D6940` (`buy_head`), both already recovered.)
         *
         * sizeof(T) == 0x50 (80, `count > 0xFFFFFFFF/80` throws):
         * Address: 0x008A9C60 (FUN_008A9C60, another cross-container reuse
         * with `count=1` -- the single-node allocator for `msvc8::map<
         * msvc8::string, moho::TerrainEnvironmentLookupEntry>`'s node
         * (`CWldTerrainRes`'s `mEnvLookup`, `TerrainRuntimeView` /
         * `TerrainVisualResourceRuntimeView` in `CWldMap.cpp`; 0x50-byte
         * node: 3 link fields + `pair<msvc8::string,
         * TerrainEnvironmentLookupEntry>` (0x1C + 0x24 = 0x40) + color/isNil,
         * padded to 0x50). Called directly with a literal `1` from
         * `FUN_008A9490` (`sub_8A9490() { return sub_8A9C60(1); }`), this
         * instantiation's `alloc_raw()`, cited on that member in `RbTree.h`.)
         *
         * sizeof(T) == 0x38 (56, `pair<msvc8::string, msvc8::string>`,
         * `count > 0xFFFFFFFF/56` throws, confirmed `cmp eax,38h` against
         * the `.asm`):
         * Address: 0x008A9BF0 (FUN_008A9BF0, msvc8::vector<
         * moho::TerrainEnvironmentLookupPair>::allocate_slots_checked --
         * `moho::TerrainEnvironmentLookupPairs`, `CWldMap.cpp`'s
         * `AppendEnvironmentLookupPair`/`IWldTerrainRes::EnumerateEnvLookup`
         * output vector, keyed/valued by two `msvc8::string`s. Reached from
         * the `_Insert_n` reallocation branch for this instantiation
         * (`FUN_008A9100`, cited below on `insert`).)
         *
         * sizeof(T) == 8 (`msvc8::vector<moho::WeakPtr<moho::CMauiControl>>`,
         * `sInputCapture`'s backing storage, UiRuntimeTypes.cpp):
         * Address: 0x007A5EF0 (FUN_007A5EF0, reciprocal-division form
         * `0xFFFFFFFF/count < 8` -- the classic Dinkumware `_Allocate<T>`
         * shape (dividing by the runtime `count`) rather than the
         * constant-folded `count > max_size()` form most other
         * instantiations show; mathematically the same predicate
         * (`floor(M/K) < n <=> floor(M/n) < K` for positive `M,K,n`), just a
         * different codegen choice for this call site -- see the
         * `sizeof(T) == 0x80`/0x14/0x18 entries above for the same
         * reciprocal-division shape already documented on this member.
         * Reached from the reallocation branch of
         * `GrowAndInsertInputCaptureWeakRef` (`FUN_007A5A70`,
         * UiRuntimeTypes.cpp).)
         *
         * sizeof(T) == 4 / 0x14 / 0x24 (four not-yet-typed instantiations,
         * `T` unresolved): `if (n) { if (0xFFFFFFFF/n < sizeof(T)) throw
         * bad_alloc; } else n=0; return operator new(sizeof(T)*n);` --
         * this member's plain constant-folded-`max_size` shape. None of
         * the four addresses below is exported by IDA as a function of its
         * own (`owner=<none>` at each single call site); each is the
         * *middle* of a tiny (~18-byte) individually-compiled,
         * `0xCC`-padded single-argument convenience wrapper (`T*
         * allocate(size_t n) { return allocate(n, nullptr); }`-shaped)
         * that IDA's auto-analysis never carved into its own token --
         * identity independently confirmed by decoding the raw PE bytes at
         * each wrapper address and verifying the `call` displacement lands
         * exactly on the address below (not inferred from proximity
         * alone):
         * Address: 0x00A53AD0 (FUN_00A53AD0) -- sizeof(T)==4, max_size
         * 0x3FFFFFFF; wrapper at 0x00A55580 (`E8 44 E5 FF FF` @0x00A55587).
         * Address: 0x00A53C40 (FUN_00A53C40) -- sizeof(T)==0x14, max_size
         * 0x0CCCCCCC; wrapper at 0x00A558D0 (`E8 64 E3 FF FF` @0x00A558D7).
         * Address: 0x00A53E10 (FUN_00A53E10) -- sizeof(T)==0x24, max_size
         * 0x071C71C7; wrapper at 0x00A55B80 (`E8 84 E2 FF FF` @0x00A55B87).
         * Address: 0x00A53EB0 (FUN_00A53EB0) -- sizeof(T)==0x24 (distinct
         * `function_sha256` from 0x00A53E10 -- a second, separate 36-byte
         * instantiation, not an ICF twin), same max_size; wrapper at
         * 0x00A55BE0 (`E8 C4 E2 FF FF` @0x00A55BE7).
         * Follow-up: the four wrapper addresses above should be
         * (re-)exported from IDA as their own functions -- they were
         * silently skipped by the auto-analysis pass, most likely because
         * they sit between `0xCC` padding rather than after a `retn` the
         * analyzer followed -- so they get their own token/xrefs/meta.json
         * and can be recovered as the one-arg `allocate(size_t)` overload
         * calling this member by name.
         *
         * sizeof(T) == 0x28 (40 bytes, owner not confirmed):
         * Address: 0x0092C150 (FUN_0092C150) -- max_size 0x0666666,
         * standard `bad_alloc`-throw shape. Sole caller (0x0092CF27) sits
         * in an IDA-unclassified gap; same 40-byte size and address
         * neighbourhood (0x0092Cxxx-0x0092Dxxx) as the `std::hash_map_
         * unk_unk` cluster cited on `buy_head` above (`FUN_0092DC30`'s
         * header node is also 0x28 bytes), plausibly that same hash_map's
         * checked bucket-vector allocator -- not proven, recorded as the
         * strongest available lead rather than a guess presented as fact.
         *
         * sizeof(T) == 0x70 (112 bytes, `gpg::gal::backends::d3d9::
         * AdapterD3D9`, `static_assert(sizeof(AdapterD3D9)==0x70)`,
         * `AdapterD3D9.hpp`):
         * Address: 0x008E8790 (FUN_008E8790) -- confirmed via the sibling
         * `max_size()` emission `FUN_008E9070` (`mov eax,2492492h; retn`,
         * and `0xFFFFFFFF/112 == 0x02492492` exactly). Three callers: one
         * in an IDA-unclassified gap (0x008E9087, likely a third growth
         * call site not independently exported); `FUN_008EEFC0` (corrected
         * below from a fabricated generic "VisionDB handle teardown lane"
         * `recovered` note with zero real citation anywhere in `src/sdk`);
         * and `FUN_008F1890`, already cited on `insert` elsewhere in this
         * file as `msvc8::vector<AdapterD3D9>::insert(pos,count,value)` for
         * `DeviceD3D9Runtime::adapters` (`D3D9Interfaces.cpp`).
         *
         * sizeof(T) == 0x14 (20 bytes, `gpg::ReadArchive::
         * TrackedPointerInfo`, `static_assert(sizeof==0x14)`,
         * `ArchiveSerialization.h`):
         * Address: 0x0094F210 (FUN_0094F210) -- three callers:
         * `FUN_0094F990` (already `skip`, trivial 1-arg forwarder, honest
         * note citing this token's then-unresolved status -- now
         * resolved); `FUN_00951EA0` (corrected below from the same
         * fabricated "VisionDB handle teardown lane" `recovered` note as
         * `FUN_008EEFC0` above -- real body is `reserve(n)`-shaped: zero 3
         * pointer fields, length-check, `v4 = allocate_slots_checked(a2)`,
         * `begin=end=v4, capacityEnd=v4+20*a2`); and `FUN_00952770`,
         * already `skip`-tagged as this instantiation's `_Insert_n`
         * (stride 20, uses `func_ReleaseRefsRange_TrackedPointerInfo` and
         * locals typed `gpg::ReadArchive::TrackedPointerInfo*`).
         *
         * sizeof(T) == 0x48 (72 bytes, `moho::SDebugScreenText`,
         * `static_assert(sizeof==0x48)`, `SDebugScreenText.h`):
         * Address: 0x0064F860 (FUN_0064F860, sub_64F860) -- `if (0xFFFFFFFF
         * / count < 0x48) throw std::bad_alloc; return operator new(0x48 *
         * count);`, this member's plain constant-folded-`max_size` shape.
         * Sole `src/sdk`-reachable caller is `_Insert_n`'s `FUN_0064E490`
         * (cited above on `insert(pos,count,value)`), called with `ECX =
         * newCap` (the 1.5x-growth-or-needed-size candidate). Two further
         * callers, `FUN_0064EEBF` and `FUN_0074E10F`, are not yet exported
         * as their own functions in this namespace; not needed to satisfy
         * this instantiation's caller evidence. DB-integrity fix: was
         * `blocked` ("DB integrity revert... zero citation anywhere in
         * src/sdk... needs real recovery from scratch"); this is that real
         * recovery.
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
         *
         * Address: 0x00751C40 (FUN_00751C40, `msvc8::vector<moho::
         * SExtraUnitData>::allocate_slots_checked` for the 0x20-byte
         * element, `Sim::mSyncSerializeGroup2`) -- `.c`-confirmed exact
         * match of this member's guard/allocate shape. Reached directly
         * from `insert`'s reallocation branch (`FUN_0074F3E0`, cited above,
         * independently reached from `Sim::AdvanceBeat`) and from the fused
         * buy helper `FUN_0074DBA0` (cited above on the copy constructor
         * and `operator=`).
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
         * Address: 0x00540580 (FUN_00540580, the 8-byte-stride throw lane for
         * `msvc8::vector<Moho::SEjectRequest>`, reached from the `_Insert_n`
         * grow lane FUN_00540330, already cited above)
         * Address: 0x00653860 (FUN_00653860, the 48-byte-stride throw lane for
         * `msvc8::vector<moho::SDebugWorldText>`, reached from the
         * `_Insert_n` grow lane FUN_00653380, already cited above)
         * Address: 0x00561900 (FUN_00561900, the 0x78-byte-stride throw lane
         * for `msvc8::vector<Moho::SSyncPublishedCommandPacket>`, reached
         * from the `reserve()` guard FUN_00561160, already cited above)
         * Address: 0x009514A0 (FUN_009514A0, the 8-byte-stride throw lane for
         * `msvc8::vector<gpg::TypeHandle>`, reached from the `_Insert_n`
         * grow lane FUN_00951F30, already cited above)
         * Address: 0x00703410 (FUN_00703410, the 40-byte-stride throw lane for
         * `msvc8::vector<SEntitySetTemplateUnit>`, reached from the
         * `_Insert_n` grow lane FUN_007030C0 for `CArmyImpl::UnitCategorySets`)
         * Address: 0x0064EEE0 (FUN_0064EEE0, the 52-byte-stride throw lane for
         * `msvc8::vector<moho::SDebugDecal>`, reached from the `_Insert_n`
         * grow lane FUN_0064E770's `size() == 0x4EC4EC4` max_size test,
         * already cited above on `insert`)
         * Address: 0x007BC060 (FUN_007BC060, the 36-byte-stride throw lane
         * for `msvc8::vector<Moho::SNetCommandArg>`, reached from the
         * `_Insert_n` grow lane FUN_007BBD60's `0xFFFFFFFF/36 (=119304647)`
         * max_size test, already cited above on `insert`. Throws
         * `std::length_error("vector<T> too long")` exactly like the other
         * per-stride throw lanes in this cluster.)
         * Address: 0x00856100 (FUN_00856100, the 8-byte-stride throw lane
         * for `msvc8::vector<boost::shared_ptr<moho::MeshInstance>>`,
         * reached from the `_Insert_n` grow lane FUN_00855DF0's
         * `0x1FFFFFFF - cur < count` max_size test, already cited above on
         * `insert`. DB previously listed this token `recovered` with no
         * note and no citation anywhere in `src/sdk` -- corrected here.)
         * Address: 0x008F6890 (FUN_008F6890, the 28-byte-stride throw lane for
         * `msvc8::vector<DXGI_MODE_DESC>`, reached from the ctor/assign fused
         * zero-then-buy helper `FUN_008F69A0` (cited above on `vector(const
         * vector&)`) and from the `_Insert_n` grow lane `FUN_008F6A50` (cited
         * above on `insert`), both guarding the same `count > 0x9249249`
         * (`0xFFFFFFFF/28`) `max_size()` test.)
         * Address: 0x0092EFF0 (FUN_0092EFF0, the 12-byte-stride throw lane for
         * `msvc8::vector<gpg::HaStar::ClusterSearchEdgeTraversalLaneRuntime>`,
         * reached from the `_Insert_n` grow lane `FUN_0092F630`'s
         * `357913941 - size < count` (`0xFFFFFFFF/12`) max_size test,
         * already cited above on `insert`.)
         * Address: 0x0092F060 (FUN_0092F060, the sibling 12-byte-stride throw
         * lane for `msvc8::vector<gpg::HaStar::ClusterSearchOpenHeapEntryRuntime>`,
         * reached from that instantiation's own `_Insert_n` grow lane
         * `FUN_0092F240`, already cited above on `insert`.)
         * Address: 0x00444270 (FUN_00444270, the 4-byte-stride throw lane for
         * `msvc8::vector<std::int32_t>`'s `ClusterSearchOpenHeapRuntime::
         * mHandleToHeapIndex` instantiation, reached from the `_Insert_n`
         * grow lane `FUN_004451A0`'s `0x3FFFFFFF - size < count` max_size
         * test, already cited above on `insert`.)
         * Address: 0x007A5D20 (FUN_007A5D20, the 8-byte-stride throw lane for
         * `msvc8::vector<moho::WeakPtr<moho::CMauiControl>>` (`sInputCapture`,
         * UiRuntimeTypes.cpp) -- guards `size() == max_size()`
         * (`0x1FFFFFFF`) before the insert-with-growth core proceeds. DB
         * previously listed this token `recovered` with no note and no
         * citation anywhere in `src/sdk` -- corrected here. Reached from
         * `GrowAndInsertInputCaptureWeakRef` (`FUN_007A5A70`).)
         * Address: 0x0092F0D0 (FUN_0092F0D0, sub_92F0D0) -- the
         * `throw_too_long` emission for `ClusterInternalCache<gpg::HaStar::
         * OccupationData>::mVec` (`OccupationCacheRuntimeMap`, 4-byte
         * `iterator` element -- same instantiation as `insert`'s
         * `FUN_0092F9E0` above). Builds `std::length_error("vector<T> too
         * long")` the same way as this member's other emissions (a
         * `std::string`, then `std::logic_error::logic_error`, then the
         * vtable overwrite to `std::length_error::`vftable'`) and routes
         * through `_CxxThrowException`. Reached from `FUN_0092F9E0`'s
         * `0x3FFFFFFF - size() < count` guard. DB previously listed this
         * token `recovered` with a blank note and no citation anywhere in
         * `src/sdk` -- corrected here.)
         * Address: 0x0064EE20 (FUN_0064EE20, sub_64EE20) -- the 0x48-byte-
         * stride throw lane for `msvc8::vector<moho::SDebugScreenText>`,
         * reached from the `_Insert_n` grow lane `FUN_0064E490`'s
         * `size() == 0x38E38E3` (`0xFFFFFFFF/0x48`) `max_size` test, already
         * cited above on `insert(pos,count,value)`. Builds `std::
         * length_error("vector<T> too long")` via the same `std::string` +
         * `std::logic_error::logic_error` + vtable-overwrite-to-
         * `length_error` shape as this member's other emissions, then
         * routes through `_CxxThrowException`. DB-integrity fix: was
         * `recovered` citing "Cited on the canonical throw_too_long member"
         * with no such citation anywhere in `src/sdk`; this is the real
         * recovery.)
         *
         * Address: 0x0074F680 (FUN_0074F680, `msvc8::vector<moho::
         * SExtraUnitData>::throw_too_long` for the 0x20-byte element,
         * `Sim::mSyncSerializeGroup2`) -- `.c`-confirmed exact match:
         * builds `std::length_error("vector<T> too long")` the same way as
         * this member's other emissions and routes through
         * `_CxxThrowException`. Reached directly from `insert`'s `max_size()
         * - cur < count` guard (`FUN_0074F3E0`, cited above, independently
         * reached from `Sim::AdvanceBeat`) and from the fused buy helper
         * `FUN_0074DBA0` (cited above on the copy constructor and
         * `operator=`).
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
    static_assert(
        sizeof(vector<int, false>) == 3 * sizeof(void*),
        "vector<T,false> (no VC8 debug-iterator lane) must drop to a bare 3-pointer layout"
    );

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

        /**
         * Address: 0x007B4FA0 (FUN_007B4FA0), among others -- see the
         * definition in Vector.cpp for the full address list.
         *
         * VC8's `_Allocate(count, (_Node*)0)` for the 28-byte red-black tree
         * node, overflow guard included. Declared here so tree code outside
         * this translation unit can buy nodes through the same checked lane
         * the binary uses instead of open-coding `operator new`.
         */
        void* AllocateChecked28ByteElements(std::uint32_t count);
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

        /**
         * Address: 0x004E32D0 (FUN_004E32D0, `msvc8::list<Moho::CSndParams*>`'s
         * node-buy lane, called from `func_RegisterCSndParams`/FUN_004DFA50)
         * Address: 0x004E3310 (FUN_004E3310, the same list's `_Incsize`-style
         * overflow-checked size increment, called immediately after the node
         * buy in the same caller)
         * Address: 0x004E3490 (FUN_004E3490, sibling `_Incsize`-style
         * overflow-checked size increment for `msvc8::list<Moho::CSndVar*>`
         * -- `gSndVarRegistry` in moho/audio/CSndVar.cpp, same `_Mysize@+0x08`
         * offset and the same `0x3FFFFFFF` cap, throwing
         * `std::length_error("list<T> too long")` via `std::logic_error`'s
         * ctor with the `??_7length_error@std@@6B@` vftable patched in before
         * `_CxxThrowException`, exactly mirroring FUN_004E3310. Reached from
         * `RegisterSndVarInstance`'s (FUN_004DF990) `push_back` call.)
         * Address: 0x00AC2D10 (FUN_00AC2D10, another 12-byte-node
         * `msvc8::list<T*>` node-buy lane for a 4-byte pointer/scalar T --
         * `operator new(0xC)`, writes `_Next`/`_Prev` from its first two
         * stack args directly and `_Value` from `*arg_8` (the third arg is a
         * pointer to the value, dereferenced once, matching `insert`'s
         * `const value_type&` parameter). Called from FUN_00AC31E0, which
         * matches this method's shape exactly: loads `head=[ebx+4]`, buys
         * the node via this lane, calls the sibling `_Incsize`-style
         * overflow check (`sub_AC3140(1)`, same family as FUN_004E3310/
         * FUN_004E3490 above), then links the fresh node as the new list
         * head and fixes up the old head's back-link -- a `push_front`-shape
         * insert at `begin()`. Two further callers of this node-buy lane
         * (FUN_00AC3220, `recovered`; FUN_00AC3420, `external_dependency`)
         * exist in the same address neighbourhood but are not needed to
         * satisfy this instantiation's caller evidence.)
         *
         * Address: 0x008C5EF0 (FUN_008C5EF0, list<const RUnitBlueprint*>
         * node-buy lane -- same 12-byte-node, 4-byte-pointer-T shape as
         * FUN_00AC2D10 above: allocator via sub_8C6330(1), _Next/_Prev
         * from the first two args, _Value from one dereference of a
         * const value_type& third arg. Reached from sub_8C1220
         * (Moho::CollectUpgradeCommandTargetBlueprints,
         * moho/unit/core/UserUnit.cpp) via a direct call.)
         * Address: 0x008C5F30 (FUN_008C5F30, sibling overflow-checked
         * size-increment lane for the same instantiation -- Mysize at
         * +0x08, the 0x3FFFFFFF cap, "list<T> too long", byte-for-byte
         * the same shape as FUN_004E3310/FUN_004E3490/sub_AC3140 above.
         * Called immediately after the node buy in sub_8C1220.)
         *
         * What it does:
         * VC8 `std::list<T>::insert(pos, v)`. FUN_004E32D0 allocates one 12-byte
         * node through the checked 12-byte-element lane (`AllocateChecked12ByteLane`,
         * FUN_004E4F70, folded onto many other 12-byte instantiations) and writes
         * `_Next`/`_Prev`/`_Value` directly into the fresh block; the recovered
         * form expresses the same net state via placement-new followed by the
         * explicit link reassignment below. FUN_004E3310 checks `_Mysize` against
         * the Dinkumware-generic `0x3FFFFFFF` cap (the same fixed bound used by
         * this file's `sizeof(T)==4` vector `max_size()`, unrelated to the
         * 12-byte node size) and throws `std::length_error("list<T> too long")`
         * before incrementing; the binary performs the node buy *before* this
         * check, so the node is not freed on the overflow path -- preserved here
         * for fidelity.
         */
        iterator insert(const_iterator pos, const value_type& v)
        {
            _Node_alloc_type al;
            _Node* node = al.allocate(1);
            new (node) _Node(v);

            if (_Mysize == static_cast<size_type>(0x3FFFFFFF)) {
                throw std::length_error("list<T> too long");
            }
            ++_Mysize;

            _Nodeptr where = pos._Ptr;
            _Nodeptr prev = where->_Prev;

            node->_Next = where;
            node->_Prev = prev;
            prev->_Next = node;
            where->_Prev = node;

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

    namespace detail
    {
        // `StringIntHeapLane` (`{const char* key; std::int32_t value;}`, defined in
        // Vector.cpp) is the layout twin of SimRecoveryRuntime.cpp's
        // `StringRankLaneRuntime` -- both are the 8-byte shape MSVC8's `std::sort`
        // instantiated for the `(string,rank)` bone-name-index sort recovered as
        // `Moho::CAniSkel::CAniSkel`'s `SortStringRankLaneRuntimeRange`
        // (FUN_0054E4B0). Forward-declared here (full definition stays local to
        // Vector.cpp) so that recovered driver can call these already-recovered
        // heap/insertion-sort fallbacks by name instead of duplicating them.
        struct StringIntHeapLane;

        // Address: 0x0054F990 (FUN_0054F990, sub_54F990) -- Floyd `make_heap`.
        const char* MakeHeapOverStringIntHeapLaneRange(StringIntHeapLane* first, StringIntHeapLane* last, int userTagArg) noexcept;
        // Address: 0x0054F9E0 (FUN_0054F9E0, sub_54F9E0) -- `sort_heap` via repeated `pop_heap`.
        std::int32_t SortHeapStringIntHeapLaneRange(StringIntHeapLane* first, StringIntHeapLane* last, int userTagArg) noexcept;
        // Address: 0x0054F290 (FUN_0054F290, sub_54F290) -- small-range insertion sort.
        char InsertionSortStringIntHeapLaneRangeAscending(StringIntHeapLane* first, StringIntHeapLane* last) noexcept;
    } // namespace detail
}
