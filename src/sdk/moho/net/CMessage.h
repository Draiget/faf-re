#pragma once

#include "gpg/core/containers/FastVector.h"
#include "platform/Platform.h"

namespace gpg
{
    class Stream;
}

namespace moho
{
    /**
     * Accept only enums with uint8_t underlying type.
     */
    template <class E>
    concept IsU8Enum =
        std::is_enum_v<E> &&
        std::is_same_v<std::underlying_type_t<E>, std::uint8_t>;

    /**
	 * Tiny wrapper over a single byte that can convert to any enum class : uint8_t.
	 */
    struct MessageType
    {
        std::uint8_t value{ 0 };

        /** 
         * Default ctor.
         */
        constexpr MessageType() = default;

        /**
         * Construct from raw byte.
         */
        explicit constexpr MessageType(std::uint8_t v) noexcept : value(v) {}

        /** 
         * Construct from any enum class : uint8_t.
         */
        template <IsU8Enum E>
        constexpr MessageType(E e) noexcept : value(static_cast<std::uint8_t>(e)) {}

        /** 
         * Implicit conversion to any enum class : uint8_t (enables: const ELobbyMsg t = GetType()).
         */
        template <IsU8Enum E>
        constexpr operator E() const noexcept { return static_cast<E>(value); }

        /** 
         * Explicit conversion to raw byte (avoid accidental promotions).
         */
        explicit constexpr operator std::uint8_t() const noexcept { return value; }

        constexpr std::uint8_t raw() const noexcept { return value; }

        /** 
         * Equality vs any enum class : uint8_t.
         */
        template <IsU8Enum E>
        friend constexpr bool operator==(MessageType t, E e) noexcept {
            return t.value == static_cast<std::uint8_t>(e);
        }
        template <IsU8Enum E>
        friend constexpr bool operator==(E e, MessageType t) noexcept {
            return t == e;
        }
        template <IsU8Enum E>
        friend constexpr bool operator!=(MessageType t, E e) noexcept {
            return !(t == e);
        }
        template <IsU8Enum E>
        friend constexpr bool operator!=(E e, MessageType t) noexcept {
            return !(t == e);
        }
    };

    /**
     * Network message data-container.
     */
    struct CMessage
    {
        gpg::core::FastVectorN<char, 64> mBuff;
        int mPos;

        CMessage();

        /**
         * Address: 0x00483490
         */
        CMessage(MessageType type, size_t size = 0);

        /**
         * Address: 0x0047BE62
         */
        void SetSize(const size_t size) {
            mBuff[1] = LOBYTE(size);
            mBuff[2] = HIBYTE(size);
        }

        /**
         * Address: 0x0047BF4C
         */
        unsigned short GetSize() {
            // return *(unsigned short *)(&mBuf[1]);
            return MAKEWORD(mBuff[1], mBuff[2]);
        }

        /**
         * Address: 0x0047BEE5
         */
        [[nodiscard]]
    	bool HasReadLength() const {
            return mPos >= 3;
        }

        /**
         * Address: 0x007BFB97
         */
        MessageType GetType() {
            return MessageType(static_cast<std::uint8_t>(this->mBuff[0]));
        }

        /**
         * Address: 0x004834E9
         */
        void SetType(const MessageType type) {
            mBuff[0] = type.raw();
        }

        template <IsU8Enum E>
        void SetType(E e) {
            this->mBuff[0] = static_cast<std::uint8_t>(e);
        }

        /**
         * Address: 0x0047BE90
         */
        int GetMessageSize();

        /**
         * Address: 0x0047BD40
         */
        bool ReadMessage(gpg::Stream* stream);

        /**
         * Address: 0x0047BEE0
         */
        bool Read(gpg::Stream* stream);

        /**
         * Address: 0x0047BDE0
         */
        unsigned int Append(const char* ptr, size_t size);

        /**
         * Address: <inlined>
         */
        void inline Clear() noexcept;
    };
}