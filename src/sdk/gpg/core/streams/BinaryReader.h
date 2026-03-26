#pragma once
#include <array>
#include <memory>
#include <stdexcept>

#include "legacy/containers/String.h"

namespace gpg
{
	class Stream;

	class BinaryReader
	{
	public:
        struct PrematureEOF : std::runtime_error
        {
            /**
             * Address: 0x0043D180 (FUN_0043D180)
             *
             * What it does:
             * Constructs PrematureEOF runtime_error payload ("Premature EOF").
             */
            PrematureEOF();
            /**
             * Address: 0x0043D270 (FUN_0043D270)
             * Demangled: gpg::BinaryReader::PrematureEOF::dtr
             *
             * What it does:
             * Destroys PrematureEOF exception payload.
             */
            ~PrematureEOF() noexcept override;
        };

        BinaryReader() = default;
        explicit BinaryReader(Stream* s, const std::uint32_t port = 0)
            : mStream(s), mPort(port), mReserved0(0), mReserved1(0) {
        }

        /**
         * Address: 0x0043D210 (FUN_0043D210)
         *
         * What it does:
         * Reads exactly `size` bytes or throws `PrematureEOF` when source underruns.
         */
        void Read(char* buf, size_t size) const;

        /**
         * Address: 0x004CCDD0 (FUN_004CCDD0)
         *
         * What it does:
         * Reads one NUL-terminated string from stream bytes.
         */
        void ReadString(msvc8::string* out) const;

        /**
         * Address: <synthetic host-build helper>
         *
         * What it does:
         * Reads one 32-bit length-prefixed byte string into legacy string storage.
         */
        void ReadLengthPrefixedString(msvc8::string* out) const;

        /**
         * Read exactly sizeof(T) bytes into T's object storage.
         */
        template<class T>
        void ReadExact(T& out) const {
            Read(reinterpret_cast<char*>(std::addressof(out)), sizeof(T));
        }

        /**
         * Read exactly count * sizeof(T) bytes into a contiguous array.
         */
        template <class T>
        void ReadExactArray(T* out, std::size_t count) const
        {
            Read(reinterpret_cast<char*>(out), sizeof(T) * count);
        }

        /**
         * Read into std::array<T, N>.
         */
        template <class T, std::size_t N>
        void ReadExact(std::array<T, N>& arr) const
        {
            ReadExactArray(arr.data(), N);
        }

        /**
         * Value-returning helper: reads T by value.
         */
        template <class T>
        T ReadExact() const
        {
            T v{};
            ReadExact(v);
            return v;
        }

        [[nodiscard]]
		const Stream* stream() const noexcept {
	        return mStream;
        }
        Stream* stream() noexcept {
	        return mStream;
        }

    private:
        Stream* mStream = nullptr; // +0
        uint32_t mPort = 0;        // +4
        uint32_t mReserved0 = 0;   // +8
        uint32_t mReserved1 = 0;   // +12
	};

    static_assert(sizeof(BinaryReader) == 16, "BinaryReader size must be 16");
}
