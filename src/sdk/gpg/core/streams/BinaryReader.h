#pragma once
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
            PrematureEOF() : std::runtime_error("Premature EOF") {}
            ~PrematureEOF() noexcept override = default;
        };

        BinaryReader() = default;
        explicit BinaryReader(Stream* s, const std::uint32_t port = 0)
            : mStream(s), mPort(port), mReserved0(0), mReserved1(0) {
        }

        /**
         * Address: 0x0043D210
         * @param buf 
         * @param size 
         */
        void Read(char* buf, size_t size) const;

        /**
         * Address: 0x004CCDD0
         * @param out 
         */
        void ReadString(msvc8::string* out) const;

        /**
         * Read exactly sizeof(T) bytes into POD-like T.
         * Requires T to be trivially copyable.
         */
        template<class T>
        void ReadExact(T& out) const {
            static_assert(std::is_trivially_copyable_v<T>, "T must be trivially copyable");
            Read(reinterpret_cast<char*>(std::addressof(out)), sizeof(T));
        }

        /**
         * Read exactly count * sizeof(T) bytes into a contiguous array.
         */
        template <class T>
        void ReadExactArray(T* out, std::size_t count) const
        {
            static_assert(std::is_trivially_copyable_v<T>,
                "ReadExactArray requires trivially copyable T");
            Read(out, sizeof(T) * count);
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
