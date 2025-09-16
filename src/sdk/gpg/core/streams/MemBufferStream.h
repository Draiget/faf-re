#pragma once

#include <stdexcept>

#include "gpg/core/utils/BoostWrappers.h"

namespace gpg
{
	template<class T>
	class MemBuffer 
	{
		using type = T;
	public:

        boost::SharedPtrRaw<type> mData;
		type* mBegin;
		type* mEnd;

        MemBuffer() :
            mData{},
            mBegin{ nullptr },
            mEnd{ nullptr }
        {
        }
        MemBuffer(const MemBuffer<type>& cpy) :
            mData{ cpy.mData },
            mBegin{ cpy.mBegin },
            mEnd{ cpy.mEnd }
        {
        }
        MemBuffer(boost::SharedPtrRaw<type> ptr, type* begin, T* end) :
            mData{ ptr },
            mBegin{ begin },
            mEnd{ end }
        {
        }
        MemBuffer(boost::SharedPtrRaw<type> ptr, unsigned int len) :
            mData{ ptr },
            mBegin{ ptr.data() },
            mEnd{ ptr.data() + len }
        {
        }

        type* GetPtr(unsigned int start, unsigned int len) {
            type* begin = &this->mBegin[start];
            if (&begin[len] > this->mEnd) {
                throw std::range_error{ std::string{"Out of bound access in MemBuffer<>::GetPtr()"} };
            }
            return begin;
        }
        gpg::MemBuffer<type> SubBuffer(unsigned int start, unsigned int len) {
            return gpg::MemBuffer<type>{this->mData, this->GetPtr(start, end), this->GetPtr(start + end, 0)};
        }
        void Reset() {
            this->mData.release();
            this->mBegin = nullptr;
            this->mEnd = nullptr;
        }
        size_t Size() {
            return (this->mEnd - this->mBegin) / sizeof(type);
        }
        gpg::MemBuffer<type>& operator=(gpg::MemBuffer<type> const& that) {
            this->mData = that.mData;
            this->mBegin = that.mBegin;
            this->mEnd = that.mEnd;
        }

		operator type* () {
            return *this->mBegin;
        }
        type* begin() {
            return this->mBegin;
        }
        type* end() {
            return this->mEnd;
        }
        type& operator[](int ind) {
            return &this->mBegin[ind];
        }
	};

    MemBuffer<char> AllocMemBuffer(size_t size); // 0x0094E320
}
