#pragma once
#include "gpg/core/containers/FastVector.h"

namespace moho
{
    template<class T, class U>
    struct BVSet
    {
        uint32_t mVal0;
        uint32_t mVal1;
        gpg::core::FastVector<T>  mVec1;
        gpg::core::FastVector<U>  mVec2;
    };
}
