#include "BitArray2D.h"

#include <cstring>

namespace gpg
{
/**
 * Address: 0x008D81F0 (FUN_008D81F0, ??0BitArray2D@gpg@@QAE@XZ)
 */
BitArray2D::BitArray2D()
    : ptr(nullptr), size(0), width(0), height(0)
{
}

/**
 * Address: 0x008D8200 (FUN_008D8200, ??1BitArray2D@gpg@@QAE@XZ)
 */
BitArray2D::~BitArray2D()
{
    operator delete(ptr);
}

/**
 * Address: 0x008D8210 (FUN_008D8210, ?Reset@BitArray2D@gpg@@QAEXII@Z)
 */
void BitArray2D::Reset(const unsigned int newWidth, const unsigned int newHeight)
{
    const unsigned int wordCount = newWidth * ((newHeight + 31u) >> 5);
    auto* const newWords = static_cast<int32_t*>(operator new(sizeof(int32_t) * wordCount));

    operator delete(ptr);
    ptr = newWords;
    size = static_cast<int32_t>(wordCount);
    width = static_cast<int32_t>(newWidth);
    height = static_cast<int32_t>(newHeight);

    std::memset(newWords, 0, sizeof(int32_t) * wordCount);
}

/**
 * Address: 0x008D8370 (FUN_008D8370, ?FillRect@BitArray2D@gpg@@QAEXHHHH_N@Z)
 */
void BitArray2D::FillRect(int x0, int z0, const int rectWidth, const int rectHeight, const bool fill)
{
    int x1 = x0 + rectWidth;
    int z1 = z0 + rectHeight;

    if (x0 < 0) {
        x0 = 0;
    }
    if (z0 < 0) {
        z0 = 0;
    }
    if (x1 > width) {
        x1 = width;
    }
    if (z1 > height) {
        z1 = height;
    }
    if (x1 <= x0 || z1 <= z0 || !ptr) {
        return;
    }

    const int fillBits = fill ? -1 : 0;
    int word = z0 >> 5;
    const int endWord = (z1 - 1) >> 5;
    int mask = -1 << (z0 & 0x1F);

    while (word <= endWord) {
        if (word == endWord && (z1 & 0x1F) != 0) {
            mask &= ~(-1 << (z1 & 0x1F));
        }

        int* dst = &ptr[x0 + word * width];
        const int setValue = fillBits & mask;
        const int keepMask = ~mask;
        for (int x = x0; x < x1; ++x, ++dst) {
            *dst = setValue | (keepMask & *dst);
        }

        ++word;
        mask = -1;
    }
}

/**
 * Address: 0x008D8270 (FUN_008D8270, ?AnyBitSet@BitArray2D@gpg@@QBE_NPAH0PAI@Z)
 */
bool BitArray2D::AnyBitSet(unsigned int* storeWidth, unsigned int* storeHeight, unsigned int* progress) const
{
    unsigned int curProgress = 0u;
    if (progress && *progress < static_cast<unsigned int>(size)) {
        curProgress = *progress;
    }

    if (size <= 0 || !ptr || !storeWidth || !storeHeight) {
        return false;
    }

    int totalWork = 0;
    while (ptr[curProgress] == 0) {
        ++curProgress;
        if (curProgress == static_cast<unsigned int>(size)) {
            curProgress = 0u;
        }

        ++totalWork;
        if (totalWork == size) {
            return false;
        }
    }

    *storeWidth = curProgress % static_cast<unsigned int>(width);

    unsigned int bitIndex = 0u;
    unsigned int bits = static_cast<unsigned int>(ptr[curProgress]);
    while ((bits & 1u) == 0u) {
        bits >>= 1u;
        ++bitIndex;
    }

    *storeHeight = bitIndex + 32u * (curProgress / static_cast<unsigned int>(width));
    if (progress) {
        *progress = curProgress;
    }
    return true;
}
}
