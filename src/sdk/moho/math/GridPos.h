#pragma once
#include "wm3/Vector3.h"

namespace moho
{
    struct GridPos
    {
        int x;
        int z;

        /**
         * Address: 0x00506E20
         * @param wldPos 
         * @param gridSize 
         */
        GridPos(Wm3::Vec3f* wldPos, int gridSize) noexcept;
    };
}
