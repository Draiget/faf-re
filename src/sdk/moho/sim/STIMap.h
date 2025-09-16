#pragma once
#include <cstdint>
#include <vector>

#include "legacy/containers/Vector.h"

namespace moho
{
	struct MapData;      // unknown yet
	struct LuaObject;    // your env type

    /**
     * Pair of minimum and maximum sample values.
     */
    template<typename T>
    struct SMinMax {
        T min{};
        T max{};
    };

    struct GridU16
	{
        uint16_t* data{ nullptr };
        int width{ 0 };
        int height{ 0 };

        /**
         * Bounds-checked read with clamping.
         */
        [[nodiscard]] uint16_t AtClamped(int x, int y) const {
            if (width <= 0 || height <= 0 || !data) {
                return 0;
            }
            if (x < 0) {
                x = 0;
            } else if (x >= width) {
                x = width - 1;
            }
            if (y < 0) {
                y = 0;
            } else if (y >= height) {
                y = height - 1;
            }
            return data[y * width + x];
        }
    };

    struct GridI16
	{
        int16_t* data{ nullptr };
        int width{ 0 };
        int height{ 0 };
    };

    struct MinMaxGridU16 {
        SMinMax<uint16_t>* data{ nullptr };
        int width{ 0 };
        int height{ 0 };

        /**
         * Bounds-checked read with clamping.
         */
        [[nodiscard]] SMinMax<uint16_t> AtClamped(int x, int y) const {
            if (width <= 0 || height <= 0 || !data) {
                return {};
            }
            if (x < 0) {
                x = 0;
            } else if (x >= width) {
                x = width - 1;
            }
            if (y < 0) {
                y = 0;
            } else if (y >= height) {
                y = height - 1;
            }
            return data[y * width + x];
        }
    };

    struct TierLevel {
        MinMaxGridU16 minmax;
        GridI16       aux;   // exact purpose unknown here; seen as int16 grid elsewhere
    };

    struct CHeightField
    {
        uint16_t* data{ nullptr }; // +0
        int       width{ 0 };      // +4
        int       height{ 0 };     // +8

        // Higher-level view
        msvc8::vector<TierLevel> tiers;

        [[nodiscard]]
    	uint16_t GetHeightAt(int x, int z) const {
            if (!data || width <= 0 || height <= 0) return 0;
            if (x < 0) x = 0; else if (x >= width)  x = width - 1;
            if (z < 0) z = 0; else if (z >= height) z = height - 1;
            return data[z * width + x];
        } // 0x00478490

        void InitField(int width, int height); // 0x004783D0
        //Wm3::AxisAlignedBox3f GetTierBox(int x, int z, char a3); // 0x00475DF0
        //Moho::SMinMax<unsigned short> GetTierBoundsUWord(int idx, int x, int y); // 0x00475BF0
    };

	class STIMap
	{
	public:
        MapData* MapData;        // 0x0000
        CHeightField* HeightField;    // 0x0004
        uint32_t      unk1[4];        // 0x0008
        // 0x0018
        void* beginData;      // 0x0018
        void* endData;        // 0x001C
        void* endData2;       // 0x0020
        void* beginData2;     // 0x0024

        // 0x0028
        char*     Data[0x100];    // type desc tables (size of LuaObject TBD)

        uint8_t* TerrainTypes;   // ... + (Y*SizeX + X)
        int32_t       SizeX;
        int32_t       SizeY;

        uint8_t       unk2[0x100];

        // 0x1534
        int32_t       Water;          // BOOL
        float         WaterLevel;
        float         DepthLevel;
        float         AbyssLevel;
        uint32_t      unk3;
	};
}
