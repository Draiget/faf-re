// Op erode_rocksoil (EdFieldEro2.cpp OpRockSoil), the weathering step: d = weather * exp(-soil / depth0); rock -= d; soil += d (in place, one thread per cell).
#include "field_weather_params.hlsli"

CBUFFER(WeatherParams, P, 0)
UAV_BUFFER(float, rock, 0)
UAV_BUFFER(float, soil, 1)

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    uint i = dtid.y * P.w + dtid.x;
    float d = P.weather * exp(-soil[i] / P.depth0);
    rock[i] = rock[i] - d;
    soil[i] = soil[i] + d;
}
