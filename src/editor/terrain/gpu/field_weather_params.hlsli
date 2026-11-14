// Constant buffer of field_weather.hlsl (op erode_rocksoil).
#ifndef GPU_FIELD_WEATHER_PARAMS_HLSLI
#define GPU_FIELD_WEATHER_PARAMS_HLSLI

struct WeatherParams
{
    uint w;
    uint h;
    uint pad0;
    uint pad1;
    float weather;   // rock weathered per step at no soil cover
    float depth0;    // soil depth at which the weathering has dropped to 1/e
    float pad2;
    float pad3;
};

#endif
