#include "GalTestSupport.h"

#include <cstring>

namespace faf_gal_tests
{
  float FloatAt(const std::span<const std::uint8_t> image, const std::size_t offset)
  {
    float value = 0.0f;
    if (offset + sizeof(value) <= image.size()) {
      std::memcpy(&value, image.data() + offset, sizeof(value));
    }
    return value;
  }

  std::uint32_t WordAt(const std::span<const std::uint8_t> image, const std::size_t offset)
  {
    std::uint32_t value = 0U;
    if (offset + sizeof(value) <= image.size()) {
      std::memcpy(&value, image.data() + offset, sizeof(value));
    }
    return value;
  }

  std::int32_t IntAt(const std::span<const std::uint8_t> image, const std::size_t offset)
  {
    return static_cast<std::int32_t>(WordAt(image, offset));
  }

  std::uint32_t Bits(const float value)
  {
    std::uint32_t bits = 0U;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
  }

  std::size_t Count(const std::string_view text, const std::string_view needle)
  {
    std::size_t count = 0U;
    for (std::size_t at = text.find(needle); !needle.empty() && at != std::string_view::npos; at = text.find(needle, at + needle.size())) {
      ++count;
    }
    return count;
  }

  const char* const kDrawEffect = R"fx(
float4x4 WorldViewProj;
float Scale = 1;
float4 Tint = float4( 1, 0.5, 0.25, 1 );
texture BaseTexture;
texture EnvTexture;
texture UnusedTexture;
string Name = "draw";

sampler2D BaseSampler = sampler_state
{
    Texture = <BaseTexture>;
    Filter = MIN_MAG_MIP_POINT;
    AddressU = WRAP;
};

samplerCUBE EnvSampler = sampler_state
{
    Texture = <EnvTexture>;
};

struct VSOut
{
    float4 pos : POSITION;
    float2 uv : TEXCOORD0;
    float3 dir : TEXCOORD1;
};

VSOut MainVS( float3 position : POSITION, float2 uv : TEXCOORD0, uniform float bias )
{
    VSOut o;
    Scale = Scale * 2;
    o.pos = mul( float4( position * Scale + bias, 1 ), WorldViewProj );
    o.uv = uv;
    o.dir = position;
    return o;
}

float4 Lookup( sampler2D s, float2 uv )
{
    return tex2D( s, uv );
}

float4 MainPS( VSOut i ) : COLOR0
{
    return Lookup( BaseSampler, i.uv ) * texCUBE( EnvSampler, i.dir ) * Tint;
}

BlendState Opaque
{
    BlendEnable[0] = FALSE;
};

technique10 Draw < string Category = "opaque"; int Order = 2; float Weight = 0.5; bool Lit = true; >
{
    pass P0
    {
        SetBlendState( Opaque, float4( 0, 0, 0, 0 ), 0xFFFFFFFF );
        SetVertexShader( CompileShader( vs_4_0, MainVS( 0.5 ) ) );
        SetPixelShader( CompileShader( ps_4_0, MainPS() ) );
    }
    pass P1
    {
        SetVertexShader( CompileShader( vs_4_0, MainVS( 0.5 ) ) );
        SetPixelShader( CompileShader( ps_4_0, MainPS() ) );
    }
    pass P2
    {
        SetVertexShader( CompileShader( vs_4_0, MainVS( 1.5 ) ) );
        SetPixelShader( CompileShader( ps_4_0, MainPS() ) );
    }
}
)fx";

  const char* const kTessellatedEffect = R"fx(
float4x4 WorldViewProj;
float Lift = 0.25;

struct ControlPoint
{
    float4 position : TEXCOORD0;
};

struct Surface
{
    float4 pos : POSITION;
    float2 uv : TEXCOORD0;
};

ControlPoint PointVS( float3 position : POSITION )
{
    ControlPoint o;
    o.position = float4( position, 1 );
    return o;
}

float4 Factors( ControlPoint a, ControlPoint b, ControlPoint c )
{
    float edge = max( distance( a.position.xyz, b.position.xyz ), 1 );
    return float4( edge, edge, edge, edge );
}

Surface Place( float3 weights, ControlPoint a, ControlPoint b, ControlPoint c, uniform float scale )
{
    Surface o;
    float4 p = a.position * weights.x + b.position * weights.y + c.position * weights.z;
    p.y -= Lift * scale;
    o.pos = mul( p, WorldViewProj );
    o.uv = p.xz;
    return o;
}

float4 FlatPS( Surface i ) : COLOR0
{
    return float4( i.uv, 0, 1 );
}

technique10 Tessellated
{
    pass P0
    {
        SetVertexShader( CompileShader( vs_4_0, PointVS() ) );
        SetHullShader( CompileShader( hs_5_0, Factors() ) );
        SetDomainShader( CompileShader( ds_5_0, Place( 2.0 ) ) );
        SetPixelShader( CompileShader( ps_4_0, FlatPS() ) );
    }
}
)fx";
} // namespace faf_gal_tests
