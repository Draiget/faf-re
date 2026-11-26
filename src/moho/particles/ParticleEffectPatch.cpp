#include "moho/particles/ParticleEffectPatch.h"

#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

namespace moho
{
  namespace
  {
    // Declarations, inserted ahead of `struct WORLD_OUTPUT` (the vertex shaders use them).
    constexpr std::string_view kDeclarations = R"HLSL(
// ---- FAF: large particles in a lower-resolution target (ParticleLowRes.cpp) ---------------------------------------------------
float4 LRParams = float4(0, 100000, 0, 0); // x: 0 every quad, 1 only the small ones, 2 only the large ones; y: threshold in pixels^2 at full resolution; zw: half the viewport size
float4 LRTarget = float4(1, 1, 1, 1);      // low-resolution target: width, height, 1/width, 1/height
float4 LRView = float4(0, 0, 1, 1);        // the viewport in the scene target: x, y, width, height
float4 LRScene = float4(1, 1, 1, 1);       // the scene target: width, height, 1/width, 1/height
float4 LRRatio = float4(2, 2, 2, 0);       // xy: viewport pixels per low-resolution pixel, z: the integer scale
float4 LRQuad = float4(1, 1, 1, 1);        // the output target of the full-screen passes: width, height, 1/width, 1/height
float4 LRRect = float4(0, 0, 1, 1);        // the part of that target the passes cover, in pixels: left, top, right, bottom (the whole target: 0, 0, width, height)
float4 FlashParams = float4(@FLASHPULL@, 2.5, 0.6, 0);   // flash depth pull: x the pull as a fraction of the quad half size (0: off), y the largest half size and z the longest lifetime (s) of a particle that gets it
float4 SoftParams = float4(0, 0, 0, 0);    // soft particles: x the soft-edge distance in world units along the view axis (0: off, the scene depth is not bound)

texture LRAccumTexture;
texture LRDepthTexture;
texture LRSceneDepthTexture;

sampler2D LRAccumSampler = sampler_state
{
	Texture   = (LRAccumTexture);
	MipFilter = NONE;
	MinFilter = POINT;
	MagFilter = POINT;
	AddressU  = CLAMP;
	AddressV  = CLAMP;
};

sampler2D LRDepthSampler = sampler_state
{
	Texture   = (LRDepthTexture);
	MipFilter = NONE;
	MinFilter = POINT;
	MagFilter = POINT;
	AddressU  = CLAMP;
	AddressV  = CLAMP;
};

sampler2D LRSceneDepthSampler = sampler_state
{
	Texture   = (LRSceneDepthTexture);
	MipFilter = NONE;
	MinFilter = POINT;
	MagFilter = POINT;
	AddressU  = CLAMP;
	AddressV  = CLAMP;
};

// Whether a quad of half size `halfSize` (world units) at view depth `viewDepth` covers LRParams.y pixels^2 or more at full resolution.
bool LRIsLarge(float halfSize, float viewDepth)
{
	float w = max(viewDepth, 0.001);
	float2 pixels = halfSize * 2.0 * float2(Projection[0][0] * LRParams.z, Projection[1][1] * LRParams.w) / w;
	return (pixels.x * pixels.y) >= LRParams.y;
}

// True when the quad is not drawn by the pass LRParams.x selects.
bool LRCull(float halfSize, float viewDepth)
{
	bool large = LRIsLarge(halfSize, viewDepth);
	return (LRParams.x < 1.5) ? large : !large;
}

// The distance along the view axis of a depth value, in world units (positive in front of the camera). The engine's projection is right
// handed (Projection[2][3] is -1, the eye z is negative); the first version of this function left out that term and returned about -3 to -6
// at any depth, so the composite's depth weights below compared nonsense. Same formula as SoftViewDistance.
float LRViewZ(float depth)
{
	return -Projection[3][2] / (depth * Projection[2][3] - Projection[2][2]);
}

)HLSL";

    // Inserted after WorldPS (the techniques that use them come before the end of the file): the pixel shaders of the
    // soft particles. The particle's depth is its own fragment's, the scene's is the copy taken before the particle
    // pass (LRSceneDepthTexture); both go through LRViewZ, so the gap is a distance along the view axis in world units
    // whatever the projection. The fade is a smoothstep of gap / SoftParams.x: 0 where the quad meets the geometry, 1
    // once it is a soft-edge distance in front. ADD and ALPHABLEND blend with the source alpha, so the alpha is scaled;
    // PREMODALPHA has the alpha in the colour already, so the whole colour is scaled.
    constexpr std::string_view kSoftShaders = R"HLSL(

// ---- FAF: soft particles (ParticleLowRes.cpp) ---------------------------------------------------------------------------------
// The distance along the view axis of a depth value (the engine's projection is right handed: Projection[2][3] is -1, the eye z is negative).
float SoftViewDistance(float depth)
{
	return -Projection[3][2] / (depth * Projection[2][3] - Projection[2][2]);
}

float SoftFade(float2 sceneUV, float fragmentDepth)
{
	float fade = 1.0;
	if (SoftParams.x > 0.0)
	{
		float gap = SoftViewDistance(tex2Dlod(LRSceneDepthSampler, float4(sceneUV, 0, 0)).x) - SoftViewDistance(fragmentDepth);
		float f = saturate(gap / SoftParams.x);
		fade = f * f * (3.0 - 2.0 * f);
	}
	return fade;
}

PS_OUTPUT WorldPSSoft(WORLD_OUTPUT inData)
{
	PS_OUTPUT o = (PS_OUTPUT)0;
	float4 color = tex2D(ParticleSampler0,inData.mTex0) * tex2D(ParticleSampler1,inData.mTex1);
	color.a *= SoftFade(inData.mPos.xy * LRScene.zw, inData.mPos.z);
	o.color = color;
	return o;
}

PS_OUTPUT WorldPSSoftPremod(WORLD_OUTPUT inData)
{
	PS_OUTPUT o = (PS_OUTPUT)0;
	float4 color = tex2D(ParticleSampler0,inData.mTex0) * tex2D(ParticleSampler1,inData.mTex1);
	o.color = color * SoftFade(inData.mPos.xy * LRScene.zw, inData.mPos.z);
	return o;
}

)HLSL";

    // Appended at the end of the file (everything it uses is declared above).
    constexpr std::string_view kShaders = R"HLSL(

// ---- FAF: large particles in a lower-resolution target (ParticleLowRes.cpp) ---------------------------------------------------
// The low-resolution passes blend the "over" classes premultiplied, with the colour factors on every channel (the backends blend alpha with
// the colour factors, as D3D9 did): the accumulation holds colour*alpha and the coverage 1-(1-a)(1-b)..., exactly. The depth test is the
// hardware's, against the downsampled scene depth that LRDownsample wrote into the target's depth buffer.
PS_OUTPUT WorldPSLRPremultiplied(WORLD_OUTPUT inData)
{
	PS_OUTPUT o = (PS_OUTPUT)0;
	float4 color = tex2D(ParticleSampler0,inData.mTex0) * tex2D(ParticleSampler1,inData.mTex1);
	o.color = float4(color.rgb * color.a, color.a);
	return o;
}

// The soft particles of the low-resolution passes (SoftParams.x = 0 makes them the plain shaders): the pixel sits in the low-resolution target,
// the scene depth copy is at full resolution, so the lookup goes to the full-resolution pixel the low-resolution pixel is centred on.
float2 LRSceneUV(float4 position)
{
	return (LRView.xy + position.xy * LRRatio.xy) * LRScene.zw;
}

PS_OUTPUT WorldPSSoftLR(WORLD_OUTPUT inData)
{
	PS_OUTPUT o = (PS_OUTPUT)0;
	float4 color = tex2D(ParticleSampler0,inData.mTex0) * tex2D(ParticleSampler1,inData.mTex1);
	color.a *= SoftFade(LRSceneUV(inData.mPos), inData.mPos.z);
	o.color = color;
	return o;
}

PS_OUTPUT WorldPSSoftLRPremod(WORLD_OUTPUT inData)
{
	PS_OUTPUT o = (PS_OUTPUT)0;
	float4 color = tex2D(ParticleSampler0,inData.mTex0) * tex2D(ParticleSampler1,inData.mTex1);
	o.color = color * SoftFade(LRSceneUV(inData.mPos), inData.mPos.z);
	return o;
}

PS_OUTPUT WorldPSSoftLRPremultiplied(WORLD_OUTPUT inData)
{
	PS_OUTPUT o = (PS_OUTPUT)0;
	float4 color = tex2D(ParticleSampler0,inData.mTex0) * tex2D(ParticleSampler1,inData.mTex1);
	color.a *= SoftFade(LRSceneUV(inData.mPos), inData.mPos.z);
	o.color = float4(color.rgb * color.a, color.a);
	return o;
}

struct LR_QUAD_IN {
   float4 Pos : POSITION;
   float2 Tex : TEXCOORD0;
};

struct LR_QUAD_OUT {
   float4 mPos : POSITION;
   float2 mTex : TEXCOORD0;
};

struct LR_DEPTH_OUT {
   float4 color : COLOR0;
   float depth : DEPTH;
};

LR_QUAD_OUT LRQuadVS(LR_QUAD_IN In)
{
	LR_QUAD_OUT Out = (LR_QUAD_OUT)0;
	// The quad's corners run over the whole target; LRRect narrows them to the rectangle that has anything to do.
	float2 corner = (In.Pos.xy + float2(0.5, 0.5)) * LRQuad.zw;
	float2 position = (LRRect.xy + corner * (LRRect.zw - LRRect.xy)) * LRQuad.zw;
	Out.mPos = float4(2 * position.x - 1, 1 - 2 * position.y, In.Pos.z, In.Pos.w);
	Out.mTex = In.Tex;
	return Out;
}

@DOWNSAMPLE@

float4 LRCompositePS(LR_QUAD_OUT inData) : COLOR
{
	// The engine's pixel coordinates (pixel j is centred on j) and the low-resolution texel (i) they fall between.
	float2 pixel = inData.mPos.xy - float2(0.5, 0.5);
	float sceneDepth = tex2D(LRSceneDepthSampler, inData.mPos.xy * LRScene.zw).x;
	float2 q = (pixel - LRView.xy) / LRRatio.xy;
	float2 texel = floor(q);
	float2 f = q - texel;
	float2 uv = (texel + float2(0.5, 0.5)) * LRTarget.zw;
	float2 du = float2(LRTarget.z, 0);
	float2 dv = float2(0, LRTarget.w);

	float4 c00 = tex2D(LRAccumSampler, uv);
	float4 c10 = tex2D(LRAccumSampler, uv + du);
	float4 c01 = tex2D(LRAccumSampler, uv + dv);
	float4 c11 = tex2D(LRAccumSampler, uv + du + dv);
	// Nothing drawn around here: nothing to blend (and the blend, the costly part of this pass, is skipped).
	if (max(max(c00.a + c00.r + c00.g + c00.b, c10.a + c10.r + c10.g + c10.b), max(c01.a + c01.r + c01.g + c01.b, c11.a + c11.r + c11.g + c11.b)) <= 0.0)
		discard;

	// Explicit level: after the discard the invocations that remain are not a full quad, so an implicit level (derivatives) is
	// undefined on some GPUs (the samplers are point, no mips: the level is 0 anyway).
	float z = LRViewZ(sceneDepth);
	float e00 = abs(LRViewZ(tex2Dlod(LRDepthSampler, float4(uv, 0, 0)).x) - z);
	float e10 = abs(LRViewZ(tex2Dlod(LRDepthSampler, float4(uv + du, 0, 0)).x) - z);
	float e01 = abs(LRViewZ(tex2Dlod(LRDepthSampler, float4(uv + dv, 0, 0)).x) - z);
	float e11 = abs(LRViewZ(tex2Dlod(LRDepthSampler, float4(uv + du + dv, 0, 0)).x) - z);

	// Bilinear weights, each divided by how far that texel's depth is from this pixel's: on a smooth surface (all within about 1.5 %) this
	// is the bilinear upsample, at a depth edge it leans on the texels that are on this pixel's side of it, without a hard switch.
	float s = 0.015 * z;
	float w00 = (1 - f.x) * (1 - f.y) / (1 + (e00 / s) * (e00 / s));
	float w10 = f.x * (1 - f.y) / (1 + (e10 / s) * (e10 / s));
	float w01 = (1 - f.x) * f.y / (1 + (e01 / s) * (e01 / s));
	float w11 = f.x * f.y / (1 + (e11 / s) * (e11 / s));
	return (c00 * w00 + c10 * w10 + c01 * w01 + c11 * w11) / max(w00 + w10 + w01 + w11, 0.000001);
}

technique LRDownsample2
{
	pass P0
	{
		AlphaState( AlphaBlend_Disable )
		DepthState( Depth_Always )
		RasterizerState( Rasterizer_Cull_None )

		VertexShader = compile vs_1_1 LRQuadVS();
		PixelShader = compile ps_2_0 LRDownsamplePS2();
	}
}

technique LRDownsample4
{
	pass P0
	{
		AlphaState( AlphaBlend_Disable )
		DepthState( Depth_Always )
		RasterizerState( Rasterizer_Cull_None )

		VertexShader = compile vs_1_1 LRQuadVS();
		PixelShader = compile ps_2_0 LRDownsamplePS4();
	}
}

technique LRComposite
{
	pass P0
	{
		AlphaState( AlphaBlend_One_InvSrcAlpha_Write_RGB )
		DepthState( Depth_Disable_Write_None )
		RasterizerState( Rasterizer_Cull_None )

		VertexShader = compile vs_1_1 LRQuadVS();
		PixelShader = compile ps_2_0 LRCompositePS();
	}
}
)HLSL";

    // The farthest scene depth in the (2n-1)^2 footprint around the full-resolution pixel a low-resolution pixel sits
    // on; n is the scale.
    std::string DownsampleShader(
      const int scale
    )
    {
      const std::string n = std::to_string(scale);
      const std::string reach = std::to_string(scale - 1);
      std::string text;
      text += "LR_DEPTH_OUT LRDownsamplePS" + n + "(LR_QUAD_OUT inData)\n{\n";
      text += "\tfloat2 center = LRView.xy + floor(inData.mPos.xy) * LRRatio.xy;\n";
      text += "\tfloat2 minPixel = LRView.xy;\n\tfloat2 maxPixel = LRView.xy + LRView.zw - float2(1, 1);\n";
      text += "\tfloat farthest = 0;\n";
      text += "\tfor (int y = -" + reach + "; y <= " + reach + "; ++y)\n\t{\n";
      text += "\t\tfor (int x = -" + reach + "; x <= " + reach + "; ++x)\n\t\t{\n";
      text += "\t\t\tfloat2 pixel = clamp(center + float2(x, y), minPixel, maxPixel);\n";
      text +=
        "\t\t\tfarthest = max(farthest, tex2D(LRSceneDepthSampler, (pixel + float2(0.5, 0.5)) * LRScene.zw).x);\n";
      text += "\t\t}\n\t}\n";
      text += "\tLR_DEPTH_OUT o;\n\to.color = float4(0, 0, 0, 0);\n\to.depth = farthest;\n\treturn o;\n}\n";
      return text;
    }

    [[nodiscard]] std::size_t CountOf(
      const std::string& text,
      const std::string_view what
    )
    {
      std::size_t count = 0U;
      for (std::size_t at = text.find(what); at != std::string::npos; at = text.find(what, at + what.size())) {
        ++count;
      }
      return count;
    }

    [[nodiscard]] std::size_t MatchingBrace(
      const std::string& text,
      const std::size_t open
    )
    {
      int depth = 0;
      for (std::size_t index = open; index < text.size(); ++index) {
        if (text[index] == '{') {
          ++depth;
        } else if (text[index] == '}' && --depth == 0) {
          return index;
        }
      }
      return std::string::npos;
    }

    /** Replaces the call `<key>( ... )` (first one in `text`) with `<key>( replacement )`; false when there is none. */
    bool ReplaceCallArgument(
      std::string& text,
      const std::string_view key,
      const std::string_view replacement
    )
    {
      const std::size_t at = text.find(key);
      if (at == std::string::npos) {
        return false;
      }
      const std::size_t open = text.find('(', at);
      const std::size_t close = text.find(')', open);
      if (open == std::string::npos || close == std::string::npos) {
        return false;
      }
      text.replace(open + 1U, close - open - 1U, std::string(" ") + std::string(replacement) + " ");
      return true;
    }

    [[nodiscard]] bool EndsWith(
      const std::string_view text,
      const std::string_view suffix
    ) noexcept
    {
      return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
    }

    enum class Blend
    {
      Add,
      Alpha,
      Premod,
    };

    /** A world-particle technique with an ADD, ALPHABLEND or PREMODALPHA blend and the plain WorldPS: `open`..`close`
     * is its `{ ... }`. */
    struct WorldTechnique
    {
      std::string name;
      Blend blend = Blend::Add;
      bool flat = false; // lies on the ground by design (TRampFlat, TRampAnimateFlat): it would fade away completely,
                         // so it stays hard-edged
      std::size_t open = 0U;
      std::size_t close = 0U;
    };

    std::vector<WorldTechnique> FindWorldTechniques(
      const std::string& source
    )
    {
      std::vector<WorldTechnique> found;
      constexpr std::string_view kKeyword = "technique ";
      std::size_t at = 0U;
      while ((at = source.find(kKeyword, at)) != std::string::npos) {
        const bool lineStart = at == 0U || source[at - 1U] == '\n';
        std::size_t nameBegin = at + kKeyword.size();
        const std::size_t nameEnd = source.find_first_of(" \t\r\n{", nameBegin);
        at = nameBegin;
        if (!lineStart || nameEnd == std::string::npos) {
          continue;
        }
        WorldTechnique technique;
        technique.name = source.substr(nameBegin, nameEnd - nameBegin);
        technique.open = source.find('{', nameEnd);
        technique.close =
          (technique.open != std::string::npos) ? MatchingBrace(source, technique.open) : std::string::npos;
        if (technique.close == std::string::npos) {
          continue;
        }
        at = technique.close;
        const bool add = EndsWith(technique.name, "_ADD");
        const bool alpha = EndsWith(technique.name, "_ALPHABLEND");
        const bool premod = EndsWith(technique.name, "_PREMODALPHA");
        if (!(add || alpha || premod) || technique.name.rfind("TRamp", 0U) != 0U) {
          continue;
        }
        const std::string body = source.substr(technique.open, technique.close - technique.open + 1U);
        if (
          body.find("WorldPS()") == std::string::npos ||
          (body.find("WorldVS(") == std::string::npos && body.find("WorldVSAlign(") == std::string::npos)
        ) {
          continue;
        }
        technique.blend = add ? Blend::Add : (alpha ? Blend::Alpha : Blend::Premod);
        technique.flat = technique.name.find("Flat") != std::string::npos;
        found.push_back(std::move(technique));
      }
      return found;
    }

    /** Replaces the plain WorldPS() of a technique body with `shader` (a call, `Name()`). */
    void UseShader(
      std::string& body,
      const std::string_view shader
    )
    {
      const std::size_t at = body.find("WorldPS()");
      if (at != std::string::npos) {
        body.replace(at, 9U, shader);
      }
    }

    /** The `_LR` twins of every world-particle technique with an ADD, ALPHABLEND or PREMODALPHA blend (with the
     * soft-particle shaders). */
    std::string BuildLowResolutionTechniques(
      const std::string& source,
      int& count
    )
    {
      std::string twins;
      for (const WorldTechnique& technique : FindWorldTechniques(source)) {
        std::string body = source.substr(technique.open, technique.close - technique.open + 1U);
        if (
          technique.blend != Blend::Add &&
          !ReplaceCallArgument(body, "AlphaState", "AlphaBlend_One_InvSrcAlpha_Write_RGBA")
        ) {
          continue;
        }
        if (technique.flat) {
          if (technique.blend == Blend::Alpha) {
            UseShader(body, "WorldPSLRPremultiplied()");
          }
        } else {
          UseShader(
            body,
            technique.blend == Blend::Add
              ? "WorldPSSoftLR()"
              : (technique.blend == Blend::Alpha ? "WorldPSSoftLRPremultiplied()" : "WorldPSSoftLRPremod()")
          );
        }
        twins += "\ntechnique " + technique.name + "_LR\n" + body + "\n";
        ++count;
      }
      return twins;
    }

    /** The same techniques at full resolution get the soft-particle shader in place of WorldPS (fade 1 while
     * SoftParams.x is 0). */
    int SoftenTechniques(
      std::string& source
    )
    {
      const std::vector<WorldTechnique> techniques = FindWorldTechniques(source);
      int softened = 0;
      // Back to front, so the offsets of the ones still to do stay valid.
      for (auto it = techniques.rbegin(); it != techniques.rend(); ++it) {
        if (it->flat) {
          continue;
        }
        ++softened;
        std::string body = source.substr(it->open, it->close - it->open + 1U);
        UseShader(body, it->blend == Blend::Premod ? "WorldPSSoftPremod()" : "WorldPSSoft()");
        source.replace(it->open, it->close - it->open + 1U, body);
      }
      return softened;
    }
  } // namespace

  namespace
  {
    bool sPatched = false;
  }

  bool ParticleAdditionsDisabled() noexcept
  {
    static const bool disabled = [] {
      std::size_t length = 0U;
      char value[8] = {};
      return ::getenv_s(&length, value, sizeof(value), "FAF_NO_RENDER_ADDITIONS") == 0 && length != 0U &&
        value[0] == '1';
    }();
    return disabled;
  }

  void SetParticleEffectPatched(
    const bool patched
  ) noexcept
  {
    sPatched = patched;
  }

  bool ParticleEffectPatched() noexcept
  {
    return sPatched;
  }

  ParticleEffectPatchResult PatchParticleEffect(
    std::string& source
  )
  {
    ParticleEffectPatchResult result;

    constexpr std::string_view kStruct = "struct WORLD_OUTPUT";
    constexpr std::string_view kBillboard = "// Billboard the quads.";
    constexpr std::string_view kViewSpace = "pos = mul( float4(pos, 1), ViewMatrix );";
    const std::size_t structAt = source.find(kStruct);
    if (
      structAt == std::string::npos || source.find("WORLD_OUTPUT WorldVS(") == std::string::npos ||
      source.find("WORLD_OUTPUT WorldVSAlign(") == std::string::npos ||
      source.find("PS_OUTPUT WorldPS(") == std::string::npos
    ) {
      result.error = "WORLD_OUTPUT, WorldVS, WorldVSAlign or WorldPS not found";
      return result;
    }
    if (
      CountOf(source, kBillboard) != 1U || CountOf(source, kViewSpace) != 1U ||
      source.find("float4x4 Projection;") == std::string::npos
    ) {
      result.error = "the vertex shader anchors are not as expected";
      return result;
    }
    if (source.find("LRParams") != std::string::npos) {
      result.error = "already patched";
      return result;
    }

    std::string patched = source;
    // The vertex shader hooks first (they are found by text that the insertions below do not touch).
    {
      const std::size_t at = patched.find(kBillboard);
      patched.insert(
        at,
        "if( !inFlat && FlashParams.x > 0 && lifetime < FlashParams.z && (Size.x + (Size.y * t)) < FlashParams.y )\n"
        "\t\t\tpos += normalize(InverseViewMatrix[3].xyz - pos) * ((Size.x + (Size.y * t)) * FlashParams.x);\n\n\t\t"
        "if( LRParams.x != 0 && LRCull(Size.x + (Size.y * t), mul(float4(pos, 1), WorldToProjection).w) )\n"
        "\t\t\treturn Out;\n\n\t\t"
      );
    }
    {
      const std::size_t at = patched.find(kViewSpace);
      patched.insert(
        at + kViewSpace.size(),
        "\n\t\tif( LRParams.x != 0 && LRCull(Size.x + (Size.y * t), pos.z) )\n\t\t\treturn Out;\n"
      );
    }
    {
      // Muzzle flashes (small, short-lived billboards) are pulled toward the camera by a fraction of their size, so the
      // barrel they sit in does not cut them in half and the soft-particle fade does not take them where they touch the
      // unit. FAF_FLASH_PULL overrides the fraction (0: off).
      std::string declarations(kDeclarations);
      double pull = 0.9;
      if (const char* const env = std::getenv("FAF_FLASH_PULL")) {
        pull = std::strtod(env, nullptr);
      }
      char number[32];
      std::snprintf(number, sizeof(number), "%.3f", pull < 0.0 ? 0.0 : pull);
      declarations.replace(declarations.find("@FLASHPULL@"), 11U, number);
      const std::size_t at = patched.find(kStruct);
      patched.insert(at, declarations);
    }

    {
      // The soft-particle shaders go right after WorldPS, which the techniques that use them come after.
      const std::size_t pixelShader = patched.find("PS_OUTPUT WorldPS(");
      const std::size_t open = patched.find('{', pixelShader);
      const std::size_t close = open != std::string::npos ? MatchingBrace(patched, open) : std::string::npos;
      if (close == std::string::npos) {
        result.error = "WorldPS has no body";
        return result;
      }
      patched.insert(close + 1U, kSoftShaders);
    }

    int twins = 0;
    const std::string lowResolution = BuildLowResolutionTechniques(patched, twins);
    if (twins == 0) {
      result.error = "no ADD / ALPHABLEND / PREMODALPHA world-particle technique found";
      return result;
    }
    result.softened = SoftenTechniques(patched);

    std::string shaders(kShaders);
    const std::string downsample = DownsampleShader(2) + "\n" + DownsampleShader(4);
    const std::size_t marker = shaders.find("@DOWNSAMPLE@");
    shaders.replace(marker, 12U, downsample);

    patched += shaders;
    patched += lowResolution;

    source = std::move(patched);
    result.patched = true;
    result.techniques = twins;
    return result;
  }
} // namespace moho
