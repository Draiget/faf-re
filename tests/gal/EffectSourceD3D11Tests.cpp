// gpg/gal/backends/d3d11/EffectSourceD3D11.h: the override layer every effect passes through before
// the Direct3D 11, 12 and Vulkan backends see it. Inputs are written as the effect preprocessor
// leaves the game's effects with d3d10states.compat (technique -> technique10, ps_2_0 -> ps_4_0);
// the D3D9 passes are modelled on range.fx's Cast technique and water2.fx's alpha test. The output
// is read back with the effect parser, so the expected values are Direct3D 11 enumerators
// (d3d11.h) for the D3D9 render states the header lists, mapped as the Direct3D 9 documentation
// defines those states (D3DRS_STENCILMASK is the read mask, the CCW_ stencil states apply to the
// back faces when TWOSIDEDSTENCILMODE is on, D3DRS_DEPTHBIAS is a fraction of the depth range).

#include <gtest/gtest.h>

#include <d3d11.h>

#include <cstdint>
#include <string>
#include <vector>

#include "gpg/gal/backends/d3d11/EffectSourceD3D11.h"
#include "gpg/gal/effects/EffectDescription.h"

using gpg::gal::d3d11::TranslatedEffectSource;
using gpg::gal::d3d11::TranslateEffectSource;
using namespace gpg::gal::effects;

namespace
{
  constexpr std::uint8_t U8(const int value)
  {
    return static_cast<std::uint8_t>(value);
  }

  bool Contains(const std::string& text, const std::string& needle)
  {
    return text.find(needle) != std::string::npos;
  }

  bool HasNote(const TranslatedEffectSource& translated, const std::string& note)
  {
    for (const std::string& line : translated.notes) {
      if (line == note) {
        return true;
      }
    }
    return false;
  }

  const Pass& OnlyPass(const EffectDescription& description, const char* const technique)
  {
    const Technique* const found = description.FindTechnique(technique);
    if (found == nullptr || found->passes.empty()) {
      ADD_FAILURE() << "no pass in technique " << technique;
      static const Pass kNone{};
      return kNone;
    }
    return found->passes[0];
  }

  const char* const kCast = R"fx(
float4x4 viewMatrix;
struct Vertex { float4 position : POSITION0; };
Vertex vertexShader( float3 vertex : POSITION0 )
{
    Vertex result = (Vertex)0;
    result.position = mul( float4( vertex, 1 ), viewMatrix );
    return result;
}
technique10 Cast
{
    pass P0
    {
        CullMode = none;
        ColorWriteEnable = 0x00;
        ZWriteEnable = false;
        ZEnable = true;
        ZFunc = less;
        StencilEnable = true;
        StencilWriteMask = 0x7F;
        StencilRef = 0xFF;
        StencilMask = 0x80;
        TwoSidedStencilMode = true;
        StencilFail = zero;
        StencilZFail = incr;
        StencilPass = keep;
        StencilFunc = notequal;
        CCW_StencilFail = keep;
        CCW_StencilZFail = decr;
        CCW_StencilPass = keep;
        CCW_StencilFunc = notequal;
        VertexShader = compile vs_4_0 vertexShader();
    }
}
)fx";

  const char* const kMixed = R"fx(
#line 1 "mixed.fx"
BlendState AlphaBlend_Disable
{
    BlendEnable[0] = false;
    RenderTargetWriteMask[0] = 0x0F;
    SrcBlend = ONE;
    DestBlend = ZERO;
    BlendOp = ADD;
    SrcBlendAlpha = ONE;
    DestBlendAlpha = ZERO;
    BlendOpAlpha = ADD;
};
BlendState Add { BlendEnable[0] = TRUE; SrcBlend = SRC_COLOR; DestBlend = ONE; SrcBlendAlpha = ONE; DestBlendAlpha = ZERO; BlendOpAlpha = ADD; };
RasterizerState Rasterizer_Bias_Decal { CullMode = BACK; DepthBias = -0.00001; SlopeScaledDepthBias = -1.5; DepthClipEnable = FALSE; };
texture RampTexture;
sampler1D RampSampler = sampler_state { Texture = <RampTexture>; };
struct Cirrus { float4 colour : COLOR0; };
struct VOut { float4 pos : POSITION; float2 uv : TEXCOORD0; float4 col : COLOR0; };
Cirrus CirrusVS( float4 p : POSITION0 ) { Cirrus c; c.colour = p; return c; }
VOut LinkVS( float4 p : POSITION ) { VOut o = (VOut)0; o.pos = p; return o; }
float4 LinkPS( float4 col : COLOR0, float2 uv : TEXCOORD0 ) : COLOR0 { return col * uv.x; }
float4 PrefixPS( float4 pos : POSITION, float2 uv : TEXCOORD0 ) : COLOR0 { return uv.xyxy; }
float4 RampPS( float u : TEXCOORD0 ) : COLOR0 { return tex1D( RampSampler, u ); }
technique10 Cirrus { pass P0 { VertexShader = compile vs_4_0 CirrusVS(); } }
technique10 Glow
{
    pass P0
    {
        SetBlendState( AlphaBlend_Disable, float4( 0, 0, 0, 0 ), 0x0000000F );
        AlphaBlendEnable = true;
        SrcBlend = SrcColor;
        DestBlend = One;
        BlendOp = RevSubtract;
        ColorWriteEnable = 0x07;
        VertexShader = compile vs_4_0 LinkVS();
    }
}
technique10 Link
{
    pass P0 { VertexShader = compile vs_4_0 LinkVS(); PixelShader = compile ps_4_0 LinkPS(); }
    pass P1 { VertexShader = compile vs_4_0 LinkVS(); PixelShader = compile ps_4_0 PrefixPS(); }
    pass P2 { VertexShader = compile vs_4_0 LinkVS(); PixelShader = compile ps_4_0 LinkPS(); }
}
technique10 Decal
{
    pass P0 { SetRasterizerState( Rasterizer_Bias_Decal ); VertexShader = compile vs_4_0 LinkVS(); }
    pass P1 { DepthBias = -0.0002; SlopeScaleDepthBias = 2; FillMode = Wireframe; VertexShader = compile vs_4_0 LinkVS(); }
}
technique10 Odd { pass P0 { ZFunc = Sometimes; FogEnable = false; AlphaTestEnable = false; Lighting = true; VertexShader = compile vs_4_0 LinkVS(); } }
technique10 Bloom { pass P0 { VertexShader = compile vs_4_0 FixedFuncVS(); PixelShader = compile ps_4_0 FixedFuncPS(); } }
technique10 Overlay { pass P0 { VertexShader = compile vs_4_0 FixedFuncVS(); } }
)fx";
} // namespace

TEST(GalEffectSourceD3D11, Direct3D9DepthAndStencilStatesBecomeAStateObject)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kCast, false, {});
  const EffectDescription description = ParseEffect(translated.source);
  const Pass& pass = OnlyPass(description, "Cast");

  ASSERT_TRUE(pass.depthStencil.has_value());
  const DepthStencilDesc& depth = *pass.depthStencil;
  EXPECT_TRUE(depth.depthEnable);
  EXPECT_FALSE(depth.depthWrite);
  EXPECT_EQ(depth.depthFunc, U8(D3D11_COMPARISON_LESS));
  EXPECT_TRUE(depth.stencilEnable);
  EXPECT_EQ(depth.stencilReadMask, 0x80U);
  EXPECT_EQ(depth.stencilWriteMask, 0x7FU);
  EXPECT_EQ(depth.front.failOp, U8(D3D11_STENCIL_OP_ZERO));
  EXPECT_EQ(depth.front.depthFailOp, U8(D3D11_STENCIL_OP_INCR));
  EXPECT_EQ(depth.front.passOp, U8(D3D11_STENCIL_OP_KEEP));
  EXPECT_EQ(depth.front.func, U8(D3D11_COMPARISON_NOT_EQUAL));
  EXPECT_EQ(depth.back.failOp, U8(D3D11_STENCIL_OP_KEEP));
  EXPECT_EQ(depth.back.depthFailOp, U8(D3D11_STENCIL_OP_DECR));
  EXPECT_EQ(depth.back.passOp, U8(D3D11_STENCIL_OP_KEEP));
  EXPECT_EQ(depth.back.func, U8(D3D11_COMPARISON_NOT_EQUAL));
  EXPECT_EQ(pass.stencilRef, 0xFFU);

  ASSERT_TRUE(pass.blend.has_value());
  EXPECT_FALSE(pass.blend->enable);
  EXPECT_EQ(pass.blend->writeMask, 0U) << "ColorWriteEnable = 0";

  ASSERT_TRUE(pass.rasterizer.has_value());
  EXPECT_EQ(pass.rasterizer->cullMode, U8(D3D11_CULL_NONE));
  EXPECT_TRUE(pass.rasterizer->depthClipEnable) << "D3D9 always clips depth";
  EXPECT_EQ(pass.vertexShader.function, "vertexShader");
  EXPECT_TRUE(description.notes.empty());

  // One-sided stencil: the back faces take the front's states.
  std::string oneSided = kCast;
  oneSided.replace(oneSided.find("TwoSidedStencilMode = true;"), 27U, "TwoSidedStencilMode = false;");
  const EffectDescription single = ParseEffect(TranslateEffectSource(oneSided, false, {}).source);
  const DepthStencilDesc& singleDepth = *OnlyPass(single, "Cast").depthStencil;
  EXPECT_EQ(singleDepth.back.failOp, U8(D3D11_STENCIL_OP_ZERO));
  EXPECT_EQ(singleDepth.back.depthFailOp, U8(D3D11_STENCIL_OP_INCR));
}

TEST(GalEffectSourceD3D11, PassBlendStatesMergeIntoTheBoundStateObject)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  const EffectDescription description = ParseEffect(translated.source);
  const Pass& glow = OnlyPass(description, "Glow");
  ASSERT_TRUE(glow.blend.has_value());
  EXPECT_TRUE(glow.blend->enable);
  EXPECT_EQ(glow.blend->srcBlend, U8(D3D11_BLEND_SRC_COLOR));
  EXPECT_EQ(glow.blend->destBlend, U8(D3D11_BLEND_ONE));
  EXPECT_EQ(glow.blend->blendOp, U8(D3D11_BLEND_OP_REV_SUBTRACT));
  EXPECT_EQ(glow.blend->srcBlendAlpha, U8(D3D11_BLEND_SRC_ALPHA)) << "D3D9 blends alpha with the colour factors";
  EXPECT_EQ(glow.blend->destBlendAlpha, U8(D3D11_BLEND_ONE));
  EXPECT_EQ(glow.blend->blendOpAlpha, U8(D3D11_BLEND_OP_REV_SUBTRACT));
  EXPECT_EQ(glow.blend->writeMask, 0x07U);
  EXPECT_EQ(glow.sampleMask, 0x0000000FU) << "the bound state's sample mask is kept";

  // The compat file's states blend alpha with their colour factors too (the text the D3D11
  // backend's effect compiler reads).
  const std::size_t add = translated.source.find("BlendState Add");
  ASSERT_NE(add, std::string::npos);
  const std::string addBody = translated.source.substr(add, translated.source.find('}', add) - add);
  EXPECT_TRUE(Contains(addBody, "SrcBlendAlpha = SRC_ALPHA;"));
  EXPECT_TRUE(Contains(addBody, "DestBlendAlpha = ONE;"));
  EXPECT_FALSE(Contains(addBody, "DestBlendAlpha = ZERO;"));
}

TEST(GalEffectSourceD3D11, OneDimensionalSamplersReadATwoDimensionalRamp)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  EXPECT_FALSE(Contains(translated.source, "sampler1D"));
  EXPECT_TRUE(Contains(translated.source, "sampler2D RampSampler"));
  EXPECT_TRUE(Contains(translated.source, "faf_tex1D( RampSampler, u )"));
  EXPECT_TRUE(Contains(translated.source, "float4 faf_tex1D(sampler2D s, float u) { return tex2D(s, float2(u, 0.5)); }"));
  EXPECT_TRUE(HasNote(translated, "1D samplers read as 2D: 1 sampler(s), 1 read(s)"));
}

TEST(GalEffectSourceD3D11, ShaderModelIsRaisedOnRequest)
{
  const TranslatedEffectSource raised = TranslateEffectSource(kMixed, true, {});
  EXPECT_FALSE(Contains(raised.source, "vs_4_0"));
  EXPECT_FALSE(Contains(raised.source, "ps_4_0"));
  EXPECT_TRUE(Contains(raised.source, "compile vs_4_1 LinkVS()"));
  EXPECT_TRUE(HasNote(raised, "shader model 4.1 profiles"));

  const TranslatedEffectSource kept = TranslateEffectSource(kMixed, false, {});
  EXPECT_TRUE(Contains(kept.source, "compile vs_4_0 LinkVS()"));
  EXPECT_FALSE(HasNote(kept, "shader model 4.1 profiles"));
}

TEST(GalEffectSourceD3D11, AStructNamedLikeATechniqueIsRenamed)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  EXPECT_TRUE(Contains(translated.source, "struct faf_Cirrus"));
  EXPECT_TRUE(Contains(translated.source, "faf_Cirrus CirrusVS("));
  EXPECT_TRUE(Contains(translated.source, "technique10 Cirrus"));
  EXPECT_TRUE(HasNote(translated, "struct Cirrus renamed: a technique has the same name"));

  const EffectDescription description = ParseEffect(translated.source);
  EXPECT_NE(description.FindTechnique("Cirrus"), nullptr);
  EXPECT_NE(description.FindStruct("faf_Cirrus"), nullptr);
  EXPECT_EQ(description.FindStruct("Cirrus"), nullptr);
}

TEST(GalEffectSourceD3D11, PixelShadersAreRelinkedBySemantic)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  EXPECT_TRUE(Contains(translated.source, "float4 faf_ps_0( VOut faf_in ) : COLOR0\n{\n    return LinkPS( faf_in.col, faf_in.uv );\n}\n"));
  EXPECT_TRUE(HasNote(translated, "pixel shader inputs re-linked through 1 wrapper(s)"));

  const EffectDescription description = ParseEffect(translated.source);
  const Technique* const link = description.FindTechnique("Link");
  ASSERT_NE(link, nullptr);
  ASSERT_EQ(link->passes.size(), 3U);
  EXPECT_EQ(link->passes[0].pixelShader.function, "faf_ps_0");
  EXPECT_EQ(link->passes[1].pixelShader.function, "PrefixPS") << "inputs that are a prefix of the outputs need no wrapper";
  EXPECT_EQ(link->passes[2].pixelShader.function, "faf_ps_0") << "one wrapper per (pixel shader, vertex output)";
}

TEST(GalEffectSourceD3D11, DepthBiasesAreScaledToDepthSteps)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  const EffectDescription description = ParseEffect(translated.source);
  const Technique* const decal = description.FindTechnique("Decal");
  ASSERT_NE(decal, nullptr);
  ASSERT_EQ(decal->passes.size(), 2U);

  // The compat state's D3D9 value: -0.00001 of the depth range, -167.77 steps of a 24-bit buffer.
  ASSERT_TRUE(decal->passes[0].rasterizer.has_value());
  EXPECT_EQ(decal->passes[0].rasterizer->depthBias, -168);
  EXPECT_FLOAT_EQ(decal->passes[0].rasterizer->slopeScaledDepthBias, -1.5f);
  EXPECT_EQ(decal->passes[0].rasterizer->cullMode, U8(D3D11_CULL_BACK));
  EXPECT_TRUE(decal->passes[0].rasterizer->depthClipEnable);

  // A pass's D3DRS_DEPTHBIAS: -0.0002 * 2^24 = -3355.44.
  ASSERT_TRUE(decal->passes[1].rasterizer.has_value());
  EXPECT_EQ(decal->passes[1].rasterizer->depthBias, -3355);
  EXPECT_FLOAT_EQ(decal->passes[1].rasterizer->slopeScaledDepthBias, 2.0f);
  EXPECT_EQ(decal->passes[1].rasterizer->fillMode, U8(D3D11_FILL_WIREFRAME));
  EXPECT_EQ(decal->passes[1].rasterizer->cullMode, U8(D3D11_CULL_NONE)) << "D3D9's begin state culls nothing";
  EXPECT_TRUE(decal->passes[1].rasterizer->depthClipEnable);
}

TEST(GalEffectSourceD3D11, UnsupportedStatesAreNotedAndDropped)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  EXPECT_TRUE(HasNote(translated, "unsupported zfunc value 'Sometimes' ignored"));
  EXPECT_TRUE(HasNote(translated, "D3D9 state fogenable = false has no D3D11 equivalent; ignored"));
  EXPECT_TRUE(HasNote(translated, "D3D9 state lighting = true has no D3D11 equivalent; ignored"));
  for (const std::string& note : translated.notes) {
    EXPECT_FALSE(Contains(note, "alphatestenable")) << "a disabled alpha test needs no note";
  }
  const EffectDescription description = ParseEffect(translated.source);
  const Pass& odd = OnlyPass(description, "Odd");
  EXPECT_FALSE(odd.depthStencil.has_value());
  EXPECT_EQ(odd.vertexShader.function, "LinkVS");
}

TEST(GalEffectSourceD3D11, FixedFunctionTechniquesAreEmulatedOrDropped)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  EXPECT_TRUE(HasNote(translated, "D3D9 fixed-function FixedFuncVS emulated for pre-transformed vertices"));
  EXPECT_TRUE(HasNote(translated, "technique Bloom dropped: it uses the undefined D3D9 fixed-function FixedFuncPS"));
  const EffectDescription description = ParseEffect(translated.source);
  EXPECT_EQ(description.FindTechnique("Bloom"), nullptr);
  EXPECT_NE(description.FindTechnique("Overlay"), nullptr);
  const Parameter* const viewport = description.FindParameter("faf_ViewportSize");
  ASSERT_NE(viewport, nullptr) << "the emulation reads the viewport the backend writes";
  EXPECT_EQ(viewport->columns, 4U);
}

TEST(GalEffectSourceD3D11, Direct3D9AlphaTestMovesIntoThePixelShader)
{
  const char* const preprocessed = R"fx(
float4 WaterPS( float4 c : TEXCOORD0 ) : COLOR0 { return c; }
void AlphaTestD3D10( float inputAlpha, int alphaFunc, int alphaRef ) { if ( inputAlpha < 0.5 ) discard; }
technique10 Water
{
    pass P0 { VertexShader = compile vs_4_0 VS(); PixelShader = compile ps_4_0 WaterPS(); }
    pass P1 { VertexShader = compile vs_4_0 VS(); PixelShader = compile ps_4_0 WaterPS(); }
}
)fx";
  const char* const original = R"fx(
// technique Water { pass P1 { AlphaTestEnable = true; } }
technique Water
{
    pass P0
    {
#ifndef DIRECT3D10
        AlphaTestEnable = true;
        AlphaRef = 0x00;
        AlphaFunc = NotEqual;
#endif
    }
    pass P1 { AlphaTestEnable = false; }
}
)fx";
  const TranslatedEffectSource translated = TranslateEffectSource(preprocessed, false, original);
  EXPECT_TRUE(Contains(translated.source, "float4 faf_alphatest_0( float4 c : TEXCOORD0 ) : COLOR0\n{\n"
                                          "    float4 faf_result = WaterPS( c );\n"
                                          "    uint faf_alpha = (uint)round(saturate(faf_result.a) * 255.0);\n"
                                          "    if (!(faf_alpha != 0u))\n        discard;\n"
                                          "    return faf_result;\n}\n"));
  EXPECT_TRUE(HasNote(translated, "D3D9 alpha test applied in the pixel shader of 1 pass(es)"));
  EXPECT_FALSE(Contains(translated.source, "if ( inputAlpha < 0.5 ) discard;")) << "the compat stand-in is emptied";

  const EffectDescription description = ParseEffect(translated.source);
  const Technique* const water = description.FindTechnique("Water");
  ASSERT_NE(water, nullptr);
  ASSERT_EQ(water->passes.size(), 2U);
  EXPECT_EQ(water->passes[0].pixelShader.function, "faf_alphatest_0");
  EXPECT_EQ(water->passes[1].pixelShader.function, "WaterPS");
}

TEST(GalEffectSourceD3D11, DirectivesAreDroppedAndD3D9MathIsPrepended)
{
  const TranslatedEffectSource translated = TranslateEffectSource(kMixed, false, {});
  EXPECT_EQ(translated.source.rfind("#define sqrt(x) sqrt(abs(x))\n#define rsqrt(x) rsqrt(abs(x))\n#define pow(x, y)", 0U), 0U);
  EXPECT_FALSE(Contains(translated.source, "#line"));
}

TEST(GalEffectSourceD3D11, FastScanAndRegexScanAgree)
{
  // ren_EffectFastScan replaced std::regex scans; FAF_FX_SCAN_VERIFY compares the two at run time.
  const bool fast = gpg::gal::d3d11::gEffectFastScan;
  const char* const original = "technique Link { pass P0 { AlphaTestEnable = true; AlphaFunc = Less; AlphaRef = 3; } }";
  for (const char* const source : {kCast, kMixed}) {
    gpg::gal::d3d11::gEffectFastScan = true;
    const TranslatedEffectSource scanned = TranslateEffectSource(source, true, original);
    gpg::gal::d3d11::gEffectFastScan = false;
    const TranslatedEffectSource matched = TranslateEffectSource(source, true, original);
    EXPECT_EQ(scanned.source, matched.source);
    EXPECT_EQ(scanned.notes, matched.notes);
  }
  gpg::gal::d3d11::gEffectFastScan = fast;

  // With the alpha test, Link's first pass goes through both wrappers.
  const TranslatedEffectSource tested = TranslateEffectSource(kMixed, false, original);
  EXPECT_TRUE(Contains(tested.source, "if (!(faf_alpha < 3u))"));
  EXPECT_TRUE(Contains(tested.source, "return faf_alphatest_0( faf_in.col, faf_in.uv );"));
}

TEST(GalEffectSourceD3D11, SeparateAlphaBlendingIsKeptInTheTranslatedText)
{
  const char* const source = R"fx(
technique10 Separate
{
    pass P0
    {
        AlphaBlendEnable = true;
        SeparateAlphaBlendEnable = true;
        SrcBlend = SrcAlpha;
        DestBlend = InvSrcAlpha;
        SrcBlendAlpha = Zero;
        DestBlendAlpha = One;
        VertexShader = compile vs_4_0 VS();
    }
}
)fx";
  const TranslatedEffectSource translated = TranslateEffectSource(source, false, {});
  EXPECT_TRUE(Contains(translated.source, "SrcBlendAlpha = ZERO;"));
  EXPECT_TRUE(Contains(translated.source, "DestBlendAlpha = ONE;"));
}

// Suspected bug: a pass that enables D3D9's SEPARATEALPHABLENDENABLE keeps its own alpha factors in
// the text the override layer writes (the test above, which the D3D11 backend compiles), but
// ParseBlendState (EffectDescription.cpp) replaces every state's alpha factors with the colour
// ones, so on Direct3D 12 and Vulkan the pass blends alpha with SRC_ALPHA / INV_SRC_ALPHA instead
// of ZERO / ONE. No effect the game ships enables separate alpha (checked in FAF's effects.nx2), so
// only a mod's effect would show it. Minimal input: the source of the test above.
TEST(GalEffectSourceD3D11, DISABLED_SeparateAlphaBlendingReachesTheEffectDescription)
{
  const char* const source = R"fx(
technique10 Separate
{
    pass P0
    {
        AlphaBlendEnable = true;
        SeparateAlphaBlendEnable = true;
        SrcBlend = SrcAlpha;
        DestBlend = InvSrcAlpha;
        SrcBlendAlpha = Zero;
        DestBlendAlpha = One;
        VertexShader = compile vs_4_0 VS();
    }
}
)fx";
  const EffectDescription description = ParseEffect(TranslateEffectSource(source, false, {}).source);
  const Pass& pass = OnlyPass(description, "Separate");
  ASSERT_TRUE(pass.blend.has_value());
  EXPECT_EQ(pass.blend->srcBlend, U8(D3D11_BLEND_SRC_ALPHA));
  EXPECT_EQ(pass.blend->srcBlendAlpha, U8(D3D11_BLEND_ZERO));
  EXPECT_EQ(pass.blend->destBlendAlpha, U8(D3D11_BLEND_ONE));
}
