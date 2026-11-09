// gpg/gal/effects/ShaderCompiler.h with the DXC next to the executable (tests/gal/CMakeLists.txt
// copies it there): the HLSL ModernHlsl generates must compile for both targets, the DXIL input
// signature and the SPIR-V interface must name the vertex shader's inputs, and the effect program
// must keep what it compiled in its cache. Containers are recognised by their published magic
// numbers: DXIL comes in a DXBC container ("DXBC"), SPIR-V starts with 0x07230203. Every test
// skips when DXC cannot be loaded.

#include <gtest/gtest.h>

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include "GalTestSupport.h"
#include "gpg/gal/backends/d3d11/EffectSourceD3D11.h"
#include "gpg/gal/effects/EffectDescription.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "gpg/gal/effects/ModernHlsl.h"
#include "gpg/gal/effects/ShadowCascades.h"
#include "gpg/gal/effects/ShaderCompiler.h"
#include "gpg/gal/effects/SpirvReflect.h"

using namespace gpg::gal::effects;

namespace
{
  const ShaderCompiler* Compiler()
  {
    const ShaderCompiler& compiler = ShaderCompiler::Instance();
    return compiler.Available() ? &compiler : nullptr;
  }

  std::string Unavailable()
  {
    return "DXC is not available: " + ShaderCompiler::Instance().LoadError();
  }

  bool IsDxil(const std::vector<std::uint8_t>& code)
  {
    return code.size() > 4U && std::memcmp(code.data(), "DXBC", 4U) == 0;
  }

  bool IsSpirv(const std::vector<std::uint8_t>& code)
  {
    std::uint32_t magic = 0U;
    if (code.size() < 20U) {
      return false;
    }
    std::memcpy(&magic, code.data(), sizeof(magic));
    return magic == 0x07230203U;
  }

  struct Generated
  {
    EffectDescription description;
    ModernEffect modern;
  };

  Generated Generate(const std::string& source)
  {
    Generated result;
    result.description = ParseEffect(source);
    result.modern = GenerateModernHlsl(source, result.description);
    return result;
  }

  const ShaderInput* FindInput(const std::vector<ShaderInput>& inputs, const std::string& semantic, const std::uint32_t index)
  {
    for (const ShaderInput& input : inputs) {
      if (input.semantic == semantic && input.index == index) {
        return &input;
      }
    }
    return nullptr;
  }
} // namespace

TEST(GalShaderCompiler, GeneratedEffectCompilesToDxilAndSpirv)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  const ShaderCompiler& compiler = *Compiler();
  EXPECT_EQ(compiler.Version().rfind("dxc ", 0U), 0U) << compiler.Version();
  EXPECT_TRUE(compiler.LoadError().empty());

  const Generated generated = Generate(faf_gal_tests::kDrawEffect);
  ASSERT_EQ(generated.modern.entries.size(), 3U);
  for (const ShaderEntry& entry : generated.modern.entries) {
    const CompiledShader dxil = compiler.Compile(generated.modern.hlsl, entry, ShaderTarget::Dxil);
    EXPECT_TRUE(dxil.succeeded) << entry.name << ":\n" << dxil.messages;
    EXPECT_TRUE(IsDxil(dxil.code)) << entry.name;
    const CompiledShader spirv = compiler.Compile(generated.modern.hlsl, entry, ShaderTarget::Spirv);
    EXPECT_TRUE(spirv.succeeded) << entry.name << ":\n" << spirv.messages;
    EXPECT_TRUE(IsSpirv(spirv.code)) << entry.name;
  }
}

// Engine addition (ren_ShadowCascades): the cascade lookups compile for both targets next to ordinary
// samplers. HLSL converts between structs whose members match one for one, so a shadow sampler type built
// from faf_sampler's members made every tex2D call ambiguous (all of mesh.fx and terrain.fx failed).
TEST(GalShaderCompiler, ShadowCascadeLookupsCompileBesideOrdinarySamplers)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  const ShaderCompiler& compiler = *Compiler();
  const std::string source = std::string(ShadowCascadeDeclaration()) + R"fx(
float4x4 ShadowMatrix;
texture ShadowTexture;
texture AlbedoTexture;
sampler2D ShadowSampler = sampler_state { Texture = (ShadowTexture); };
sampler2D ShadowHorizontalBlurSampler = sampler_state { Texture = (ShadowTexture); };
sampler2D AlbedoSampler = sampler_state { Texture = (AlbedoTexture); };
struct VSOut
{
    float4 pos : POSITION;
    float4 shadow : TEXCOORD0;
    float2 uv : TEXCOORD1;
};
VSOut LitVS( float3 position : POSITION, float2 uv : TEXCOORD0 )
{
    VSOut o;
    o.pos = float4( position, 1 );
    o.shadow = mul( float4( position, 1 ), ShadowMatrix );
    o.uv = uv;
    return o;
}
float4 LitPS( VSOut i ) : COLOR0
{
    float shadow = tex2D( ShadowSampler, i.shadow.xy ).g;
    shadow *= tex2Dproj( ShadowSampler, i.shadow ).r;
    shadow *= tex2D( ShadowSampler, i.shadow ).g;
    return tex2D( AlbedoSampler, i.uv ) * shadow + tex2D( ShadowHorizontalBlurSampler, i.uv );
}
technique10 Lit
{
    pass P0
    {
        SetVertexShader( CompileShader( vs_4_0, LitVS() ) );
        SetPixelShader( CompileShader( ps_4_0, LitPS() ) );
    }
}
)fx";
  const Generated generated = Generate(source);
  ASSERT_NE(generated.modern.hlsl.find("faf_make_shadow_sampler("), std::string::npos);
  ASSERT_EQ(generated.modern.entries.size(), 2U);
  for (const ShaderEntry& entry : generated.modern.entries) {
    const CompiledShader dxil = compiler.Compile(generated.modern.hlsl, entry, ShaderTarget::Dxil);
    EXPECT_TRUE(dxil.succeeded) << entry.name << ":\n" << dxil.messages;
    const CompiledShader spirv = compiler.Compile(generated.modern.hlsl, entry, ShaderTarget::Spirv);
    EXPECT_TRUE(spirv.succeeded) << entry.name << ":\n" << spirv.messages;
  }
}

// Engine addition (tessellation): the generated hull and domain entry points compile for both targets with the
// vertex and pixel shaders of the same pass.
TEST(GalShaderCompiler, TessellatedEffectCompilesToDxilAndSpirv)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  const ShaderCompiler& compiler = *Compiler();
  const Generated generated = Generate(faf_gal_tests::kTessellatedEffect);
  ASSERT_EQ(generated.modern.entries.size(), 4U);
  for (const ShaderEntry& entry : generated.modern.entries) {
    const CompiledShader dxil = compiler.Compile(generated.modern.hlsl, entry, ShaderTarget::Dxil);
    EXPECT_TRUE(dxil.succeeded) << entry.name << ":\n" << dxil.messages;
    EXPECT_TRUE(IsDxil(dxil.code)) << entry.name;
    const CompiledShader spirv = compiler.Compile(generated.modern.hlsl, entry, ShaderTarget::Spirv);
    EXPECT_TRUE(spirv.succeeded) << entry.name << ":\n" << spirv.messages;
    EXPECT_TRUE(IsSpirv(spirv.code)) << entry.name;
  }
}

TEST(GalShaderCompiler, VertexInputsAreReflectedFromBothTargets)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  const ShaderCompiler& compiler = *Compiler();
  const Generated generated = Generate(faf_gal_tests::kDrawEffect);
  const ShaderEntry& vertex = generated.modern.entries[0];
  ASSERT_EQ(vertex.stage, ShaderStage::Vertex);

  const CompiledShader dxil = compiler.Compile(generated.modern.hlsl, vertex, ShaderTarget::Dxil);
  ASSERT_TRUE(dxil.succeeded) << dxil.messages;
  const std::vector<ShaderInput> inputs = compiler.ReflectInputs(dxil.code);
  ASSERT_EQ(inputs.size(), 2U);
  const ShaderInput* const position = FindInput(inputs, "POSITION", 0U);
  ASSERT_NE(position, nullptr);
  EXPECT_EQ(position->component, ShaderInput::Component::Float);
  EXPECT_EQ(position->mask, 0x7U) << "a float3: x, y and z";
  EXPECT_FALSE(position->systemValue);
  const ShaderInput* const uv = FindInput(inputs, "TEXCOORD", 0U);
  ASSERT_NE(uv, nullptr);
  EXPECT_EQ(uv->mask, 0x3U);
  EXPECT_TRUE(compiler.ReflectInputs({}).empty());
  EXPECT_TRUE(compiler.ReflectInputs({1, 2, 3, 4}).empty()) << "not a shader";

  // -fspv-reflect records the HLSL semantics; the interface reader finds them.
  const CompiledShader spirv = compiler.Compile(generated.modern.hlsl, vertex, ShaderTarget::Spirv);
  ASSERT_TRUE(spirv.succeeded) << spirv.messages;
  const SpirvInterface interface = ReflectSpirvInterface(spirv.code);
  ASSERT_EQ(interface.inputs.size(), 2U);
  bool sawPosition = false;
  bool sawTexcoord = false;
  for (const SpirvInterfaceVariable& input : interface.inputs) {
    sawPosition = sawPosition || (input.semantic == "POSITION" && input.components == 3U);
    sawTexcoord = sawTexcoord || (input.semantic == "TEXCOORD" && input.semanticIndex == 0U && input.components == 2U);
  }
  EXPECT_TRUE(sawPosition);
  EXPECT_TRUE(sawTexcoord);
  bool sawBuiltIn = false;
  for (const SpirvInterfaceVariable& output : interface.outputs) {
    sawBuiltIn = sawBuiltIn || output.builtIn;
  }
  EXPECT_TRUE(sawBuiltIn) << "SV_Position";

  const std::vector<std::uint8_t> stripped = StripSpirvReflection(spirv.code);
  EXPECT_LT(stripped.size(), spirv.code.size());
  EXPECT_TRUE(IsSpirv(stripped));
  const std::string google = "SPV_GOOGLE";
  EXPECT_EQ(std::search(stripped.begin(), stripped.end(), google.begin(), google.end()), stripped.end());
  EXPECT_EQ(ReflectSpirvInterface(stripped).inputs.size(), 2U);
}

TEST(GalShaderCompiler, ErrorsComeBackAsMessages)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  const ShaderCompiler& compiler = *Compiler();
  ShaderEntry entry;
  entry.stage = ShaderStage::Pixel;
  entry.name = "Broken";
  const CompiledShader broken = compiler.Compile("float4 Broken() : SV_Target0 { return undefinedThing; }", entry, ShaderTarget::Dxil);
  EXPECT_FALSE(broken.succeeded);
  EXPECT_TRUE(broken.code.empty());
  EXPECT_NE(broken.messages.find("undefinedThing"), std::string::npos) << broken.messages;

  entry.name = "Missing";
  EXPECT_FALSE(compiler.Compile("float4 Other() : SV_Target0 { return 1; }", entry, ShaderTarget::Spirv).succeeded);
}

TEST(GalShaderCompiler, RawProgramsCompileWithTheirOwnProfile)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  const ShaderCompiler& compiler = *Compiler();
  const char* const compute = "RWStructuredBuffer<uint> Output : register(u0);\n"
                              "[numthreads(64, 1, 1)] void Main(uint3 id : SV_DispatchThreadID) { Output[id.x] = id.x * 2; }\n";
  const CompiledShader dxil = compiler.CompileRaw(compute, "Main", L"cs_6_0", {});
  EXPECT_TRUE(dxil.succeeded) << dxil.messages;
  EXPECT_TRUE(IsDxil(dxil.code));
  const CompiledShader spirv = compiler.CompileRaw(compute, "Main", L"cs_6_0", {L"-spirv"});
  EXPECT_TRUE(spirv.succeeded) << spirv.messages;
  EXPECT_TRUE(IsSpirv(spirv.code));
  EXPECT_FALSE(compiler.CompileRaw(compute, "Main", L"cs_9_9", {}).succeeded);
}

TEST(GalShaderCompiler, OverrideLayerOutputCompilesEndToEnd)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  // A D3D9-style pass (render states, a 1D ramp, an alpha test) through the whole chain the Direct3D
  // 12 and Vulkan backends run: the D3D11 override layer, the parser, the HLSL rewrite and DXC.
  const char* const preprocessed = R"fx(
float4x4 WorldViewProj;
texture RampTexture;
sampler1D RampSampler = sampler_state { Texture = <RampTexture>; };
struct VertexOut { float4 position : POSITION0; float shade : TEXCOORD0; };
VertexOut RampVS( float3 position : POSITION0, float shade : TEXCOORD0 )
{
    VertexOut result = (VertexOut)0;
    result.position = mul( float4( position, 1 ), WorldViewProj );
    result.shade = shade;
    return result;
}
float4 RampPS( VertexOut input ) : COLOR0
{
    return tex1D( RampSampler, input.shade ) * pow( input.shade, 3 );
}
technique10 Ramp
{
    pass P0
    {
        AlphaBlendEnable = true;
        SrcBlend = SrcAlpha;
        DestBlend = InvSrcAlpha;
        ZWriteEnable = false;
        CullMode = none;
        VertexShader = compile vs_4_0 RampVS();
        PixelShader = compile ps_4_0 RampPS();
    }
}
)fx";
  const char* const original = "technique Ramp { pass P0 { AlphaTestEnable = true; AlphaFunc = Greater; AlphaRef = 16; } }";
  const gpg::gal::d3d11::TranslatedEffectSource translated = gpg::gal::d3d11::TranslateEffectSource(preprocessed, true, original);
  const std::shared_ptr<EffectProgram> program =
    std::make_shared<EffectProgram>("tests/ramp.fx", translated.source, ShaderTarget::Dxil, original);
  ASSERT_EQ(program->Description().techniques.size(), 1U);
  const Pass& pass = program->Description().techniques[0].passes[0];
  ASSERT_TRUE(pass.blend.has_value());
  EXPECT_TRUE(pass.blend->enable);
  ASSERT_TRUE(pass.depthStencil.has_value());
  EXPECT_FALSE(pass.depthStencil->depthWrite);
  ASSERT_TRUE(pass.rasterizer.has_value());
  ASSERT_TRUE(pass.alphaTest.has_value());

  for (const ShaderEntry& entry : program->Modern().entries) {
    const CompiledShader dxil = Compiler()->Compile(program->Modern().hlsl, entry, ShaderTarget::Dxil);
    EXPECT_TRUE(dxil.succeeded) << entry.name << ":\n" << dxil.messages << "\n" << program->Modern().hlsl;
    const CompiledShader spirv = Compiler()->Compile(program->Modern().hlsl, entry, ShaderTarget::Spirv);
    EXPECT_TRUE(spirv.succeeded) << entry.name << ":\n" << spirv.messages;
  }
}

TEST(GalShaderCompiler, EffectProgramsCompileOnUseAndKeepACache)
{
  if (Compiler() == nullptr) {
    GTEST_SKIP() << Unavailable();
  }
  // The cache directory is read once per process: point it at a folder of this run before the
  // first program asks for it.
  const std::filesystem::path folder =
    std::filesystem::temp_directory_path() / ("faf_gal_tests_" + std::to_string(::GetCurrentProcessId()));
  ASSERT_EQ(_putenv_s("FAF_SHADER_CACHE_DIR", folder.string().c_str()), 0);
  ASSERT_EQ(ShaderCacheDirectory().rfind(folder.string(), 0U), 0U) << ShaderCacheDirectory();

  const std::shared_ptr<EffectProgram> program =
    std::make_shared<EffectProgram>("tests/draw.fx", faf_gal_tests::kDrawEffect, ShaderTarget::Dxil);
  const CompiledEntry& vertex = program->Shader(0U);
  ASSERT_TRUE(vertex.attempted);
  ASSERT_TRUE(vertex.succeeded) << vertex.messages;
  EXPECT_TRUE(IsDxil(vertex.code));
  EXPECT_EQ(vertex.entryName, "faf_entry_vs_0");
  EXPECT_EQ(vertex.inputs.size(), 2U) << "DXIL vertex shaders carry their input signature";
  EXPECT_EQ(&program->Shader(0U), &vertex) << "the second request returns the same entry";

  char name[32]{};
  std::snprintf(name, sizeof(name), "%016llx.dxil", static_cast<unsigned long long>(vertex.key));
  const std::filesystem::path cached = folder / name;
  ASSERT_TRUE(std::filesystem::exists(cached));
  std::ifstream file(cached, std::ios::binary);
  char magic[8]{};
  file.read(magic, sizeof(magic));
  EXPECT_EQ(std::string(magic, sizeof(magic)), "FAFSHDR1");
  file.close();

  // A second program of the same source reads the same code back.
  const std::shared_ptr<EffectProgram> again =
    std::make_shared<EffectProgram>("tests/draw.fx", faf_gal_tests::kDrawEffect, ShaderTarget::Dxil);
  const CompiledEntry& reread = again->Shader(0U);
  EXPECT_TRUE(reread.succeeded);
  EXPECT_EQ(reread.key, vertex.key);
  EXPECT_EQ(reread.code, vertex.code);

  // Every entry, for SPIR-V too; the keys differ by target.
  const std::shared_ptr<EffectProgram> spirv =
    std::make_shared<EffectProgram>("tests/draw.fx", faf_gal_tests::kDrawEffect, ShaderTarget::Spirv);
  spirv->CompileAll();
  for (std::uint32_t entry = 0U; entry < spirv->Modern().entries.size(); ++entry) {
    EXPECT_TRUE(spirv->Shader(entry).succeeded) << entry;
    EXPECT_TRUE(IsSpirv(spirv->Shader(entry).code)) << entry;
    EXPECT_TRUE(spirv->Shader(entry).inputs.empty()) << "only DXIL vertex shaders are reflected";
  }
  EXPECT_NE(spirv->Shader(0U).key, vertex.key);

  std::error_code ignored;
  std::filesystem::remove_all(folder, ignored);
}
