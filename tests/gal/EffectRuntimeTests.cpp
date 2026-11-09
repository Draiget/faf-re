// gpg/gal/effects/EffectRuntime.h: the effect objects of the Direct3D 12 and Vulkan backends, up to
// the point where a pass needs the device (BeginTechnique asks the device; compiling is in
// ShaderCompilerTests.cpp). The program is built from the shared kDrawEffect; what each call must
// do is what the gal interfaces document: names resolve to parameters, samplers or an error, the
// annotations read as D3DX's GetBool/GetInt/GetFloat/GetString, and the setters write the
// parameter store.

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "GalTestSupport.h"
#include "boost/shared_ptr.h"
#include "gpg/gal/DrawStatistics.h"
#include "gpg/gal/EffectContext.hpp"
#include "gpg/gal/Error.hpp"
#include "gpg/gal/Matrix.h"
#include "gpg/gal/effects/EffectRuntime.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"

using namespace gpg::gal;
using faf_gal_tests::FloatAt;
using faf_gal_tests::IntAt;

namespace
{
  class RecordingBinder final : public effects::PassBinder
  {
  public:
    void BindPass(effects::EffectProgram&, std::uint32_t technique, std::uint32_t pass) override
    {
      bound.emplace_back(technique, pass);
    }
    void UnbindPass() override { ++unbound; }

    std::vector<std::pair<std::uint32_t, std::uint32_t>> bound;
    int unbound = 0;
  };

  std::shared_ptr<effects::EffectProgram> MakeProgram(const char* const source = faf_gal_tests::kDrawEffect)
  {
    return std::make_shared<effects::EffectProgram>("tests/draw.fx", source, effects::ShaderTarget::Dxil);
  }

  std::uint32_t OffsetOf(const effects::EffectProgram& program, const char* const name)
  {
    const std::int32_t parameter = program.FindParameter(name);
    const effects::ConstantSlot* const slot =
      (parameter >= 0) ? program.Modern().constants.Find(static_cast<std::uint32_t>(parameter)) : nullptr;
    return (slot != nullptr) ? slot->offset : 0xFFFFFFFFU;
  }

  std::string ErrorMessage(const std::function<void()>& call)
  {
    try {
      call();
    } catch (const Error& error) {
      return error.what();
    }
    return "<no error>";
  }
} // namespace

TEST(GalFnv1a64, MatchesThePublishedVectors)
{
  // FNV-1a 64-bit reference values (Fowler, Noll, Vo; draft-eastlake-fnv test vectors).
  effects::Fnv1a64 empty;
  EXPECT_EQ(empty.Value(), 0xCBF29CE484222325ULL);
  effects::Fnv1a64 a;
  a.Add("a", 1U);
  EXPECT_EQ(a.Value(), 0xAF63DC4C8601EC8CULL);
  effects::Fnv1a64 foobar;
  foobar.Add("foobar", 6U);
  EXPECT_EQ(foobar.Value(), 0x85944171F73967E8ULL);

  // Text is hashed with its terminator, so "ab" + "c" and "a" + "bc" differ.
  effects::Fnv1a64 text;
  text.Add(std::string_view("a"));
  effects::Fnv1a64 bytes;
  bytes.Add("a\0", 2U);
  EXPECT_EQ(text.Value(), bytes.Value());
  effects::Fnv1a64 first;
  first.Add(std::string_view("ab"));
  first.Add(std::string_view("c"));
  effects::Fnv1a64 second;
  second.Add(std::string_view("a"));
  second.Add(std::string_view("bc"));
  EXPECT_NE(first.Value(), second.Value());
}

TEST(GalEffectProgram, BuildsTheDescriptionHlslAndParameters)
{
  const std::shared_ptr<effects::EffectProgram> program = MakeProgram();
  EXPECT_EQ(program->Name(), "tests/draw.fx");
  ASSERT_EQ(program->Description().techniques.size(), 1U);
  ASSERT_EQ(program->Modern().entries.size(), 3U);

  const effects::PassEntries& p0 = program->Entries(0U, 0U);
  EXPECT_EQ(p0.vertex, 0);
  EXPECT_EQ(p0.pixel, 1);
  EXPECT_EQ(program->Entries(0U, 1U).vertex, 0);
  EXPECT_EQ(program->Entries(0U, 2U).vertex, 2);
  EXPECT_EQ(program->Entries(0U, 2U).pixel, 1);
  EXPECT_EQ(program->Entries(0U, 3U).vertex, -1) << "out of range: no entries";
  EXPECT_EQ(program->Entries(1U, 0U).pixel, -1);

  EXPECT_EQ(program->FindParameter("WorldViewProj"), 0);
  EXPECT_EQ(program->FindParameter("Tint"), 2);
  EXPECT_EQ(program->FindParameter("BaseSampler"), -1) << "samplers are not parameters";
  EXPECT_EQ(program->FindParameter("missing"), -1);

  const std::vector<std::int32_t>& slots = program->TextureSlotParameters();
  ASSERT_EQ(slots.size(), 2U);
  EXPECT_EQ(slots[0], program->FindParameter("BaseTexture"));
  EXPECT_EQ(slots[1], program->FindParameter("EnvTexture"));

  // The defaults are in the image from the start.
  const std::span<const std::uint8_t> image = program->Parameters().Constants();
  EXPECT_FLOAT_EQ(FloatAt(image, OffsetOf(*program, "Scale")), 1.0f);
  EXPECT_FLOAT_EQ(FloatAt(image, OffsetOf(*program, "Tint") + 4U), 0.5f);

  EXPECT_EQ(program->BackendState().get(), nullptr);
  program->BackendState() = std::make_shared<int>(5);
  EXPECT_NE(program->BackendState().get(), nullptr);

  const effects::CompiledEntry& missing = program->Shader(99U);
  EXPECT_FALSE(missing.attempted);
  EXPECT_FALSE(missing.succeeded);
}

TEST(GalEffectProgram, OriginalSourceSuppliesTheAlphaTest)
{
  const std::shared_ptr<effects::EffectProgram> program = std::make_shared<effects::EffectProgram>(
    "tests/draw.fx", faf_gal_tests::kDrawEffect, effects::ShaderTarget::Spirv,
    "technique Draw { pass P0 { AlphaTestEnable = true; AlphaFunc = Greater; AlphaRef = 64; } pass P1 { } pass P2 { } }"
  );
  EXPECT_TRUE(program->Description().direct3D9PassStates);
  ASSERT_TRUE(program->Description().techniques[0].passes[0].alphaTest.has_value());
  EXPECT_EQ(program->Modern().entries.size(), 4U) << "P0's pixel entry tests alpha, P1's and P2's do not";
  EXPECT_NE(program->Entries(0U, 0U).pixel, program->Entries(0U, 1U).pixel);
  EXPECT_EQ(program->Entries(0U, 1U).pixel, program->Entries(0U, 2U).pixel);
}

TEST(GalEffectProgram, UnstructuredSourceIsRefused)
{
  EXPECT_THROW(MakeProgram("float4 PS() : COLOR0 { return 1;"), std::runtime_error);
}

TEST(GalProgramEffect, TechniquesAndVariablesResolveByName)
{
  RecordingBinder binder;
  EffectContext context;
  ProgramEffect effect(context, MakeProgram(), binder);
  EXPECT_NE(effect.GetContext(), nullptr);
  effect.OnLost();
  effect.OnReset();

  fa::vector<boost::shared_ptr<EffectTechnique>> techniques;
  effect.GetTechniques(techniques);
  ASSERT_EQ(techniques.size(), 1U);
  EXPECT_STREQ(techniques[0]->GetName()->c_str(), "Draw");

  const boost::shared_ptr<EffectTechnique> draw = effect.GetTechnique("Draw");
  ASSERT_NE(draw.get(), nullptr);
  EXPECT_STREQ(draw->GetName()->c_str(), "Draw");
  EXPECT_EQ(ErrorMessage([&] { static_cast<void>(effect.GetTechnique("Missing")); }), "invalid effect technique requested: Missing");
  EXPECT_EQ(ErrorMessage([&] { static_cast<void>(effect.GetTechnique(nullptr)); }), "invalid effect technique requested: ");

  const boost::shared_ptr<EffectVariable> tint = effect.GetVariable("Tint");
  ASSERT_NE(tint.get(), nullptr);
  EXPECT_STREQ(tint->GetName()->c_str(), "Tint");
  // A sampler is a known name without a parameter: its setters do nothing.
  const boost::shared_ptr<EffectVariable> sampler = effect.GetVariable("BaseSampler");
  ASSERT_NE(sampler.get(), nullptr);
  sampler->SetFloat(1.0f);
  bool flag = false;
  EXPECT_FALSE(sampler->GetAnnotationBool(&flag, fa::string("anything")));
  EXPECT_EQ(ErrorMessage([&] { static_cast<void>(effect.GetVariable("Nope")); }), "invalid effect variable requested: Nope");
}

TEST(GalProgramEffect, TechniqueAnnotationsReadAsD3DXDoes)
{
  RecordingBinder binder;
  ProgramEffect effect(EffectContext{}, MakeProgram(), binder);
  const boost::shared_ptr<EffectTechnique> draw = effect.GetTechnique("Draw");

  fa::string text;
  EXPECT_TRUE(draw->GetAnnotationString(&text, fa::string("Category")));
  EXPECT_STREQ(text.c_str(), "opaque");
  EXPECT_FALSE(draw->GetAnnotationString(&text, fa::string("Order"))) << "a number is not a string";

  int order = 0;
  EXPECT_TRUE(draw->GetAnnotationInt(&order, fa::string("Order")));
  EXPECT_EQ(order, 2);
  float weight = 0.0f;
  EXPECT_TRUE(draw->GetAnnotationFloat(&weight, fa::string("Weight")));
  EXPECT_FLOAT_EQ(weight, 0.5f);
  bool lit = false;
  EXPECT_TRUE(draw->GetAnnotationBool(&lit, fa::string("Lit")));
  EXPECT_TRUE(lit);
  int asInt = 0;
  EXPECT_TRUE(draw->GetAnnotationInt(&asInt, fa::string("Weight")));
  EXPECT_EQ(asInt, 0);

  EXPECT_FALSE(draw->GetAnnotationInt(&order, fa::string("Category"))) << "a string is not a number";
  EXPECT_FALSE(draw->GetAnnotationFloat(&weight, fa::string("Category")));
  EXPECT_FALSE(draw->GetAnnotationBool(&lit, fa::string("Category")));
  EXPECT_FALSE(draw->GetAnnotationBool(&lit, fa::string("Missing")));
  EXPECT_EQ(order, 2) << "a failed read leaves the output alone";
}

TEST(GalProgramEffect, PassesNeedABegunTechnique)
{
  RecordingBinder binder;
  ProgramEffect effect(EffectContext{}, MakeProgram(), binder);
  const boost::shared_ptr<EffectTechnique> draw = effect.GetTechnique("Draw");
  EXPECT_EQ(ErrorMessage([&] { draw->BeginPass(0); }), "effect technique begin/end mismatch");
  EXPECT_EQ(ErrorMessage([&] { draw->EndPass(); }), "effect technique begin/end mismatch");
  EXPECT_EQ(ErrorMessage([&] { draw->EndTechnique(); }), "effect technique begin/end mismatch");
  EXPECT_TRUE(binder.bound.empty());
  EXPECT_EQ(binder.unbound, 0);
}

TEST(GalProgramEffect, VariableSettersWriteTheParameterStore)
{
  RecordingBinder binder;
  const std::shared_ptr<effects::EffectProgram> program = MakeProgram(R"fx(
float Scale < float UIMin = 0.25; int Steps = 4; bool Shown = false; string Label = "scale"; > = 1;
int Mode;
bool Enabled;
float4 Colour;
float4 Palette[2];
float Weights[4];
float4x4 World;
float4x4 Bones[2];
texture Base;
)fx");
  ProgramEffect effect(EffectContext{}, program, binder);
  const auto image = [&] { return program->Parameters().Constants(); };

  const boost::shared_ptr<EffectVariable> scale = effect.GetVariable("Scale");
  scale->SetFloat(3.5f);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "Scale")), 3.5f);
  float minimum = 0.0f;
  EXPECT_TRUE(scale->GetAnnotationFloat(&minimum, fa::string("UIMin")));
  EXPECT_FLOAT_EQ(minimum, 0.25f);
  int steps = 0;
  EXPECT_TRUE(scale->GetAnnotationInt(&steps, fa::string("Steps")));
  EXPECT_EQ(steps, 4);
  bool shown = true;
  EXPECT_TRUE(scale->GetAnnotationBool(&shown, fa::string("Shown")));
  EXPECT_FALSE(shown);
  fa::string label;
  EXPECT_TRUE(scale->GetAnnotationString(&label, fa::string("Label")));
  EXPECT_STREQ(label.c_str(), "scale");
  EXPECT_FALSE(scale->GetAnnotationString(&label, fa::string("Steps")));
  EXPECT_FALSE(scale->GetAnnotationFloat(&minimum, fa::string("Label")));

  effect.GetVariable("Mode")->SetInt(-4);
  EXPECT_EQ(IntAt(image(), OffsetOf(*program, "Mode")), -4);
  const std::int32_t raw = 9;
  effect.GetVariable("Mode")->SetValue(&raw, 4U);
  EXPECT_EQ(IntAt(image(), OffsetOf(*program, "Mode")), 9) << "SetValue on int data stores its bits";
  effect.GetVariable("Enabled")->SetBool(true);
  EXPECT_EQ(IntAt(image(), OffsetOf(*program, "Enabled")), 1);

  const float colour[4] = {0.1f, 0.2f, 0.3f, 0.4f};
  effect.GetVariable("Colour")->SetVector(colour);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "Colour") + 12U), 0.4f);
  const float palette[8] = {1, 2, 3, 4, 5, 6, 7, 8};
  effect.GetVariable("Palette")->SetVectorArray(2U, palette);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "Palette") + 16U), 5.0f);
  const float weights[4] = {0.5f, 1.5f, 2.5f, 3.5f};
  effect.GetVariable("Weights")->SetFloatArray(4U, weights);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "Weights") + 48U), 3.5f);
  effect.GetVariable("Weights")->SetValue(colour, 8U);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "Weights") + 16U), 0.2f) << "SetValue on float data converts as SetFloatArray";

  Matrix world{};
  world.r[3].x = 7.0f;
  world.r[0].x = 1.0f;
  effect.GetVariable("World")->SetMatrix4x4(&world);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "World")), 1.0f);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "World") + 48U), 7.0f);
  Matrix bones[2]{};
  bones[1].r[2].z = 9.0f;
  effect.GetVariable("Bones")->SetMatrixArray(2U, bones);
  EXPECT_FLOAT_EQ(FloatAt(image(), OffsetOf(*program, "Bones") + 64U + 32U + 8U), 9.0f);
  effect.GetVariable("World")->SetMatrix4x4(nullptr);
  effect.GetVariable("Bones")->SetMatrixArray(1U, nullptr);

  // Texture bindings count as pipeline state changes.
  static_cast<void>(TakeDrawStatistics());
  const boost::shared_ptr<EffectVariable> base = effect.GetVariable("Base");
  const boost::shared_ptr<Texture> texture(new faf_gal_tests::FakeTexture());
  base->SetTexture(texture);
  EXPECT_EQ(program->Parameters().Binding(static_cast<std::uint32_t>(program->FindParameter("Base"))).texture.get(), texture.get());
  const boost::shared_ptr<RenderTarget> target(new faf_gal_tests::FakeRenderTarget());
  base->SetRenderTarget(target);
  EXPECT_EQ(program->Parameters().Binding(static_cast<std::uint32_t>(program->FindParameter("Base"))).renderTarget.get(), target.get());
  base->SetCubeRenderTarget(boost::shared_ptr<CubeRenderTarget>());
  EXPECT_EQ(TakeDrawStatistics().stateChanges, 2U);
}
