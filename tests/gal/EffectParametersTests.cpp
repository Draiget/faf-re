// gpg/gal/effects/EffectParameters.h: the $Globals image the Direct3D 12 and Vulkan backends upload,
// written with Direct3D 9 / Effects 11 semantics. The offsets come from the HLSL packing rules (see
// ModernHlslTests.cpp); the conversions are the ones the setters document: values converted to the
// parameter's scalar type, SetValue's packed 4-byte components taken as bits, a row-major matrix
// stored a register per row and a column-major one a register per column.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "GalTestSupport.h"
#include "boost/shared_ptr.h"
#include "gpg/gal/effects/EffectDescription.h"
#include "gpg/gal/effects/EffectParameters.h"
#include "gpg/gal/effects/ModernHlsl.h"

using namespace gpg::gal::effects;
using faf_gal_tests::Bits;
using faf_gal_tests::FloatAt;
using faf_gal_tests::IntAt;
using faf_gal_tests::WordAt;

namespace
{
  class GalParameterStore : public ::testing::Test
  {
  protected:
    void Load(const std::string& source)
    {
      mDescription = ParseEffect(source);
      mLayout = ComputeConstantLayout(mDescription);
      mStore.Initialize(mDescription, mLayout);
    }

    [[nodiscard]] std::uint32_t Index(const std::string& name) const
    {
      for (std::uint32_t index = 0U; index < mDescription.parameters.size(); ++index) {
        if (mDescription.parameters[index].name == name) {
          return index;
        }
      }
      ADD_FAILURE() << "no parameter " << name;
      return 0xFFFFFFFFU;
    }

    [[nodiscard]] std::uint32_t Offset(const std::string& name) const
    {
      const ConstantSlot* const slot = mLayout.Find(Index(name));
      return (slot != nullptr) ? slot->offset : 0xFFFFFFFFU;
    }

    [[nodiscard]] float F(const std::size_t offset) const { return FloatAt(mStore.Constants(), offset); }
    [[nodiscard]] std::uint32_t W(const std::size_t offset) const { return WordAt(mStore.Constants(), offset); }
    [[nodiscard]] std::int32_t I(const std::size_t offset) const { return IntAt(mStore.Constants(), offset); }

    EffectDescription mDescription;
    ConstantLayout mLayout;
    ParameterStore mStore;
  };

  const char* const kDefaults = R"fx(
float a = 2;
int n = -3;
bool flag = true;
uint u = 7;
float3 v = float3( 1, 2, 3 );
float4 quads[2] = { 1, 2, 3, 4, 5, 6, 7, 8 };
float2 pairs[2] = { float2( 1, 2 ), float2( 3, 4 ) };
float weights[3] = { 0.5, 0.25, 0.125 };
float4x4 identity = { 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1 };
texture t;
struct Pair { float2 uv; float k; };
Pair packed = { 1, 2, 3 };
float z;
)fx";
} // namespace

TEST_F(GalParameterStore, DefaultsAreWrittenInTheParametersTypes)
{
  Load(kDefaults);
  EXPECT_EQ(mStore.Version(), 1U);
  EXPECT_EQ(mStore.TextureVersion(), 1U);
  EXPECT_EQ(mStore.Constants().size() % 16U, 0U);
  EXPECT_GE(mStore.Constants().size(), mLayout.size);

  EXPECT_FLOAT_EQ(F(Offset("a")), 2.0f);
  EXPECT_EQ(I(Offset("n")), -3);
  EXPECT_EQ(W(Offset("flag")), 1U);
  EXPECT_EQ(W(Offset("u")), 7U);
  const std::uint32_t v = Offset("v");
  EXPECT_FLOAT_EQ(F(v), 1.0f);
  EXPECT_FLOAT_EQ(F(v + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(v + 8U), 3.0f);
  const std::uint32_t quads = Offset("quads");
  for (std::uint32_t index = 0U; index < 8U; ++index) {
    EXPECT_FLOAT_EQ(F(quads + index * 4U), static_cast<float>(index + 1U)) << index;
  }
  // float2 elements each start a register.
  const std::uint32_t pairs = Offset("pairs");
  EXPECT_FLOAT_EQ(F(pairs), 1.0f);
  EXPECT_FLOAT_EQ(F(pairs + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(pairs + 8U), 0.0f);
  EXPECT_FLOAT_EQ(F(pairs + 16U), 3.0f);
  EXPECT_FLOAT_EQ(F(pairs + 20U), 4.0f);
  const std::uint32_t weights = Offset("weights");
  EXPECT_FLOAT_EQ(F(weights), 0.5f);
  EXPECT_FLOAT_EQ(F(weights + 16U), 0.25f);
  EXPECT_FLOAT_EQ(F(weights + 32U), 0.125f);
  const std::uint32_t identity = Offset("identity");
  for (std::uint32_t row = 0U; row < 4U; ++row) {
    for (std::uint32_t column = 0U; column < 4U; ++column) {
      EXPECT_FLOAT_EQ(F(identity + row * 16U + column * 4U), row == column ? 1.0f : 0.0f);
    }
  }
  // A struct's initializer goes member by member.
  const std::uint32_t packed = Offset("packed");
  EXPECT_FLOAT_EQ(F(packed), 1.0f);
  EXPECT_FLOAT_EQ(F(packed + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(packed + 8U), 3.0f);
  EXPECT_FLOAT_EQ(F(Offset("z")), 0.0f) << "no initializer: zero";
}

TEST_F(GalParameterStore, ScalarsConvertToTheParametersType)
{
  Load("float f; int i; uint u; bool b; float3 v; int2 iv; float4x4 m;");
  const std::uint64_t start = mStore.Version();

  mStore.SetScalar(Index("f"), 1.75);
  EXPECT_FLOAT_EQ(F(Offset("f")), 1.75f);
  mStore.SetScalar(Index("i"), -2.7);
  EXPECT_EQ(I(Offset("i")), -2) << "truncated toward zero";
  mStore.SetScalar(Index("u"), -5.0);
  EXPECT_EQ(W(Offset("u")), 0U) << "a negative value clamps to zero";
  mStore.SetScalar(Index("u"), 9.9);
  EXPECT_EQ(W(Offset("u")), 9U);
  mStore.SetScalar(Index("b"), 0.5);
  EXPECT_EQ(W(Offset("b")), 1U);
  mStore.SetScalar(Index("b"), 0.0);
  EXPECT_EQ(W(Offset("b")), 0U);

  // A vector takes the value in every component.
  mStore.SetScalar(Index("v"), 4.0);
  EXPECT_FLOAT_EQ(F(Offset("v")), 4.0f);
  EXPECT_FLOAT_EQ(F(Offset("v") + 8U), 4.0f);
  mStore.SetScalar(Index("iv"), 3.0);
  EXPECT_EQ(I(Offset("iv") + 4U), 3);
  EXPECT_EQ(mStore.Version(), start + 8U);

  // A matrix takes no scalar, and the version does not move.
  mStore.SetScalar(Index("m"), 1.0);
  EXPECT_FLOAT_EQ(F(Offset("m")), 0.0f);
  EXPECT_EQ(mStore.Version(), start + 8U);
}

TEST_F(GalParameterStore, VectorsWriteTheirComponentsOnly)
{
  Load("float2 two; float tail; float s; float4 four; float4 list[2]; float2 pairs[3];");
  const float vector[4] = {1.0f, 2.0f, 3.0f, 4.0f};
  mStore.SetVector(Index("two"), vector);
  EXPECT_FLOAT_EQ(F(Offset("two")), 1.0f);
  EXPECT_FLOAT_EQ(F(Offset("two") + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(Offset("tail")), 0.0f) << "the float packed after the float2 is untouched";
  mStore.SetVector(Index("s"), vector);
  EXPECT_FLOAT_EQ(F(Offset("s")), 1.0f);
  mStore.SetVector(Index("four"), vector);
  EXPECT_FLOAT_EQ(F(Offset("four") + 12U), 4.0f);

  // Arrays: count is bounded by the array.
  const float vectors[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  mStore.SetVectorArray(Index("list"), vectors, 3U);
  EXPECT_FLOAT_EQ(F(Offset("list") + 16U), 5.0f);
  EXPECT_FLOAT_EQ(F(Offset("list") + 28U), 8.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs")), 0.0f) << "the third vector does not run into the next parameter";
  mStore.SetVectorArray(Index("pairs"), vectors, 3U);
  EXPECT_FLOAT_EQ(F(Offset("pairs")), 1.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 16U), 5.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 32U), 9.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 36U), 10.0f);
}

TEST_F(GalParameterStore, FloatArraysFollowSetFloatArray)
{
  Load("float w[3]; float2 pairs[2]; float4 quads[2]; float3 v; float after;");
  const float values[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  mStore.SetFloats(Index("w"), values, 5U);
  EXPECT_FLOAT_EQ(F(Offset("w")), 1.0f);
  EXPECT_FLOAT_EQ(F(Offset("w") + 16U), 2.0f);
  EXPECT_FLOAT_EQ(F(Offset("w") + 32U), 3.0f);

  // `columns` floats per element.
  mStore.SetFloats(Index("pairs"), values, 4U);
  EXPECT_FLOAT_EQ(F(Offset("pairs")), 1.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 16U), 3.0f);
  EXPECT_FLOAT_EQ(F(Offset("pairs") + 20U), 4.0f);

  // float4 arrays are the image's own layout; more values than the array holds stop at its end.
  mStore.SetFloats(Index("quads"), values, 10U);
  EXPECT_FLOAT_EQ(F(Offset("quads")), 1.0f);
  EXPECT_FLOAT_EQ(F(Offset("quads") + 28U), 8.0f);
  EXPECT_FLOAT_EQ(F(Offset("v")), 0.0f);

  mStore.SetFloats(Index("v"), values, 3U);
  EXPECT_FLOAT_EQ(F(Offset("v") + 8U), 3.0f);
  EXPECT_FLOAT_EQ(F(Offset("after")), 0.0f);

  const std::uint64_t version = mStore.Version();
  mStore.SetFloats(Index("v"), nullptr, 3U);
  EXPECT_EQ(mStore.Version(), version) << "null data is ignored";
}

TEST_F(GalParameterStore, MatricesAreStoredRowOrColumnMajor)
{
  Load("float4x4 rows; column_major float4x4 columns; float3x4 short3; float4x4 bones[2]; float4 asVectors[4]; float tail;");
  float matrix[16];
  for (int index = 0; index < 16; ++index) {
    matrix[index] = static_cast<float>(index + 1);
  }
  mStore.SetMatrix(Index("rows"), matrix);
  mStore.SetMatrix(Index("columns"), matrix);
  mStore.SetMatrix(Index("short3"), matrix);
  for (std::uint32_t row = 0U; row < 4U; ++row) {
    for (std::uint32_t column = 0U; column < 4U; ++column) {
      const float expected = matrix[row * 4U + column];
      EXPECT_FLOAT_EQ(F(Offset("rows") + row * 16U + column * 4U), expected);
      EXPECT_FLOAT_EQ(F(Offset("columns") + column * 16U + row * 4U), expected);
    }
  }
  // Three rows only.
  EXPECT_FLOAT_EQ(F(Offset("short3") + 2U * 16U + 12U), 12.0f);
  EXPECT_FLOAT_EQ(F(Offset("short3") + 48U), 0.0f);

  float three[48];
  for (int index = 0; index < 48; ++index) {
    three[index] = static_cast<float>(100 + index);
  }
  mStore.SetMatrixArray(Index("bones"), three, 3U);
  EXPECT_FLOAT_EQ(F(Offset("bones")), 100.0f);
  EXPECT_FLOAT_EQ(F(Offset("bones") + 64U + 60U), 131.0f);
  EXPECT_FLOAT_EQ(F(Offset("asVectors")), 0.0f) << "the third matrix does not run past the array";

  // SetMatrix on a non-matrix: 16 floats as SetFloatArray.
  mStore.SetMatrix(Index("asVectors"), matrix);
  EXPECT_FLOAT_EQ(F(Offset("asVectors") + 48U + 12U), 16.0f);
  EXPECT_FLOAT_EQ(F(Offset("tail")), 0.0f);

  // SetMatrixArray needs a matrix parameter.
  const std::uint64_t version = mStore.Version();
  mStore.SetMatrixArray(Index("asVectors"), three, 1U);
  EXPECT_EQ(mStore.Version(), version);
  EXPECT_FLOAT_EQ(F(Offset("asVectors")), 1.0f);
}

TEST_F(GalParameterStore, PackedValuesAreRawComponents)
{
  Load("int i; int2 pair; column_major float2x2 cm; float2x2 rm; struct S { float2 uv; int k; }; S s; S list[2];");
  const std::int32_t five = 5;
  mStore.SetPacked(Index("i"), &five, 4U);
  EXPECT_EQ(I(Offset("i")), 5) << "the bits, not a float conversion";

  const std::int32_t two[2] = {-1, 7};
  mStore.SetPacked(Index("pair"), two, 8U);
  EXPECT_EQ(I(Offset("pair")), -1);
  EXPECT_EQ(I(Offset("pair") + 4U), 7);

  // Packed input is row by row; a column-major image holds columns.
  const float matrix[4] = {1.0f, 2.0f, 3.0f, 4.0f};
  mStore.SetPacked(Index("cm"), matrix, 16U);
  EXPECT_FLOAT_EQ(F(Offset("cm")), 1.0f);
  EXPECT_FLOAT_EQ(F(Offset("cm") + 4U), 3.0f);
  EXPECT_FLOAT_EQ(F(Offset("cm") + 16U), 2.0f);
  EXPECT_FLOAT_EQ(F(Offset("cm") + 20U), 4.0f);
  mStore.SetFloats(Index("rm"), matrix, 4U);
  EXPECT_FLOAT_EQ(F(Offset("rm") + 4U), 2.0f);
  EXPECT_FLOAT_EQ(F(Offset("rm") + 16U), 3.0f);

  // Struct members at their own offsets and in their own types.
  const std::uint32_t words[6] = {Bits(0.5f), Bits(0.25f), 9U, Bits(2.0f), Bits(3.0f), 11U};
  mStore.SetPacked(Index("s"), words, 12U);
  EXPECT_FLOAT_EQ(F(Offset("s")), 0.5f);
  EXPECT_FLOAT_EQ(F(Offset("s") + 4U), 0.25f);
  EXPECT_EQ(W(Offset("s") + 8U), 9U);
  mStore.SetPacked(Index("list"), words, 24U);
  EXPECT_EQ(W(Offset("list") + 8U), 9U);
  EXPECT_FLOAT_EQ(F(Offset("list") + 16U), 2.0f);
  EXPECT_EQ(W(Offset("list") + 24U), 11U);
}

TEST_F(GalParameterStore, TexturesAndOutOfRangeParameters)
{
  Load("texture t; float f; string s = \"x\";");
  const std::uint32_t texture = Index("t");
  EXPECT_TRUE(mStore.Binding(texture).Empty());
  EXPECT_TRUE(mStore.Binding(99U).Empty());

  const boost::shared_ptr<gpg::gal::Texture> image(new faf_gal_tests::FakeTexture());
  const boost::shared_ptr<gpg::gal::RenderTarget> target(new faf_gal_tests::FakeRenderTarget());
  const std::uint64_t version = mStore.Version();
  mStore.SetTexture(texture, image);
  EXPECT_EQ(mStore.Binding(texture).texture.get(), image.get());
  EXPECT_EQ(mStore.Binding(texture).renderTarget.get(), nullptr);
  EXPECT_EQ(mStore.TextureVersion(), 2U);
  mStore.SetRenderTarget(texture, target);
  EXPECT_EQ(mStore.Binding(texture).texture.get(), nullptr) << "a render target replaces the texture";
  EXPECT_EQ(mStore.Binding(texture).renderTarget.get(), target.get());
  EXPECT_EQ(mStore.TextureVersion(), 3U);
  EXPECT_EQ(mStore.Version(), version + 2U);
  mStore.SetTexture(99U, image);
  mStore.SetRenderTarget(99U, target);
  EXPECT_EQ(mStore.TextureVersion(), 3U);

  // A parameter without a constant slot accepts and drops values.
  const float values[4] = {1, 2, 3, 4};
  mStore.SetFloats(texture, values, 4U);
  mStore.SetVector(Index("s"), values);
  mStore.SetScalar(99U, 1.0);
  mStore.SetMatrix(99U, values);
  EXPECT_EQ(mStore.Version(), version + 2U);
  EXPECT_FLOAT_EQ(F(Offset("f")), 0.0f);
}

TEST_F(GalParameterStore, AnEffectWithoutNumbersHasAnEmptyImage)
{
  const EffectDescription description = ParseEffect("texture t; string s = \"x\";");
  const ConstantLayout layout = ComputeConstantLayout(description);
  ParameterStore store;
  store.Initialize(description, layout);
  EXPECT_TRUE(store.Constants().empty());
  const float value = 1.0f;
  store.SetFloats(0U, &value, 1U);
  EXPECT_TRUE(store.Constants().empty());

  ParameterStore uninitialized;
  uninitialized.SetScalar(0U, 1.0);
  EXPECT_TRUE(uninitialized.Constants().empty());
  EXPECT_TRUE(uninitialized.Binding(0U).Empty());
}
