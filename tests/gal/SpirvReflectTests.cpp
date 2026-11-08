// gpg/gal/effects/SpirvReflect.h: the stage interface of a SPIR-V module, the input-location patch
// and the removal of the reflection decorations. The modules are assembled here word by word from
// the SPIR-V 1.x specification: the header (magic 0x07230203, version, generator, bound, schema),
// then instructions whose first word holds the word count in the high half and the opcode in the
// low half; literal strings are UTF-8, nul-terminated and padded to whole words, first character
// in the lowest byte. Opcodes and enumerants used (section 3 of the specification):
// OpExtension 10, OpMemoryModel 14, OpCapability 17, OpTypeInt 21, OpTypeFloat 22, OpTypeVector 23,
// OpTypeMatrix 24, OpTypeArray 28, OpTypePointer 32, OpConstant 43, OpVariable 59, OpDecorate 71,
// OpDecorateString 5632, OpMemberDecorateString 5633; decorations BuiltIn 11, Location 30,
// UserSemantic 5635, UserTypeGOOGLE 5636; storage classes Input 1, Uniform 2, Output 3, Private 6.

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <map>
#include <string>
#include <vector>

#include "gpg/gal/effects/SpirvReflect.h"

using namespace gpg::gal::effects;

namespace
{
  class Module
  {
  public:
    Module() { mWords = {0x07230203U, 0x00010000U, 0U, 100U, 0U}; }

    void Op(const std::uint16_t opcode, const std::initializer_list<std::uint32_t> operands)
    {
      mWords.push_back((static_cast<std::uint32_t>(operands.size() + 1U) << 16U) | opcode);
      mWords.insert(mWords.end(), operands.begin(), operands.end());
    }

    /** An instruction whose operands are `operands` followed by the literal string `text`. */
    void OpString(const std::uint16_t opcode, const std::initializer_list<std::uint32_t> operands, const std::string& text)
    {
      std::vector<std::uint32_t> literal((text.size() + 4U) / 4U, 0U);
      std::memcpy(literal.data(), text.data(), text.size());
      mWords.push_back((static_cast<std::uint32_t>(operands.size() + literal.size() + 1U) << 16U) | opcode);
      mWords.insert(mWords.end(), operands.begin(), operands.end());
      mWords.insert(mWords.end(), literal.begin(), literal.end());
    }

    [[nodiscard]] std::vector<std::uint8_t> Bytes() const
    {
      std::vector<std::uint8_t> bytes(mWords.size() * 4U);
      std::memcpy(bytes.data(), mWords.data(), bytes.size());
      return bytes;
    }

    [[nodiscard]] std::size_t WordCount() const noexcept { return mWords.size(); }
    std::vector<std::uint32_t>& Words() noexcept { return mWords; }

  private:
    std::vector<std::uint32_t> mWords;
  };

  constexpr std::uint16_t kOpExtension = 10;
  constexpr std::uint16_t kOpMemoryModel = 14;
  constexpr std::uint16_t kOpCapability = 17;
  constexpr std::uint16_t kOpTypeInt = 21;
  constexpr std::uint16_t kOpTypeFloat = 22;
  constexpr std::uint16_t kOpTypeVector = 23;
  constexpr std::uint16_t kOpTypeMatrix = 24;
  constexpr std::uint16_t kOpTypeArray = 28;
  constexpr std::uint16_t kOpTypePointer = 32;
  constexpr std::uint16_t kOpConstant = 43;
  constexpr std::uint16_t kOpVariable = 59;
  constexpr std::uint16_t kOpDecorate = 71;
  constexpr std::uint16_t kOpDecorateString = 5632;
  constexpr std::uint16_t kOpMemberDecorateString = 5633;
  constexpr std::uint32_t kBuiltIn = 11;
  constexpr std::uint32_t kLocation = 30;
  constexpr std::uint32_t kUserSemantic = 5635;
  constexpr std::uint32_t kUserTypeGoogle = 5636;
  constexpr std::uint32_t kInput = 1;
  constexpr std::uint32_t kUniform = 2;
  constexpr std::uint32_t kOutput = 3;
  constexpr std::uint32_t kPrivate = 6;
  constexpr std::uint32_t kBuiltInPosition = 0;

  // Result ids.
  enum : std::uint32_t
  {
    kFloat = 1,
    kInt,
    kUint,
    kVec2,
    kVec4,
    kIVec4,
    kUVec2,
    kMat4,
    kThree,
    kVec2Array3,
    kPtrInVec4,
    kPtrInVec2,
    kPtrInArray,
    kPtrInMat4,
    kPtrInIVec4,
    kPtrInUVec2,
    kPtrInFloat,
    kPtrOutVec4,
    kPtrUniformVec4,
    kInPosition,
    kInUv,
    kInArray,
    kInMatrix,
    kInIndices,
    kInPacked,
    kInScalar,
    kInNoLocation,
    kOutPosition,
    kOutColour,
    kUniformVariable,
    kPrivateVariable,
  };

  /** A vertex-shader-like interface with every variable shape ReflectSpirvInterface reads. */
  Module InterfaceModule()
  {
    Module module;
    module.Op(kOpCapability, {1U});
    module.OpString(kOpExtension, {}, "SPV_GOOGLE_hlsl_functionality1");
    module.OpString(kOpExtension, {}, "SPV_GOOGLE_user_type");
    module.OpString(kOpExtension, {}, "SPV_KHR_storage_buffer_storage_class");
    module.Op(kOpMemoryModel, {0U, 1U});

    module.Op(kOpDecorate, {kInPosition, kLocation, 0U});
    module.OpString(kOpDecorateString, {kInPosition, kUserSemantic}, "POSITION");
    module.Op(kOpDecorate, {kInUv, kLocation, 1U});
    module.OpString(kOpDecorateString, {kInUv, kUserSemantic}, "TEXCOORD3");
    module.Op(kOpDecorate, {kInArray, kLocation, 2U});
    module.OpString(kOpDecorateString, {kInArray, kUserSemantic}, "texcoord4");
    module.Op(kOpDecorate, {kInMatrix, kLocation, 5U});
    module.OpString(kOpDecorateString, {kInMatrix, kUserSemantic}, "WORLD12");
    module.Op(kOpDecorate, {kInIndices, kLocation, 9U});
    module.OpString(kOpDecorateString, {kInIndices, kUserSemantic}, "BLENDINDICES");
    module.Op(kOpDecorate, {kInPacked, kLocation, 10U});
    module.Op(kOpDecorate, {kInScalar, kLocation, 11U});
    module.OpString(kOpDecorateString, {kInScalar, kUserTypeGoogle}, "float");
    module.Op(kOpDecorate, {kOutPosition, kBuiltIn, kBuiltInPosition});
    module.Op(kOpDecorate, {kOutColour, kLocation, 0U});
    module.OpString(kOpDecorateString, {kOutColour, kUserSemantic}, "SV_Target");
    module.OpString(kOpMemberDecorateString, {kVec2Array3, 0U, kUserSemantic}, "MEMBER");

    module.Op(kOpTypeFloat, {kFloat, 32U});
    module.Op(kOpTypeInt, {kInt, 32U, 1U});
    module.Op(kOpTypeInt, {kUint, 32U, 0U});
    module.Op(kOpTypeVector, {kVec2, kFloat, 2U});
    module.Op(kOpTypeVector, {kVec4, kFloat, 4U});
    module.Op(kOpTypeVector, {kIVec4, kInt, 4U});
    module.Op(kOpTypeVector, {kUVec2, kUint, 2U});
    module.Op(kOpTypeMatrix, {kMat4, kVec4, 4U});
    module.Op(kOpConstant, {kUint, kThree, 3U});
    module.Op(kOpTypeArray, {kVec2Array3, kVec2, kThree});
    module.Op(kOpTypePointer, {kPtrInVec4, kInput, kVec4});
    module.Op(kOpTypePointer, {kPtrInVec2, kInput, kVec2});
    module.Op(kOpTypePointer, {kPtrInArray, kInput, kVec2Array3});
    module.Op(kOpTypePointer, {kPtrInMat4, kInput, kMat4});
    module.Op(kOpTypePointer, {kPtrInIVec4, kInput, kIVec4});
    module.Op(kOpTypePointer, {kPtrInUVec2, kInput, kUVec2});
    module.Op(kOpTypePointer, {kPtrInFloat, kInput, kFloat});
    module.Op(kOpTypePointer, {kPtrOutVec4, kOutput, kVec4});
    module.Op(kOpTypePointer, {kPtrUniformVec4, kUniform, kVec4});

    module.Op(kOpVariable, {kPtrInVec4, kInPosition, kInput});
    module.Op(kOpVariable, {kPtrInVec2, kInUv, kInput});
    module.Op(kOpVariable, {kPtrInArray, kInArray, kInput});
    module.Op(kOpVariable, {kPtrInMat4, kInMatrix, kInput});
    module.Op(kOpVariable, {kPtrInIVec4, kInIndices, kInput});
    module.Op(kOpVariable, {kPtrInUVec2, kInPacked, kInput});
    module.Op(kOpVariable, {kPtrInFloat, kInScalar, kInput});
    module.Op(kOpVariable, {kPtrInVec4, kInNoLocation, kInput});
    module.Op(kOpVariable, {kPtrOutVec4, kOutPosition, kOutput});
    module.Op(kOpVariable, {kPtrOutVec4, kOutColour, kOutput});
    module.Op(kOpVariable, {kPtrUniformVec4, kUniformVariable, kUniform});
    module.Op(kOpVariable, {kPtrInVec4, kPrivateVariable, kPrivate});
    return module;
  }

  const SpirvInterfaceVariable* Find(const std::vector<SpirvInterfaceVariable>& variables, const std::uint32_t id)
  {
    for (const SpirvInterfaceVariable& variable : variables) {
      if (variable.id == id) {
        return &variable;
      }
    }
    return nullptr;
  }

  bool HasBytes(const std::vector<std::uint8_t>& code, const std::string& text)
  {
    return std::search(code.begin(), code.end(), text.begin(), text.end()) != code.end();
  }
} // namespace

TEST(GalSpirvReflect, InterfaceVariablesTakeLocationShapeAndSemantic)
{
  const SpirvInterface result = ReflectSpirvInterface(InterfaceModule().Bytes());
  ASSERT_EQ(result.inputs.size(), 7U) << "the input without a Location or BuiltIn is left out";
  ASSERT_EQ(result.outputs.size(), 2U);

  const SpirvInterfaceVariable* const position = Find(result.inputs, kInPosition);
  ASSERT_NE(position, nullptr);
  EXPECT_EQ(position->location, 0U);
  EXPECT_EQ(position->locations, 1U);
  EXPECT_EQ(position->components, 4U);
  EXPECT_EQ(position->component, SpirvInterfaceVariable::Component::Float);
  EXPECT_EQ(position->semantic, "POSITION");
  EXPECT_EQ(position->semanticIndex, 0U);
  EXPECT_FALSE(position->builtIn);

  const SpirvInterfaceVariable* const uv = Find(result.inputs, kInUv);
  ASSERT_NE(uv, nullptr);
  EXPECT_EQ(uv->location, 1U);
  EXPECT_EQ(uv->components, 2U);
  EXPECT_EQ(uv->semantic, "TEXCOORD");
  EXPECT_EQ(uv->semanticIndex, 3U);

  // An array takes a location per element, from its length constant; the semantic is upper-cased.
  const SpirvInterfaceVariable* const array = Find(result.inputs, kInArray);
  ASSERT_NE(array, nullptr);
  EXPECT_EQ(array->location, 2U);
  EXPECT_EQ(array->locations, 3U);
  EXPECT_EQ(array->components, 2U);
  EXPECT_EQ(array->semantic, "TEXCOORD");
  EXPECT_EQ(array->semanticIndex, 4U);

  // A matrix takes a location per column.
  const SpirvInterfaceVariable* const matrix = Find(result.inputs, kInMatrix);
  ASSERT_NE(matrix, nullptr);
  EXPECT_EQ(matrix->locations, 4U);
  EXPECT_EQ(matrix->components, 4U);
  EXPECT_EQ(matrix->semantic, "WORLD");
  EXPECT_EQ(matrix->semanticIndex, 12U);

  const SpirvInterfaceVariable* const indices = Find(result.inputs, kInIndices);
  ASSERT_NE(indices, nullptr);
  EXPECT_EQ(indices->component, SpirvInterfaceVariable::Component::Sint);
  EXPECT_EQ(indices->semantic, "BLENDINDICES");

  const SpirvInterfaceVariable* const packed = Find(result.inputs, kInPacked);
  ASSERT_NE(packed, nullptr);
  EXPECT_EQ(packed->component, SpirvInterfaceVariable::Component::Uint);
  EXPECT_EQ(packed->components, 2U);
  EXPECT_EQ(packed->semantic, "") << "no UserSemantic decoration";

  const SpirvInterfaceVariable* const scalar = Find(result.inputs, kInScalar);
  ASSERT_NE(scalar, nullptr);
  EXPECT_EQ(scalar->components, 1U);
  EXPECT_EQ(scalar->location, 11U);

  const SpirvInterfaceVariable* const outPosition = Find(result.outputs, kOutPosition);
  ASSERT_NE(outPosition, nullptr);
  EXPECT_TRUE(outPosition->builtIn);
  EXPECT_EQ(outPosition->location, 0U);
  const SpirvInterfaceVariable* const colour = Find(result.outputs, kOutColour);
  ASSERT_NE(colour, nullptr);
  EXPECT_EQ(colour->semantic, "SV_TARGET");
  EXPECT_TRUE(colour->builtIn) << "an SV_ semantic is a system value";

  EXPECT_EQ(Find(result.inputs, kUniformVariable), nullptr);
  EXPECT_EQ(Find(result.inputs, kPrivateVariable), nullptr);
}

TEST(GalSpirvReflect, MalformedModulesGiveAnEmptyInterface)
{
  EXPECT_TRUE(ReflectSpirvInterface({}).inputs.empty());

  std::vector<std::uint8_t> code = InterfaceModule().Bytes();
  std::vector<std::uint8_t> wrongMagic = code;
  wrongMagic[0] ^= 0xFFU;
  const SpirvInterface fromWrongMagic = ReflectSpirvInterface(wrongMagic);
  EXPECT_TRUE(fromWrongMagic.inputs.empty());
  EXPECT_TRUE(fromWrongMagic.outputs.empty());

  // An instruction whose word count runs past the end.
  Module truncated = InterfaceModule();
  truncated.Words().push_back((9U << 16U) | kOpDecorate);
  truncated.Words().push_back(kInPosition);
  EXPECT_TRUE(ReflectSpirvInterface(truncated.Bytes()).inputs.empty());

  // A zero word count.
  Module zero = InterfaceModule();
  zero.Words().push_back(kOpCapability);
  EXPECT_TRUE(ReflectSpirvInterface(zero.Bytes()).inputs.empty());

  // A header alone, and a trailing partial word, are not errors.
  EXPECT_TRUE(ReflectSpirvInterface(Module().Bytes()).inputs.empty());
  code.push_back(0xAB);
  EXPECT_EQ(ReflectSpirvInterface(code).inputs.size(), 7U);
}

TEST(GalSpirvReflect, InputLocationsCanBeMovedById)
{
  const std::vector<std::uint8_t> code = InterfaceModule().Bytes();
  const std::vector<std::uint8_t> patched = PatchSpirvInputLocations(code, {{kInPosition, 7U}, {kInUv, 3U}, {999U, 1U}});
  ASSERT_EQ(patched.size(), code.size());
  const SpirvInterface result = ReflectSpirvInterface(patched);
  EXPECT_EQ(Find(result.inputs, kInPosition)->location, 7U);
  EXPECT_EQ(Find(result.inputs, kInUv)->location, 3U);
  EXPECT_EQ(Find(result.inputs, kInArray)->location, 2U);
  EXPECT_EQ(Find(result.outputs, kOutColour)->location, 0U);

  EXPECT_EQ(PatchSpirvInputLocations(code, {}), code);
  // Malformed input comes back unchanged.
  std::vector<std::uint8_t> wrongMagic = code;
  wrongMagic[3] = 0U;
  EXPECT_EQ(PatchSpirvInputLocations(wrongMagic, {{kInPosition, 7U}}), wrongMagic);
  Module truncated = InterfaceModule();
  truncated.Words().push_back((9U << 16U) | kOpDecorate);
  const std::vector<std::uint8_t> truncatedBytes = truncated.Bytes();
  EXPECT_EQ(PatchSpirvInputLocations(truncatedBytes, {{kInPosition, 7U}}), truncatedBytes);
}

TEST(GalSpirvReflect, StrippingRemovesOnlyTheReflectionDecorations)
{
  const Module module = InterfaceModule();
  const std::vector<std::uint8_t> code = module.Bytes();
  const std::vector<std::uint8_t> stripped = StripSpirvReflection(code);

  // Removed: the two GOOGLE extensions (9 + 7 words), six UserSemantic decorations
  // (6 + 6 + 6 + 5 + 7 + 6), one UserTypeGOOGLE decoration (5) and one member UserSemantic (6).
  EXPECT_EQ(code.size() - stripped.size(), (16U + 36U + 5U + 6U) * 4U);
  EXPECT_FALSE(HasBytes(stripped, "SPV_GOOGLE"));
  EXPECT_FALSE(HasBytes(stripped, "TEXCOORD3"));
  EXPECT_FALSE(HasBytes(stripped, "MEMBER"));
  EXPECT_TRUE(HasBytes(stripped, "SPV_KHR_storage_buffer_storage_class"));
  EXPECT_EQ(std::vector<std::uint8_t>(stripped.begin(), stripped.begin() + 20), std::vector<std::uint8_t>(code.begin(), code.begin() + 20))
    << "the header is kept";

  // Locations, types and built-ins survive; the semantics are gone.
  const SpirvInterface result = ReflectSpirvInterface(stripped);
  ASSERT_EQ(result.inputs.size(), 7U);
  EXPECT_EQ(Find(result.inputs, kInUv)->location, 1U);
  EXPECT_EQ(Find(result.inputs, kInUv)->semantic, "");
  EXPECT_EQ(Find(result.inputs, kInArray)->locations, 3U);
  EXPECT_TRUE(Find(result.outputs, kOutPosition)->builtIn);

  EXPECT_EQ(StripSpirvReflection(stripped), stripped) << "stripping twice changes nothing";
  EXPECT_TRUE(StripSpirvReflection({}).empty());
  std::vector<std::uint8_t> wrongMagic = code;
  wrongMagic[1] = 0U;
  EXPECT_EQ(StripSpirvReflection(wrongMagic), wrongMagic);
  Module zero = InterfaceModule();
  zero.Words().push_back(kOpCapability);
  const std::vector<std::uint8_t> zeroBytes = zero.Bytes();
  EXPECT_EQ(StripSpirvReflection(zeroBytes), zeroBytes);
}
