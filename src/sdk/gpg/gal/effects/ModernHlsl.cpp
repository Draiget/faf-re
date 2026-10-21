// FAF addition, not in the shipped binary: see ModernHlsl.h.

#include "ModernHlsl.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <tuple>
#include <utility>

#include "EffectText.h"

namespace gpg::gal::effects
{
  using namespace text;

  namespace
  {
    // Register numbers of the placeholder views a faf_sampler carries for the
    // dimensions its texture is never sampled in. The compiler removes them
    // with the dead fields; ModernEffect consumers can check none survive.
    constexpr const char* kPrelude = R"hlsl(
// ---- FAF effect layer prelude (generated) ----
struct faf_sampler
{
    Texture2D t2;
    TextureCube tc;
    Texture3D t3;
    SamplerState s;
};
faf_sampler faf_make_sampler(Texture2D t2, TextureCube tc, Texture3D t3, SamplerState s)
{
    faf_sampler r;
    r.t2 = t2;
    r.tc = tc;
    r.t3 = t3;
    r.s = s;
    return r;
}
Texture2D faf_null2D : register(t125);
TextureCube faf_nullCube : register(t126);
Texture3D faf_null3D : register(t127);
#ifdef FAF_VERTEX_STAGE
// Vertex shaders have no derivatives: Direct3D 9 sampled mip 0.
float4 tex2D(faf_sampler s, float2 uv) { return s.t2.SampleLevel(s.s, uv, 0); }
float4 tex2Dbias(faf_sampler s, float4 uv) { return s.t2.SampleLevel(s.s, uv.xy, 0); }
float4 tex2Dproj(faf_sampler s, float4 uv) { return s.t2.SampleLevel(s.s, uv.xy / uv.w, 0); }
float4 texCUBE(faf_sampler s, float3 uv) { return s.tc.SampleLevel(s.s, uv, 0); }
float4 texCUBEbias(faf_sampler s, float4 uv) { return s.tc.SampleLevel(s.s, uv.xyz, 0); }
float4 texCUBEproj(faf_sampler s, float4 uv) { return s.tc.SampleLevel(s.s, uv.xyz / uv.w, 0); }
float4 tex3D(faf_sampler s, float3 uv) { return s.t3.SampleLevel(s.s, uv, 0); }
float4 tex3Dbias(faf_sampler s, float4 uv) { return s.t3.SampleLevel(s.s, uv.xyz, 0); }
float4 tex3Dproj(faf_sampler s, float4 uv) { return s.t3.SampleLevel(s.s, uv.xyz / uv.w, 0); }
#else
float4 tex2D(faf_sampler s, float2 uv) { return s.t2.Sample(s.s, uv); }
float4 tex2Dbias(faf_sampler s, float4 uv) { return s.t2.SampleBias(s.s, uv.xy, uv.w); }
float4 tex2Dproj(faf_sampler s, float4 uv) { return s.t2.Sample(s.s, uv.xy / uv.w); }
float4 texCUBE(faf_sampler s, float3 uv) { return s.tc.Sample(s.s, uv); }
float4 texCUBEbias(faf_sampler s, float4 uv) { return s.tc.SampleBias(s.s, uv.xyz, uv.w); }
float4 texCUBEproj(faf_sampler s, float4 uv) { return s.tc.Sample(s.s, uv.xyz / uv.w); }
float4 tex3D(faf_sampler s, float3 uv) { return s.t3.Sample(s.s, uv); }
float4 tex3Dbias(faf_sampler s, float4 uv) { return s.t3.SampleBias(s.s, uv.xyz, uv.w); }
float4 tex3Dproj(faf_sampler s, float4 uv) { return s.t3.Sample(s.s, uv.xyz / uv.w); }
#endif
float4 tex2D(faf_sampler s, float2 uv, float2 dx, float2 dy) { return s.t2.SampleGrad(s.s, uv, dx, dy); }
float4 tex2Dgrad(faf_sampler s, float2 uv, float2 dx, float2 dy) { return s.t2.SampleGrad(s.s, uv, dx, dy); }
float4 tex2Dlod(faf_sampler s, float4 uv) { return s.t2.SampleLevel(s.s, uv.xy, uv.w); }
float4 texCUBE(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.tc.SampleGrad(s.s, uv, dx, dy); }
float4 texCUBEgrad(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.tc.SampleGrad(s.s, uv, dx, dy); }
float4 texCUBElod(faf_sampler s, float4 uv) { return s.tc.SampleLevel(s.s, uv.xyz, uv.w); }
float4 tex3D(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.t3.SampleGrad(s.s, uv, dx, dy); }
float4 tex3Dgrad(faf_sampler s, float3 uv, float3 dx, float3 dy) { return s.t3.SampleGrad(s.s, uv, dx, dy); }
float4 tex3Dlod(faf_sampler s, float4 uv) { return s.t3.SampleLevel(s.s, uv.xyz, uv.w); }
// ---- end of prelude ----
)hlsl";

    // Direct3D 9 shader math that Shader Model 6 lost. A NaN that reaches
    // blending stores zero, so each of these shows as black pixels:
    // - sqrt and rsqrt compile to rsq, which takes the absolute value of its
    //   operand (normal reconstruction sqrt(1 - dot(xy, xy)));
    // - pow with an integer literal exponent compiles to multiplications,
    //   any other pow to log and exp, and log also takes the absolute value.
    //   That is |x|^y, negated for an odd integer exponent. DXC turns every
    //   exponent but 2 into log/exp of x and returns NaN for a negative x
    //   (FresnelSchlick's pow(1 - dot(h, v), 5) when the dot rounds above 1).
    constexpr const char* kDirect3D9Math = R"hlsl(#define sqrt(x) sqrt(abs(x))
#define rsqrt(x) rsqrt(abs(x))
#define pow(x, y) (pow(abs(x), (y)) * (((x) < 0 && frac((y) * 0.5) == 0.5) ? -1 : 1))
)hlsl";

    // Diagnostics: FAF_GAL_D3D10_MATH=1 keeps Shader Model 4 sqrt/rsqrt.
    [[nodiscard]] bool UseDirect3D9Math() noexcept
    {
      static const bool keepModern = [] {
        const char* const value = std::getenv("FAF_GAL_D3D10_MATH");
        return value != nullptr && value[0] == '1';
      }();
      return !keepModern;
    }

    // Diagnostics: FAF_GAL_NAN_CHECK=1 draws NaN or infinite pixel colours in magenta.
    [[nodiscard]] bool NanCheckRequested() noexcept
    {
      static const bool requested = [] {
        const char* const value = std::getenv("FAF_GAL_NAN_CHECK");
        return value != nullptr && value[0] == '1';
      }();
      return requested;
    }

    constexpr const char* kSamplerTypes[] = {"samplerCUBE", "sampler3D", "sampler2D", "sampler1D", "sampler"};

    [[nodiscard]] const char* ViewSuffix(const TextureDimension dimension) noexcept
    {
      switch (dimension) {
      case TextureDimension::TextureCube:
        return "__faf_cube";
      case TextureDimension::Texture3D:
        return "__faf_3d";
      default:
        return "";
      }
    }

    [[nodiscard]] const char* ViewType(const TextureDimension dimension) noexcept
    {
      switch (dimension) {
      case TextureDimension::TextureCube:
        return "TextureCube";
      case TextureDimension::Texture3D:
        return "Texture3D";
      default:
        return "Texture2D";
      }
    }

    /** The dimensions a sampler can be read in. */
    [[nodiscard]] std::vector<TextureDimension> SamplerDimensions(const SamplerDesc& sampler, const std::string_view source)
    {
      const std::string type = Lower(sampler.declaredType);
      if (type == "samplercube") {
        return {TextureDimension::TextureCube};
      }
      if (type == "sampler3d") {
        return {TextureDimension::Texture3D};
      }
      if (type != "sampler") {
        return {TextureDimension::Texture2D};
      }
      // An untyped `sampler` takes the kind of the lookup that reads it: the
      // primitive batcher reads one sampler as 2D or cube per technique.
      std::vector<TextureDimension> dimensions{TextureDimension::Texture2D};
      if (source.find("texCUBE") != std::string_view::npos) {
        dimensions.push_back(TextureDimension::TextureCube);
      }
      if (source.find("tex3D") != std::string_view::npos) {
        dimensions.push_back(TextureDimension::Texture3D);
      }
      return dimensions;
    }

    [[nodiscard]] std::string ReplaceSamplerTypes(std::string text)
    {
      for (const char* const type : kSamplerTypes) {
        text = ReplaceIdentifier(text, type, "faf_sampler");
      }
      return text;
    }

    /** Strips the annotation block, initializer and semantic of a global declaration. */
    [[nodiscard]] std::string GlobalDeclaration(const Parameter& parameter)
    {
      std::string type = " " + parameter.typeName + " ";
      for (const char* const modifier : {" const ", " uniform ", " shared ", " extern ", " volatile "}) {
        std::size_t position;
        while ((position = type.find(modifier)) != std::string::npos) {
          type.replace(position, std::char_traits<char>::length(modifier), " ");
        }
      }
      std::string declaration = Trim(type) + " " + parameter.name;
      if (parameter.elements != 0U) {
        declaration += "[" + std::to_string(parameter.elements) + "]";
      }
      return declaration + ";";
    }

    [[nodiscard]] std::string LocalCopyType(const Parameter& parameter)
    {
      std::string type = " " + parameter.typeName + " ";
      for (const char* const modifier :
           {" const ", " uniform ", " shared ", " extern ", " volatile ", " row_major ", " column_major "}) {
        std::size_t position;
        while ((position = type.find(modifier)) != std::string::npos) {
          type.replace(position, std::char_traits<char>::length(modifier), " ");
        }
      }
      return Trim(type);
    }

    /** True when `body` writes `name` (assignment, compound assignment, ++/--), through an index or swizzle too. */
    [[nodiscard]] bool AssignsIdentifier(const std::string_view body, const std::string_view name)
    {
      std::size_t index = 0U;
      while ((index = body.find(name, index)) != std::string_view::npos) {
        const std::size_t after = index + name.size();
        const bool whole = (index == 0U || !IsIdentifierChar(body[index - 1U])) && (after >= body.size() || !IsIdentifierChar(body[after]));
        if (!whole) {
          index = after;
          continue;
        }
        std::size_t before = index;
        while (before > 0U && body[before - 1U] == ' ') {
          --before;
        }
        if (before > 0U && body[before - 1U] == '.') {
          index = after;
          continue; // a member of something else
        }
        if (before >= 2U && ((body[before - 1U] == '+' && body[before - 2U] == '+') || (body[before - 1U] == '-' && body[before - 2U] == '-'))) {
          return true;
        }
        std::size_t next = after;
        for (;;) {
          while (next < body.size() && body[next] == ' ') {
            ++next;
          }
          if (next < body.size() && body[next] == '[') {
            const std::size_t close = Matching(body, next);
            next = (close == std::string_view::npos) ? body.size() : close + 1U;
            continue;
          }
          if (next < body.size() && body[next] == '.') {
            ++next;
            while (next < body.size() && body[next] == ' ') {
              ++next;
            }
            while (next < body.size() && IsIdentifierChar(body[next])) {
              ++next;
            }
            continue;
          }
          break;
        }
        if (next < body.size()) {
          const char c = body[next];
          const char c2 = (next + 1U < body.size()) ? body[next + 1U] : '\0';
          if ((c == '=' && c2 != '=') || ((c == '+' || c == '-' || c == '*' || c == '/' || c == '%' || c == '&' || c == '|' || c == '^') && c2 == '=') ||
              (c == '+' && c2 == '+') || (c == '-' && c2 == '-')) {
            return true;
          }
        }
        index = after;
      }
      return false;
    }

    /** True when `body` declares a local named `name` (`float3 name ...`): the global is shadowed. */
    [[nodiscard]] bool DeclaresIdentifier(const std::string_view body, const std::string_view name)
    {
      std::size_t index = 0U;
      while ((index = body.find(name, index)) != std::string_view::npos) {
        const std::size_t after = index + name.size();
        if ((index != 0U && IsIdentifierChar(body[index - 1U])) || (after < body.size() && IsIdentifierChar(body[after]))) {
          index = after;
          continue;
        }
        std::size_t end = index;
        while (end > 0U && body[end - 1U] == ' ') {
          --end;
        }
        std::size_t begin = end;
        while (begin > 0U && IsIdentifierChar(body[begin - 1U])) {
          --begin;
        }
        const std::string_view previous = body.substr(begin, end - begin);
        if (!previous.empty() && previous != "return" && previous != "else" && previous != "case" && previous != "in" &&
            previous != "out" && previous != "inout" && std::isdigit(static_cast<unsigned char>(previous[0])) == 0) {
          return true;
        }
        index = after;
      }
      return false;
    }

    /** A function definition: `[modifiers] ReturnType Name ( params ) [: semantic] { body }`. */
    struct Function
    {
      std::string returnType;
      std::string name;
      std::vector<std::string> parameters; // squeezed, as written
      std::string semantic;                // the return semantic, without ':'
    };

    [[nodiscard]] bool ParseFunctionHead(const std::string& head, Function& function)
    {
      const std::size_t open = head.find('(');
      if (open == std::string::npos) {
        return false;
      }
      const std::size_t close = Matching(head, open);
      if (close == std::string::npos) {
        return false;
      }
      const std::string before = Trim(head.substr(0U, open));
      const std::size_t space = before.rfind(' ');
      if (space == std::string::npos) {
        return false;
      }
      function.name = before.substr(space + 1U);
      function.returnType = Trim(before.substr(0U, space));
      for (const char* const modifier : {"inline ", "static "}) {
        if (function.returnType.rfind(modifier, 0U) == 0U) {
          function.returnType = Trim(function.returnType.substr(std::char_traits<char>::length(modifier)));
        }
      }
      function.parameters.clear();
      const std::string list = head.substr(open + 1U, close - open - 1U);
      if (!Trim(list).empty() && Trim(list) != "void") {
        for (const std::string& parameter : SplitTopLevel(list, ',')) {
          function.parameters.push_back(Trim(parameter));
        }
      }
      const std::string after = Trim(head.substr(close + 1U));
      function.semantic = (!after.empty() && after[0] == ':') ? Trim(after.substr(1U)) : std::string();
      return true;
    }

    struct ParameterParts
    {
      std::string modifiers; // in / out / inout / uniform ...
      std::string type;
      std::string name;
      std::string suffix;    // array dimensions
      std::string semantic;  // without ':'
      bool isUniform = false;
      bool isOut = false;
    };

    [[nodiscard]] ParameterParts SplitParameter(const std::string& parameter)
    {
      ParameterParts parts;
      std::string declaration = parameter;
      const std::size_t equals = declaration.find('=');
      if (equals != std::string::npos) {
        declaration = Trim(declaration.substr(0U, equals));
      }
      const std::size_t colon = declaration.find(':');
      if (colon != std::string::npos) {
        parts.semantic = Trim(declaration.substr(colon + 1U));
        declaration = Trim(declaration.substr(0U, colon));
      }
      const std::size_t bracket = declaration.find('[');
      if (bracket != std::string::npos) {
        parts.suffix = Squeeze(declaration.substr(bracket));
        declaration = Trim(declaration.substr(0U, bracket));
      }
      std::vector<std::string> words;
      for (const std::string& word : SplitTopLevel(Squeeze(declaration), ' ')) {
        if (!word.empty()) {
          words.push_back(word);
        }
      }
      if (words.empty()) {
        return parts;
      }
      parts.name = words.back();
      words.pop_back();
      for (const std::string& word : words) {
        if (word == "uniform") {
          parts.isUniform = true;
        } else if (word == "out" || word == "inout") {
          parts.isOut = true;
          parts.modifiers += word + " ";
        } else if (word == "in" || word == "const" || word == "linear" || word == "centroid" || word == "nointerpolation" ||
                   word == "noperspective" || word == "sample") {
          parts.modifiers += word + " ";
        } else {
          parts.type += (parts.type.empty() ? "" : " ") + word;
        }
      }
      return parts;
    }

    /** "COLOR1" -> ("COLOR", "1"). */
    [[nodiscard]] std::pair<std::string, std::string> SplitSemantic(const std::string& semantic)
    {
      std::size_t digits = semantic.size();
      while (digits > 0U && std::isdigit(static_cast<unsigned char>(semantic[digits - 1U])) != 0) {
        --digits;
      }
      return {Lower(semantic.substr(0U, digits)), semantic.substr(digits)};
    }

    enum class SemanticRole : std::uint8_t
    {
      VertexOutput, // POSITION -> SV_Position
      PixelInput,   // POSITION, VPOS -> SV_Position
      PixelOutput,  // COLORn -> SV_Targetn, DEPTH -> SV_Depth
    };

    [[nodiscard]] std::string ModernSemantic(const std::string& semantic, const SemanticRole role)
    {
      const auto [name, index] = SplitSemantic(semantic);
      switch (role) {
      case SemanticRole::VertexOutput:
        if (name == "position" && (index.empty() || index == "0")) {
          return "SV_Position";
        }
        break;
      case SemanticRole::PixelInput:
        if ((name == "position" && (index.empty() || index == "0")) || name == "vpos") {
          return "SV_Position";
        }
        break;
      case SemanticRole::PixelOutput:
        if (name == "color") {
          return "SV_Target" + (index.empty() ? std::string("0") : index);
        }
        if (name == "depth") {
          return "SV_Depth";
        }
        break;
      }
      return semantic;
    }

    /** Rewrites the member semantics of a struct body for `role`. */
    [[nodiscard]] std::string RewriteStructSemantics(const std::string& body, const SemanticRole role)
    {
      std::string out;
      for (const std::string& member : SplitTopLevel(body, ';')) {
        const std::string trimmed = Trim(member);
        if (trimmed.empty()) {
          continue;
        }
        const std::size_t colon = trimmed.rfind(':');
        if (colon == std::string::npos) {
          out += "    " + trimmed + ";\n";
          continue;
        }
        const std::string semantic = Trim(trimmed.substr(colon + 1U));
        out += "    " + Trim(trimmed.substr(0U, colon)) + " : " + ModernSemantic(semantic, role) + ";\n";
      }
      return out;
    }

    [[nodiscard]] std::uint32_t AlignUp(const std::uint32_t value, const std::uint32_t alignment) noexcept
    {
      return (value + alignment - 1U) / alignment * alignment;
    }
  } // namespace

  const ConstantSlot* ConstantLayout::Find(const std::uint32_t parameter) const noexcept
  {
    for (const ConstantSlot& slot : slots) {
      if (slot.parameter == parameter) {
        return &slot;
      }
    }
    return nullptr;
  }

  namespace
  {
    struct Placement
    {
      std::uint32_t offset = 0;
      std::uint32_t size = 0;
      std::uint32_t elementStride = 0;
    };

    /**
     * Places one value at `offset` by the HLSL constant-buffer rules: a
     * scalar or vector packs into the current 16-byte register when it fits;
     * arrays, matrices and structs start a register, and array elements each
     * start one. Row-major matrices take one register per row.
     */
    [[nodiscard]] Placement PlaceValue(
      const std::uint32_t offset,
      const ParameterClass parameterClass,
      const std::uint32_t rows,
      const std::uint32_t columns,
      const std::uint32_t elements,
      const bool columnMajor,
      const std::uint32_t structBytes
    )
    {
      std::uint32_t registers = 1U;
      std::uint32_t elementBytes = columns * 4U;
      if (parameterClass == ParameterClass::Matrix) {
        registers = columnMajor ? columns : rows;
        elementBytes = (registers - 1U) * 16U + (columnMajor ? rows : columns) * 4U;
      } else if (parameterClass == ParameterClass::Struct) {
        registers = (structBytes + 15U) / 16U;
        elementBytes = structBytes;
      }

      Placement placement;
      if (elements == 0U && registers == 1U && parameterClass != ParameterClass::Struct) {
        placement.offset = ((offset % 16U) + elementBytes > 16U) ? AlignUp(offset, 16U) : offset;
        placement.size = elementBytes;
        placement.elementStride = 16U;
        return placement;
      }
      placement.offset = AlignUp(offset, 16U);
      placement.elementStride = std::max<std::uint32_t>(registers, 1U) * 16U;
      placement.size = (std::max<std::uint32_t>(elements, 1U) - 1U) * placement.elementStride + elementBytes;
      return placement;
    }
  } // namespace

  ConstantLayout ComputeConstantLayout(const EffectDescription& description)
  {
    ConstantLayout layout;
    std::uint32_t offset = 0U;
    for (std::uint32_t index = 0U; index < description.parameters.size(); ++index) {
      const Parameter& parameter = description.parameters[index];
      ConstantSlot slot;
      slot.parameter = index;
      std::uint32_t structBytes = 0U;
      if (parameter.parameterClass == ParameterClass::Struct) {
        const StructType* const structType = description.FindStruct(parameter.typeName.substr(parameter.typeName.rfind(' ') + 1U));
        if (structType == nullptr) {
          continue;
        }
        for (const StructMember& member : structType->members) {
          if (member.parameterClass != ParameterClass::Scalar && member.parameterClass != ParameterClass::Vector &&
              member.parameterClass != ParameterClass::Matrix) {
            structBytes = 0U;
            break; // nothing the shaders read through $Globals
          }
          const Placement placement =
            PlaceValue(structBytes, member.parameterClass, member.rows, member.columns, member.elements, false, 0U);
          slot.members.push_back(ConstantMember{
            placement.offset,
            placement.size,
            placement.elementStride,
            member.rows,
            member.columns,
            std::max<std::uint32_t>(member.elements, 1U),
            member.parameterClass,
            member.scalarType,
          });
          structBytes = placement.offset + placement.size;
        }
        if (structBytes == 0U) {
          continue;
        }
      } else if (parameter.parameterClass != ParameterClass::Scalar && parameter.parameterClass != ParameterClass::Vector &&
                 parameter.parameterClass != ParameterClass::Matrix) {
        continue;
      }
      const Placement placement = PlaceValue(
        offset, parameter.parameterClass, parameter.rows, parameter.columns, parameter.elements, parameter.columnMajor, structBytes
      );
      slot.offset = placement.offset;
      slot.size = placement.size;
      slot.elementStride = placement.elementStride;
      offset = slot.offset + slot.size;
      layout.slots.push_back(std::move(slot));
    }
    layout.size = offset;
    return layout;
  }

  ModernEffect GenerateModernHlsl(const std::string_view source, EffectDescription& description)
  {
    ModernEffect modern;
    const std::vector<Item> items = SplitItems(source);

    // ---- texture views and sampler registers ----------------------------------
    std::map<std::string, std::vector<TextureDimension>> textureDimensions;
    std::vector<std::vector<TextureDimension>> samplerDimensions;
    for (const SamplerDesc& sampler : description.samplers) {
      samplerDimensions.push_back(SamplerDimensions(sampler, source));
      if (sampler.texture.empty()) {
        continue;
      }
      std::vector<TextureDimension>& dimensions = textureDimensions[sampler.texture];
      for (const TextureDimension dimension : samplerDimensions.back()) {
        if (std::find(dimensions.begin(), dimensions.end(), dimension) == dimensions.end()) {
          dimensions.push_back(dimension);
        }
      }
    }
    std::map<std::pair<std::string, TextureDimension>, std::uint32_t> viewSlots;
    for (const Parameter& parameter : description.parameters) {
      if (parameter.parameterClass != ParameterClass::Texture) {
        continue;
      }
      const auto found = textureDimensions.find(parameter.name);
      if (found == textureDimensions.end()) {
        continue; // never sampled
      }
      for (const TextureDimension dimension : found->second) {
        const std::uint32_t slot = static_cast<std::uint32_t>(modern.textures.size());
        modern.textures.push_back(TextureSlot{parameter.name, dimension, slot});
        viewSlots[{parameter.name, dimension}] = slot;
      }
    }
    if (modern.textures.size() > kMaxTextureSlots) {
      modern.notes.push_back("more texture views than the register budget");
    }
    if (description.samplers.size() > kMaxSamplerSlots) {
      modern.notes.push_back("more samplers than the register budget");
    }

    // ---- parameters a function writes -------------------------------------------
    std::map<std::string, const Parameter*> numericParameters;
    for (const Parameter& parameter : description.parameters) {
      if (parameter.parameterClass == ParameterClass::Scalar || parameter.parameterClass == ParameterClass::Vector ||
          parameter.parameterClass == ParameterClass::Matrix) {
        numericParameters[parameter.name] = &parameter;
      }
    }

    // ---- functions and the roles of their structs --------------------------------
    std::map<std::string, Function> functions;
    for (const Item& item : items) {
      Function function;
      if (item.braced && item.head.find('(') != std::string::npos && !HasTopLevelAssignment(item.head) &&
          ParseFunctionHead(item.head, function) && functions.find(function.name) == functions.end()) {
        functions[function.name] = function;
      }
    }

    std::map<std::string, SemanticRole> structRoles;
    std::set<std::string> vertexInputStructs;
    const auto isStruct = [&](const std::string& name) { return description.FindStruct(name) != nullptr; };
    // Roles belong to the struct definition, typedef'd names included.
    const auto baseStruct = [&](const std::string& name) {
      const StructType* const found = description.FindStruct(name);
      return (found != nullptr && !found->aliasOf.empty()) ? found->aliasOf : name;
    };
    for (const Technique& technique : description.techniques) {
      for (const Pass& pass : technique.passes) {
        for (const auto& [reference, stage] :
             {std::pair{&pass.vertexShader, ShaderStage::Vertex}, std::pair{&pass.pixelShader, ShaderStage::Pixel}}) {
          const auto found = functions.find(reference->function);
          if (found == functions.end()) {
            continue;
          }
          const Function& function = found->second;
          if (stage == ShaderStage::Vertex) {
            if (isStruct(function.returnType)) {
              structRoles.emplace(baseStruct(function.returnType), SemanticRole::VertexOutput);
            }
            for (const std::string& parameter : function.parameters) {
              const ParameterParts parts = SplitParameter(parameter);
              if (!isStruct(parts.type)) {
                continue;
              }
              if (parts.isOut) {
                structRoles.emplace(baseStruct(parts.type), SemanticRole::VertexOutput);
              } else if (!parts.isUniform) {
                vertexInputStructs.insert(baseStruct(parts.type));
              }
            }
          } else {
            if (isStruct(function.returnType)) {
              structRoles[baseStruct(function.returnType)] = SemanticRole::PixelOutput;
            }
            for (const std::string& parameter : function.parameters) {
              const ParameterParts parts = SplitParameter(parameter);
              if (!isStruct(parts.type)) {
                continue;
              }
              if (parts.isOut) {
                structRoles[baseStruct(parts.type)] = SemanticRole::PixelOutput;
              } else if (!parts.isUniform) {
                structRoles.emplace(baseStruct(parts.type), SemanticRole::PixelInput);
              }
            }
          }
        }
      }
    }
    for (const std::string& name : vertexInputStructs) {
      const auto found = structRoles.find(name);
      if (found != structRoles.end() && found->second != SemanticRole::PixelOutput) {
        modern.notes.push_back("struct " + name + " is both a vertex input and a stage output; semantics left as written");
        structRoles.erase(found);
      }
    }

    // ---- the body ---------------------------------------------------------------
    std::string body;
    body.reserve(source.size() + 4096U);
    body += kPrelude;
    if (UseDirect3D9Math()) {
      body += kDirect3D9Math;
    }
    std::size_t cursor = 0U;
    const auto keepGap = [&](const std::size_t until) {
      // Whitespace between items.
      if (until > cursor) {
        body.append(source.substr(cursor, until - cursor));
      }
    };

    for (const Item& item : items) {
      keepGap(item.begin);
      cursor = item.end;
      const std::string& head = item.head;
      const std::string original(source.substr(item.begin, item.end - item.begin));

      if (StartsWithWord(head, "technique") || StartsWithWord(head, "technique10") || StartsWithWord(head, "technique11") ||
          StartsWithWord(head, "BlendState") || StartsWithWord(head, "DepthStencilState") || StartsWithWord(head, "RasterizerState") ||
          StartsWithWord(head, "VertexShader") || StartsWithWord(head, "PixelShader") || StartsWithWord(head, "GeometryShader") ||
          StartsWithWord(head, "string")) {
        continue; // the effect description carries these
      }

      // Sampler states.
      const auto sampler = std::find_if(description.samplers.begin(), description.samplers.end(), [&](const SamplerDesc& candidate) {
        return candidate.begin == item.begin && candidate.end == item.end;
      });
      if (sampler != description.samplers.end()) {
        const std::size_t index = static_cast<std::size_t>(sampler - description.samplers.begin());
        const auto view = [&](const TextureDimension dimension, const char* const placeholder) -> std::string {
          const auto& dimensions = samplerDimensions[index];
          if (sampler->texture.empty() || std::find(dimensions.begin(), dimensions.end(), dimension) == dimensions.end()) {
            return placeholder;
          }
          return sampler->texture + ViewSuffix(dimension);
        };
        char declaration[256]{};
        std::snprintf(declaration, sizeof(declaration), "SamplerState faf_smp_%s : register(s%u);\n", sampler->name.c_str(),
                      static_cast<unsigned>(index));
        body += declaration;
        body += "#define " + sampler->name + " faf_make_sampler(" + view(TextureDimension::Texture2D, "faf_null2D") + ", " +
          view(TextureDimension::TextureCube, "faf_nullCube") + ", " + view(TextureDimension::Texture3D, "faf_null3D") +
          ", faf_smp_" + sampler->name + ")\n";
        continue;
      }

      // Parameters.
      const auto parameter = std::find_if(description.parameters.begin(), description.parameters.end(), [&](const Parameter& candidate) {
        return candidate.begin == item.begin && candidate.end == item.end;
      });
      if (parameter != description.parameters.end()) {
        if (parameter->parameterClass == ParameterClass::Texture) {
          for (const TextureSlot& slot : modern.textures) {
            if (slot.parameter == parameter->name) {
              char declaration[256]{};
              std::snprintf(declaration, sizeof(declaration), "%s %s%s : register(t%u);\n", ViewType(slot.dimension),
                            slot.parameter.c_str(), ViewSuffix(slot.dimension), static_cast<unsigned>(slot.slot));
              body += declaration;
            }
          }
        } else if (numericParameters.count(parameter->name) != 0U || parameter->parameterClass == ParameterClass::Struct) {
          body += GlobalDeclaration(*parameter) + "\n";
        }
        // Anything else (strings, sampler parameters without state) has no shader-side form.
        continue;
      }

      if (!item.braced) {
        // Static globals, typedefs, prototypes.
        body += ReplaceSamplerTypes(original);
        continue;
      }

      if (StartsWithWord(head, "struct")) {
        const std::string name = Trim(head.substr(6U));
        const auto role = structRoles.find(name);
        if (role == structRoles.end()) {
          body += ReplaceSamplerTypes(original);
        } else {
          body += "struct " + name + "\n{\n" + RewriteStructSemantics(ReplaceSamplerTypes(item.body), role->second) + "};";
        }
        continue;
      }

      Function function;
      if (head.find('(') != std::string::npos && !HasTopLevelAssignment(head) && ParseFunctionHead(head, function)) {
        // A function: local copies of the parameters it writes.
        std::string functionBody = item.body;
        std::string copies;
        for (const auto& [name, global] : numericParameters) {
          bool shadowed = false;
          for (const std::string& parameterText : function.parameters) {
            if (SplitParameter(parameterText).name == name) {
              shadowed = true;
            }
          }
          if (shadowed || DeclaresIdentifier(functionBody, name) || !AssignsIdentifier(functionBody, name)) {
            continue;
          }
          functionBody = ReplaceIdentifier(functionBody, name, "faf_local_" + name);
          std::string type = LocalCopyType(*global);
          copies += " " + type + " faf_local_" + name + (global->elements != 0U ? "[" + std::to_string(global->elements) + "]" : "") +
            " = " + name + ";";
        }
        const std::size_t open = original.find('{', original.find(')'));
        body += ReplaceSamplerTypes(original.substr(0U, open)) + "{" + copies + ReplaceSamplerTypes(functionBody) + "}";
        continue;
      }

      // Initializer lists and anything else braced at top level.
      body += ReplaceSamplerTypes(original);
    }
    keepGap(source.size());

    // ---- entry points -------------------------------------------------------------
    std::map<std::tuple<ShaderStage, std::string, std::string>, std::string> entryNames;
    std::string wrappers;
    for (Technique& technique : description.techniques) {
      for (Pass& pass : technique.passes) {
        for (const auto& [reference, stage] :
             {std::pair{&pass.vertexShader, ShaderStage::Vertex}, std::pair{&pass.pixelShader, ShaderStage::Pixel}}) {
          if (reference->function.empty()) {
            continue;
          }
          const std::string arguments = Squeeze(reference->arguments);
          const auto key = std::make_tuple(stage, reference->function, arguments);
          const auto known = entryNames.find(key);
          if (known != entryNames.end()) {
            reference->entry = known->second;
            continue;
          }
          const auto found = functions.find(reference->function);
          if (found == functions.end()) {
            modern.notes.push_back("technique " + technique.name + ": shader function " + reference->function + " not found");
            continue;
          }
          const Function& function = found->second;
          char name[64]{};
          std::snprintf(name, sizeof(name), "faf_entry_%s_%u", stage == ShaderStage::Vertex ? "vs" : "ps",
                        static_cast<unsigned>(modern.entries.size()));

          std::vector<std::string> uniformArguments;
          if (!arguments.empty()) {
            for (const std::string& argument : SplitTopLevel(arguments, ',')) {
              uniformArguments.push_back(Trim(argument));
            }
          }
          std::string parameters;
          std::string callArguments;
          std::size_t nextUniform = 0U;
          std::map<std::string, std::string> inputsBySemantic;
          for (const std::string& parameterText : function.parameters) {
            const ParameterParts parts = SplitParameter(parameterText);
            if (!callArguments.empty()) {
              callArguments += ", ";
            }
            if (parts.isUniform) {
              if (nextUniform < uniformArguments.size()) {
                callArguments += uniformArguments[nextUniform++];
              } else {
                // A uniform parameter the pass leaves out takes its default.
                const std::size_t equals = parameterText.find('=');
                callArguments += (equals != std::string::npos) ? Trim(parameterText.substr(equals + 1U)) : std::string("0");
              }
              continue;
            }
            if (!parts.isOut && !parts.semantic.empty()) {
              // Two inputs on one semantic (mesh.fx reads NORMAL0 as `normal`
              // and NORMAL as `UnusedNormal`): FXC bound both to one
              // register; DXIL refuses the overlap, so the second reads the first.
              const auto [semanticName, semanticIndex] = SplitSemantic(parts.semantic);
              const std::string key = semanticName + (semanticIndex.empty() ? std::string("0") : semanticIndex);
              const auto earlier = inputsBySemantic.find(key);
              if (earlier != inputsBySemantic.end()) {
                callArguments += "(" + parts.type + ")" + earlier->second;
                continue;
              }
              inputsBySemantic.emplace(key, parts.name);
            }
            callArguments += parts.name;
            std::string semantic = parts.semantic;
            if (!semantic.empty()) {
              const SemanticRole role = (stage == ShaderStage::Vertex) ? SemanticRole::VertexOutput
                : parts.isOut                                          ? SemanticRole::PixelOutput
                                                                       : SemanticRole::PixelInput;
              if (stage == ShaderStage::Pixel || parts.isOut) {
                semantic = ModernSemantic(semantic, role);
              }
            }
            if (!parameters.empty()) {
              parameters += ", ";
            }
            parameters += parts.modifiers + ReplaceSamplerTypes(parts.type) + " " + parts.name + parts.suffix +
              (semantic.empty() ? std::string() : " : " + semantic);
          }
          std::string returnSemantic = function.semantic;
          if (!returnSemantic.empty()) {
            returnSemantic =
              ModernSemantic(returnSemantic, stage == ShaderStage::Vertex ? SemanticRole::VertexOutput : SemanticRole::PixelOutput);
          }
          const bool returnsVoid = (function.returnType == "void");
          // Diagnostics (FAF_GAL_NAN_CHECK): a struct output is checked on its
          // first member when that is the float4 colour.
          std::string checkedMember;
          if (stage == ShaderStage::Pixel && NanCheckRequested() && function.returnType != "float4") {
            for (const StructType& type : description.structs) {
              if (type.name == function.returnType && !type.members.empty() && type.members.front().typeName == "float4") {
                checkedMember = type.members.front().name;
              }
            }
          }
          if (!checkedMember.empty()) {
            wrappers += function.returnType + " " + name + "(" + parameters + ")" +
              (returnSemantic.empty() ? std::string() : " : " + returnSemantic) + "\n{\n    " + function.returnType +
              " faf_output = " + function.name + "(" + callArguments + ");\n    if (any(isnan(faf_output." + checkedMember +
              ")) || any(isinf(faf_output." + checkedMember + "))) faf_output." + checkedMember +
              " = float4(1, 0, 1, 1);\n    return faf_output;\n}\n";
          } else if (stage == ShaderStage::Pixel && function.returnType == "float4" && NanCheckRequested()) {
            // Diagnostics: a pixel whose colour is NaN or infinite turns magenta.
            wrappers += function.returnType + " " + name + "(" + parameters + ")" +
              (returnSemantic.empty() ? std::string() : " : " + returnSemantic) + "\n{\n    float4 faf_colour = " + function.name +
              "(" + callArguments + ");\n    return (any(isnan(faf_colour)) || any(isinf(faf_colour))) ? float4(1, 0, 1, 1) : faf_colour;\n}\n";
          } else {
            wrappers += function.returnType + " " + name + "(" + parameters + ")" +
              (returnSemantic.empty() ? std::string() : " : " + returnSemantic) + "\n{\n    " + (returnsVoid ? "" : "return ") +
              function.name + "(" + callArguments + ");\n}\n";
          }

          modern.entries.push_back(ShaderEntry{stage, function.name, arguments, name});
          entryNames.emplace(key, name);
          reference->entry = name;
        }
      }
    }

    modern.hlsl = std::move(body);
    modern.hlsl += "\n// ---- entry points (generated) ----\n";
    modern.hlsl += wrappers;
    modern.constants = ComputeConstantLayout(description);
    return modern;
  }
} // namespace gpg::gal::effects
