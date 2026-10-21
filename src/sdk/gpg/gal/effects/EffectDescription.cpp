// FAF addition, not in the shipped binary: see EffectDescription.h.

#include "EffectDescription.h"
#include "EffectText.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <map>
#include <stdexcept>
#include <utility>

namespace gpg::gal::effects
{
  using namespace text;

  namespace
  {
    [[nodiscard]] Annotations ParseAnnotations(std::string_view body)
    {
      Annotations annotations;
      for (const std::string& rawStatement : SplitTopLevel(body, ';')) {
        const std::string statement = Trim(rawStatement);
        const std::size_t equals = statement.find('=');
        if (statement.empty() || equals == std::string::npos) {
          continue;
        }
        const std::string declaration = Trim(statement.substr(0U, equals));
        const std::string value = Trim(statement.substr(equals + 1U));
        const std::size_t space = declaration.rfind(' ');
        if (space == std::string::npos) {
          continue;
        }
        Annotation annotation;
        annotation.name = declaration.substr(space + 1U);
        const std::string type = Lower(declaration.substr(0U, space));
        if (type == "string") {
          annotation.kind = Annotation::Kind::String;
          const std::size_t first = value.find('"');
          const std::size_t last = value.rfind('"');
          annotation.text = (first != std::string::npos && last > first) ? value.substr(first + 1U, last - first - 1U) : value;
        } else {
          double folded = 0.0;
          if (EvaluateConstant(value, folded)) {
            annotation.number = folded;
          } else {
            const std::vector<float> numbers = ParseNumbers(value);
            annotation.number = numbers.empty() ? 0.0 : numbers.front();
          }
          annotation.kind = (type == "bool") ? Annotation::Kind::Bool
            : (type == "int" || type == "uint" || type == "dword") ? Annotation::Kind::Int
                                                                   : Annotation::Kind::Float;
          annotation.text = value;
        }
        annotations.push_back(std::move(annotation));
      }
      return annotations;
    }

    // ---------------------------------------------------------------------
    // Enumerators of the FX state assignments

    [[nodiscard]] std::string EnumKey(std::string_view value)
    {
      std::string key = Lower(Trim(value));
      for (const char* const prefix : {"d3d10_blend_op_", "d3d10_blend_", "d3d10_comparison_", "d3d10_stencil_op_", "d3d11_blend_op_",
                                       "d3d11_blend_", "d3d11_comparison_", "d3d11_stencil_op_"}) {
        if (key.rfind(prefix, 0U) == 0U) {
          key.erase(0U, std::char_traits<char>::length(prefix));
        }
      }
      key.erase(std::remove(key.begin(), key.end(), '_'), key.end());
      return key;
    }

    [[nodiscard]] bool ParseBool(std::string_view value, const bool fallback)
    {
      const std::string key = EnumKey(value);
      if (key == "true" || key == "1") {
        return true;
      }
      if (key == "false" || key == "0") {
        return false;
      }
      return fallback;
    }

    [[nodiscard]] std::uint32_t ParseUnsigned(std::string_view value, const std::uint32_t fallback)
    {
      // Integers directly: a float cannot hold 0xFFFFFFFF (the sample masks).
      const std::string text = Trim(value);
      if (!text.empty() && std::isdigit(static_cast<unsigned char>(text[0])) != 0) {
        char* end = nullptr;
        const unsigned long long parsed = std::strtoull(text.c_str(), &end, 0);
        if (end != nullptr && end != text.c_str()) {
          return static_cast<std::uint32_t>(parsed);
        }
      }
      const std::vector<float> numbers = ParseNumbers(value);
      return numbers.empty() ? fallback : static_cast<std::uint32_t>(numbers.front());
    }

    [[nodiscard]] std::uint8_t ParseBlend(std::string_view value, const std::uint8_t fallback)
    {
      static const std::map<std::string, std::uint8_t> kValues = {
        {"zero", 1}, {"one", 2}, {"srccolor", 3}, {"invsrccolor", 4}, {"srcalpha", 5}, {"invsrcalpha", 6},
        {"destalpha", 7}, {"invdestalpha", 8}, {"destcolor", 9}, {"invdestcolor", 10}, {"srcalphasat", 11},
        {"blendfactor", 14}, {"invblendfactor", 15},
      };
      const auto found = kValues.find(EnumKey(value));
      return (found != kValues.end()) ? found->second : fallback;
    }

    [[nodiscard]] std::uint8_t ParseBlendOp(std::string_view value, const std::uint8_t fallback)
    {
      static const std::map<std::string, std::uint8_t> kValues = {
        {"add", 1}, {"subtract", 2}, {"revsubtract", 3}, {"min", 4}, {"max", 5},
      };
      const auto found = kValues.find(EnumKey(value));
      return (found != kValues.end()) ? found->second : fallback;
    }

    [[nodiscard]] std::uint8_t ParseComparison(std::string_view value, const std::uint8_t fallback)
    {
      static const std::map<std::string, std::uint8_t> kValues = {
        {"never", 1}, {"less", 2}, {"equal", 3}, {"lessequal", 4}, {"greater", 5}, {"notequal", 6}, {"greaterequal", 7}, {"always", 8},
      };
      const auto found = kValues.find(EnumKey(value));
      return (found != kValues.end()) ? found->second : fallback;
    }

    [[nodiscard]] std::uint8_t ParseStencilOp(std::string_view value, const std::uint8_t fallback)
    {
      static const std::map<std::string, std::uint8_t> kValues = {
        {"keep", 1}, {"zero", 2}, {"replace", 3}, {"incrsat", 4}, {"decrsat", 5}, {"invert", 6}, {"incr", 7}, {"decr", 8},
      };
      const auto found = kValues.find(EnumKey(value));
      return (found != kValues.end()) ? found->second : fallback;
    }

    [[nodiscard]] std::uint8_t ParseAddress(std::string_view value, const std::uint8_t fallback)
    {
      static const std::map<std::string, std::uint8_t> kValues = {
        {"wrap", 1}, {"mirror", 2}, {"clamp", 3}, {"border", 4}, {"mirroronce", 5},
      };
      const auto found = kValues.find(EnumKey(value));
      return (found != kValues.end()) ? found->second : fallback;
    }

    [[nodiscard]] std::uint32_t ParseFilter(std::string_view value, const std::uint32_t fallback)
    {
      static const std::map<std::string, std::uint32_t> kValues = {
        {"minmagmippoint", 0x00}, {"minmagpointmiplinear", 0x01}, {"minpointmaglinearmippoint", 0x04},
        {"minpointmagmiplinear", 0x05}, {"minlinearmagmippoint", 0x10}, {"minlinearmagpointmiplinear", 0x11},
        {"minmaglinearmippoint", 0x14}, {"minmagmiplinear", 0x15}, {"anisotropic", 0x55},
        {"comparisonminmagmippoint", 0x80}, {"comparisonminmagmiplinear", 0x95}, {"comparisonanisotropic", 0xD5},
      };
      const auto found = kValues.find(EnumKey(value));
      return (found != kValues.end()) ? found->second : fallback;
    }

    /** "BlendEnable [ 0 ]" -> ("blendenable", 0). */
    [[nodiscard]] std::pair<std::string, int> FieldName(std::string_view field)
    {
      std::string compact;
      for (const char c : field) {
        if (std::isspace(static_cast<unsigned char>(c)) == 0) {
          compact.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
      }
      int index = 0;
      const std::size_t bracket = compact.find('[');
      if (bracket != std::string::npos) {
        index = std::atoi(compact.c_str() + bracket + 1U);
        compact.erase(bracket);
      }
      return {compact, index};
    }

    template <class Apply>
    void ForEachAssignment(std::string_view body, Apply&& apply)
    {
      for (const std::string& rawStatement : SplitTopLevel(body, ';')) {
        const std::string statement = Trim(rawStatement);
        const std::size_t equals = statement.find('=');
        if (statement.empty() || equals == std::string::npos) {
          continue;
        }
        const auto [field, index] = FieldName(statement.substr(0U, equals));
        apply(field, index, Trim(statement.substr(equals + 1U)));
      }
    }

    // Diagnostics: FAF_GAL_D3D10_ALPHA_BLEND=1 keeps the state packs' alpha blend.
    [[nodiscard]] bool UseDirect3D9AlphaBlend() noexcept
    {
      static const bool keepPacks = [] {
        const char* const value = std::getenv("FAF_GAL_D3D10_ALPHA_BLEND");
        return value != nullptr && value[0] == '1';
      }();
      return !keepPacks;
    }

    /** The alpha-channel form of a colour blend factor (D3D11/12 enumerators). */
    [[nodiscard]] std::uint8_t AlphaFactor(const std::uint8_t factor) noexcept
    {
      switch (factor) {
      case 3: // SRC_COLOR
        return 5; // SRC_ALPHA
      case 4: // INV_SRC_COLOR
        return 6; // INV_SRC_ALPHA
      case 9: // DEST_COLOR
        return 7; // DEST_ALPHA
      case 10: // INV_DEST_COLOR
        return 8; // INV_DEST_ALPHA
      case 16: // SRC1_COLOR
        return 18; // SRC1_ALPHA
      case 17: // INV_SRC1_COLOR
        return 19; // INV_SRC1_ALPHA
      default:
        return factor;
      }
    }

    // Unset fields of an FX state object take the Direct3D 10 defaults.
    [[nodiscard]] BlendDesc ParseBlendState(std::string_view body)
    {
      BlendDesc desc{};
      ForEachAssignment(body, [&](const std::string& field, const int index, const std::string& value) {
        if (field == "alphatocoverageenable") {
          desc.alphaToCoverage = ParseBool(value, false);
        } else if (field == "blendenable" && index == 0) {
          desc.enable = ParseBool(value, false);
        } else if (field == "srcblend") {
          desc.srcBlend = ParseBlend(value, desc.srcBlend);
        } else if (field == "destblend") {
          desc.destBlend = ParseBlend(value, desc.destBlend);
        } else if (field == "blendop") {
          desc.blendOp = ParseBlendOp(value, desc.blendOp);
        } else if (field == "srcblendalpha") {
          desc.srcBlendAlpha = ParseBlend(value, desc.srcBlendAlpha);
        } else if (field == "destblendalpha") {
          desc.destBlendAlpha = ParseBlend(value, desc.destBlendAlpha);
        } else if (field == "blendopalpha") {
          desc.blendOpAlpha = ParseBlendOp(value, desc.blendOpAlpha);
        } else if (field == "rendertargetwritemask" && index == 0) {
          desc.writeMask = static_cast<std::uint8_t>(ParseUnsigned(value, 0x0F) & 0x0FU);
        }
      });
      if (UseDirect3D9AlphaBlend()) {
        // Direct3D 9 had separate alpha blending off: the alpha channel blends
        // with the colour factors. d3d10states.compat writes SrcBlendAlpha =
        // ONE, DestBlendAlpha = ZERO into every state, which replaces the
        // target's alpha with the source alpha. The frame's alpha is the glow
        // mask, so an additive light quad then lit up its whole rectangle.
        desc.srcBlendAlpha = AlphaFactor(desc.srcBlend);
        desc.destBlendAlpha = AlphaFactor(desc.destBlend);
        desc.blendOpAlpha = desc.blendOp;
      }
      return desc;
    }

    [[nodiscard]] DepthStencilDesc ParseDepthStencilState(std::string_view body)
    {
      DepthStencilDesc desc{};
      desc.depthFunc = 2; // LESS
      ForEachAssignment(body, [&](const std::string& field, int, const std::string& value) {
        if (field == "depthenable") {
          desc.depthEnable = ParseBool(value, true);
        } else if (field == "depthwritemask") {
          const std::string key = EnumKey(value);
          desc.depthWrite = !(key == "zero" || key == "0" || key == "false");
        } else if (field == "depthfunc") {
          desc.depthFunc = ParseComparison(value, desc.depthFunc);
        } else if (field == "stencilenable") {
          desc.stencilEnable = ParseBool(value, false);
        } else if (field == "stencilreadmask") {
          desc.stencilReadMask = static_cast<std::uint8_t>(ParseUnsigned(value, 0xFF));
        } else if (field == "stencilwritemask") {
          desc.stencilWriteMask = static_cast<std::uint8_t>(ParseUnsigned(value, 0xFF));
        } else if (field == "frontfacestencilfail") {
          desc.front.failOp = ParseStencilOp(value, desc.front.failOp);
        } else if (field == "frontfacestencildepthfail") {
          desc.front.depthFailOp = ParseStencilOp(value, desc.front.depthFailOp);
        } else if (field == "frontfacestencilpass") {
          desc.front.passOp = ParseStencilOp(value, desc.front.passOp);
        } else if (field == "frontfacestencilfunc") {
          desc.front.func = ParseComparison(value, desc.front.func);
        } else if (field == "backfacestencilfail") {
          desc.back.failOp = ParseStencilOp(value, desc.back.failOp);
        } else if (field == "backfacestencildepthfail") {
          desc.back.depthFailOp = ParseStencilOp(value, desc.back.depthFailOp);
        } else if (field == "backfacestencilpass") {
          desc.back.passOp = ParseStencilOp(value, desc.back.passOp);
        } else if (field == "backfacestencilfunc") {
          desc.back.func = ParseComparison(value, desc.back.func);
        }
      });
      return desc;
    }

    [[nodiscard]] RasterizerDesc ParseRasterizerState(std::string_view body)
    {
      RasterizerDesc desc{};
      desc.depthClipEnable = true;
      desc.multisampleEnable = false;
      ForEachAssignment(body, [&](const std::string& field, int, const std::string& value) {
        const std::string key = EnumKey(value);
        if (field == "fillmode") {
          desc.fillMode = (key == "wireframe") ? 2 : 3;
        } else if (field == "cullmode") {
          desc.cullMode = (key == "none") ? 1 : (key == "front") ? 2 : 3;
        } else if (field == "frontcounterclockwise") {
          desc.frontCounterClockwise = ParseBool(value, false);
        } else if (field == "depthbias") {
          double bias = 0.0;
          if (!EvaluateConstant(value, bias)) {
            const std::vector<float> numbers = ParseNumbers(value);
            bias = numbers.empty() ? 0.0 : numbers.front();
          }
          // d3d10states.compat carries D3D9's DEPTHBIAS values (-0.02,
          // -0.00001 ...), a fraction of the depth range. Direct3D 10+ takes
          // an integer count of depth steps, so the effect compiler turned
          // them into 0 and the biased decals z-fought the terrain. A fraction
          // is converted as D3D9 meant it, in 24-bit depth steps.
          if (bias != 0.0 && bias > -1.0 && bias < 1.0) {
            bias *= 16777216.0;
          }
          desc.depthBias = static_cast<std::int32_t>(bias < 0.0 ? bias - 0.5 : bias + 0.5);
        } else if (field == "depthbiasclamp") {
          const std::vector<float> numbers = ParseNumbers(value);
          desc.depthBiasClamp = numbers.empty() ? 0.0f : numbers.front();
        } else if (field == "slopescaleddepthbias") {
          const std::vector<float> numbers = ParseNumbers(value);
          desc.slopeScaledDepthBias = numbers.empty() ? 0.0f : numbers.front();
        } else if (field == "depthclipenable") {
          desc.depthClipEnable = ParseBool(value, true);
        } else if (field == "scissorenable") {
          desc.scissorEnable = ParseBool(value, false);
        } else if (field == "multisampleenable") {
          desc.multisampleEnable = ParseBool(value, false);
        } else if (field == "antialiasedlineenable") {
          desc.antialiasedLineEnable = ParseBool(value, false);
        }
      });
      return desc;
    }

    void ParseSamplerState(std::string_view body, SamplerDesc& desc)
    {
      ForEachAssignment(body, [&](const std::string& field, int, const std::string& value) {
        if (field == "texture") {
          std::string name;
          for (const char c : value) {
            if (IsIdentifierChar(c)) {
              name.push_back(c);
            }
          }
          desc.texture = name;
        } else if (field == "filter") {
          desc.filter = ParseFilter(value, desc.filter);
        } else if (field == "addressu") {
          desc.addressU = ParseAddress(value, desc.addressU);
        } else if (field == "addressv") {
          desc.addressV = ParseAddress(value, desc.addressV);
        } else if (field == "addressw") {
          desc.addressW = ParseAddress(value, desc.addressW);
        } else if (field == "maxanisotropy") {
          desc.maxAnisotropy = ParseUnsigned(value, 1U);
        } else if (field == "miplodbias") {
          const std::vector<float> numbers = ParseNumbers(value);
          desc.mipLodBias = numbers.empty() ? 0.0f : numbers.front();
        } else if (field == "minlod") {
          const std::vector<float> numbers = ParseNumbers(value);
          desc.minLod = numbers.empty() ? 0.0f : numbers.front();
        } else if (field == "maxlod") {
          const std::vector<float> numbers = ParseNumbers(value);
          if (!numbers.empty()) {
            desc.maxLod = numbers.front();
          }
        } else if (field == "bordercolor") {
          const std::vector<float> numbers = ParseNumbers(value);
          for (std::size_t index = 0U; index < 4U && index < numbers.size(); ++index) {
            desc.borderColor[index] = numbers[index];
          }
        }
      });
    }

    // ---------------------------------------------------------------------
    // Parameter types

    struct TypeInfo
    {
      ParameterClass parameterClass = ParameterClass::Other;
      ScalarType scalarType = ScalarType::Float;
      std::uint32_t rows = 1;
      std::uint32_t columns = 1;
    };

    [[nodiscard]] TypeInfo ParseType(const std::string& typeName, const std::vector<std::string>& structs)
    {
      TypeInfo info{};
      std::string base = Lower(typeName);
      for (const char* const modifier : {"row_major ", "column_major ", "uniform ", "shared ", "volatile ", "extern ", "const ", "static "}) {
        std::size_t position;
        while ((position = base.find(modifier)) != std::string::npos) {
          base.erase(position, std::char_traits<char>::length(modifier));
        }
      }
      base = Trim(base);
      if (base == "texture" || base == "texture1d" || base == "texture2d" || base == "texture3d" || base == "texturecube") {
        info.parameterClass = ParameterClass::Texture;
        return info;
      }
      if (std::find(structs.begin(), structs.end(), typeName) != structs.end()) {
        info.parameterClass = ParameterClass::Struct;
        return info;
      }
      const std::pair<const char*, ScalarType> scalars[] = {
        {"float", ScalarType::Float}, {"half", ScalarType::Float}, {"double", ScalarType::Float}, {"int", ScalarType::Int},
        {"uint", ScalarType::Uint}, {"dword", ScalarType::Uint}, {"bool", ScalarType::Bool},
      };
      for (const auto& [name, scalar] : scalars) {
        const std::size_t length = std::char_traits<char>::length(name);
        if (base.rfind(name, 0U) != 0U) {
          continue;
        }
        const std::string dims = base.substr(length);
        info.scalarType = scalar;
        if (dims.empty()) {
          info.parameterClass = ParameterClass::Scalar;
        } else if (dims.size() == 1U && std::isdigit(static_cast<unsigned char>(dims[0])) != 0) {
          info.parameterClass = ParameterClass::Vector;
          info.columns = static_cast<std::uint32_t>(dims[0] - '0');
        } else if (dims.size() == 3U && dims[1] == 'x') {
          info.parameterClass = ParameterClass::Matrix;
          info.rows = static_cast<std::uint32_t>(dims[0] - '0');
          info.columns = static_cast<std::uint32_t>(dims[2] - '0');
        } else {
          continue;
        }
        return info;
      }
      if (base == "matrix") {
        info.parameterClass = ParameterClass::Matrix;
        info.rows = 4U;
        info.columns = 4U;
      } else if (base == "vector") {
        info.parameterClass = ParameterClass::Vector;
        info.columns = 4U;
      }
      return info;
    }

    [[nodiscard]] std::pair<std::string, Annotations> NameAndAnnotations(const std::string& text)
    {
      const std::size_t open = text.find('<');
      if (open == std::string::npos) {
        return {Trim(text), {}};
      }
      const std::size_t close = Matching(text, open);
      Annotations annotations =
        (close != std::string::npos) ? ParseAnnotations(std::string_view(text).substr(open + 1U, close - open - 1U)) : Annotations{};
      return {Trim(text.substr(0U, open)), std::move(annotations)};
    }

    /** "compile vs_4_1 Function ( a , b )" or "CompileShader ( vs_4_0 , Function ( ) )". */
    [[nodiscard]] ShaderReference ParseShaderReference(const std::string& value)
    {
      ShaderReference reference;
      std::string text = Trim(value);
      if (StartsWithWord(text, "CompileShader")) {
        const std::size_t open = text.find('(');
        const std::size_t close = Matching(text, open);
        const std::vector<std::string> parts = SplitTopLevel(std::string_view(text).substr(open + 1U, close - open - 1U), ',');
        text = (parts.size() >= 2U) ? "compile " + Trim(parts[0]) + " " + Trim(parts[1]) : std::string();
      }
      if (!StartsWithWord(text, "compile")) {
        return reference; // NULL
      }
      std::size_t position = text.find(' ', 8U); // past the profile
      if (position == std::string::npos) {
        return reference;
      }
      const std::string call = Trim(text.substr(position + 1U));
      const std::size_t open = call.find('(');
      if (open == std::string::npos) {
        reference.function = call;
        return reference;
      }
      reference.function = Trim(call.substr(0U, open));
      const std::size_t close = Matching(call, open);
      reference.arguments = Trim(call.substr(open + 1U, (close == std::string::npos ? call.size() : close) - open - 1U));
      return reference;
    }
  } // namespace

  const Annotation* FindAnnotation(const Annotations& annotations, const std::string_view name) noexcept
  {
    for (const Annotation& annotation : annotations) {
      if (annotation.name == name) {
        return &annotation;
      }
    }
    return nullptr;
  }

  const Parameter* EffectDescription::FindParameter(const std::string_view name) const noexcept
  {
    for (const Parameter& parameter : parameters) {
      if (parameter.name == name) {
        return &parameter;
      }
    }
    return nullptr;
  }

  const StructType* EffectDescription::FindStruct(const std::string_view name) const noexcept
  {
    for (const StructType& structType : structs) {
      if (structType.name == name) {
        return &structType;
      }
    }
    return nullptr;
  }

  const Technique* EffectDescription::FindTechnique(const std::string_view name) const noexcept
  {
    for (const Technique& technique : techniques) {
      if (technique.name == name) {
        return &technique;
      }
    }
    return nullptr;
  }

  EffectDescription ParseEffect(const std::string_view source)
  {
    EffectDescription effect;
    const std::vector<Item> items = SplitItems(source);

    std::vector<std::string> structs;
    std::map<std::string, BlendDesc> blendStates;
    std::map<std::string, DepthStencilDesc> depthStencilStates;
    std::map<std::string, RasterizerDesc> rasterizerStates;
    std::vector<const Item*> techniques;

    for (const Item& item : items) {
      const std::string& head = item.head;
      if (StartsWithWord(head, "struct")) {
        StructType structType;
        structType.name = Trim(head.substr(6U));
        structs.push_back(structType.name);
        for (const std::string& rawMember : SplitTopLevel(item.body, ';')) {
          std::string member = Squeeze(rawMember);
          const std::size_t colon = member.find(':');
          if (colon != std::string::npos) {
            member = Trim(member.substr(0U, colon));
          }
          if (member.empty()) {
            continue;
          }
          StructMember structMember;
          const std::size_t bracket = member.find('[');
          if (bracket != std::string::npos) {
            const std::vector<float> size = ParseNumbers(member.substr(bracket));
            structMember.elements = size.empty() ? 0U : static_cast<std::uint32_t>(size.front());
            member = Trim(member.substr(0U, bracket));
          }
          const std::size_t space = member.rfind(' ');
          if (space == std::string::npos) {
            continue;
          }
          structMember.name = member.substr(space + 1U);
          structMember.typeName = Trim(member.substr(0U, space));
          const TypeInfo info = ParseType(structMember.typeName, structs);
          structMember.parameterClass = info.parameterClass;
          structMember.scalarType = info.scalarType;
          structMember.rows = info.rows;
          structMember.columns = info.columns;
          structType.members.push_back(std::move(structMember));
        }
        effect.structs.push_back(std::move(structType));
        continue;
      }
      if (StartsWithWord(head, "typedef")) {
        const std::size_t space = head.rfind(' ');
        const std::string alias = head.substr(space + 1U);
        const std::string target = Trim(head.substr(7U, space - 7U));
        structs.push_back(alias); // treated like a struct: not a writable parameter
        if (const StructType* const base = effect.FindStruct(target)) {
          StructType copy = *base;
          copy.name = alias;
          copy.aliasOf = base->aliasOf.empty() ? base->name : base->aliasOf;
          effect.structs.push_back(std::move(copy));
        }
        continue;
      }
      if (StartsWithWord(head, "technique10") || StartsWithWord(head, "technique11") || StartsWithWord(head, "technique")) {
        techniques.push_back(&item);
        continue;
      }
      if (item.braced && StartsWithWord(head, "BlendState")) {
        blendStates[NameAndAnnotations(head.substr(10U)).first] = ParseBlendState(item.body);
        continue;
      }
      if (item.braced && StartsWithWord(head, "DepthStencilState")) {
        depthStencilStates[NameAndAnnotations(head.substr(17U)).first] = ParseDepthStencilState(item.body);
        continue;
      }
      if (item.braced && StartsWithWord(head, "RasterizerState")) {
        rasterizerStates[NameAndAnnotations(head.substr(15U)).first] = ParseRasterizerState(item.body);
        continue;
      }
      if (item.braced && (head.find("sampler_state") != std::string::npos || StartsWithWord(head, "SamplerState") ||
                          StartsWithWord(head, "sampler2D") || StartsWithWord(head, "sampler") || StartsWithWord(head, "samplerCUBE") ||
                          StartsWithWord(head, "sampler3D") || StartsWithWord(head, "sampler1D"))) {
        SamplerDesc sampler;
        std::string declaration = head;
        const std::size_t equals = declaration.find('=');
        if (equals != std::string::npos) {
          declaration = Trim(declaration.substr(0U, equals));
        }
        const std::size_t space = declaration.find(' ');
        const std::string type = Lower(declaration.substr(0U, space));
        sampler.name = NameAndAnnotations(declaration.substr(space + 1U)).first;
        sampler.declaredType = declaration.substr(0U, space);
        sampler.begin = item.begin;
        sampler.end = item.end;
        sampler.kind = (type == "samplercube") ? SamplerDesc::Kind::TextureCube
          : (type == "sampler3d")              ? SamplerDesc::Kind::Texture3D
                                               : SamplerDesc::Kind::Texture2D;
        ParseSamplerState(item.body, sampler);
        effect.samplers.push_back(std::move(sampler));
        continue;
      }
      const bool initializerList = item.braced && HasTopLevelAssignment(head) && head.find("sampler_state") == std::string::npos;
      if (item.braced && !initializerList) {
        continue; // a function, cbuffer or anything else with a body
      }

      // A variable declaration: [modifiers] type name [N] [: semantic] [<annotations>] [= initializer]
      std::string declaration = initializerList ? head + " { " + item.body + " }" : head;
      std::string initializer;
      {
        // The first '=' outside an annotation block.
        int angle = 0;
        for (std::size_t index = 0U; index < declaration.size(); ++index) {
          if (declaration[index] == '<') {
            ++angle;
          } else if (declaration[index] == '>') {
            --angle;
          } else if (declaration[index] == '=' && angle == 0) {
            initializer = Trim(declaration.substr(index + 1U));
            declaration = Trim(declaration.substr(0U, index));
            break;
          }
        }
      }
      auto [declarator, annotations] = NameAndAnnotations(declaration);
      if (declarator.find('(') != std::string::npos) {
        continue; // a function declaration
      }
      const std::size_t colon = declarator.find(':');
      if (colon != std::string::npos) {
        declarator = Trim(declarator.substr(0U, colon));
      }
      std::uint32_t elements = 0U;
      const std::size_t bracket = declarator.find('[');
      if (bracket != std::string::npos) {
        const std::vector<float> size = ParseNumbers(declarator.substr(bracket));
        elements = size.empty() ? 0U : static_cast<std::uint32_t>(size.front());
        declarator = Trim(declarator.substr(0U, bracket));
      }
      const std::size_t space = declarator.rfind(' ');
      if (space == std::string::npos) {
        continue;
      }
      const std::string typeName = Trim(declarator.substr(0U, space));
      // `const` globals stay parameters (in $Globals, with their initializer
      // as the default), as in the Direct3D 9 effect framework.
      if (StartsWithWord(typeName, "static") || typeName.find(" static ") != std::string::npos) {
        continue;
      }
      Parameter parameter;
      parameter.name = Trim(declarator.substr(space + 1U));
      parameter.typeName = typeName;
      const TypeInfo info = ParseType(typeName, structs);
      parameter.parameterClass = info.parameterClass;
      parameter.scalarType = info.scalarType;
      parameter.rows = info.rows;
      parameter.columns = info.columns;
      parameter.elements = elements;
      parameter.columnMajor = ContainsIdentifier(typeName, "column_major");
      parameter.annotations = std::move(annotations);
      parameter.begin = item.begin;
      parameter.end = item.end;
      if (!initializer.empty() && parameter.parameterClass != ParameterClass::Texture) {
        parameter.defaults = ParseNumbers(initializer);
      }
      if (bracket != std::string::npos && elements == 0U) {
        // `float k[] = { ... }`: the initializer sizes the array.
        parameter.unsized = true;
        const std::size_t perElement = static_cast<std::size_t>(info.rows) * info.columns;
        parameter.elements = static_cast<std::uint32_t>((parameter.defaults.size() + perElement - 1U) / perElement);
      }
      effect.parameters.push_back(std::move(parameter));
    }

    for (const Item* const item : techniques) {
      Technique technique;
      std::string head = item->head;
      head = Trim(head.substr(head.find(' ') == std::string::npos ? head.size() : head.find(' ')));
      auto [name, annotations] = NameAndAnnotations(head);
      technique.name = name;
      technique.annotations = std::move(annotations);

      for (const Item& passItem : SplitItems(item->body)) {
        if (!passItem.braced || !StartsWithWord(passItem.head, "pass")) {
          continue;
        }
        Pass pass;
        auto [passName, passAnnotations] = NameAndAnnotations(passItem.head.substr(4U));
        pass.name = passName;
        pass.annotations = std::move(passAnnotations);

        for (const std::string& rawStatement : SplitTopLevel(passItem.body, ';')) {
          const std::string statement = Squeeze(rawStatement);
          if (statement.empty()) {
            continue;
          }
          const std::size_t open = statement.find('(');
          const std::string call = Trim(statement.substr(0U, open));
          if (open != std::string::npos && (call == "SetBlendState" || call == "SetDepthStencilState" || call == "SetRasterizerState" ||
                                            call == "SetVertexShader" || call == "SetPixelShader" || call == "SetGeometryShader")) {
            const std::size_t close = Matching(statement, open);
            const std::vector<std::string> arguments =
              SplitTopLevel(std::string_view(statement).substr(open + 1U, close - open - 1U), ',');
            const std::string object = arguments.empty() ? std::string() : Trim(arguments[0]);
            if (call == "SetBlendState") {
              const auto found = blendStates.find(object);
              if (found != blendStates.end()) {
                pass.blend = found->second;
              } else {
                effect.notes.push_back("technique " + technique.name + ": unknown blend state " + object);
              }
              if (arguments.size() > 1U) {
                const std::vector<float> factor = ParseNumbers(arguments[1]);
                for (std::size_t index = 0U; index < 4U && index < factor.size(); ++index) {
                  pass.blendFactor[index] = factor[index];
                }
              }
              if (arguments.size() > 2U) {
                pass.sampleMask = ParseUnsigned(arguments[2], 0xFFFFFFFFU);
              }
            } else if (call == "SetDepthStencilState") {
              const auto found = depthStencilStates.find(object);
              if (found != depthStencilStates.end()) {
                pass.depthStencil = found->second;
              } else {
                effect.notes.push_back("technique " + technique.name + ": unknown depth-stencil state " + object);
              }
              if (arguments.size() > 1U) {
                pass.stencilRef = ParseUnsigned(arguments[1], 0U);
              }
            } else if (call == "SetRasterizerState") {
              const auto found = rasterizerStates.find(object);
              if (found != rasterizerStates.end()) {
                pass.rasterizer = found->second;
              } else {
                effect.notes.push_back("technique " + technique.name + ": unknown rasterizer state " + object);
              }
            } else if (call == "SetVertexShader") {
              pass.vertexShader = ParseShaderReference(object);
            } else if (call == "SetPixelShader") {
              pass.pixelShader = ParseShaderReference(object);
            }
            continue;
          }
          const std::size_t equals = statement.find('=');
          if (equals == std::string::npos) {
            continue;
          }
          const std::string target = Lower(Trim(statement.substr(0U, equals)));
          if (target == "vertexshader") {
            pass.vertexShader = ParseShaderReference(statement.substr(equals + 1U));
          } else if (target == "pixelshader") {
            pass.pixelShader = ParseShaderReference(statement.substr(equals + 1U));
          } else {
            effect.notes.push_back("technique " + technique.name + ": pass statement ignored: " + statement);
          }
        }
        technique.passes.push_back(std::move(pass));
      }
      effect.techniques.push_back(std::move(technique));
    }
    return effect;
  }

  namespace
  {
    constexpr std::string_view kWhitespace = " \t\r\n";

    /** The source with comments and preprocessor lines (and their continuations) blanked out. */
    [[nodiscard]] std::string WithoutCommentsAndDirectives(const std::string_view source)
    {
      std::string text(source);
      for (std::size_t index = 0U; index < text.size(); ++index) {
        if (text[index] == '"') {
          const std::size_t close = text.find('"', index + 1U);
          index = (close == std::string::npos) ? text.size() : close;
        } else if (text.compare(index, 2U, "//") == 0) {
          for (; index < text.size() && text[index] != '\n'; ++index) {
            text[index] = ' ';
          }
        } else if (text.compare(index, 2U, "/*") == 0) {
          const std::size_t close = text.find("*/", index + 2U);
          const std::size_t end = (close == std::string::npos) ? text.size() : close + 2U;
          for (; index < end; ++index) {
            if (text[index] != '\n') {
              text[index] = ' ';
            }
          }
          --index;
        }
      }
      std::size_t line = 0U;
      bool continued = false;
      while (line < text.size()) {
        const std::size_t next = std::min(text.find('\n', line), text.size());
        const std::size_t first = text.find_first_not_of(" \t", line);
        if (continued || (first < next && text[first] == '#')) {
          const std::size_t last = (next == line) ? std::string::npos : text.find_last_not_of(" \t\r", next - 1U);
          continued = last != std::string::npos && last >= line && text[last] == '\\';
          std::fill(text.begin() + static_cast<std::ptrdiff_t>(line), text.begin() + static_cast<std::ptrdiff_t>(next), ' ');
        }
        line = next + 1U;
      }
      return text;
    }

    /** Each `<keyword> Name [< annotations >] { body }` block in `text`, in order. */
    [[nodiscard]] std::vector<std::pair<std::string, std::string_view>> NamedBlocks(
      const std::string_view text, const std::string_view keyword
    )
    {
      std::vector<std::pair<std::string, std::string_view>> blocks;
      std::size_t at = 0U;
      while ((at = text.find(keyword, at)) != std::string_view::npos) {
        const std::size_t after = at + keyword.size();
        if ((at != 0U && IsIdentifierChar(text[at - 1U])) || (after < text.size() && IsIdentifierChar(text[after]))) {
          at = after;
          continue;
        }
        std::size_t index = text.find_first_not_of(kWhitespace, after);
        std::size_t nameEnd = index;
        while (nameEnd < text.size() && IsIdentifierChar(text[nameEnd])) {
          ++nameEnd;
        }
        std::string name = (index == std::string_view::npos) ? std::string() : std::string(text.substr(index, nameEnd - index));
        index = text.find_first_not_of(kWhitespace, nameEnd);
        if (index != std::string_view::npos && text[index] == '<') {
          const std::size_t close = Matching(text, index);
          index = (close == std::string_view::npos) ? close : text.find_first_not_of(kWhitespace, close + 1U);
        }
        if (index == std::string_view::npos || text[index] != '{') {
          at = after;
          continue;
        }
        const std::size_t close = Matching(text, index);
        if (close == std::string_view::npos) {
          break;
        }
        blocks.emplace_back(std::move(name), text.substr(index + 1U, close - index - 1U));
        at = close + 1U;
      }
      return blocks;
    }

    [[nodiscard]] std::uint8_t ParseDirect3D9Comparison(const std::string& value, const std::uint8_t fallback)
    {
      static constexpr std::pair<const char*, std::uint8_t> kNames[] = {
        {"never", 1}, {"less", 2}, {"equal", 3}, {"lessequal", 4}, {"greater", 5}, {"notequal", 6}, {"greaterequal", 7}, {"always", 8},
      };
      const std::string key = Lower(Trim(value));
      for (const auto& [name, func] : kNames) {
        if (key == name) {
          return func;
        }
      }
      const std::uint32_t number = ParseUnsigned(key, fallback);
      return (number >= 1U && number <= 8U) ? static_cast<std::uint8_t>(number) : fallback;
    }
  } // namespace

  void ApplyDirect3D9PassStates(const std::string_view originalSource, EffectDescription& description)
  {
    const std::string text = WithoutCommentsAndDirectives(originalSource);
    description.direct3D9PassStates = true;
    std::size_t alphaTested = 0U;
    for (const auto& [techniqueName, techniqueBody] : NamedBlocks(text, "technique")) {
      const auto technique = std::find_if(description.techniques.begin(), description.techniques.end(), [&](const Technique& candidate) {
        return candidate.name == techniqueName;
      });
      if (technique == description.techniques.end()) {
        continue;
      }
      const auto passes = NamedBlocks(techniqueBody, "pass");
      for (std::size_t index = 0U; index < passes.size() && index < technique->passes.size(); ++index) {
        bool enabled = false;
        AlphaTestDesc alphaTest;
        for (const std::string& rawStatement : SplitTopLevel(passes[index].second, ';')) {
          const std::string statement = Trim(rawStatement);
          const std::size_t equals = statement.find('=');
          if (equals == std::string::npos) {
            continue;
          }
          // The state macros before an assignment carry no ';' (`AlphaState( ... )
          // DepthState( ... ) AlphaTestEnable = true`): the field is the last word.
          const std::string left = Trim(statement.substr(0U, equals));
          std::size_t word = left.size();
          while (word > 0U && IsIdentifierChar(left[word - 1U])) {
            --word;
          }
          const std::string field = Lower(left.substr(word));
          const std::string value = Trim(statement.substr(equals + 1U));
          if (field == "alphatestenable") {
            enabled = ParseBool(value, false);
          } else if (field == "alphafunc") {
            alphaTest.func = ParseDirect3D9Comparison(value, alphaTest.func);
          } else if (field == "alpharef") {
            alphaTest.ref = static_cast<std::uint8_t>(ParseUnsigned(value, 0U) & 0xFFU);
          }
        }
        if (enabled && alphaTest.func != 8U) {
          technique->passes[index].alphaTest = alphaTest;
          ++alphaTested;
        }
      }
    }
    if (alphaTested != 0U) {
      description.notes.push_back(std::to_string(alphaTested) + " passes take Direct3D 9's alpha test");
    }
  }
} // namespace gpg::gal::effects
