// FAF addition, not in the shipped binary: see EffectSourceD3D11.h.

#include "EffectSourceD3D11.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <map>
#include <optional>
#include <regex>
#include <utility>

namespace gpg::gal::d3d11
{
  namespace
  {
    using Fields = std::vector<std::pair<std::string, std::string>>; // in declaration order

    enum class StateKind
    {
      Blend,
      DepthStencil,
      Rasterizer,
    };

    struct StateObject
    {
      StateKind kind;
      Fields fields;
    };

    [[nodiscard]] std::string Lower(std::string_view text)
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      return out;
    }

    [[nodiscard]] std::string Trim(std::string_view text)
    {
      std::size_t begin = 0U;
      std::size_t end = text.size();
      while (begin < end && std::isspace(static_cast<unsigned char>(text[begin])) != 0) {
        ++begin;
      }
      while (end > begin && std::isspace(static_cast<unsigned char>(text[end - 1U])) != 0) {
        --end;
      }
      return std::string(text.substr(begin, end - begin));
    }

    /** Field key for merging: lower case, no spaces ("BlendEnable[ 0 ]" -> "blendenable[0]"). */
    [[nodiscard]] std::string FieldKey(std::string_view field)
    {
      std::string key;
      for (const char c : field) {
        if (std::isspace(static_cast<unsigned char>(c)) == 0) {
          key.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
      }
      return key;
    }

    [[nodiscard]] bool IsIdentifierChar(const char c) noexcept
    {
      return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '_';
    }

    /** Index of the brace closing the one at `open`, or npos. */
    [[nodiscard]] std::size_t MatchingBrace(const std::string& text, const std::size_t open)
    {
      int depth = 0;
      for (std::size_t index = open; index < text.size(); ++index) {
        if (text[index] == '{') {
          ++depth;
        } else if (text[index] == '}') {
          if (--depth == 0) {
            return index;
          }
        }
      }
      return std::string::npos;
    }

    /** Splits on `separator` outside parentheses and braces. */
    [[nodiscard]] std::vector<std::string> SplitTopLevel(std::string_view text, const char separator)
    {
      std::vector<std::string> parts;
      int depth = 0;
      std::size_t start = 0U;
      for (std::size_t index = 0U; index < text.size(); ++index) {
        const char c = text[index];
        if (c == '(' || c == '{' || c == '[') {
          ++depth;
        } else if (c == ')' || c == '}' || c == ']') {
          --depth;
        } else if (c == separator && depth == 0) {
          parts.push_back(std::string(text.substr(start, index - start)));
          start = index + 1U;
        }
      }
      parts.push_back(std::string(text.substr(start)));
      return parts;
    }

    /** Replaces whole identifiers `from` with `to`. Returns the count. */
    std::size_t ReplaceIdentifier(std::string& text, const std::string_view from, const std::string_view to)
    {
      std::size_t count = 0U;
      std::size_t position = 0U;
      while ((position = text.find(from, position)) != std::string::npos) {
        const bool startOk = position == 0U || !IsIdentifierChar(text[position - 1U]);
        const std::size_t end = position + from.size();
        const bool endOk = end >= text.size() || !IsIdentifierChar(text[end]);
        if (startOk && endOk) {
          text.replace(position, from.size(), to);
          position += to.size();
          ++count;
        } else {
          position = end;
        }
      }
      return count;
    }

    /** Drops `#line` (and any other directive) lines the preprocessor left. */
    [[nodiscard]] std::string StripDirectives(std::string_view text)
    {
      std::string out;
      out.reserve(text.size());
      std::size_t start = 0U;
      while (start < text.size()) {
        std::size_t end = text.find('\n', start);
        if (end == std::string_view::npos) {
          end = text.size();
        }
        const std::string_view line = text.substr(start, end - start);
        std::size_t first = 0U;
        while (first < line.size() && (line[first] == ' ' || line[first] == '\t')) {
          ++first;
        }
        if (first >= line.size() || line[first] != '#') {
          out.append(line);
        }
        out.push_back('\n');
        start = end + 1U;
      }
      return out;
    }

    void SetField(Fields& fields, const std::string& name, const std::string& value)
    {
      const std::string key = FieldKey(name);
      for (auto& [field, existing] : fields) {
        if (FieldKey(field) == key) {
          existing = value;
          return;
        }
      }
      fields.emplace_back(name, value);
    }

    [[nodiscard]] Fields DefaultFields(const StateKind kind)
    {
      // The pack `BeginTechnique` binds before every pass (PipelineStateD3D11).
      switch (kind) {
      case StateKind::Blend:
        return {{"BlendEnable[0]", "FALSE"}, {"SrcBlend", "ONE"}, {"DestBlend", "ZERO"}, {"BlendOp", "ADD"},
                {"SrcBlendAlpha", "ONE"}, {"DestBlendAlpha", "ZERO"}, {"BlendOpAlpha", "ADD"},
                {"RenderTargetWriteMask[0]", "0x0F"}};
      case StateKind::DepthStencil:
        return {{"DepthEnable", "TRUE"}, {"DepthWriteMask", "ALL"}, {"DepthFunc", "LESS_EQUAL"}};
      case StateKind::Rasterizer:
      default:
        return {{"FillMode", "SOLID"}, {"CullMode", "BACK"}, {"DepthClipEnable", "FALSE"}, {"MultisampleEnable", "TRUE"}};
      }
    }

    [[nodiscard]] std::optional<std::string> Translate(const std::map<std::string, std::string>& table, const std::string& value)
    {
      const auto found = table.find(Lower(Trim(value)));
      if (found == table.end()) {
        return std::nullopt;
      }
      return found->second;
    }

    const std::map<std::string, std::string> kBools = {{"true", "TRUE"}, {"false", "FALSE"}, {"1", "TRUE"}, {"0", "FALSE"}};
    const std::map<std::string, std::string> kCompare = {
      {"never", "NEVER"}, {"less", "LESS"}, {"equal", "EQUAL"}, {"lessequal", "LESS_EQUAL"},
      {"greater", "GREATER"}, {"notequal", "NOT_EQUAL"}, {"greaterequal", "GREATER_EQUAL"}, {"always", "ALWAYS"},
    };
    const std::map<std::string, std::string> kStencilOps = {
      {"keep", "KEEP"}, {"zero", "ZERO"}, {"replace", "REPLACE"}, {"incrsat", "INCR_SAT"},
      {"decrsat", "DECR_SAT"}, {"invert", "INVERT"}, {"incr", "INCR"}, {"decr", "DECR"},
    };
    const std::map<std::string, std::string> kBlends = {
      {"zero", "ZERO"}, {"one", "ONE"}, {"srccolor", "SRC_COLOR"}, {"invsrccolor", "INV_SRC_COLOR"},
      {"srcalpha", "SRC_ALPHA"}, {"invsrcalpha", "INV_SRC_ALPHA"}, {"destalpha", "DEST_ALPHA"},
      {"invdestalpha", "INV_DEST_ALPHA"}, {"destcolor", "DEST_COLOR"}, {"invdestcolor", "INV_DEST_COLOR"},
      {"srcalphasat", "SRC_ALPHA_SAT"}, {"blendfactor", "BLEND_FACTOR"}, {"invblendfactor", "INV_BLEND_FACTOR"},
    };
    const std::map<std::string, std::string> kBlendOps = {
      {"add", "ADD"}, {"subtract", "SUBTRACT"}, {"revsubtract", "REV_SUBTRACT"}, {"min", "MIN"}, {"max", "MAX"},
    };
    // D3D9 culls the named winding; with FrontCounterClockwise = FALSE the
    // clockwise faces are the front ones.
    const std::map<std::string, std::string> kCullModes = {{"none", "NONE"}, {"cw", "FRONT"}, {"ccw", "BACK"}};
    const std::map<std::string, std::string> kFillModes = {{"solid", "SOLID"}, {"wireframe", "WIREFRAME"}, {"point", "SOLID"}};

    /** The alpha factor D3D9 uses for a colour factor when blending alpha with the same factors. */
    [[nodiscard]] std::string AlphaFactor(const std::string& factor)
    {
      if (factor == "SRC_COLOR") {
        return "SRC_ALPHA";
      }
      if (factor == "INV_SRC_COLOR") {
        return "INV_SRC_ALPHA";
      }
      if (factor == "DEST_COLOR") {
        return "DEST_ALPHA";
      }
      if (factor == "INV_DEST_COLOR") {
        return "INV_DEST_ALPHA";
      }
      return factor;
    }

    /** "- 0.00001f" -> -0.00001 */
    [[nodiscard]] std::optional<double> ParseNumber(std::string_view text)
    {
      std::string compact;
      for (const char c : text) {
        if (std::isspace(static_cast<unsigned char>(c)) == 0 && c != 'f' && c != 'F' && c != '(' && c != ')') {
          compact.push_back(c);
        }
      }
      if (compact.empty()) {
        return std::nullopt;
      }
      char* end = nullptr;
      const double value = std::strtod(compact.c_str(), &end);
      if (end == nullptr || *end != '\0') {
        return std::nullopt;
      }
      return value;
    }

    [[nodiscard]] bool IsShaderAssignment(const std::string& lowerName)
    {
      return lowerName == "vertexshader" || lowerName == "pixelshader" || lowerName == "geometryshader" ||
        lowerName == "computeshader" || lowerName == "hullshader" || lowerName == "domainshader";
    }

    class Translator
    {
    public:
      Translator(std::string text, const bool shaderModel41)
        : mText(std::move(text))
        , mShaderModel41(shaderModel41)
      {}

      TranslatedEffectSource Run()
      {
        RaiseShaderModel();
        RewriteOneDimensionalSamplers();
        RenameTypesShadowingTechniques();
        CollectStateObjects();
        DropUndefinedFixedFunctionTechniques();
        CollectStructsAndFunctions();
        RewritePasses();
        if (mWrappers != 0U) {
          mNotes.push_back("pixel shader inputs re-linked through " + std::to_string(mWrappers) + " wrapper(s)");
        }
        return TranslatedEffectSource{std::move(mText), std::move(mNotes)};
      }

    private:
      /**
       * The compat preamble maps every D3D9 profile to vs_4_0/ps_4_0. Shader
       * model 4.1 doubles the vertex inputs to 32: mesh.fx's float16
       * instanced format (vertex format 16) declares 17 elements.
       */
      void RaiseShaderModel()
      {
        if (!mShaderModel41) {
          return;
        }
        const std::size_t vertex = ReplaceIdentifier(mText, "vs_4_0", "vs_4_1");
        const std::size_t pixel = ReplaceIdentifier(mText, "ps_4_0", "ps_4_1");
        if (vertex + pixel != 0U) {
          mNotes.push_back("shader model 4.1 profiles");
        }
      }

      struct Variable
      {
        std::string type;
        std::string name;
        std::string semantic; // upper case, normalised; empty for none
        bool uniform = false;
        bool out = false;
      };

      struct Function
      {
        std::string returnType;
        std::vector<Variable> parameters;
        std::string returnSemantic;
      };

      /** POSITION0 -> POSITION, COLOR -> COLOR0, TEXCOORD -> TEXCOORD0, SV_Position -> POSITION. */
      static std::string NormaliseSemantic(std::string semantic)
      {
        semantic = Trim(semantic);
        std::transform(semantic.begin(), semantic.end(), semantic.begin(), [](const unsigned char c) {
          return static_cast<char>(std::toupper(c));
        });
        if (semantic == "SV_POSITION" || semantic == "POSITION0") {
          return "POSITION";
        }
        if (!semantic.empty() && std::isdigit(static_cast<unsigned char>(semantic.back())) == 0 && semantic != "POSITION" &&
            semantic != "VPOS" && semantic != "VFACE") {
          semantic += "0";
        }
        return semantic;
      }

      static Variable ParseVariable(const std::string& declaration)
      {
        Variable variable{};
        std::string text = Trim(declaration);
        const std::size_t colon = text.rfind(':');
        if (colon != std::string::npos) {
          variable.semantic = NormaliseSemantic(text.substr(colon + 1U));
          text = Trim(text.substr(0U, colon));
        }
        std::vector<std::string> words;
        std::size_t start = 0U;
        while (start < text.size()) {
          while (start < text.size() && std::isspace(static_cast<unsigned char>(text[start])) != 0) {
            ++start;
          }
          std::size_t end = start;
          while (end < text.size() && std::isspace(static_cast<unsigned char>(text[end])) == 0) {
            ++end;
          }
          if (end > start) {
            words.push_back(text.substr(start, end - start));
          }
          start = end;
        }
        std::vector<std::string> typeWords;
        for (std::size_t index = 0U; index + 1U < words.size(); ++index) {
          const std::string& word = words[index];
          if (word == "uniform") {
            variable.uniform = true;
          } else if (word == "out" || word == "inout") {
            variable.out = true;
          } else if (word != "in" && word != "const" && word != "static") {
            typeWords.push_back(word);
          }
        }
        if (!words.empty()) {
          variable.name = words.back();
        }
        for (const std::string& word : typeWords) {
          variable.type += (variable.type.empty() ? "" : " ") + word;
        }
        return variable;
      }

      /**
       * D3D9 effects may name a technique like a struct (sky.fx's `Cirrus`);
       * fx_5_0 rejects the clash. The struct is renamed: the engine looks
       * techniques up by name.
       */
      void RenameTypesShadowingTechniques()
      {
        static const std::regex techniqueName(R"(\btechnique1[01]\s+(\w+))");
        static const std::regex structName(R"(\bstruct\s+(\w+))");
        std::vector<std::string> techniques;
        for (auto it = std::sregex_iterator(mText.begin(), mText.end(), techniqueName); it != std::sregex_iterator(); ++it) {
          techniques.push_back((*it)[1].str());
        }
        std::vector<std::string> clashes;
        for (auto it = std::sregex_iterator(mText.begin(), mText.end(), structName); it != std::sregex_iterator(); ++it) {
          if (std::find(techniques.begin(), techniques.end(), (*it)[1].str()) != techniques.end()) {
            clashes.push_back((*it)[1].str());
          }
        }
        for (const std::string& name : clashes) {
          ReplaceIdentifier(mText, name, "faf_" + name);
          const std::regex renamedTechnique("(\\btechnique1[01]\\s+)faf_" + name + "\\b");
          mText = std::regex_replace(mText, renamedTechnique, "$1" + name);
          mNotes.push_back("struct " + name + " renamed: a technique has the same name");
        }
      }

      void CollectStructsAndFunctions()
      {
        static const std::regex structHead(R"(\bstruct\s+(\w+)\s*\{)");
        for (auto it = std::sregex_iterator(mText.begin(), mText.end(), structHead); it != std::sregex_iterator(); ++it) {
          const std::size_t open = static_cast<std::size_t>(it->position(0) + it->length(0) - 1);
          const std::size_t close = MatchingBrace(mText, open);
          if (close == std::string::npos) {
            continue;
          }
          std::vector<Variable> members;
          for (const std::string& member : SplitTopLevel(std::string_view(mText).substr(open + 1U, close - open - 1U), ';')) {
            if (!Trim(member).empty()) {
              members.push_back(ParseVariable(member));
            }
          }
          mStructs[(*it)[1].str()] = std::move(members);
        }

        static const std::regex functionHead(R"((\w+)\s+(\w+)\s*\(([^(){};]*)\)\s*(:\s*(\w+)\s*)?\{)");
        for (auto it = std::sregex_iterator(mText.begin(), mText.end(), functionHead); it != std::sregex_iterator(); ++it) {
          const std::string name = (*it)[2].str();
          if (mFunctions.count(name) != 0U || name == "if" || name == "while" || name == "for" || name == "switch") {
            continue;
          }
          Function function{};
          function.returnType = (*it)[1].str();
          function.returnSemantic = (*it)[5].matched ? (*it)[5].str() : std::string();
          const std::string parameters = (*it)[3].str();
          if (!Trim(parameters).empty()) {
            for (const std::string& parameter : SplitTopLevel(parameters, ',')) {
              function.parameters.push_back(ParseVariable(parameter));
            }
          }
          mFunctions[name] = std::move(function);
        }
      }

      /** The shader function a `VertexShader = compile vs_4_0 F ( args )` statement names, and its args. */
      static bool ParseCompile(const std::string& value, std::string& function, std::string& arguments)
      {
        static const std::regex compile(R"(^\s*compile\s+\w+\s+(\w+)\s*\((.*)\)\s*$)");
        std::smatch match;
        if (!std::regex_match(value, match, compile)) {
          return false;
        }
        function = match[1].str();
        arguments = match[2].str();
        return true;
      }

      /**
       * Shader model 4 links a pixel shader's inputs to the vertex shader's
       * outputs by register; D3D9 linked them by semantic. When a pass's
       * pixel shader does not take exactly the vertex shader's output struct
       * (or a prefix of it), route it through a wrapper that does and
       * forwards each input by semantic.
       */
      std::string RelinkPixelShader(const std::string& vertexValue, const std::string& pixelValue, std::string& declarations)
      {
        std::string vertexName;
        std::string vertexArguments;
        std::string pixelName;
        std::string pixelArguments;
        if (!ParseCompile(vertexValue, vertexName, vertexArguments) || !ParseCompile(pixelValue, pixelName, pixelArguments)) {
          return pixelValue;
        }
        const auto vertex = mFunctions.find(vertexName);
        const auto pixel = mFunctions.find(pixelName);
        if (vertex == mFunctions.end() || pixel == mFunctions.end()) {
          return pixelValue;
        }
        const auto outputs = mStructs.find(vertex->second.returnType);
        if (outputs == mStructs.end()) {
          return pixelValue;
        }

        // The pixel shader's varying inputs, in register order.
        std::vector<std::string> inputs;
        for (const Variable& parameter : pixel->second.parameters) {
          if (parameter.uniform) {
            continue;
          }
          if (parameter.out) {
            return pixelValue;
          }
          if (parameter.semantic.empty()) {
            const auto members = mStructs.find(parameter.type);
            if (members == mStructs.end()) {
              return pixelValue;
            }
            for (const Variable& member : members->second) {
              inputs.push_back(member.semantic);
            }
          } else {
            inputs.push_back(parameter.semantic);
          }
        }
        bool linked = inputs.size() <= outputs->second.size();
        for (std::size_t index = 0U; linked && index < inputs.size(); ++index) {
          linked = inputs[index] == outputs->second[index].semantic;
        }
        if (linked) {
          return pixelValue;
        }

        const std::string key = pixelName + "|" + vertex->second.returnType;
        auto wrapper = mWrapperNames.find(key);
        if (wrapper == mWrapperNames.end()) {
          const std::string name = "faf_ps_" + std::to_string(mWrapperNames.size());
          const auto memberFor = [&](const std::string& semantic, const std::string& type) {
            for (const Variable& member : outputs->second) {
              if (member.semantic == semantic) {
                return "faf_in." + member.name;
              }
            }
            return "(" + type + ")0";
          };

          std::string signature = pixel->second.returnType + " " + name + "( " + vertex->second.returnType + " faf_in";
          std::string body;
          std::string call = pixelName + "(";
          bool first = true;
          for (const Variable& parameter : pixel->second.parameters) {
            std::string argument;
            if (parameter.uniform) {
              signature += ", uniform " + parameter.type + " " + parameter.name;
              argument = parameter.name;
            } else if (parameter.semantic.empty()) {
              const std::string local = "faf_" + parameter.name;
              body += "    " + parameter.type + " " + local + ";\n";
              for (const Variable& member : mStructs[parameter.type]) {
                body += "    " + local + "." + member.name + " = " + memberFor(member.semantic, member.type) + ";\n";
              }
              argument = local;
            } else {
              argument = memberFor(parameter.semantic, parameter.type);
            }
            call += (first ? " " : ", ") + argument;
            first = false;
          }
          call += " )";
          signature += " )";
          if (!pixel->second.returnSemantic.empty()) {
            signature += " : " + pixel->second.returnSemantic;
          }
          declarations += signature + "\n{\n" + body + "    return " + call + ";\n}\n";
          wrapper = mWrapperNames.emplace(key, name).first;
          ++mWrappers;
        }

        static const std::regex compileHead(R"(^(\s*compile\s+\w+\s+)\w+)");
        return std::regex_replace(pixelValue, compileHead, "$1" + wrapper->second, std::regex_constants::format_first_only);
      }

      void RewriteOneDimensionalSamplers()
      {
        const std::size_t samplers = ReplaceIdentifier(mText, "sampler1D", "sampler2D");
        const std::size_t reads = ReplaceIdentifier(mText, "tex1D", "faf_tex1D");
        if (reads != 0U) {
          mText.insert(0U, "float4 faf_tex1D(sampler2D s, float u) { return tex2D(s, float2(u, 0.5)); }\n");
        }
        if (samplers != 0U || reads != 0U) {
          mNotes.push_back("1D samplers read as 2D: " + std::to_string(samplers) + " sampler(s), " + std::to_string(reads) + " read(s)");
        }
      }

      void CollectStateObjects()
      {
        static const std::regex declaration(R"(\b(BlendState|DepthStencilState|RasterizerState)\s+(\w+)\s*\{)");
        for (auto it = std::sregex_iterator(mText.begin(), mText.end(), declaration); it != std::sregex_iterator(); ++it) {
          const std::smatch& match = *it;
          const std::size_t open = static_cast<std::size_t>(match.position(0) + match.length(0) - 1);
          const std::size_t close = MatchingBrace(mText, open);
          if (close == std::string::npos) {
            continue;
          }
          StateObject object{};
          const std::string kind = match[1].str();
          object.kind = (kind == "BlendState") ? StateKind::Blend
            : (kind == "DepthStencilState")    ? StateKind::DepthStencil
                                               : StateKind::Rasterizer;
          for (const std::string& statement : SplitTopLevel(std::string_view(mText).substr(open + 1U, close - open - 1U), ';')) {
            const std::size_t equals = statement.find('=');
            if (equals == std::string::npos) {
              continue;
            }
            object.fields.emplace_back(Trim(statement.substr(0U, equals)), Trim(statement.substr(equals + 1U)));
          }
          mStateObjects[match[2].str()] = std::move(object);
        }
      }

      void DropUndefinedFixedFunctionTechniques()
      {
        for (const char* const function : {"FixedFuncVS", "FixedFuncBloomVS", "FixedFuncPS"}) {
          const std::regex definition(std::string(R"(\b\w+\s+)") + function + R"(\s*\([^;{]*\)\s*(:\s*\w+\s*)?\{)");
          if (mText.find(function) == std::string::npos || std::regex_search(mText, definition)) {
            continue;
          }
          if (std::string_view(function) == "FixedFuncVS") {
            // D3D9 ran these passes with no vertex shader on pre-transformed
            // (XYZRHW) vertices in render-target pixels, vertex format 7; the
            // viewport only clipped them. The emulation maps the pixels into
            // the bound viewport's clip space so the viewport transform puts
            // them back where they were; the backend writes the viewport into
            // faf_ViewportSize before each pass. D3D9 put pixel centres on
            // integers, D3D10 on halves, hence the + 0.5.
            mText.insert(0U,
              "float4 faf_ViewportSize; // (left, top, 1/width, 1/height), set by the D3D11 backend\n"
              "struct faf_FixedFuncVertex { float4 position : POSITION0; float2 texcoord : TEXCOORD0; };\n"
              "faf_FixedFuncVertex FixedFuncVS(float4 position : POSITION0, float2 texcoord : TEXCOORD0)\n"
              "{\n"
              "    faf_FixedFuncVertex o;\n"
              "    o.position = float4((position.x + 0.5 - faf_ViewportSize.x) * faf_ViewportSize.z * 2.0 - 1.0,\n"
              "                        1.0 - (position.y + 0.5 - faf_ViewportSize.y) * faf_ViewportSize.w * 2.0,\n"
              "                        saturate(position.z), 1.0);\n"
              "    o.texcoord = texcoord;\n"
              "    return o;\n"
              "}\n");
            mNotes.push_back("D3D9 fixed-function FixedFuncVS emulated for pre-transformed vertices");
            continue;
          }
          static const std::regex techniqueHead(R"(\btechnique1[01]\s+(\w+)\s*(<(?:[^>"]|"[^"]*")*>)?\s*\{)");
          std::size_t searchFrom = 0U;
          std::smatch match;
          while (true) {
            const std::string::const_iterator begin = mText.cbegin() + static_cast<std::ptrdiff_t>(searchFrom);
            if (!std::regex_search(begin, mText.cend(), match, techniqueHead)) {
              break;
            }
            const std::size_t start = searchFrom + static_cast<std::size_t>(match.position(0));
            const std::size_t open = start + static_cast<std::size_t>(match.length(0)) - 1U;
            const std::size_t close = MatchingBrace(mText, open);
            if (close == std::string::npos) {
              break;
            }
            const std::string_view body = std::string_view(mText).substr(open, close - open);
            if (body.find(function) != std::string_view::npos) {
              mNotes.push_back("technique " + match[1].str() + " dropped: it uses the undefined D3D9 fixed-function " + function);
              mText.erase(start, close + 1U - start);
              searchFrom = start;
            } else {
              searchFrom = close + 1U;
            }
          }
        }
      }

      void RewritePasses()
      {
        static const std::regex techniqueHead(R"(\btechnique1[01]\s+\w+\s*(<(?:[^>"]|"[^"]*")*>)?\s*\{)");
        static const std::regex passHead(R"(\bpass\s+\w*\s*(<(?:[^>"]|"[^"]*")*>)?\s*\{)");

        std::size_t searchFrom = 0U;
        std::smatch technique;
        while (true) {
          const std::string::const_iterator begin = mText.cbegin() + static_cast<std::ptrdiff_t>(searchFrom);
          if (!std::regex_search(begin, mText.cend(), technique, techniqueHead)) {
            break;
          }
          const std::size_t techniqueStart = searchFrom + static_cast<std::size_t>(technique.position(0));
          const std::size_t techniqueOpen = techniqueStart + static_cast<std::size_t>(technique.length(0)) - 1U;
          std::size_t techniqueClose = MatchingBrace(mText, techniqueOpen);
          if (techniqueClose == std::string::npos) {
            break;
          }

          std::string declarations;
          std::size_t passFrom = techniqueOpen + 1U;
          std::smatch pass;
          while (passFrom < techniqueClose) {
            const std::string::const_iterator passBegin = mText.cbegin() + static_cast<std::ptrdiff_t>(passFrom);
            const std::string::const_iterator passEnd = mText.cbegin() + static_cast<std::ptrdiff_t>(techniqueClose);
            if (!std::regex_search(passBegin, passEnd, pass, passHead)) {
              break;
            }
            const std::size_t passOpen = passFrom + static_cast<std::size_t>(pass.position(0) + pass.length(0)) - 1U;
            const std::size_t passClose = MatchingBrace(mText, passOpen);
            if (passClose == std::string::npos || passClose > techniqueClose) {
              break;
            }
            const std::string body = mText.substr(passOpen + 1U, passClose - passOpen - 1U);
            const std::string rewritten = RewritePassBody(body, declarations);
            mText.replace(passOpen + 1U, passClose - passOpen - 1U, rewritten);
            const std::ptrdiff_t delta = static_cast<std::ptrdiff_t>(rewritten.size()) - static_cast<std::ptrdiff_t>(body.size());
            techniqueClose = static_cast<std::size_t>(static_cast<std::ptrdiff_t>(techniqueClose) + delta);
            passFrom = passOpen + 1U + rewritten.size() + 1U;
          }

          if (!declarations.empty()) {
            mText.insert(techniqueStart, declarations);
            techniqueClose += declarations.size();
          }
          searchFrom = techniqueClose + 1U;
        }
      }

      std::string RewritePassBody(const std::string& body, std::string& declarations)
      {
        std::map<std::string, std::string> legacy; // lower-case D3D9 state -> value
        std::vector<std::string> kept;
        std::map<StateKind, std::vector<std::string>> setCalls; // arguments of an existing Set*State

        for (const std::string& rawStatement : SplitTopLevel(body, ';')) {
          const std::string statement = Trim(rawStatement);
          if (statement.empty()) {
            continue;
          }
          const std::size_t paren = statement.find('(');
          const std::string head = Trim(statement.substr(0U, paren));
          if (paren != std::string::npos && statement.back() == ')' &&
              (head == "SetBlendState" || head == "SetDepthStencilState" || head == "SetRasterizerState")) {
            const StateKind kind = (head == "SetBlendState") ? StateKind::Blend
              : (head == "SetDepthStencilState")             ? StateKind::DepthStencil
                                                             : StateKind::Rasterizer;
            std::vector<std::string> arguments;
            for (const std::string& argument :
                 SplitTopLevel(std::string_view(statement).substr(paren + 1U, statement.size() - paren - 2U), ',')) {
              arguments.push_back(Trim(argument));
            }
            setCalls[kind] = std::move(arguments);
            continue;
          }

          const std::size_t equals = statement.find('=');
          if (equals != std::string::npos && statement.find('(') > equals) {
            const std::string name = Lower(Trim(statement.substr(0U, equals)));
            if (!IsShaderAssignment(name) && name.find_first_of(" \t[") == std::string::npos) {
              legacy[name] = Trim(statement.substr(equals + 1U));
              continue;
            }
          }
          if (equals != std::string::npos) {
            const std::string name = Lower(Trim(statement.substr(0U, equals)));
            if (!IsShaderAssignment(name) && name.find_first_of(" \t") == std::string::npos) {
              legacy[name] = Trim(statement.substr(equals + 1U));
              continue;
            }
          }
          kept.push_back(statement);
        }

        // Shader-model-4 stage linkage (see RelinkPixelShader).
        bool relinked = false;
        {
          std::size_t vertexIndex = kept.size();
          std::size_t pixelIndex = kept.size();
          for (std::size_t index = 0U; index < kept.size(); ++index) {
            const std::size_t equals = kept[index].find('=');
            if (equals == std::string::npos) {
              continue;
            }
            const std::string name = Lower(Trim(kept[index].substr(0U, equals)));
            if (name == "vertexshader") {
              vertexIndex = index;
            } else if (name == "pixelshader") {
              pixelIndex = index;
            }
          }
          if (vertexIndex < kept.size() && pixelIndex < kept.size()) {
            const std::string& vertex = kept[vertexIndex];
            const std::string& pixel = kept[pixelIndex];
            const std::string pixelValue = Trim(pixel.substr(pixel.find('=') + 1U));
            const std::string relinkedValue =
              RelinkPixelShader(Trim(vertex.substr(vertex.find('=') + 1U)), pixelValue, declarations);
            if (relinkedValue != pixelValue) {
              kept[pixelIndex] = "PixelShader = " + relinkedValue;
              relinked = true;
            }
          }
        }

        if (legacy.empty() && !relinked) {
          // Re-emit unchanged (the Set calls were lifted out above).
          return body;
        }

        const auto take = [&legacy](const char* const name) -> std::optional<std::string> {
          const auto found = legacy.find(name);
          if (found == legacy.end()) {
            return std::nullopt;
          }
          std::string value = found->second;
          legacy.erase(found);
          return value;
        };

        const auto baseFields = [this, &setCalls](const StateKind kind) {
          const auto call = setCalls.find(kind);
          if (call != setCalls.end() && !call->second.empty()) {
            const auto object = mStateObjects.find(call->second.front());
            if (object != mStateObjects.end() && object->second.kind == kind) {
              return object->second.fields;
            }
          }
          return DefaultFields(kind);
        };

        // Depth-stencil.
        {
          Fields fields = baseFields(StateKind::DepthStencil);
          bool touched = false;
          const auto apply = [&](const char* const d3d9, const char* const field, const std::map<std::string, std::string>* const table) {
            if (const std::optional<std::string> value = take(d3d9)) {
              const std::optional<std::string> translated = (table != nullptr) ? Translate(*table, *value) : value;
              if (translated) {
                SetField(fields, field, *translated);
                touched = true;
              } else {
                mNotes.push_back(std::string("unsupported ") + d3d9 + " value '" + *value + "' ignored");
              }
            }
          };
          if (const std::optional<std::string> zwrite = take("zwriteenable")) {
            const std::optional<std::string> flag = Translate(kBools, *zwrite);
            SetField(fields, "DepthWriteMask", (flag && *flag == "TRUE") ? "ALL" : "ZERO");
            touched = true;
          }
          apply("zenable", "DepthEnable", &kBools);
          apply("zfunc", "DepthFunc", &kCompare);
          apply("stencilenable", "StencilEnable", &kBools);
          apply("stencilmask", "StencilReadMask", nullptr);
          apply("stencilwritemask", "StencilWriteMask", nullptr);

          const std::optional<std::string> twoSided = take("twosidedstencilmode");
          const bool separateBack = twoSided && Translate(kBools, *twoSided) == std::optional<std::string>("TRUE");
          const std::optional<std::string> frontFunc = take("stencilfunc");
          const std::optional<std::string> frontFail = take("stencilfail");
          const std::optional<std::string> frontDepthFail = take("stencilzfail");
          const std::optional<std::string> frontPass = take("stencilpass");
          const std::optional<std::string> backFunc = take("ccw_stencilfunc");
          const std::optional<std::string> backFail = take("ccw_stencilfail");
          const std::optional<std::string> backDepthFail = take("ccw_stencilzfail");
          const std::optional<std::string> backPass = take("ccw_stencilpass");
          const auto stencil = [&](const char* const field, const std::optional<std::string>& value, const std::map<std::string, std::string>& table) {
            if (value) {
              if (const std::optional<std::string> translated = Translate(table, *value)) {
                SetField(fields, field, *translated);
                touched = true;
              }
            }
          };
          stencil("FrontFaceStencilFunc", frontFunc, kCompare);
          stencil("FrontFaceStencilFail", frontFail, kStencilOps);
          stencil("FrontFaceStencilDepthFail", frontDepthFail, kStencilOps);
          stencil("FrontFaceStencilPass", frontPass, kStencilOps);
          stencil("BackFaceStencilFunc", separateBack ? backFunc : frontFunc, kCompare);
          stencil("BackFaceStencilFail", separateBack ? backFail : frontFail, kStencilOps);
          stencil("BackFaceStencilDepthFail", separateBack ? backDepthFail : frontDepthFail, kStencilOps);
          stencil("BackFaceStencilPass", separateBack ? backPass : frontPass, kStencilOps);

          std::string reference = "0";
          const auto existing = setCalls.find(StateKind::DepthStencil);
          if (existing != setCalls.end() && existing->second.size() > 1U) {
            reference = existing->second[1];
          }
          if (const std::optional<std::string> stencilRef = take("stencilref")) {
            reference = *stencilRef;
            touched = true;
          }

          if (touched) {
            const std::string name = NewName("DepthStencil");
            declarations += Declare("DepthStencilState", name, fields);
            setCalls[StateKind::DepthStencil] = {name, reference};
          }
        }

        // Blend.
        {
          Fields fields = baseFields(StateKind::Blend);
          bool touched = false;
          if (const std::optional<std::string> enable = take("alphablendenable")) {
            if (const std::optional<std::string> flag = Translate(kBools, *enable)) {
              SetField(fields, "BlendEnable[0]", *flag);
              touched = true;
            }
          }
          const std::optional<std::string> separate = take("separatealphablendenable");
          const bool separateAlpha = separate && Translate(kBools, *separate) == std::optional<std::string>("TRUE");
          const auto factor = [&](const char* const d3d9, const char* const field, const char* const alphaField) {
            if (const std::optional<std::string> value = take(d3d9)) {
              if (const std::optional<std::string> translated = Translate(kBlends, *value)) {
                SetField(fields, field, *translated);
                if (!separateAlpha) {
                  SetField(fields, alphaField, AlphaFactor(*translated));
                }
                touched = true;
              }
            }
          };
          factor("srcblend", "SrcBlend", "SrcBlendAlpha");
          factor("destblend", "DestBlend", "DestBlendAlpha");
          if (const std::optional<std::string> op = take("blendop")) {
            if (const std::optional<std::string> translated = Translate(kBlendOps, *op)) {
              SetField(fields, "BlendOp", *translated);
              if (!separateAlpha) {
                SetField(fields, "BlendOpAlpha", *translated);
              }
              touched = true;
            }
          }
          if (separateAlpha) {
            if (const std::optional<std::string> value = take("srcblendalpha")) {
              if (const auto translated = Translate(kBlends, *value)) {
                SetField(fields, "SrcBlendAlpha", AlphaFactor(*translated));
              }
            }
            if (const std::optional<std::string> value = take("destblendalpha")) {
              if (const auto translated = Translate(kBlends, *value)) {
                SetField(fields, "DestBlendAlpha", AlphaFactor(*translated));
              }
            }
            if (const std::optional<std::string> value = take("blendopalpha")) {
              if (const auto translated = Translate(kBlendOps, *value)) {
                SetField(fields, "BlendOpAlpha", *translated);
              }
            }
            touched = true;
          }
          if (const std::optional<std::string> mask = take("colorwriteenable")) {
            SetField(fields, "RenderTargetWriteMask[0]", *mask);
            touched = true;
          }
          if (touched) {
            const std::string name = NewName("Blend");
            declarations += Declare("BlendState", name, fields);
            std::vector<std::string> arguments = {name, "float4(0,0,0,0)", "0xFFFFFFFF"};
            const auto existing = setCalls.find(StateKind::Blend);
            if (existing != setCalls.end() && existing->second.size() == 3U) {
              arguments[1] = existing->second[1];
              arguments[2] = existing->second[2];
            }
            setCalls[StateKind::Blend] = arguments;
          }
        }

        // Rasterizer.
        {
          Fields fields = baseFields(StateKind::Rasterizer);
          bool touched = false;
          if (const std::optional<std::string> cull = take("cullmode")) {
            if (const std::optional<std::string> translated = Translate(kCullModes, *cull)) {
              SetField(fields, "CullMode", *translated);
              touched = true;
            }
          }
          if (const std::optional<std::string> fill = take("fillmode")) {
            if (const std::optional<std::string> translated = Translate(kFillModes, *fill)) {
              SetField(fields, "FillMode", *translated);
              touched = true;
            }
          }
          if (const std::optional<std::string> bias = take("depthbias")) {
            if (const std::optional<double> value = ParseNumber(*bias)) {
              // D3D9's bias is in depth units; D3D10's in units of the 24-bit
              // depth buffer's resolution.
              SetField(fields, "DepthBias", std::to_string(static_cast<long>(std::lround(*value * 16777216.0))));
              touched = true;
            }
          }
          if (const std::optional<std::string> slope = take("slopescaledepthbias")) {
            if (const std::optional<double> value = ParseNumber(*slope)) {
              SetField(fields, "SlopeScaledDepthBias", std::to_string(*value));
              touched = true;
            }
          }
          if (touched) {
            const std::string name = NewName("Rasterizer");
            declarations += Declare("RasterizerState", name, fields);
            setCalls[StateKind::Rasterizer] = {name};
          }
        }

        for (const auto& [name, value] : legacy) {
          if (name == "alphatestenable" && Translate(kBools, value) == std::optional<std::string>("FALSE")) {
            continue;
          }
          mNotes.push_back("D3D9 state " + name + " = " + value + " has no D3D11 equivalent; ignored");
        }

        std::string out = "\n";
        const auto emit = [&out](const std::string& statement) { out += "        " + statement + ";\n"; };
        for (const auto& [kind, arguments] : setCalls) {
          std::string call = (kind == StateKind::Blend) ? "SetBlendState(" : (kind == StateKind::DepthStencil) ? "SetDepthStencilState(" : "SetRasterizerState(";
          for (std::size_t index = 0U; index < arguments.size(); ++index) {
            call += (index != 0U ? ", " : " ") + arguments[index];
          }
          emit(call + " )");
        }
        for (const std::string& statement : kept) {
          emit(statement);
        }
        out += "    ";
        ++mPassesRewritten;
        return out;
      }

      std::string NewName(const char* const kind)
      {
        return "faf_d3d11_" + std::string(kind) + "_" + std::to_string(mGenerated++);
      }

      static std::string Declare(const char* const type, const std::string& name, const Fields& fields)
      {
        std::string text = std::string(type) + " " + name + "\n{\n";
        for (const auto& [field, value] : fields) {
          text += "    " + field + " = " + value + ";\n";
        }
        text += "};\n";
        return text;
      }

      std::string mText;
      std::vector<std::string> mNotes;
      std::map<std::string, StateObject> mStateObjects;
      std::size_t mGenerated = 0U;
      std::size_t mPassesRewritten = 0U;
      std::map<std::string, std::vector<Variable>> mStructs;
      std::map<std::string, Function> mFunctions;
      std::map<std::string, std::string> mWrapperNames; // pixel shader | input struct -> wrapper
      std::size_t mWrappers = 0U;
      bool mShaderModel41 = false;
    };
  } // namespace

  TranslatedEffectSource TranslateEffectSource(const std::string_view preprocessed, const bool shaderModel41)
  {
    return Translator(StripDirectives(preprocessed), shaderModel41).Run();
  }
} // namespace gpg::gal::d3d11
