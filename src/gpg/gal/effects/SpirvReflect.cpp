// FAF addition, not in the shipped binary: see SpirvReflect.h.

#include "SpirvReflect.h"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace gpg::gal::effects
{
  namespace
  {
    // The SPIR-V opcodes and enumerants used here (SPIR-V 1.x unified spec).
    constexpr std::uint32_t kMagic = 0x07230203U;
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
    constexpr std::uint32_t kDecorationBuiltIn = 11;
    constexpr std::uint32_t kDecorationLocation = 30;
    constexpr std::uint32_t kDecorationUserSemantic = 5635;
    constexpr std::uint32_t kStorageInput = 1;
    constexpr std::uint32_t kStorageOutput = 3;

    struct Type
    {
      std::uint16_t opcode = 0;
      std::uint32_t operand0 = 0; // component type / pointee / element type, or width
      std::uint32_t operand1 = 0; // count / signedness / length id
    };

    [[nodiscard]] std::vector<std::uint32_t> Words(const std::vector<std::uint8_t>& code)
    {
      std::vector<std::uint32_t> words(code.size() / 4U);
      if (!words.empty()) {
        std::memcpy(words.data(), code.data(), words.size() * 4U);
      }
      return words;
    }

    [[nodiscard]] std::string LiteralString(const std::vector<std::uint32_t>& words, const std::size_t first, const std::size_t end)
    {
      std::string text;
      for (std::size_t index = first; index < end; ++index) {
        for (int byte = 0; byte < 4; ++byte) {
          const char c = static_cast<char>((words[index] >> (8 * byte)) & 0xFFU);
          if (c == '\0') {
            return text;
          }
          text.push_back(c);
        }
      }
      return text;
    }
  } // namespace

  SpirvInterface ReflectSpirvInterface(const std::vector<std::uint8_t>& code)
  {
    SpirvInterface result;
    const std::vector<std::uint32_t> words = Words(code);
    if (words.size() < 5U || words[0] != kMagic) {
      return result;
    }

    std::map<std::uint32_t, Type> types;
    std::map<std::uint32_t, std::uint32_t> constants;
    std::map<std::uint32_t, std::uint32_t> locations;
    std::map<std::uint32_t, std::string> semantics;
    std::map<std::uint32_t, bool> builtIns;
    struct Variable
    {
      std::uint32_t id;
      std::uint32_t type;
      std::uint32_t storage;
    };
    std::vector<Variable> variables;

    for (std::size_t index = 5U; index < words.size();) {
      const std::uint16_t opcode = static_cast<std::uint16_t>(words[index] & 0xFFFFU);
      const std::uint16_t count = static_cast<std::uint16_t>(words[index] >> 16U);
      if (count == 0U || index + count > words.size()) {
        return SpirvInterface{};
      }
      const std::uint32_t* const op = &words[index];
      switch (opcode) {
      case kOpTypeInt:
        types[op[1]] = Type{opcode, op[2], op[3]};
        break;
      case kOpTypeFloat:
        types[op[1]] = Type{opcode, op[2], 0U};
        break;
      case kOpTypeVector:
      case kOpTypeMatrix:
        types[op[1]] = Type{opcode, op[2], op[3]};
        break;
      case kOpTypeArray:
        types[op[1]] = Type{opcode, op[2], op[3]};
        break;
      case kOpTypePointer:
        types[op[1]] = Type{opcode, op[3], op[2]};
        break;
      case kOpConstant:
        if (count >= 4U) {
          constants[op[2]] = op[3];
        }
        break;
      case kOpVariable:
        variables.push_back(Variable{op[2], op[1], op[3]});
        break;
      case kOpDecorate:
        if (count >= 3U && op[2] == kDecorationLocation && count >= 4U) {
          locations[op[1]] = op[3];
        } else if (count >= 3U && op[2] == kDecorationBuiltIn) {
          builtIns[op[1]] = true;
        }
        break;
      case kOpDecorateString:
        if (count >= 4U && op[2] == kDecorationUserSemantic) {
          semantics[op[1]] = LiteralString(words, index + 3U, index + count);
        }
        break;
      default:
        break;
      }
      index += count;
    }

    for (const Variable& variable : variables) {
      if (variable.storage != kStorageInput && variable.storage != kStorageOutput) {
        continue;
      }
      SpirvInterfaceVariable entry;
      entry.id = variable.id;
      entry.builtIn = builtIns.count(variable.id) != 0U;
      const auto location = locations.find(variable.id);
      if (location == locations.end() && !entry.builtIn) {
        continue;
      }
      entry.location = (location != locations.end()) ? location->second : 0U;

      // Pointer -> (array of) (vector of) scalar.
      std::uint32_t type = 0U;
      if (const auto pointer = types.find(variable.type); pointer != types.end()) {
        type = pointer->second.operand0;
      }
      if (const auto array = types.find(type); array != types.end() && array->second.opcode == kOpTypeArray) {
        const auto length = constants.find(array->second.operand1);
        entry.locations = (length != constants.end()) ? length->second : 1U;
        type = array->second.operand0;
      }
      // A matrix takes one location per column.
      if (const auto matrix = types.find(type); matrix != types.end() && matrix->second.opcode == kOpTypeMatrix) {
        entry.locations *= matrix->second.operand1;
        type = matrix->second.operand0;
      }
      if (const auto vector = types.find(type); vector != types.end() && vector->second.opcode == kOpTypeVector) {
        entry.components = vector->second.operand1;
        type = vector->second.operand0;
      } else {
        entry.components = 1U;
      }
      if (const auto scalar = types.find(type); scalar != types.end()) {
        if (scalar->second.opcode == kOpTypeInt) {
          entry.component = (scalar->second.operand1 != 0U) ? SpirvInterfaceVariable::Component::Sint
                                                            : SpirvInterfaceVariable::Component::Uint;
        }
      }

      // "TEXCOORD3" -> ("TEXCOORD", 3).
      std::string semantic = semantics.count(variable.id) != 0U ? semantics[variable.id] : std::string();
      std::transform(semantic.begin(), semantic.end(), semantic.begin(), [](const unsigned char c) {
        return static_cast<char>(std::toupper(c));
      });
      std::size_t digits = semantic.size();
      while (digits > 0U && std::isdigit(static_cast<unsigned char>(semantic[digits - 1U])) != 0) {
        --digits;
      }
      entry.semanticIndex = (digits < semantic.size()) ? static_cast<std::uint32_t>(std::stoul(semantic.substr(digits))) : 0U;
      entry.semantic = semantic.substr(0U, digits);
      if (entry.semantic.rfind("SV_", 0U) == 0U) {
        entry.builtIn = true;
      }
      (variable.storage == kStorageInput ? result.inputs : result.outputs).push_back(std::move(entry));
    }
    return result;
  }

  std::vector<std::uint8_t> PatchSpirvInputLocations(
    const std::vector<std::uint8_t>& code, const std::map<std::uint32_t, std::uint32_t>& locations
  )
  {
    std::vector<std::uint32_t> words = Words(code);
    if (words.size() < 5U || words[0] != kMagic) {
      return code;
    }
    for (std::size_t index = 5U; index < words.size();) {
      const std::uint16_t opcode = static_cast<std::uint16_t>(words[index] & 0xFFFFU);
      const std::uint16_t count = static_cast<std::uint16_t>(words[index] >> 16U);
      if (count == 0U || index + count > words.size()) {
        return code;
      }
      if (opcode == kOpDecorate && count >= 4U && words[index + 2U] == kDecorationLocation) {
        const auto found = locations.find(words[index + 1U]);
        if (found != locations.end()) {
          words[index + 3U] = found->second;
        }
      }
      index += count;
    }
    std::vector<std::uint8_t> patched(words.size() * 4U);
    std::memcpy(patched.data(), words.data(), patched.size());
    return patched;
  }

  std::vector<std::uint8_t> StripSpirvReflection(const std::vector<std::uint8_t>& code)
  {
    constexpr std::uint16_t kOpExtension = 10;
    constexpr std::uint16_t kOpMemberDecorateString = 5633;
    constexpr std::uint32_t kDecorationUserTypeGoogle = 5636;
    const std::vector<std::uint32_t> words = Words(code);
    if (words.size() < 5U || words[0] != kMagic) {
      return code;
    }
    std::vector<std::uint32_t> kept(words.begin(), words.begin() + 5);
    for (std::size_t index = 5U; index < words.size();) {
      const std::uint16_t opcode = static_cast<std::uint16_t>(words[index] & 0xFFFFU);
      const std::uint16_t count = static_cast<std::uint16_t>(words[index] >> 16U);
      if (count == 0U || index + count > words.size()) {
        return code;
      }
      bool drop = false;
      if (opcode == kOpDecorateString && count >= 3U) {
        drop = words[index + 2U] == kDecorationUserSemantic || words[index + 2U] == kDecorationUserTypeGoogle;
      } else if (opcode == kOpMemberDecorateString && count >= 4U) {
        drop = words[index + 3U] == kDecorationUserSemantic || words[index + 3U] == kDecorationUserTypeGoogle;
      } else if (opcode == kOpExtension) {
        const std::string name = LiteralString(words, index + 1U, index + count);
        drop = name == "SPV_GOOGLE_hlsl_functionality1" || name == "SPV_GOOGLE_user_type";
      }
      if (!drop) {
        kept.insert(kept.end(), words.begin() + static_cast<std::ptrdiff_t>(index),
                    words.begin() + static_cast<std::ptrdiff_t>(index + count));
      }
      index += count;
    }
    std::vector<std::uint8_t> stripped(kept.size() * 4U);
    std::memcpy(stripped.data(), kept.data(), stripped.size());
    return stripped;
  }
} // namespace gpg::gal::effects
