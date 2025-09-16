#include "asm_utils.h"
#include <algorithm>
#include <cstring>

using namespace asm_utils;

namespace
{
    /**
     * \brief Helper: rel32 immediate present for CALL/JMP or 0F 80..8F Jcc.
     */
    bool is_rel32(const bool twoByte, const std::uint8_t opcode) noexcept {
        if (!twoByte) {
            // E8 (CALL rel32), E9 (JMP rel32)
            return (opcode & 0xFE) == 0xE8;
        }
        // 0F 80..8F : Jcc rel32
        return opcode >= 0x80 && opcode <= 0x8F;
    }
}

bool asm_utils::is_prefix(const std::uint8_t b) noexcept {
    switch (b) {
    case kPrefixLock: case kPrefixRepne: case kPrefixRepe:
    case kPrefixOperandSize: case kPrefixAddressSize:
    case kPrefixCs: case kPrefixSs: case kPrefixDs:
    case kPrefixEs: case kPrefixFs: case kPrefixGs:
        return true;
    default: return false;
    }
}

/**
 * \brief Internal copy/count loop with optional relocation fixups for rel32.
 * \tparam Write If true, bytes are written into \p dst with fixed immediate-s.
 */
template<bool Write>
static std::uint32_t decode_loop_with_fixups(
    decoder& /*dec*/,
    std::uint8_t* src,
    std::uint8_t* dst,
    const std::uint32_t required)
{
    std::uint32_t copied = 0;

    while (copied < required) {
        const std::uint8_t* const s = src + copied;
        std::uint8_t* const out = dst ? (dst + copied) : nullptr;

        std::size_t len = 0;
        bool twoByte = false;
        bool fpuEsc = false;
        int operandSize = 4;

        // 1) Prefixes
        while (is_prefix(s[len])) {
            if constexpr (Write) out[len] = s[len];
            if (s[len] == kPrefixOperandSize) operandSize = 2;
            // FPU escape is not an actual prefix — we keep an early-exit for parity with legacy.
            ++len;
        }

        // 2) 0F escape
        if (s[len] == 0x0F) {
            twoByte = true;
            if constexpr (Write) out[len] = s[len];
            ++len;
            if constexpr (Write) out[len] = s[len];
            ++len;
        }

        // 3) Opcode
        if (s[len] == kOpInt) break;
        const std::uint8_t opcode = s[len];
        if constexpr (Write) out[len] = s[len];
        ++len;

        // 4) ModRM presence
        auto needsModRm = [&](const std::uint8_t opc) noexcept -> bool {
            if (fpuEsc) return false;
            if (twoByte) return (opc & 0xC0) != 0xC0;
            return (opc & 0xC4) == 0x00 || (opc & 0xF0) == 0x80 || (opc & 0xF6) == 0xF6;
        };

        std::uint8_t modRm = 0xFF;
        if (needsModRm(opcode) && s[len] != kOpInt) {
            modRm = s[len];
            if constexpr (Write) out[len] = s[len];
            ++len;
        }

        // 5) SIB
        if (needsModRm(opcode) && (modRm & 7) == 4 && (modRm & 0xC0) != 0xC0) {
            if constexpr (Write) out[len] = s[len];
            ++len;
        }

        // 6) Displacement
        if (needsModRm(opcode)) {
            const std::uint8_t mod = (modRm & 0xC0) >> 6;
            if (mod == 1) {
	            if constexpr (Write) out[len] = s[len]; ++len;
            }
            if (mod == 2) {
                if constexpr (Write) std::memcpy(out + len, s + len, 4);
                len += 4;
            }
            if ((modRm & 0xC5) == 0x05) {
                if constexpr (Write) std::memcpy(out + len, s + len, 4);
                len += 4;
            }
        }

        // 7) Immediate
        // ReSharper disable CommentTypo
        auto immSize = [&]() noexcept -> std::size_t {
            if (twoByte) {
                if (opcode >= 0x80 && opcode <= 0x8F) return 4;
                return 0;
            }
            if ((opcode & 0xFC) == 0x80) {
	            // ReSharper disable once CppDefaultCaseNotHandledInSwitchStatement
	            switch (opcode & 0x03) {
                case 0: return 1;
                case 1: return static_cast<std::size_t>(operandSize);
                case 2: return 1;  // NOLINT(bugprone-branch-clone)
                case 3: return 1;
                }
            }

            // PUSH imm8
            if (opcode == 0x6A) {
                return 1;
            }
            // PUSH imm32
            if (opcode == 0x68) {
                return 4;
            }
            // CALL/JMP rel32
            if ((opcode & 0xFE) == 0xE8) {
	            return 4;
            }
            // Jcc short
            if (opcode == kOpJmpShort || (opcode & 0xF0) == 0x70) {
	            return 1;
            }
            // RET imm16
            if (opcode == kOpRetnWithImm) {
                return 2;
            }
            // MOV moffs
            if ((opcode & 0xF8) == 0xA0) {
                return 4;
            }
            // TEST
            if ((opcode & 0xFD) == 0xA8) {
                return opcode == 0xA9 ? 
                    static_cast<std::size_t>(operandSize) :
            		1;
            }
            return 0;
        }();
        // ReSharper restore CommentTypo

        const std::size_t immOff = len;
        if (immSize) {
            if constexpr (Write) std::memcpy(out + len, s + len, immSize);
            len += immSize;

            if constexpr (Write) {
                // Adjust rel32 displacement for relocated CALL/JMP/Jcc
                if (immSize == 4 && is_rel32(twoByte, opcode)) {
                    const std::int32_t oldDis = *reinterpret_cast<const std::int32_t*>(s + immOff);
                    const auto srcNext = reinterpret_cast<std::uintptr_t>(s + len);
                    const auto dstNext = reinterpret_cast<std::uintptr_t>(out + len);
                    const auto target = srcNext + oldDis;
                    const auto newDis = static_cast<std::int32_t>(target - dstNext);
                    *reinterpret_cast<std::int32_t*>(out + immOff) = newDis;
                }
            }
        }

        copied += len;
    }
    return copied;
}

std::uint32_t asm_utils::decode_copy_bytes(std::uint8_t* src, std::uint8_t* dst, const std::uint32_t requiredLen) {
    decoder dec(std::span(reinterpret_cast<byte const*>(src), 128), reinterpret_cast<byte*>(dst));
    return decode_loop_with_fixups<true>(dec, src, dst, requiredLen);
}

std::uint32_t asm_utils::decode_count_bytes(std::uint8_t* src, const std::uint32_t requiredLen) {
    decoder dec(std::span(reinterpret_cast<byte const*>(src), 128), nullptr);
    return decode_loop_with_fixups<false>(dec, src, /*dst*/nullptr, requiredLen);
}

std::uint32_t asm_utils::compute_stolen_len_covering_seh(const std::uint8_t* entry) {
    // Minimal 5 bytes for E9 rel32
    std::uint32_t need = decode_count_bytes(const_cast<std::uint8_t*>(entry), kOpJmpRel32Size);

    // Pattern: FS:[0] SEH prologue + stack allocation
    //   64 A1 00..00    mov eax, fs:[0]
    //   50              push eax
    //   64 89 25 00..00 mov fs:[0], esp
    //   83 EC imm8 | 81 EC imm32   (optional stack frame reserve)
    for (std::size_t i = 0; i < 64; ++i) {
        if (entry[i] == 0x64 && entry[i + 1] == 0xA1 && entry[i + 6] == 0x50 &&
            entry[i + 7] == 0x64 && entry[i + 8] == 0x89 && entry[i + 9] == 0x25 &&
            entry[i + 10] == 0 && entry[i + 11] == 0 && entry[i + 12] == 0 && entry[i + 13] == 0)
        {
            std::size_t j = i + 14;
            while (is_prefix(entry[j])) ++j;
            const std::size_t after =
                (entry[j] == 0x83 && entry[j + 1] == 0xEC) ? (j + 3) :
                (entry[j] == 0x81 && entry[j + 1] == 0xEC) ? (j + 6) :
                (j + 1);

            while (need < after) {
                need = decode_count_bytes(const_cast<std::uint8_t*>(entry), need + 1);
            }
            return need;
        }
    }

    // Fallback: avoid cutting 'push imm32' (0x68 imm32) — steal at least 10 bytes.
    while (need < 10) {
        need = decode_count_bytes(const_cast<std::uint8_t*>(entry), need + 1);
    }
    return need;
}

void asm_utils::copy_or_iterate(std::uint8_t*& func, std::uint8_t*& dest) {
    if (dest) {
        *dest++ = *func++;
    } else {
        func++;
    }
}

std::uint32_t asm_utils::copy_bytes(std::uint8_t* func, std::uint8_t* dest, const std::uint32_t len) {
    // Legacy path preserved for compatibility. Prefer decode_copy_bytes().
    std::uint32_t resultByteCount = 0;

    // ReSharper disable CommentTypo
    while (resultByteCount < len && *func != kOpInt) {
        // prefixes F0h, F2h, F3h, 66h, 67h, D8h-DFh, 2Eh, 36h, 3Eh, 26h, 64h and 65h
        int operandSize = 4;
        std::uint8_t fpu = 0;
        bool twoByte = false;

        while (
            *func == kOpLock ||
            *func == 0xF2 || // REPNZ, REPNE, REP
            *func == 0xF3 || // REPZ, REPE, REP
            (*func & kOpClearDirectionFlag) == kOpFs ||
            (*func & kOpClearCarryFlag) == kOpEsc ||
            (*func & kOpJle) == kOpBound)
        {
            if (*func == kOpOperandSize) {
                operandSize = 2;
            } else if ((*func & kOpClearCarryFlag) == kOpEsc) {
                fpu = *func;
                copy_or_iterate(func, dest);
                resultByteCount++;
                break;
            }
            copy_or_iterate(func, dest);
            resultByteCount++;
        }

        if (*func == kOpIncDec) {
            twoByte = true;
            copy_or_iterate(func, dest);
            resultByteCount++;
        }

        const auto opCode = *func++;
        if (dest) {
            *dest++ = opCode;
        }
        resultByteCount++;

        std::uint8_t modRm = 0xFF;

        if (fpu) {
            if ((opCode & 0xC0) != 0xC0) {
                modRm = opCode;
            }
        } else if (!twoByte) {
            if ((opCode & 0xC4) == 0x00 ||
                (opCode & 0xF4) == 0x60 && ((opCode & 0x0A) == 0x02 || (opCode & 0x09) == 0x09) ||
                (opCode & 0xF0) == 0x80 ||
                (opCode & 0xF8) == 0xC0 && (opCode & 0x0E) != 0x02 ||
                (opCode & 0xFC) == 0xD0 ||
                (opCode & 0xF6) == 0xF6)
            {
                modRm = *func++;
                if (dest) *dest++ = modRm;
                resultByteCount++;
            }
        } else {
            if ((opCode & 0xF0) == 0x00 && (opCode & 0x0F) >= 0x04 && (opCode & 0x0D) != 0x0D ||
                (opCode & 0xF0) == 0x30 ||
                opCode == 0x77 ||
                (opCode & 0xF0) == 0x80 ||
                (opCode & 0xF0) == 0xA0 && (opCode & 0x07) <= 0x02 ||
                (opCode & 0xF8) == 0xC8)
            {
                // No mod R/M byte
            } else {
                modRm = *func++;
                if (dest) *dest++ = modRm;
                resultByteCount++;
            }
        }

        if ((modRm & 0x07) == 0x04 && (modRm & 0xC0) != 0xC0) {
            copy_or_iterate(func, dest);
            resultByteCount++;
        }

        if ((modRm & 0xC5) == 0x05) {
            if (dest) {
                *reinterpret_cast<std::uint32_t*>(dest) = *reinterpret_cast<std::uint32_t*>(func);
                dest += 4;
            }
            func += 4;
            resultByteCount += 4;
        }

        if ((modRm & 0xC0) == 0x40) {
            copy_or_iterate(func, dest);
            resultByteCount++;
        }

        if ((modRm & 0xC0) == 0x80) {
            if (dest) {
                *reinterpret_cast<std::uint32_t*>(dest) = *reinterpret_cast<std::uint32_t*>(func);
                dest += 4;
            }
            func += 4;
            resultByteCount += 4;
        }

        if (fpu) {
            // no immediates
        } else if (!twoByte) {
            if ((opCode & 0xC7) == 0x04 ||
                (opCode & 0xFE) == 0x6A || // PUSH/POP/IMUL
                (opCode & 0xF0) == 0x70 || // Jcc
                opCode == 0x80 ||
                opCode == 0x83 ||
                (opCode & 0xFD) == 0xA0 || // MOV
                opCode == 0xA8 ||          // TEST
                (opCode & 0xF8) == 0xB0 || // MOV
                (opCode & 0xFE) == 0xC0 || // RCL
                opCode == 0xC6 ||          // MOV
                opCode == 0xCD ||          // INT
                (opCode & 0xFE) == 0xD4 || // AAD/AAM
                (opCode & 0xF8) == 0xE0 || // LOOP/JCXZ
                opCode == 0xEB ||
                opCode == 0xF6 && (modRm & 0x30) == 0x00) // TEST
            {
                copy_or_iterate(func, dest);
                resultByteCount++;
            } else if ((opCode & 0xF7) == kOpRetn) {
                if (dest) {
                    *reinterpret_cast<std::uint16_t*>(dest) = *reinterpret_cast<std::uint16_t*>(func);
                    dest += 2;
                }
                func += 2;
                resultByteCount += 2;
            } else if ((opCode & 0xFC) == 0x80 ||
                (opCode & 0xC7) == 0x05 ||
                (opCode & 0xF8) == 0xB8 ||
                (opCode & 0xFE) == 0xE8 ||      // CALL/Jcc
                (opCode & 0xFE) == 0x68 ||
                (opCode & 0xFC) == 0xA0 ||
                (opCode & 0xEE) == 0xA8 ||
                opCode == 0xC7 ||
                opCode == 0xF7 && (modRm & 0x30) == 0x00)
            {
                if (dest) {
                    if ((opCode & 0xFE) == 0xE8) {
                        if (operandSize == 4) {
                            *reinterpret_cast<long*>(dest) = func + *reinterpret_cast<long*>(func) - dest;
                        } else {
                            *reinterpret_cast<short*>(dest) = static_cast<short>(func + *reinterpret_cast<short*>(func) - dest);
                        }
                    } else {
                        if (operandSize == 4) {
                            *reinterpret_cast<std::uint32_t*>(dest) = *reinterpret_cast<unsigned long*>(func);
                        } else {
                            *reinterpret_cast<std::uint16_t*>(dest) = *reinterpret_cast<std::uint16_t*>(func);
                        }
                    }
                    dest += operandSize;
                }
                func += operandSize;
                resultByteCount += static_cast<std::uint32_t>(operandSize);
            }
        } else { // two-byte
            if (opCode == 0xBA || // BT
                opCode == 0x0F || // 3DNow!
                (opCode & 0xFC) == 0x70 || // PSLLW
                (opCode & 0xF7) == 0xA4 || // SHLD
                opCode == 0xC2 ||
                opCode == 0xC4 ||
                opCode == 0xC5 ||
                opCode == 0xC6)
            {
                copy_or_iterate(func, dest);
            } else if ((opCode & 0xF0) == 0x80) { // Jcc -i
                if (dest) {
                    if (operandSize == 4) {
                        *reinterpret_cast<unsigned long*>(dest) = *reinterpret_cast<unsigned long*>(func);
                    } else {
                        *reinterpret_cast<unsigned short*>(dest) = *reinterpret_cast<unsigned short*>(func);
                    }
                    dest += operandSize;
                }
                func += operandSize;
                resultByteCount += static_cast<std::uint32_t>(operandSize);
            }
        }
    }
    // ReSharper restore CommentTypo

    return resultByteCount;
}

void asm_utils::inject_jump(void* source, void* destination) {
    auto* const cSrc = static_cast<std::uint8_t*>(source);
    const auto* const cDest = static_cast<std::uint8_t*>(destination);
    *cSrc = kOpJmp; // 0xE9
    *reinterpret_cast<std::int32_t*>(cSrc + 1) =
        cDest - (cSrc + kOpJmpRel32Size);
}

void asm_utils::fill_nop(void* src, std::uint8_t len) {
    auto* p = static_cast<std::uint8_t*>(src);
    while (len--) {
        *p++ = kOpNop;
    }
}

void* asm_utils::eval_jump(void* source) {
    auto* address = static_cast<std::uint8_t*>(source);
    if (!address) return nullptr;

    // Pattern: FF 25 [mem32]  => absolute jmp through pointer
    if (address[0] == kOpIncDec && address[1] == kOpJmpSeg) {
        address += 2;
        address = *reinterpret_cast<unsigned char**>(address);
        return *reinterpret_cast<void**>(address);
    }
    // Pattern: EB +rel8; E9 +rel32  => resolve chain
    if (address[0] == kOpJmpByte) {
        address = &address[kOpJmpByteSize] + *reinterpret_cast<char*>(&address[1]);
        if (address[0] == kOpJmp) address = address + *reinterpret_cast<int*>(&address[1]);
        return address;
    }
    return address;
}
