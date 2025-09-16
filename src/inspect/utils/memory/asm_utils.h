#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>

/**
 * \brief Low-level helpers for decoding, copying and patching x86 instructions.
 *
 * The primary consumers are trampoline/detour builders that must copy a small
 * prologue from a function to an executable buffer and then jump back. We make
 * sure not to cut any instruction, and we fix relative displacements so that
 * control-flow stays correct after relocation.
 *
 * All comments are in English per project convention.
 */
namespace asm_utils
{
    ////////////////////////////////////////////////////////////////////////////////
    //                            Opcode constants
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * Opcode: LOCK prefix (F0h).
     */
    inline constexpr std::uint8_t kOpLock = 0xF0;

    /**
     * Bit-mask helper: checks "legacy prefix" ranges.
     */
    inline constexpr std::uint8_t kOpClearDirectionFlag = 0xFC;

    /**
     * Opcode: FS segment override prefix (64h).
     */
    inline constexpr std::uint8_t kOpFs = 0x64;

    /**
     * Opcode: Operand-size override prefix (66h).
     *
     */
    inline constexpr std::uint8_t kOpOperandSize = 0x66;

    /**
     * Opcode: BOUND (used in legacy prefix detection path).
     */
    inline constexpr std::uint8_t kOpBound = 0x62;

    /**
     * Opcode: JL/LE mask helper.
     */
    inline constexpr std::uint8_t kOpJle = 0x7E;

    /**
     * Opcode: x87 escape range starts (D8h..DFh).
     */
    inline constexpr std::uint8_t kOpEsc = 0xD8;

    /**
     * Opcode: CF-clear mask helper.
     */
    inline constexpr std::uint8_t kOpClearCarryFlag = 0xF8;

    /**
     * Opcode: INC/DEC with ModRM (FFh).
     */
    inline constexpr std::uint8_t kOpIncDec = 0xFF;

    // ReSharper disable once CommentTypo
    // ReSharper disable once IdentifierTypo
    /**
     * Opcode: RETN imm16 (C2h).
     */
    inline constexpr std::uint8_t kOpRetn = 0xC2;

    /**
     *  Opcode: NOP (90h).
     */
    inline constexpr std::uint8_t kOpNop = 0x90;

    /**
     * Size of E9 rel32 jump instruction.
     */
    inline constexpr std::uint8_t kOpJmpSize = 5;

    /**
     * Opcode for far/indirect jump encoding helper.
     */
    inline constexpr std::uint8_t kOpJmpSeg = 0x25;

    /**
     * Opcode: Short jump (EBh).
     */
    inline constexpr std::uint8_t kOpJmpByte = 0xEB;

    /**
     * Size of short jump instruction.
     */
    inline constexpr std::uint8_t kOpJmpByteSize = 2;

    /**
     * E9 rel32: 1 + 4.
     */
    inline constexpr std::uint32_t kOpJmpRel32Size = 5;

    /**
     * FF 25 [imm32]: 2 + 4 (absolute through mem32).
     */
    inline constexpr std::uint32_t kOpJmpAbsFf25Size = 6;

    /**
     * `INT3` instruction marker.
     */
    inline constexpr std::uint8_t kOpInt = 0xCC;

    /**
     * `JMP rel32` instruction marker.
     */
    inline constexpr std::uint8_t kOpJmp = 0xE9;

    /**
     * `short JMP` instruction marker.
     */
    inline constexpr std::uint8_t kOpJmpShort = 0xEB;

    // ReSharper disable once CommentTypo
    // ReSharper disable once IdentifierTypo
    /**
     * `RETN imm16` instruction marker.
     */
    inline constexpr std::uint8_t kOpRetnWithImm = 0xC2;

    // Legacy prefixes (subset we care about in the fast decoder)
    inline constexpr std::uint8_t kPrefixLock = 0xF0;
    inline constexpr std::uint8_t kPrefixRepne = 0xF2;
    inline constexpr std::uint8_t kPrefixRepe = 0xF3;
    inline constexpr std::uint8_t kPrefixOperandSize = 0x66;
    inline constexpr std::uint8_t kPrefixAddressSize = 0x67;
    inline constexpr std::uint8_t kPrefixCs = 0x2E;
    inline constexpr std::uint8_t kPrefixSs = 0x36;
    inline constexpr std::uint8_t kPrefixDs = 0x3E;
    inline constexpr std::uint8_t kPrefixEs = 0x26;
    inline constexpr std::uint8_t kPrefixFs = 0x64;
    inline constexpr std::uint8_t kPrefixGs = 0x65;

    /**
     * \brief Returns true if byte is a legacy instruction prefix.
     */
    bool is_prefix(std::uint8_t b) noexcept;

    ////////////////////////////////////////////////////////////////////////////////
    //                            Public API
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * \brief Copy single byte from \p func to \p dest or advance source if \p dest == nullptr.
     *
     * This is used by the legacy path and remains for compatibility. Prefer using
     * decode_copy_bytes() for new code.
     */
    void copy_or_iterate(std::uint8_t*& func, std::uint8_t*& dest);

    /**
     * \brief Copy whole x86 instructions up to at least \p len bytes.
     *
     * This legacy implementation tries to mirror the original project's behavior.
     * Use decode_copy_bytes() for relocation-aware copying with rel32 fixups.
     */
    [[deprecated("Use decode_copy_bytes() instead for relocation-aware copying")]]
    std::uint32_t copy_bytes(std::uint8_t* func, std::uint8_t* dest, std::uint32_t len);

    /**
     * \brief Write an unconditional jump at \p source to \p destination (E9 rel32).
     */
    void inject_jump(void* source, void* destination);

    /**
     * \brief Fill a memory range with NOPs (90h).
     */
    void fill_nop(void* src, std::uint8_t len);

    // ReSharper disable once CommentTypo
    /**
     * \brief Resolve possible jump stubs to the ultimate destination.
     *
     * Handles patterns:
     *  - FF 25 [imm32] (jmp dword ptr [abs])
     *  - EB xx ; E9 xxxx (short then near jmp)
     */
    void* eval_jump(void* source);

    /**
     * \brief Compute the minimal stolen length that fully covers an SEH prologue.
     *
     * Many Windows functions start with an FS:[0] based SEH frame setup. If we
     * patch into the middle of that, unwinding/debugging can break. We ensure
     * the stolen bytes end strictly after this prologue if present.
     */
    std::uint32_t compute_stolen_len_covering_seh(const std::uint8_t* entry);

    /**
     * \brief Copy instructions (with relocation fixups) until \p required_len is reached.
     *
     * We use a tiny decoder to walk instructions and, when writing, fix rel32
     * displacements for CALL/JMP and 0F 80..8F Jcc so the relocated block is
     * functionally identical.
     */
    std::uint32_t decode_copy_bytes(std::uint8_t* src, std::uint8_t* dst, std::uint32_t requiredLen);

    /**
     * \brief Count-only variant of decode_copy_bytes().
     */
    std::uint32_t decode_count_bytes(std::uint8_t* src, std::uint32_t requiredLen);

    /** \brief Alias for raw byte type (for spans). */
    using byte = std::byte;

    ////////////////////////////////////////////////////////////////////////////////
    //                            Minimal decoder
    ////////////////////////////////////////////////////////////////////////////////

    /**
     * \brief Minimal single-instruction decoder for x86 used by the copier.
     *
     * It recognizes enough encoding patterns to safely compute instruction size
     * and copy immediate/displacements. It does not execute or validate semantics.
     */
    class decoder
    {
    public:
        /**
         * \brief Construct the decoder.
         * \param src Source bytes (read-only view).
         * \param dst Optional destination pointer; when using decode_instruction<true>(),
         *            exact bytes will be copied 1:1 into the \p dst buffer at the same
         *            relative offset from the instruction start.
         */
        decoder(const std::span<const byte> src, byte* dst) noexcept
            : src_{ src }, dst_{ dst }, ip_{ 0 }, operandSize_{ 4 } {
        }

        /**
         * \brief Decode a single instruction and optionally copy its raw encoding.
         * \tparam Write If true, writes source bytes to \p dst starting at offset 0 for this instruction.
         * \return Number of bytes consumed for this instruction (0 if not enough data).
         */
        template<bool Write>
        std::size_t decode_instruction();

        /**
         * \brief Decode instructions until at least \p required_len bytes are consumed/copied.
         * \tparam Write If true, raw bytes are copied verbatim into \p dst (no relocation).
         * \return The number of bytes decoded (>= required_len unless end-of-buffer).
         */
        template<bool Write>
        std::size_t copy_bytes(const std::size_t requiredLen) {
            std::size_t copied = 0;
            while (copied < requiredLen && ip_ < src_.size()) {
                const std::size_t len = decode_instruction<Write>();
                if (len == 0) break;
                copied += len;
            }
            return copied;
        }

    private:
        /**
         * \brief Source bytes (instruction stream).
         */
        std::span<const byte> src_;

        /**
         * \brief Optional destination for raw byte mirroring.
         */
        byte* dst_;

        /**
         * \brief Current instruction pointer inside \p src_.
         */
        std::size_t ip_;

        /**
         * \brief Current operand-size in bytes (2 for 66h, 4 otherwise).
         */
        int operandSize_;

        /**
         * \brief Determine if this opcode form expects a ModRM byte.
         */
        static bool needs_mod_rm(std::uint8_t opcode, bool twoByte, bool fpu) noexcept;

        /**
         * \brief Return size of immediate for current opcode form (0 if none).
         */
        [[nodiscard]]
    	std::size_t immediate_size(std::uint8_t opcode, bool twoByte) const noexcept;

        /**
         * \brief Copy \p n bytes of displacement/immediate if Write==true, then advance IP.
         */
        template<bool Write>
        void copy_disp(std::size_t n, std::size_t start);
    };
} // namespace asm_utils
