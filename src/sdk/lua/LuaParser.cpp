#include "LuaRuntimeTypes.h"

#include "lua/LuaError.h"

#include <array>
#include <cctype>
#include <climits>
#include <cmath>
#include <cstring>
#include <utility>

namespace lua
{
  /**
   * Address: 0x00F317C0 (lua::enable_tailcalls)
   *
   * What it does:
   * Enables the parser's tail-call rewrite. On by default in the shipped
   * binary. With it off, `return f()` emits an ordinary OP_CALL and the frame
   * stays on the stack, which is what a debugger needs to show the caller.
   */
  int enable_tailcalls = 1;
} // namespace lua

namespace LuaPlus
{
  // Shared binary-bytecode loader (lundump) state views. These mirror the
  // definitions in LuaObject.cpp, where the chunk-header validator and the
  // recursive proto reader are recovered alongside the sub-loaders. Both TUs
  // must name the exact same `LuaPlus::LuaLoadStateRuntimeView` type so
  // luaU_undump here can build the load state and hand it to those entry
  // points. Layout matches the original ZIO / LoadState structs
  // (FUN_009285C0 / FUN_00928ED0 / FUN_009290F0).
  struct LuaZioRuntimeView
  {
    int remainingBytes; // ZIO::n
    const char* cursor; // ZIO::p
  };

  struct LuaLoadStateRuntimeView
  {
    lua_State* state;          // LoadState::L    (+0x0)
    LuaZioRuntimeView* stream; // LoadState::Z    (+0x4)
    Mbuffer* scratchBuffer;    // LoadState::b    (+0x8)
    int swapBytes;             // LoadState::swap (+0xC)
    const char* chunkName;     // LoadState::name (+0x10)
  };
  static_assert(offsetof(LuaLoadStateRuntimeView, state) == 0x0, "LuaLoadStateRuntimeView::state offset must be 0x0");
  static_assert(offsetof(LuaLoadStateRuntimeView, stream) == 0x4, "LuaLoadStateRuntimeView::stream offset must be 0x4");
  static_assert(offsetof(LuaLoadStateRuntimeView, scratchBuffer) == 0x8, "LuaLoadStateRuntimeView::scratchBuffer offset must be 0x8");
  static_assert(offsetof(LuaLoadStateRuntimeView, swapBytes) == 0xC, "LuaLoadStateRuntimeView::swapBytes offset must be 0xC");
  static_assert(offsetof(LuaLoadStateRuntimeView, chunkName) == 0x10, "LuaLoadStateRuntimeView::chunkName offset must be 0x10");
  static_assert(sizeof(LuaLoadStateRuntimeView) == 0x14, "LuaLoadStateRuntimeView size must be 0x14");

  // Recovered binary-chunk loader entry points (defined in LuaObject.cpp).
  void LuaLoadChunkHeader(LuaLoadStateRuntimeView* loadState);
  Proto* LuaLoadProtoObject(LuaLoadStateRuntimeView* loadState, TString* fallbackSource);
}

namespace
{
  struct FuncState;

  union SemInfo
  {
    float r;
    TString* ts;
  };

  struct Token
  {
    std::int32_t token;
    SemInfo seminfo;
  };

  struct LexState
  {
    std::int32_t current;
    std::int32_t linenumber;
    std::int32_t lastline;
    Token t;
    Token lookahead;
    FuncState* fs;
    lua_State* L;
    void* z;
    void* buff;
    TString* source;
    std::int32_t nestlevel;
  };

  struct LuaZioRuntimeView
  {
    std::int32_t remainingBytes;
    const char* cursor;
  };

  struct SParser
  {
    void* z;
    Mbuffer buff;
    std::int32_t bin;
  };

  struct expdesc
  {
    std::int32_t k;
    std::int32_t info;
    std::int32_t aux;
    std::int32_t t;
    std::int32_t f;
  };

  struct LHS_assign
  {
    LHS_assign* prev;
    expdesc v;
  };

  struct ConsControl
  {
    expdesc v;             // +0x00
    expdesc* t = nullptr;  // +0x14
    std::int32_t nh = 0;   // +0x18
    std::int32_t na = 0;   // +0x1C
    std::int32_t tostore = 0; // +0x20
  };
  static_assert(offsetof(ConsControl, v) == 0x00, "ConsControl::v offset must be 0x00");
  static_assert(offsetof(ConsControl, t) == 0x14, "ConsControl::t offset must be 0x14");
  static_assert(offsetof(ConsControl, nh) == 0x18, "ConsControl::nh offset must be 0x18");
  static_assert(offsetof(ConsControl, na) == 0x1C, "ConsControl::na offset must be 0x1C");
  static_assert(offsetof(ConsControl, tostore) == 0x20, "ConsControl::tostore offset must be 0x20");
  static_assert(sizeof(ConsControl) == 0x24, "ConsControl size must be 0x24");

  struct BlockCntRuntimeView
  {
    BlockCntRuntimeView* previous; // +0x00 enclosing block
    std::int32_t breaklist;        // +0x04 jumps out of this loop
    std::int32_t continuelist;     // +0x08 jumps back to this loop's step
    std::int32_t nactvar;          // +0x0C actives outside the block
    std::int32_t upval;            // +0x10 some local here is an upvalue
    std::int32_t isbreakable;      // +0x14 block is a loop
  };

  struct FuncStateRuntimeView
  {
    Proto* f;              // +0x00
    Table* h;              // +0x04
    FuncState* prev;       // +0x08
    void* lexState;        // +0x0C
    lua_State* L;          // +0x10
    BlockCntRuntimeView* bl; // +0x14
    std::int32_t pc;       // +0x18
    std::int32_t lasttarget; // +0x1C
    std::int32_t jpc;      // +0x20
    union
    {
      std::int32_t freeRegisterIndex;
      std::int32_t freereg;
    };                     // +0x24
    std::int32_t nk;       // +0x28
    union
    {
      std::int32_t nestedProtoCount;
      std::int32_t np;
    };                     // +0x2C
    union
    {
      std::int32_t nlocvars;
      std::int32_t localVariableCount;
    };                     // +0x30
    union
    {
      std::int32_t activeVariableCount;
      std::int32_t nactvar;
    };                     // +0x34
    expdesc upvalues[0x20]; // +0x38
    std::int32_t actvar[0xC8]; // +0x2B8
  };

  struct LuaUndumpZioRuntimeView
  {
    std::int32_t remainingBytes;
    const char* cursor;
    void* reader;
    void* data;
    const char* name;
  };

  static_assert(offsetof(Token, token) == 0x00, "Token::token offset must be 0x00");
  static_assert(offsetof(Token, seminfo) == 0x04, "Token::seminfo offset must be 0x04");
  static_assert(sizeof(Token) == 0x08, "Token size must be 0x08");
  static_assert(offsetof(LexState, current) == 0x00, "LexState::current offset must be 0x00");
  static_assert(offsetof(LexState, linenumber) == 0x04, "LexState::linenumber offset must be 0x04");
  static_assert(offsetof(LexState, lastline) == 0x08, "LexState::lastline offset must be 0x08");
  static_assert(offsetof(LexState, t) == 0x0C, "LexState::t offset must be 0x0C");
  static_assert(offsetof(LexState, lookahead) == 0x14, "LexState::lookahead offset must be 0x14");
  static_assert(offsetof(LexState, fs) == 0x1C, "LexState::fs offset must be 0x1C");
  static_assert(offsetof(LexState, L) == 0x20, "LexState::L offset must be 0x20");
  static_assert(offsetof(LexState, z) == 0x24, "LexState::z offset must be 0x24");
  static_assert(offsetof(LexState, buff) == 0x28, "LexState::buff offset must be 0x28");
  static_assert(offsetof(LexState, source) == 0x2C, "LexState::source offset must be 0x2C");
  static_assert(offsetof(LexState, nestlevel) == 0x30, "LexState::nestlevel offset must be 0x30");
  static_assert(sizeof(LexState) == 0x34, "LexState size must be 0x34");
  static_assert(offsetof(SParser, z) == 0x00, "SParser::z offset must be 0x00");
  static_assert(offsetof(SParser, buff) == 0x04, "SParser::buff offset must be 0x04");
  static_assert(offsetof(SParser, bin) == 0x0C, "SParser::bin offset must be 0x0C");
  static_assert(sizeof(SParser) == 0x10, "SParser size must be 0x10");
  static_assert(offsetof(expdesc, k) == 0x00, "expdesc::k offset must be 0x00");
  static_assert(offsetof(expdesc, info) == 0x04, "expdesc::info offset must be 0x04");
  static_assert(offsetof(expdesc, aux) == 0x08, "expdesc::aux offset must be 0x08");
  static_assert(offsetof(expdesc, t) == 0x0C, "expdesc::t offset must be 0x0C");
  static_assert(offsetof(expdesc, f) == 0x10, "expdesc::f offset must be 0x10");
  static_assert(sizeof(expdesc) == 0x14, "expdesc size must be 0x14");
  static_assert(offsetof(LHS_assign, prev) == 0x00, "LHS_assign::prev offset must be 0x00");
  static_assert(offsetof(LHS_assign, v) == 0x04, "LHS_assign::v offset must be 0x04");
  static_assert(sizeof(LHS_assign) == 0x18, "LHS_assign size must be 0x18");
  static_assert(offsetof(BlockCntRuntimeView, previous) == 0x00, "BlockCntRuntimeView::previous offset must be 0x00");
  static_assert(offsetof(BlockCntRuntimeView, breaklist) == 0x04, "BlockCntRuntimeView::breaklist offset must be 0x04");
  static_assert(
    offsetof(BlockCntRuntimeView, continuelist) == 0x08,
    "BlockCntRuntimeView::continuelist offset must be 0x08"
  );
  static_assert(offsetof(BlockCntRuntimeView, nactvar) == 0x0C, "BlockCntRuntimeView::nactvar offset must be 0x0C");
  static_assert(offsetof(BlockCntRuntimeView, upval) == 0x10, "BlockCntRuntimeView::upval offset must be 0x10");
  static_assert(
    offsetof(BlockCntRuntimeView, isbreakable) == 0x14,
    "BlockCntRuntimeView::isbreakable offset must be 0x14"
  );
  static_assert(sizeof(BlockCntRuntimeView) == 0x18, "BlockCntRuntimeView size must be 0x18");
  static_assert(offsetof(FuncStateRuntimeView, f) == 0x00, "FuncStateRuntimeView::f offset must be 0x00");
  static_assert(offsetof(FuncStateRuntimeView, h) == 0x04, "FuncStateRuntimeView::h offset must be 0x04");
  static_assert(offsetof(FuncStateRuntimeView, prev) == 0x08, "FuncStateRuntimeView::prev offset must be 0x08");
  static_assert(offsetof(FuncStateRuntimeView, lexState) == 0x0C, "FuncStateRuntimeView::lexState offset must be 0x0C");
  static_assert(offsetof(FuncStateRuntimeView, L) == 0x10, "FuncStateRuntimeView::L offset must be 0x10");
  static_assert(offsetof(FuncStateRuntimeView, bl) == 0x14, "FuncStateRuntimeView::bl offset must be 0x14");
  static_assert(offsetof(FuncStateRuntimeView, pc) == 0x18, "FuncStateRuntimeView::pc offset must be 0x18");
  static_assert(offsetof(FuncStateRuntimeView, lasttarget) == 0x1C, "FuncStateRuntimeView::lasttarget offset must be 0x1C");
  static_assert(offsetof(FuncStateRuntimeView, jpc) == 0x20, "FuncStateRuntimeView::jpc offset must be 0x20");
  static_assert(
    offsetof(FuncStateRuntimeView, freeRegisterIndex) == 0x24,
    "FuncStateRuntimeView::freeRegisterIndex offset must be 0x24"
  );
  static_assert(offsetof(FuncStateRuntimeView, nk) == 0x28, "FuncStateRuntimeView::nk offset must be 0x28");
  static_assert(offsetof(FuncStateRuntimeView, np) == 0x2C, "FuncStateRuntimeView::np offset must be 0x2C");
  static_assert(offsetof(FuncStateRuntimeView, nlocvars) == 0x30, "FuncStateRuntimeView::nlocvars offset must be 0x30");
  static_assert(
    offsetof(FuncStateRuntimeView, activeVariableCount) == 0x34,
    "FuncStateRuntimeView::activeVariableCount offset must be 0x34"
  );
  static_assert(offsetof(FuncStateRuntimeView, upvalues) == 0x38, "FuncStateRuntimeView::upvalues offset must be 0x38");
  static_assert(offsetof(FuncStateRuntimeView, actvar) == 0x2B8, "FuncStateRuntimeView::actvar offset must be 0x2B8");
  static_assert(sizeof(FuncStateRuntimeView) == 0x5D8, "FuncStateRuntimeView size must be 0x5D8");
  static_assert(offsetof(LuaUndumpZioRuntimeView, name) == 0x10, "LuaUndumpZioRuntimeView::name offset must be 0x10");

  constexpr std::int32_t NO_JUMP = -1;
  constexpr std::int32_t VVOID = 0x00;
  constexpr std::int32_t VNIL = 0x01;
  constexpr std::int32_t VTRUE = 0x02;
  constexpr std::int32_t VFALSE = 0x03;
  constexpr std::int32_t VK = 0x04;
  constexpr std::int32_t VLOCAL = 0x05;
  constexpr std::int32_t VUPVAL = 0x06;
  constexpr std::int32_t VGLOBAL = 0x07;
  constexpr std::int32_t VJMP = 0x09;
  constexpr std::int32_t VRELOCABLE = 0x0A;
  constexpr std::int32_t VNONRELOC = 0x0B;
  constexpr std::int32_t VCALL = 0x0C;
  constexpr std::int32_t VINDEXED = 0x08;
  constexpr std::int32_t NO_REG = 0xFF;

  // Opcode numbering for this build. It is stock Lua 5.0.2 with the four FAF
  // bit operators (BAND/BOR/BSHL/BSHR) spliced in after OP_DIV, which shifts
  // every opcode from OP_POW upwards by four. Confirmed against the binary:
  // luaK_jump emits 0x7FFF98 (opcode 24 = JMP), luaK_prefix emits opcode 0x15
  // for unary minus, luaK_posfix emits 0x17 for concat, luaK_self emits 0x0B,
  // patchlistaux tests for 0x1C, and the comparison dispatch table at
  // 0x00D45640 holds { 25, 25, 26, 27, 26, 27 } for OPR_NE..OPR_GE. The
  // opmode table below independently agrees: its "test" bit (0x80) is set for
  // exactly 25, 26, 27, 28 and 33 - EQ, LT, LE, TEST and TFORLOOP.
  constexpr std::int32_t OP_MOVE = 0x00;
  constexpr std::int32_t OP_LOADK = 0x01;
  constexpr std::int32_t OP_LOADBOOL = 0x02;
  constexpr std::int32_t OP_LOADNIL = 0x03;
  constexpr std::int32_t OP_GETUPVAL = 0x04;
  constexpr std::int32_t OP_GETGLOBAL = 0x05;
  constexpr std::int32_t OP_GETTABLE = 0x06;
  constexpr std::int32_t OP_SETGLOBAL = 0x07;
  constexpr std::int32_t OP_SETUPVAL = 0x08;
  constexpr std::int32_t OP_SETTABLE = 0x09;
  constexpr std::int32_t OP_NEWTABLE = 0x0A;
  constexpr std::int32_t OP_SELF = 0x0B;
  constexpr std::int32_t OP_ADD = 0x0C;
  constexpr std::int32_t OP_UNM = 0x15;
  constexpr std::int32_t OP_NOT = 0x16;
  constexpr std::int32_t OP_CONCAT = 0x17;
  constexpr std::int32_t OP_JMP = 0x18;
  constexpr std::int32_t OP_EQ = 0x19;
  constexpr std::int32_t OP_LT = 0x1A;
  constexpr std::int32_t OP_LE = 0x1B;
  constexpr std::int32_t OP_TEST = 0x1C;
  constexpr std::int32_t OP_CALL = 0x1D;
  constexpr std::int32_t OP_TAILCALL = 0x1E;
  constexpr std::int32_t OP_RETURN = 0x1F;
  constexpr std::int32_t OP_FORLOOP = 0x20;
  constexpr std::int32_t OP_TFORLOOP = 0x21;
  constexpr std::int32_t OP_TFORPREP = 0x22;
  constexpr std::int32_t OP_SETLIST = 0x23;
  constexpr std::int32_t OP_SETLISTO = 0x24;
  constexpr std::int32_t OP_CLOSE = 0x25;
  constexpr std::int32_t OP_CLOSURE = 0x26;
  constexpr std::int32_t OP_SUB = 0x0D;
  constexpr std::int32_t LFIELDS_PER_FLUSH = 0x20;

  // Parser ceilings.
  constexpr std::int32_t MAXVARS = 0xC8;            // locals per function
  constexpr std::int32_t MAXPARAMS = 0x64;          // declared parameters
  constexpr std::int32_t MAXUPVALUES = 0x20;        // upvalues per closure
  constexpr std::int32_t MAXEXPWHILE = 0x64;        // instructions in a rotated `while' condition
  constexpr std::int32_t LUA_MAXPARSERLEVEL = 0xC8; // nested chunks

  constexpr std::int32_t kLuaEndOfStream = -1;
  constexpr std::int32_t MAXSTACK = 0xFA;
  // Lua's MAX_INT: INT_MAX-2, kept clear of the maximum so `n+1` and `n+2`
  // stay representable.
  constexpr std::int32_t MAX_INT = 0x7FFFFFFD;

  // Instruction field geometry (lopcodes.h in the original tree).
  constexpr int kSizeOp = 6;
  constexpr int kSizeC = 9;
  constexpr int kSizeB = 9;
  constexpr int kSizeBx = kSizeC + kSizeB;
  constexpr int kPosC = kSizeOp;
  constexpr int kPosBx = kPosC;
  constexpr int kPosB = kPosC + kSizeC;
  constexpr int kPosA = kPosB + kSizeB;
  constexpr std::int32_t LUA_MAXARG_Bx = (1 << kSizeBx) - 1;
  constexpr std::int32_t LUA_MAXARG_sBx = LUA_MAXARG_Bx >> 1;
  constexpr std::int32_t MAXARG_A = (1 << 8) - 1;
  constexpr std::int32_t MAXARG_B = (1 << kSizeB) - 1;
  constexpr std::int32_t MAXARG_C = (1 << kSizeC) - 1;

  [[nodiscard]] constexpr std::int32_t GET_OPCODE(const Instruction i) noexcept
  {
    return static_cast<std::int32_t>(i & ((1u << kSizeOp) - 1u));
  }

  [[nodiscard]] constexpr std::int32_t GETARG_A(const Instruction i) noexcept
  {
    return static_cast<std::int32_t>((i >> kPosA) & MAXARG_A);
  }

  [[nodiscard]] constexpr std::int32_t GETARG_B(const Instruction i) noexcept
  {
    return static_cast<std::int32_t>((i >> kPosB) & MAXARG_B);
  }

  [[nodiscard]] constexpr std::int32_t GETARG_C(const Instruction i) noexcept
  {
    return static_cast<std::int32_t>((i >> kPosC) & MAXARG_C);
  }

  [[nodiscard]] constexpr std::int32_t GETARG_sBx(const Instruction i) noexcept
  {
    return static_cast<std::int32_t>((i >> kPosBx) & LUA_MAXARG_Bx) - LUA_MAXARG_sBx;
  }

  constexpr void SETARG_A(Instruction& i, const std::int32_t a) noexcept
  {
    i = (i & ~(static_cast<Instruction>(MAXARG_A) << kPosA))
      | (static_cast<Instruction>(a) << kPosA);
  }

  constexpr void SETARG_B(Instruction& i, const std::int32_t b) noexcept
  {
    i = (i & ~(static_cast<Instruction>(MAXARG_B) << kPosB))
      | (static_cast<Instruction>(b) << kPosB);
  }

  constexpr void SETARG_C(Instruction& i, const std::int32_t c) noexcept
  {
    i = (i & ~(static_cast<Instruction>(MAXARG_C) << kPosC))
      | (static_cast<Instruction>(c) << kPosC);
  }

  constexpr void SETARG_sBx(Instruction& i, const std::int32_t offset) noexcept
  {
    i = (i & ~(static_cast<Instruction>(LUA_MAXARG_Bx) << kPosBx))
      | (static_cast<Instruction>(offset + LUA_MAXARG_sBx) << kPosBx);
  }

  [[nodiscard]] constexpr Instruction
  CREATE_ABC(const std::int32_t o, const std::int32_t a, const std::int32_t b, const std::int32_t c) noexcept
  {
    return static_cast<Instruction>(o)
      | (static_cast<Instruction>(a) << kPosA)
      | (static_cast<Instruction>(b) << kPosB)
      | (static_cast<Instruction>(c) << kPosC);
  }

  [[nodiscard]] constexpr Instruction
  CREATE_ABx(const std::int32_t o, const std::int32_t a, const std::uint32_t bx) noexcept
  {
    return static_cast<Instruction>(o)
      | (static_cast<Instruction>(a) << kPosA)
      | (static_cast<Instruction>(bx) << kPosBx);
  }
  constexpr std::int32_t OPR_ADD = 0x00;
  constexpr std::int32_t OPR_SUB = 0x01;
  constexpr std::int32_t OPR_MULT = 0x02;
  constexpr std::int32_t OPR_DIV = 0x03;
  constexpr std::int32_t OPR_BAND = 0x04;
  constexpr std::int32_t OPR_BOR = 0x05;
  constexpr std::int32_t OPR_BSHL = 0x06;
  constexpr std::int32_t OPR_BSHR = 0x07;
  constexpr std::int32_t OPR_POW = 0x08;
  constexpr std::int32_t OPR_CONCAT = 0x09;
  constexpr std::int32_t OPR_NE = 0x0A;
  constexpr std::int32_t OPR_EQ = 0x0B;
  constexpr std::int32_t OPR_LT = 0x0C;
  constexpr std::int32_t OPR_LE = 0x0D;
  constexpr std::int32_t OPR_GT = 0x0E;
  constexpr std::int32_t OPR_GE = 0x0F;
  constexpr std::int32_t OPR_AND = 0x10;
  constexpr std::int32_t OPR_OR = 0x11;
  constexpr std::int32_t OPR_NOBINOPR = 0x12;
  constexpr std::int32_t OPR_MINUS = 0x00;
  constexpr std::int32_t OPR_NOT = 0x01;
  constexpr std::int32_t OPR_NOUNOPR = 0x02;
  // Token codes. The reserved words come first in alphabetical order starting
  // at FIRST_RESERVED, so the numbering is fixed by the keyword list - which
  // for this build carries FAF's extra `continue`, shifting everything from
  // `do` onwards by one relative to stock Lua 5.0.2. Read back from the token
  // name table the lexer indexes at 0x00D45C0C[token].
  constexpr std::int32_t FIRST_RESERVED = 0x101;
  constexpr std::int32_t TK_AND = 0x101;
  constexpr std::int32_t TK_BREAK = 0x102;
  constexpr std::int32_t TK_CONTINUE = 0x103;
  constexpr std::int32_t TK_DO = 0x104;
  constexpr std::int32_t TK_ELSE = 0x105;
  constexpr std::int32_t TK_ELSEIF = 0x106;
  constexpr std::int32_t TK_END = 0x107;
  constexpr std::int32_t TK_FALSE = 0x108;
  constexpr std::int32_t TK_FOR = 0x109;
  constexpr std::int32_t TK_FUNCTION = 0x10A;
  constexpr std::int32_t TK_IF = 0x10B;
  constexpr std::int32_t TK_IN = 0x10C;
  constexpr std::int32_t TK_LOCAL = 0x10D;
  constexpr std::int32_t TK_NIL = 0x10E;
  constexpr std::int32_t TK_NOT = 0x10F;
  constexpr std::int32_t TK_OR = 0x110;
  constexpr std::int32_t TK_REPEAT = 0x111;
  constexpr std::int32_t TK_RETURN = 0x112;
  constexpr std::int32_t TK_THEN = 0x113;
  constexpr std::int32_t TK_TRUE = 0x114;
  constexpr std::int32_t TK_UNTIL = 0x115;
  constexpr std::int32_t TK_WHILE = 0x116;
  constexpr std::int32_t TK_NAME = 0x117;
  constexpr std::int32_t TK_CONCAT = 0x118;
  constexpr std::int32_t TK_DOTS = 0x119;
  constexpr std::int32_t TK_EQ = 0x11A;
  constexpr std::int32_t TK_GE = 0x11B;
  constexpr std::int32_t TK_LE = 0x11C;
  constexpr std::int32_t TK_NE = 0x11D;
  constexpr std::int32_t TK_NUMBER = 0x11E;
  constexpr std::int32_t TK_STRING = 0x11F;
  constexpr std::int32_t TK_BSHL = 0x120;
  constexpr std::int32_t TK_BSHR = 0x121;
  constexpr std::int32_t TK_EOS = 0x122;
  constexpr std::int32_t UNARY_PRIORITY = 8;

  // Printable names, in token order from FIRST_RESERVED. Mirrors the table the
  // binary indexes at 0x00D45C0C[token].
  constexpr std::array<const char*, (TK_EOS - FIRST_RESERVED) + 1> luaX_tokens{
    "and", "break", "continue", "do", "else", "elseif", "end", "false", "for",
    "function", "if", "in", "local", "nil", "not", "or", "repeat", "return",
    "then", "true", "until", "while",
    "*name", "..", "...", "==", ">=", "<=", "~=", "*number", "*string",
    "<<", ">>", "<eof>"
  };

  // LuaPlus's parser records the left and right binding powers as one
  // two-byte pair per BinOpr. std::pair expresses that source-level record
  // without introducing another recovered layout type.
  using BinaryOperatorPriority = std::pair<std::uint8_t, std::uint8_t>;
  constexpr std::array<BinaryOperatorPriority, OPR_NOBINOPR> kBinaryOperatorPriorities{{
    {6, 6}, {6, 6}, {7, 7}, {7, 7},
    {8, 8}, {8, 8}, {8, 8}, {8, 8},
    {10, 9}, {5, 4},
    {3, 3}, {3, 3},
    {3, 3}, {3, 3}, {3, 3}, {3, 3},
    {2, 2}, {1, 1}
  }};
  static_assert(kBinaryOperatorPriorities.size() == OPR_NOBINOPR);

  constexpr unsigned char kLuaOpcodeModes[] = {
    0x24, 0x61, 0x20, 0x24, 0x20, 0x61, 0x34, 0x41, 0x00, 0x18,
    0x20, 0x34, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38, 0x38,
    0x38, 0x24, 0x24, 0x34, 0x02, 0x98, 0x98, 0x98, 0xA4, 0x00,
    0x00, 0x00, 0x02, 0x80, 0x02, 0x01, 0x01, 0x00, 0x21
  };

  [[nodiscard]] constexpr bool LuaOpcodeNeedsFollowingJump(const Instruction instruction)
  {
    const std::size_t opcode = static_cast<std::size_t>(instruction & 0x3Fu);
    return opcode < (sizeof(kLuaOpcodeModes) / sizeof(kLuaOpcodeModes[0]))
      && ((kLuaOpcodeModes[opcode] & 0x80u) != 0u);
  }

  /**
   * Address: 0x009100A0 (FUN_009100A0, getjumpcontrol)
   *
   * What it does:
   * Returns the instruction lane that controls jump semantics for `pc`,
   * stepping back one slot when the prior opcode is a test-with-following-jump.
   */
  [[nodiscard]] Instruction* LuaResolveControllingInstruction(FuncState* const fs, const std::int32_t pc) noexcept
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Instruction* controllingInstruction = &fsView->f->code[pc];
    if (pc >= 1 && LuaOpcodeNeedsFollowingJump(*(controllingInstruction - 1))) {
      --controllingInstruction;
    }
    return controllingInstruction;
  }

  /**
   * Address: 0x00910150 (FUN_00910150, patchtestreg)
   *
   * What it does:
   * Patches one Lua test-instruction A-register lane; when `registerIndex`
   * equals `NO_REG` (`0xFF`), keeps the existing encoded register value.
   */
  void LuaPatchTestRegisterField(std::int32_t registerIndex, Instruction* const instructionSlot) noexcept
  {
    if (registerIndex == NO_REG) {
      registerIndex = GETARG_B(*instructionSlot);
    }

    SETARG_A(*instructionSlot, registerIndex);
  }

  /**
   * Address: 0x00912F00 (FUN_00912F00, isinstack)
   *
   * What it does:
   * Returns `1` when `stackValue` is within one call frame stack window
   * `[base, top)`; returns `0` otherwise.
   */
  [[nodiscard]] std::int32_t isinstack(CallInfo* const callInfo, LuaPlus::TObject* const stackValue)
  {
    LuaPlus::StkId cursor = callInfo->base;
    const LuaPlus::StkId top = callInfo->top;
    while (cursor < top) {
      if (cursor == stackValue) {
        return 1;
      }
      ++cursor;
    }
    return 0;
  }

  /**
   * Address: 0x009103C0 (FUN_009103C0, freereg)
   *
   * What it does:
   * Releases one register lane when it is outside the active-local range and
   * below the Lua max stack sentinel.
   */
  void freereg(FuncState* const fs, const std::int32_t registerIndex)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    if (registerIndex >= fsView->nactvar && registerIndex < MAXSTACK) {
      --fsView->freereg;
    }
  }

  /**
   * Address: 0x009103E0 (FUN_009103E0, freeexp)
   *
   * What it does:
   * Releases one expression register lane when expression kind is
   * non-relocatable.
   */
  void freeexp(expdesc* const expression, FuncState* const fs)
  {
    if (expression->k == VNONRELOC) {
      freereg(fs, expression->info);
    }
  }

  void singlevaraux(FuncState* fs, TString* name, expdesc* outVariable, int base);
  std::int32_t explist1(LexState* ls, expdesc* expression);
  void lastlistfield(FuncState* fs, ConsControl* cc);
  void adjustlocalvars(LexState* ls, int nvars);
  void adjust_assign(LexState* ls, int nvars, expdesc* expression, int nexps);
  void check_conflict(LHS_assign* lhs, LexState* ls, expdesc* value);
  void pushclosure(expdesc* outExpression, LexState* ls, FuncState* childFunction);
  void open_func(LexState* ls, FuncState* fs);
  FuncState* close_func(LexState* ls);
  void ifstat(LexState* ls, std::int32_t line);
  void funcstat(LexState* ls, int line);
  void exprstat(LexState* ls);
  void enterblock(FuncState* fs, BlockCntRuntimeView* bl, std::int32_t isbreakable);
  void leaveblock(FuncState* fs);
  void new_localvar(LexState* ls, TString* name, int n);
  void parlist(LexState* ls);
  std::int32_t statement(LexState* ls);

  extern "C"
  {
    void next(LexState* ls);
    void cond(LexState* ls, expdesc* v);
    void check(LexState* ls, std::int32_t c);
    void block(LexState* ls);
    void check_match(LexState* ls, std::int32_t what, std::int32_t who, std::int32_t where);

    /**
     * Address: 0x0091C680 (FUN_0091C680, subexpr)
     *
     * What it does:
     * Parses unary and binary expressions with Lua's precedence and
     * associativity rules, returning the first operator left for its caller.
     */
    std::int32_t subexpr(LexState* ls, expdesc* expression, std::int32_t limit);

    void assignment(LexState* ls, LHS_assign* lhs, std::int32_t nvars);
    std::int32_t luaK_code(FuncState* fs, Instruction i, int line);
    std::int32_t luaK_jump(FuncState* fs);
    void luaK_concat(FuncState* fs, std::int32_t* l1, std::int32_t l2);
    void luaK_patchtohere(FuncState* fs, std::int32_t list);
    void luaK_reserveregs(FuncState* fs, int n);
    std::int32_t luaK_stringK(FuncState* fs, TString* stringToken);
    void removevars(LexState* ls, int limit);
    void* luaM_realloc(lua_State* L, void* oldblock, lu_mem oldsize, lu_mem size);
    void* luaM_growaux(lua_State* L, void* block, int* size, int sizeElem, int limit, const char* what);
    std::int32_t luaK_codeABC(FuncState* fs, int o, int a, int b, int c);
    std::int32_t luaK_codeABx(FuncState* fs, int o, int a, unsigned int bc);
    void luaK_dischargevars(FuncState* fs, expdesc* e);
    void discharge2anyreg(FuncState* fs, expdesc* e);
    void luaK_setcallreturns(FuncState* fs, expdesc* e, int nresults);
    void luaK_nil(FuncState* fs, int from, int n);
    void luaK_exp2nextreg(FuncState* fs, expdesc* e);
    std::int32_t luaK_numberK(FuncState* fs, float r);
    std::int32_t jumponcond(FuncState* fs, int cond, expdesc* e);
    void invertjump(FuncState* fs, expdesc* e);
    void luaC_collectgarbage(lua_State* L);
    void luaD_growstack(lua_State* L, int n);
    Proto* luaF_newproto(lua_State* L);
    Table* luaH_new(lua_State* L, int narray, int lnhash);
    LClosure* luaF_newLclosure(lua_State* L, int nelems, LuaPlus::TObject* e);
    Proto* luaU_undump(lua_State* state, LuaUndumpZioRuntimeView* stream, Mbuffer* buffer);
    Proto* luaY_parser(lua_State* L, LuaUndumpZioRuntimeView* z, Mbuffer* buff);
    std::int32_t luaX_lex(LexState* ls, SemInfo* seminfo);
    std::int32_t indexupvalue(FuncState* fs, expdesc* value, TString* name);
    TString* str_checkname(LexState* ls);
    void luaX_syntaxerror(LexState* ls, const char* msg);
    void luaY_field(LexState* ls, expdesc* outExpression);
    void luaK_storevar(FuncState* fs, expdesc* outVariableExpression, expdesc* valueExpression);
    void luaK_fixline(FuncState* fs, int line);
    void codestring(TString* stringToken, LexState* ls, expdesc* outExpression);
    void constructor(expdesc* outExpression, LexState* ls);
    void body(LexState* ls, expdesc* outExpression, int needself, int line);
    void primaryexp(expdesc* outExpression, LexState* ls);
    std::int32_t luaZ_fill(LuaZioRuntimeView* stream);
    void luaO_chunkid(char* out, const char* source, int bufflen);
    int luaO_log2(unsigned int x);
    int luaO_str2d(const char* s, float* result);
    void inclinenumber(LexState* ls);
    std::int32_t read_numeral(LexState* ls, int period, SemInfo* seminfo);
    void read_long_string(LexState* ls, SemInfo* seminfo);
    void read_string(LexState* ls, int del, SemInfo* seminfo);
    unsigned int luaO_int2fb(unsigned int x);
    void funcargs(LexState* ls, expdesc* f);
    void recfield(LexState* ls, ConsControl* cc);
    void prefixexp(LexState* ls, expdesc* v);
    void error_expected(LexState* ls, std::int32_t token);
    void luaY_index(LexState* ls, expdesc* v);
    void luaK_self(FuncState* fs, expdesc* e, expdesc* key);
    void luaK_patchlist(FuncState* fs, std::int32_t list, std::int32_t target);
    void luaX_setinput(lua_State* L, LexState* ls, LuaUndumpZioRuntimeView* z, TString* source);
    void chunk(LexState* ls);
    void f_parser(SParser* parser, lua_State* state);
    int luaI_registerlocalvar(LexState* ls, TString* varname);
    void new_localvarstr(const char* name, LexState* ls, int n);
    void code_params(LexState* ls, int nparams, int dots);
    void cond(LexState* ls, expdesc* v);
    void test_then_block(LexState* ls, expdesc* v);
    void forbody(LexState* ls, int base, int line, int nvars, int isnum);
    TString* luaS_newlstr(lua_State* L, const char* str, std::size_t len);
    char* luaZ_openspace(lua_State* L, Mbuffer* buff, std::size_t n);
    void luaG_runerror(lua_State* L, const char* format, ...);
    int luaK_exp2anyreg(FuncState* fs, expdesc* e);
    void luaK_indexed(FuncState* fs, expdesc* t, expdesc* k);
    void luaK_prefix(FuncState* fs, std::int32_t op, expdesc* expression);
    void luaK_infix(FuncState* fs, std::int32_t op, expdesc* expression);
    void luaK_posfix(
      FuncState* fs,
      std::int32_t op,
      expdesc* leftExpression,
      expdesc* rightExpression
    );
  }

  // ---------------------------------------------------------------------
  // llex.c - error reporting and limit checks.
  //
  // luaX_errorline throws, and these carry C language linkage so they replace
  // the same symbols in the prebuilt LuaPlus library; MSVC warns about the
  // combination under /EHc even though the throw is exactly what the binary
  // does.
  // ---------------------------------------------------------------------
#pragma warning(push)
#pragma warning(disable : 4297) // function assumed not to throw but does

  /**
   * Address: 0x00918120 (FUN_00918120, luaX_token2str)
   *
   * IDA signature:
   * const char *__cdecl luaX_token2str(LexState *ls, int token);
   *
   * What it does:
   * Names a token for an error message: reserved words and multi-character
   * symbols come from the token table, single characters are formatted into a
   * fresh Lua string.
   */
  extern "C" const char* luaX_token2str(LexState* const ls, const int token)
  {
    if (token < FIRST_RESERVED) {
      return luaO_pushfstring(ls->L, "%c", token);
    }
    return luaX_tokens[static_cast<std::size_t>(token - FIRST_RESERVED)];
  }

  /**
   * Address: 0x00918310 (FUN_00918310, luaX_errorline)
   *
   * IDA signature:
   * void __cdecl __noreturn luaX_errorline(LexState *ls, const char *s,
   *                                        const char *token, int line);
   *
   * What it does:
   * Builds "<chunk>(<line>): <message> near `<token>'", pushes it on the Lua
   * stack and throws it as a syntax error.
   */
  extern "C" void
  luaX_errorline(LexState* const ls, const char* const s, const char* const token, const int line)
  {
    // llex.c's own cap on how much of a chunk name an error may quote; this is
    // MAXSRC, not the (smaller) LUA_IDSIZE that lua_Debug::short_src uses.
    constexpr int kMaxSourceNameLength = 80;

    lua_State* const L = ls->L;
    char buff[kMaxSourceNameLength];
    luaO_chunkid(buff, ls->source->str, kMaxSourceNameLength);
    luaO_pushfstring(L, "%s(%d): %s near `%s'", buff, line, s, token);
    throw lua_SyntaxError(lua::lua_Error(L, LUA_ERRSYNTAX));
  }

  /**
   * Address: 0x009183B0 (FUN_009183B0, luaX_syntaxerror)
   *
   * What it does:
   * Reports `msg` against whatever the lexer is currently looking at. Names and
   * literals quote their own text - the literal straight out of the lexer's
   * scratch buffer, since its token value carries no string - everything else
   * is named through the token table.
   */
  extern "C" void luaX_syntaxerror(LexState* const ls, const char* const msg)
  {
    const char* lasttoken = nullptr;
    switch (ls->t.token) {
    case TK_NAME:
      lasttoken = ls->t.seminfo.ts->str;
      break;

    case TK_STRING:
    case TK_NUMBER:
      lasttoken = static_cast<Mbuffer*>(ls->buff)->buffer;
      break;

    default:
      lasttoken = luaX_token2str(ls, ls->t.token);
      break;
    }

    luaX_errorline(ls, msg, lasttoken, ls->linenumber);
  }

  /**
   * Address: 0x009188F0 (FUN_009188F0, luaX_checklimit)
   *
   * What it does:
   * Raises "too many <what> (limit=<n>)" when a compile-time count runs past
   * one of the parser's fixed ceilings.
   */
  extern "C" void luaX_checklimit(LexState* const ls, const int val, const int limit, const char* const msg)
  {
    if (val > limit) {
      luaX_syntaxerror(ls, luaO_pushfstring(ls->L, "too many %s (limit=%d)", msg, limit));
    }
  }

#pragma warning(pop)

  /**
   * What it does:
   * Reads the next source character into `ls->current`, refilling the stream
   * buffer when it runs dry. This is llex.c's `next` macro; the parser's `next`
   * is a different thing (luaX_next, which reads a whole token).
   */
  std::size_t ReadIdentifierName(char firstCharacter, LexState* lexState);

  /**
   * What it does:
   * True for a lowercased hexadecimal digit.
   */
  [[nodiscard]] constexpr bool IsHexDigit(const int lowercased) noexcept
  {
    return (lowercased >= '0' && lowercased <= '9') || (lowercased >= 'a' && lowercased <= 'f');
  }

  std::int32_t nextchar(LexState* const ls)
  {
    auto* const z = static_cast<LuaZioRuntimeView*>(ls->z);
    const std::uint32_t remaining = static_cast<std::uint32_t>(z->remainingBytes--);
    ls->current = (remaining > 0u)
      ? static_cast<unsigned char>(*z->cursor++)
      : luaZ_fill(z);
    return ls->current;
  }

  // ---------------------------------------------------------------------
  // llex.c - the scanner.
  //
  // Literals are assembled in the shared LexState scratch buffer, which grows
  // on demand; `l` is the write cursor throughout, matching the original's
  // save()/checkbuffer() macro pair.
  // ---------------------------------------------------------------------

  /**
   * What it does:
   * Makes room in the token scratch buffer for `length` bytes plus the slack
   * the readers write past the cursor (llex.c's checkbuffer).
   */
  void checkbuffer(LexState* const ls, const std::int32_t length)
  {
    auto* const buff = static_cast<Mbuffer*>(ls->buff);
    if (static_cast<std::size_t>(length + 5) > buff->buffsize) {
      (void)luaZ_openspace(ls->L, buff, static_cast<std::size_t>(length + 32));
    }
  }

  [[nodiscard]] char* lexbuffer(LexState* const ls) noexcept
  {
    return static_cast<Mbuffer*>(ls->buff)->buffer;
  }

  /**
   * Address: 0x00918920 (FUN_00918920, inclinenumber)
   *
   * What it does:
   * Steps over a newline and bumps the line counter.
   */
  extern "C" void inclinenumber(LexState* const ls)
  {
    nextchar(ls); // skip the '\n'
    ++ls->linenumber;
    if (ls->linenumber > MAX_INT) {
      luaX_syntaxerror(ls, luaO_pushfstring(ls->L, "too many %s (limit=%d)", "lines in a chunk", MAX_INT));
    }
  }

  /**
   * Address: 0x00918440 (FUN_00918440, read_numeral)
   *
   * IDA signature:
   * int __usercall read_numeral(LexState *LS, int period, SemInfo *seminfo);
   *
   * What it does:
   * Scans a numeric literal. `period` says the leading '.' was already
   * consumed. A `0x` prefix is scanned here as up to eight hex digits - this
   * build accepts hex literals, stock Lua 5.0 does not - and everything else is
   * assembled as text and handed to luaO_str2d.
   */
  extern "C" std::int32_t read_numeral(LexState* const ls, const int period, SemInfo* const seminfo)
  {
    std::int32_t l = 0;
    bool isReal = false;
    const bool startWithZero = (ls->current == '0');

    checkbuffer(ls, 0);
    if (period != 0) {
      lexbuffer(ls)[l++] = '.';
      isReal = true;
    }

    if (startWithZero) {
      nextchar(ls); // skip the '0'
      if (ls->current == 'x') {
        nextchar(ls); // skip the 'x'
        std::int32_t value = 0;
        std::int32_t digits = 0;
        do {
          const int c = std::tolower(ls->current);
          if (std::isdigit(c) != 0) {
            value = value * 16 + (c - '0');
          } else if (c >= 'a' && c <= 'f') {
            value = value * 16 + (c - 'a' + 10);
          }
          nextchar(ls);
          ++digits;
        } while (digits < 8 && IsHexDigit(std::tolower(ls->current)));

        seminfo->r = static_cast<float>(value);
        return TK_NUMBER;
      }

      checkbuffer(ls, 1);
      lexbuffer(ls)[l++] = '0';
    }

    while (std::isdigit(ls->current) != 0) {
      checkbuffer(ls, l);
      lexbuffer(ls)[l++] = static_cast<char>(ls->current);
      nextchar(ls);
    }

    if (ls->current == '.') {
      lexbuffer(ls)[l++] = static_cast<char>(ls->current);
      isReal = true;
      nextchar(ls);
      if (ls->current == '.') {
        // `1..x' could be a malformed number or a concatenation; either way the
        // author has to say which.
        lexbuffer(ls)[l++] = '.';
        nextchar(ls);
        lexbuffer(ls)[l] = '\0';
        luaX_errorline(
          ls,
          "ambiguous syntax (decimal point x string concatenation)",
          lexbuffer(ls),
          ls->linenumber
        );
      }
    }

    while (std::isdigit(ls->current) != 0) {
      checkbuffer(ls, l);
      lexbuffer(ls)[l++] = static_cast<char>(ls->current);
      nextchar(ls);
    }

    if (ls->current == 'e' || ls->current == 'E') {
      lexbuffer(ls)[l++] = static_cast<char>(ls->current);
      isReal = true;
      nextchar(ls);
      if (ls->current == '+' || ls->current == '-') {
        lexbuffer(ls)[l++] = static_cast<char>(ls->current); // optional exponent sign
        nextchar(ls);
      }
      while (std::isdigit(ls->current) != 0) {
        checkbuffer(ls, l);
        lexbuffer(ls)[l++] = static_cast<char>(ls->current);
        nextchar(ls);
      }
    }

    lexbuffer(ls)[l] = '\0';
    if (luaO_str2d(lexbuffer(ls), &seminfo->r) == 0) {
      luaX_errorline(ls, isReal ? "malformed number" : "malformed integer", lexbuffer(ls), ls->linenumber);
    }
    return TK_NUMBER;
  }

  /**
   * Address: 0x00918980 (FUN_00918980, read_long_string)
   *
   * IDA signature:
   * void __usercall read_long_string(LexState *LS@<eax>, SemInfo *seminfo);
   *
   * What it does:
   * Scans a `[[ ... ]]` literal, honouring nesting. A null `seminfo` means this
   * is a long comment, in which case the text is discarded and the buffer is
   * reset at every newline so a long comment costs no memory.
   */
  extern "C" void read_long_string(LexState* const ls, SemInfo* const seminfo)
  {
    std::int32_t cont = 0;
    std::int32_t l = 0;

    checkbuffer(ls, 0);
    lexbuffer(ls)[l++] = '['; // save first '['
    lexbuffer(ls)[l++] = static_cast<char>(ls->current); // save second '['
    nextchar(ls); // skip the second '['
    if (ls->current == '\n') {
      inclinenumber(ls); // skip a newline right after the opening bracket
    }

    for (;;) {
      checkbuffer(ls, l);
      switch (ls->current) {
      case kLuaEndOfStream:
        lexbuffer(ls)[l] = '\0';
        luaX_errorline(
          ls,
          (seminfo != nullptr) ? "unfinished long string" : "unfinished long comment",
          "<eof>",
          ls->linenumber
        );
        break;

      case '[':
        lexbuffer(ls)[l++] = static_cast<char>(ls->current);
        nextchar(ls);
        if (ls->current == '[') {
          ++cont;
          lexbuffer(ls)[l++] = static_cast<char>(ls->current);
          nextchar(ls);
        }
        break;

      case ']':
        lexbuffer(ls)[l++] = static_cast<char>(ls->current);
        nextchar(ls);
        if (ls->current == ']') {
          if (cont == 0) {
            lexbuffer(ls)[l++] = static_cast<char>(ls->current);
            nextchar(ls);
            lexbuffer(ls)[l] = '\0';
            if (seminfo != nullptr) {
              // trim the two brackets off each end
              seminfo->ts = luaS_newlstr(ls->L, lexbuffer(ls) + 2, static_cast<std::size_t>(l - 4));
            }
            return;
          }
          --cont;
          lexbuffer(ls)[l++] = static_cast<char>(ls->current);
          nextchar(ls);
        }
        break;

      case '\n':
        lexbuffer(ls)[l++] = '\n';
        inclinenumber(ls);
        if (seminfo == nullptr) {
          l = 0; // a comment keeps nothing, so reuse the buffer
        }
        break;

      default:
        lexbuffer(ls)[l++] = static_cast<char>(ls->current);
        nextchar(ls);
        break;
      }
    }
  }

  /**
   * Address: 0x00918C40 (FUN_00918C40, read_string)
   *
   * IDA signature:
   * TString *__usercall read_string@<eax>(LexState *LS@<eax>, int del, SemInfo *seminfo);
   *
   * What it does:
   * Scans a quoted string, resolving escapes. Alongside stock Lua's named and
   * decimal escapes this build accepts `\xNN`.
   */
  extern "C" void read_string(LexState* const ls, const int del, SemInfo* const seminfo)
  {
    std::int32_t l = 0;

    checkbuffer(ls, 0);
    lexbuffer(ls)[l++] = static_cast<char>(ls->current); // save the delimiter
    nextchar(ls);

    while (ls->current != del) {
      checkbuffer(ls, l);
      switch (ls->current) {
      case kLuaEndOfStream:
        lexbuffer(ls)[l] = '\0';
        luaX_errorline(ls, "unfinished string", "<eof>", ls->linenumber);
        break;

      case '\n':
        lexbuffer(ls)[l] = '\0';
        luaX_errorline(ls, "unfinished string", lexbuffer(ls), ls->linenumber);
        break;

      case '\\': {
        nextchar(ls); // do not save the '\'
        switch (ls->current) {
        case 'a': lexbuffer(ls)[l++] = '\a'; nextchar(ls); break;
        case 'b': lexbuffer(ls)[l++] = '\b'; nextchar(ls); break;
        case 'f': lexbuffer(ls)[l++] = '\f'; nextchar(ls); break;
        case 'n': lexbuffer(ls)[l++] = '\n'; nextchar(ls); break;
        case 'r': lexbuffer(ls)[l++] = '\r'; nextchar(ls); break;
        case 't': lexbuffer(ls)[l++] = '\t'; nextchar(ls); break;
        case 'v': lexbuffer(ls)[l++] = '\v'; nextchar(ls); break;

        case '\n':
          lexbuffer(ls)[l++] = '\n';
          inclinenumber(ls);
          break;

        case kLuaEndOfStream:
          break; // will raise an error next loop

        case 'x': {
          nextchar(ls); // skip the 'x'
          if (!IsHexDigit(std::tolower(ls->current))) {
            lexbuffer(ls)[l++] = 'x'; // not an escape after all
            break;
          }

          std::int32_t value = 0;
          std::int32_t digits = 0;
          for (;;) {
            const int c = std::tolower(ls->current);
            if (std::isdigit(c) != 0) {
              value = value * 16 + (c - '0');
            } else if (c >= 'a' && c <= 'f') {
              value = value * 16 + (c - 'a' + 10);
            }
            nextchar(ls);
            if (++digits >= 2 || !IsHexDigit(std::tolower(ls->current))) {
              break;
            }
          }
          lexbuffer(ls)[l++] = static_cast<char>(value);
          break;
        }

        default:
          if (std::isdigit(ls->current) == 0) {
            lexbuffer(ls)[l++] = static_cast<char>(ls->current); // handles \\, \" and \'
            nextchar(ls);
            break;
          }

          std::int32_t value = 0;
          std::int32_t digits = 0;
          do {
            value = value * 10 + (ls->current - '0');
            nextchar(ls);
            ++digits;
          } while (digits < 3 && std::isdigit(ls->current) != 0);

          if (value > UCHAR_MAX) {
            lexbuffer(ls)[l] = '\0';
            luaX_errorline(ls, "escape sequence too large", lexbuffer(ls), ls->linenumber);
          }
          lexbuffer(ls)[l++] = static_cast<char>(value);
          break;
        }
        break;
      }

      default:
        lexbuffer(ls)[l++] = static_cast<char>(ls->current);
        nextchar(ls);
        break;
      }
    }

    lexbuffer(ls)[l++] = static_cast<char>(ls->current); // save the closing delimiter
    nextchar(ls);
    lexbuffer(ls)[l] = '\0';
    // trim the delimiter off each end
    seminfo->ts = luaS_newlstr(ls->L, lexbuffer(ls) + 1, static_cast<std::size_t>(l - 2));
  }

  /**
   * Address: 0x00919100 (FUN_00919100, luaX_lex)
   *
   * IDA signature:
   * int __cdecl luaX_lex(LexState *LS, SemInfo *seminfo);
   *
   * What it does:
   * Produces the next token. Single characters return as themselves, reserved
   * words return their code straight out of the interned string's `reserved`
   * field, and literals fill `seminfo`.
   *
   * Three things here are not stock Lua 5.0: `<<` and `>>` are tokens, `!=` is
   * accepted as a spelling of `~=`, and a UTF-8 byte-order mark at the start of
   * a file is skipped rather than rejected as an invalid character.
   */
  extern "C" std::int32_t luaX_lex(LexState* const ls, SemInfo* const seminfo)
  {
    for (;;) {
      switch (ls->current) {
      case kLuaEndOfStream:
        return TK_EOS;

      case '\n':
        inclinenumber(ls);
        continue;

      case '-':
        nextchar(ls);
        if (ls->current != '-') {
          return '-';
        }
        nextchar(ls);
        if (ls->current == '[') {
          nextchar(ls);
          if (ls->current == '[') {
            read_long_string(ls, nullptr); // long comment
            continue;
          }
        }
        // else short comment: skip to end of line
        while (ls->current != '\n' && ls->current != kLuaEndOfStream) {
          nextchar(ls);
        }
        continue;

      case '[':
        nextchar(ls);
        if (ls->current != '[') {
          return '[';
        }
        read_long_string(ls, seminfo);
        return TK_STRING;

      case '=':
        nextchar(ls);
        if (ls->current != '=') {
          return '=';
        }
        nextchar(ls);
        return TK_EQ;

      case '<':
        nextchar(ls);
        if (ls->current == '<') {
          nextchar(ls);
          return TK_BSHL;
        }
        if (ls->current == '=') {
          nextchar(ls);
          return TK_LE;
        }
        return '<';

      case '>':
        nextchar(ls);
        if (ls->current == '>') {
          nextchar(ls);
          return TK_BSHR;
        }
        if (ls->current == '=') {
          nextchar(ls);
          return TK_GE;
        }
        return '>';

      case '!':
        nextchar(ls);
        if (ls->current != '=') {
          luaX_errorline(ls, "invalid character", "!", ls->linenumber);
        }
        nextchar(ls);
        return TK_NE;

      case '~':
        nextchar(ls);
        if (ls->current != '=') {
          return '~';
        }
        nextchar(ls);
        return TK_NE;

      case '"':
      case '\'':
        read_string(ls, ls->current, seminfo);
        return TK_STRING;

      case '.':
        nextchar(ls);
        if (ls->current == '.') {
          nextchar(ls);
          if (ls->current == '.') {
            nextchar(ls);
            return TK_DOTS; // ...
          }
          return TK_CONCAT; // ..
        }
        if (std::isdigit(ls->current) == 0) {
          return '.';
        }
        return read_numeral(ls, 1, seminfo);

      case '#':
        // `#' to end of line: the shebang guard in luaX_setinput only covers
        // the first line, so treat it as a comment wherever else it appears.
        nextchar(ls);
        while (ls->current != '\n' && ls->current != kLuaEndOfStream) {
          nextchar(ls);
        }
        continue;

      default:
        if ((ls->current & 0x80) != 0) {
          // A UTF-8 byte-order mark is tolerated; any other high byte is not.
          if (ls->current == '\xEF') {
            nextchar(ls);
            if (ls->current == '\xBB') {
              nextchar(ls);
              if (ls->current == '\xBF') {
                nextchar(ls);
                continue;
              }
            }
          }
          luaX_errorline(
            ls,
            "invalid character",
            luaO_pushfstring(ls->L, "char(%d)", ls->current),
            ls->linenumber
          );
          continue;
        }

        if (std::isspace(ls->current) != 0) {
          nextchar(ls);
          continue;
        }

        if (std::isdigit(ls->current) != 0) {
          return read_numeral(ls, 0, seminfo);
        }

        if (std::isalpha(ls->current) != 0 || ls->current == '_') {
          const std::size_t l = ReadIdentifierName(0, ls);
          TString* const ts = luaS_newlstr(ls->L, lexbuffer(ls), l);
          if (ts->reserved != 0) { // reserved word?
            return static_cast<std::int32_t>(ts->reserved) + (FIRST_RESERVED - 1);
          }
          seminfo->ts = ts;
          return TK_NAME;
        }

        {
          const std::int32_t c = ls->current;
          if (std::iscntrl(c) != 0) {
            luaX_errorline(
              ls,
              "invalid control char",
              luaO_pushfstring(ls->L, "char(%d)", c),
              ls->linenumber
            );
          }
          nextchar(ls);
          return c; // single-char tokens (+ - / ...)
        }
      }
    }
  }

  /**
   * Address: 0x0091C4B0 (FUN_0091C4B0, getbinopr)
   *
   * What it does:
   * Maps one lexer token into the parser binary-operator enum lane consumed by
   * sub-expression precedence parsing.
   */
  [[maybe_unused]]
  [[nodiscard]]
  std::int32_t GetBinaryOperatorFromToken(const std::int32_t token) noexcept
  {
    switch (token) {
    case '&':
      return OPR_BAND;
    case '*':
      return OPR_MULT;
    case '+':
      return OPR_ADD;
    case '-':
      return OPR_SUB;
    case '/':
      return OPR_DIV;
    case '<':
      return OPR_LT;
    case '>':
      return OPR_GT;
    case '^':
      return OPR_POW;
    case '|':
      return OPR_BOR;
    case TK_AND:
      return OPR_AND;
    case TK_OR:
      return OPR_OR;
    case TK_CONCAT:
      return OPR_CONCAT;
    case TK_EQ:
      return OPR_EQ;
    case TK_GE:
      return OPR_GE;
    case TK_LE:
      return OPR_LE;
    case TK_NE:
      return OPR_NE;
    case TK_BSHL:
      return OPR_BSHL;
    case TK_BSHR:
      return OPR_BSHR;
    default:
      return OPR_NOBINOPR;
    }
  }

  /**
   * Address: 0x0091AA50 (FUN_0091AA50, next)
   *
   * What it does:
   * Advances the current lexer token, consuming any pending lookahead token
   * before asking the lexer for a fresh token.
   */
  extern "C" void next(LexState* const ls)
  {
    ls->lastline = ls->linenumber;
    if (ls->lookahead.token == TK_EOS) {
      ls->t.token = luaX_lex(ls, &ls->t.seminfo);
      return;
    }

    ls->t.token = ls->lookahead.token;
    ls->t.seminfo = ls->lookahead.seminfo;
    ls->lookahead.token = TK_EOS;
  }

  /**
   * Address: 0x0091AAE0 (FUN_0091AAE0, testnext)
   *
   * What it does:
   * Consumes and returns true for one expected token lane, updating `lastline`
   * and shifting lookahead/current token state with the same fast-path shape as
   * the lexer `next` helper.
   */
  extern "C" int testnext(LexState* const ls, const int expectedToken)
  {
    if (ls->t.token != expectedToken) {
      return 0;
    }

    ls->lastline = ls->linenumber;
    if (ls->lookahead.token == TK_EOS) {
      ls->t.token = luaX_lex(ls, &ls->t.seminfo);
    } else {
      ls->t.token = ls->lookahead.token;
      ls->t.seminfo = ls->lookahead.seminfo;
      ls->lookahead.token = TK_EOS;
    }

    return 1;
  }

  /**
   * Address: 0x0091AD80 (FUN_0091AD80, adjustlocalvars)
   *
   * What it does:
   * Activates `nvars` local-variable lanes in the current function state and
   * stamps each new `LocVar::startpc` with the current program-counter lane.
   */
  void adjustlocalvars(LexState* const ls, int nvars)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    fsView->nactvar += nvars;

    while (nvars != 0) {
      const int activeVariableIndex = fsView->nactvar - nvars;
      const std::int32_t localVariableSlot = fsView->actvar[activeVariableIndex];
      fsView->f->locvars[localVariableSlot].startpc = fsView->pc;
      --nvars;
    }
  }

  /**
   * Address: 0x0091ADC0 (FUN_0091ADC0, removevars)
   *
   * What it does:
   * Closes active locals down to `tolevel` by stamping `LocVar::endpc` with the
   * current PC and shrinking `FuncState::nactvar`.
   */
  extern "C" void removevars(LexState* const ls, const int tolevel)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    while (fsView->nactvar > tolevel) {
      --fsView->nactvar;
      const std::int32_t activeVarSlot = fsView->actvar[fsView->nactvar];
      fsView->f->locvars[activeVarSlot].endpc = fsView->pc;
    }
  }

  /**
   * Address: 0x009181F0 (FUN_009181F0, readname)
   *
   * What it does:
   * Appends one lexer identifier token into the active scratch buffer,
   * consuming `[A-Za-z0-9_]` continuation bytes from the input stream and
   * returning token length.
   */
  std::size_t ReadIdentifierName(const char firstCharacter, LexState* const lexState)
  {
    auto* const buffer = static_cast<Mbuffer*>(lexState->buff);
    std::size_t length = 0;

    if (buffer->buffsize < 5u) {
      (void)luaZ_openspace(lexState->L, buffer, 0x20u);
    }

    if (firstCharacter != '\0') {
      if (buffer->buffsize < 5u) {
        (void)luaZ_openspace(lexState->L, buffer, 0x20u);
      }
      buffer->buffer[0] = firstCharacter;
      length = 1;
    }

    auto* const stream = static_cast<LuaZioRuntimeView*>(lexState->z);
    for (;;) {
      if (length + 5u > buffer->buffsize) {
        (void)luaZ_openspace(lexState->L, buffer, length + 32u);
      }

      buffer->buffer[length] = static_cast<char>(lexState->current);
      ++length;

      std::int32_t nextCharacter = 0;
      const std::int32_t remainingBeforeRead = stream->remainingBytes;
      stream->remainingBytes = remainingBeforeRead - 1;
      if (remainingBeforeRead == 0) {
        nextCharacter = luaZ_fill(stream);
      } else {
        nextCharacter = static_cast<unsigned char>(*stream->cursor);
        ++stream->cursor;
      }

      lexState->current = nextCharacter;
      if (std::isalnum(static_cast<unsigned char>(nextCharacter)) == 0 && nextCharacter != '_') {
        break;
      }
    }

    buffer->buffer[length] = '\0';
    return length;
  }

  /**
   * Address: 0x0091B670 (FUN_0091B670, lastlistfield)
   *
   * What it does:
   * Flushes pending list-constructor value lanes, preserving VCALL/multret
   * semantics for the final list field store.
   */
  void lastlistfield(FuncState* const functionState, ConsControl* const constructorState)
  {
    if (constructorState->tostore == 0) {
      return;
    }

    if (constructorState->v.k == VCALL) {
      luaK_setcallreturns(functionState, &constructorState->v, LUA_MULTRET);
      (void)luaK_codeABx(functionState, 36, constructorState->t->info, constructorState->na - 1);
      reinterpret_cast<FuncStateRuntimeView*>(functionState)->freeRegisterIndex = constructorState->t->info + 1;
      return;
    }

    if (constructorState->v.k != 0) {
      luaK_exp2nextreg(functionState, &constructorState->v);
    }

    (void)luaK_codeABx(functionState, 35, constructorState->t->info, constructorState->na - 1);
    reinterpret_cast<FuncStateRuntimeView*>(functionState)->freeRegisterIndex = constructorState->t->info + 1;
  }

  /**
   * Address: 0x0091B090 (FUN_0091B090, singlevar)
   *
   * What it does:
   * Reads one identifier token and resolves it as local/upvalue/global
   * expression metadata through `singlevaraux`.
   */
  TString* singlevar(LexState* const lexState, expdesc* const outVariable, const int base)
  {
    TString* const name = str_checkname(lexState);
    singlevaraux(lexState->fs, name, outVariable, base);
    return name;
  }

  /**
   * Address: 0x0091AC20 (FUN_0091AC20, str_checkname)
   *
   * IDA signature:
   * TString *__usercall str_checkname@<eax>(LexState *ls@<esi>);
   *
   * What it does:
   * Asserts the current lexer token is `TK_NAME`, captures the semantic-info
   * `TString*`, advances to the next token, and returns the captured
   * identifier.
   */
  extern "C" TString* str_checkname(LexState* const ls)
  {
    if (ls->t.token != TK_NAME) {
      luaX_syntaxerror(ls, "<name> expected");
    }

    TString* const ts = ls->t.seminfo.ts;
    next(ls);
    return ts;
  }

  /**
   * Address: 0x0091B470 (lparser.c::luaY_field, file-local in original Lua)
   *
   * What it does:
   * Parses one `.NAME` / `:NAME` field access: emits the receiver expression
   * to any register, advances past the dot/colon, builds a `VK` constant key
   * for the field name, and forms an indexed access through `luaK_indexed`.
   * Recovered here so `funcname` can resolve the call. The inline-codestring
   * sequence (NO_JUMP `t`/`f`, `VK` kind, `luaK_stringK` index) replaces the
   * original file-local `checkname` helper which is unreachable from the lib.
   */
  extern "C" void luaY_field(LexState* const ls, expdesc* const v)
  {
    FuncState* const fs = ls->fs;
    luaK_exp2anyreg(fs, v);
    next(ls);

    TString* const name = str_checkname(ls);

    expdesc key{};
    key.t = -1;
    key.f = -1;
    key.k = VK;
    key.info = luaK_stringK(fs, name);

    luaK_indexed(fs, v, &key);
  }

  /**
   * Address: 0x0091D850 (FUN_0091D850, funcname)
   *
   * What it does:
   * Parses one function-name lane (`name[.name]*[:name]`) and returns whether
   * method-call sugar (`:`) is present.
   */
  extern "C" std::int32_t funcname(expdesc* const outExpression, LexState* const lexState)
  {
    (void)singlevar(lexState, outExpression, 1);

    while (lexState->t.token == '.') {
      luaY_field(lexState, outExpression);
    }

    if (lexState->t.token != ':') {
      return 0;
    }

    luaY_field(lexState, outExpression);
    return 1;
  }

  /**
   * Address: 0x0091AFB0 (FUN_0091AFB0, singlevaraux)
   *
   * What it does:
   * Resolves one parser identifier lane by searching local variables first,
   * then recursively promoting to upvalue/global descriptors.
   */
  void singlevaraux(FuncState* const fs, TString* const name, expdesc* const outVariable, const int base)
  {
    if (fs == nullptr) {
      outVariable->t = LUA_MULTRET;
      outVariable->f = LUA_MULTRET;
      outVariable->k = VGLOBAL;
      outVariable->info = NO_REG;
      return;
    }

    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    int localIndex = fsView->activeVariableCount - 1;

    while (localIndex >= 0) {
      const std::int32_t activeVariableSlot = fsView->actvar[localIndex];
      if (name == fsView->f->locvars[activeVariableSlot].varname) {
        outVariable->t = LUA_MULTRET;
        outVariable->f = LUA_MULTRET;
        outVariable->k = VLOCAL;
        outVariable->info = localIndex;

        if (base == 0) {
          BlockCntRuntimeView* block = fsView->bl;
          if (block != nullptr) {
            while (block->nactvar > localIndex) {
              block = block->previous;
              if (block == nullptr) {
                return;
              }
            }
            block->upval = 1;
          }
        }
        return;
      }

      --localIndex;
    }

    singlevaraux(fsView->prev, name, outVariable, 0);
    if (outVariable->k == VGLOBAL) {
      if (base != 0) {
        outVariable->info = luaK_stringK(fs, name);
      }
      return;
    }

    outVariable->info = indexupvalue(fs, outVariable, name);
    outVariable->k = VUPVAL;
  }

  /**
   * Address: 0x0091B0C0 (FUN_0091B0C0, adjust_assign)
   *
   * What it does:
   * Balances assignment arity between variable and expression lanes, expanding
   * call returns or emitting trailing nil writes for missing values.
   */
  void adjust_assign(LexState* const ls, const int nvars, expdesc* const expression, const int nexps)
  {
    auto* const functionState = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    int extraRegisters = nvars - nexps;

    if (expression->k == VCALL) {
      ++extraRegisters;
      if (extraRegisters > 0) {
        luaK_reserveregs(ls->fs, extraRegisters - 1);
        luaK_setcallreturns(ls->fs, expression, extraRegisters);
      } else {
        luaK_setcallreturns(ls->fs, expression, 0);
      }
      return;
    }

    if (expression->k != 0) {
      luaK_exp2nextreg(ls->fs, expression);
    }

    if (extraRegisters > 0) {
      const int firstRegister = functionState->freeRegisterIndex;
      luaK_reserveregs(ls->fs, extraRegisters);
      luaK_nil(ls->fs, firstRegister, extraRegisters);
    }
  }

  /**
   * Address: 0x0091B230 (FUN_0091B230, pushclosure)
   *
   * What it does:
   * Appends one nested `Proto` to parent `FuncState::f->p`, emits OP_CLOSURE,
   * then emits one OP_MOVE/OP_GETUPVAL lane for each child upvalue.
   */
  void pushclosure(expdesc* const outExpression, LexState* const ls, FuncState* const childFunction)
  {
    auto* const parentView = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    Proto* const parentProto = parentView->f;
    int& parentProtoCapacity = parentProto->sizep;
    if (parentView->nestedProtoCount + 1 > parentProtoCapacity) {
      parentProto->p = static_cast<Proto**>(
        luaM_growaux(
          ls->L,
          parentProto->p,
          &parentProtoCapacity,
          static_cast<int>(sizeof(Proto*)),
          LUA_MAXARG_Bx,
          "constant table overflow"
        )
      );
    }

    const auto* const childView = reinterpret_cast<const FuncStateRuntimeView*>(childFunction);
    parentProto->p[parentView->nestedProtoCount++] = childView->f;

    outExpression->t = -1;
    outExpression->f = -1;
    outExpression->k = VRELOCABLE;
    outExpression->info = luaK_codeABx(
      ls->fs,
      OP_CLOSURE,
      0,
      static_cast<unsigned int>(parentView->nestedProtoCount - 1)
    );

    const int upvalueCount = static_cast<int>(childView->f->nups);
    for (int index = 0; index < upvalueCount; ++index) {
      const expdesc& upvalue = childView->upvalues[index];
      const std::int32_t opcode = (upvalue.k == VLOCAL) ? OP_MOVE : OP_GETUPVAL;
      luaK_codeABC(ls->fs, opcode, 0, upvalue.info, 0);
    }
  }

  /**
   * Address: 0x009107E0 (FUN_009107E0, luaK_condjump)
   *
   * What it does:
   * Emits one conditional-test opcode and one following jump lane, then links
   * the fresh jump into the pending-jump chain.
   */
  extern "C" std::int32_t
  luaK_condjump(const int a, FuncState* const fs, const int op, const int b, const int c)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);
    const Instruction instruction = static_cast<Instruction>(op | ((c | ((b | (a << 9)) << 9)) << 6));
    luaK_code(fs, instruction, lexState->lastline);

    const std::int32_t previousJpc = fsView->jpc;
    fsView->jpc = NO_JUMP;

    std::int32_t jumpList = luaK_code(fs, static_cast<Instruction>(0x7FFF98u), lexState->lastline);
    luaK_concat(fs, &jumpList, previousJpc);
    return jumpList;
  }

  /**
   * Address: 0x00910940 (FUN_00910940, code_label)
   *
   * What it does:
   * Marks the current bytecode slot as the newest label target and emits one
   * `OP_LOADBOOL` lane with packed `A/B/C` fields.
   */
  extern "C" std::int32_t
  code_label(const int a, FuncState* const fs, const int b, const int c)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);
    fsView->lasttarget = fsView->pc;
    const Instruction instruction = static_cast<Instruction>((((c | ((b | (a << 9)) << 9)) << 6) | 2));
    return luaK_code(fs, instruction, lexState->lastline);
  }

  /**
   * Address: 0x00911380 (FUN_00911380, codebinop)
   *
   * What it does:
   * Lowers one binary-operator lane into bytecode (`OP_*`) or conditional-jump
   * form and stores the resulting expression kind/info lanes.
   */
  // Comparison lowering table at 0x00D45640, indexed by `BinOpr - OPR_NE`.
  // GT/GE reuse the LT/LE opcodes with the operands swapped, and NE reuses EQ
  // with the jump sense inverted, so only three opcodes appear here.
  constexpr std::array<std::int32_t, 6> kComparisonOpcodes{
    OP_EQ, // OPR_NE - taken with cond 0
    OP_EQ, // OPR_EQ
    OP_LT, // OPR_LT
    OP_LE, // OPR_LE
    OP_LT, // OPR_GT - operands swapped
    OP_LE  // OPR_GE - operands swapped
  };

  void codebinop(
    int rightOperand,
    const int binaryOperator,
    int leftOperand,
    expdesc* const result,
    FuncState* const fs
  )
  {
    if (binaryOperator > OPR_POW) {
      int jumpSense = 1;
      if (binaryOperator < OPR_GT) {
        // `a ~= b` is `a == b` with the jump sense flipped.
        jumpSense = (binaryOperator != OPR_NE) ? 1 : 0;
      } else {
        // `a > b` / `a >= b` are `b < a` / `b <= a`.
        std::swap(leftOperand, rightOperand);
      }

      const std::int32_t comparisonOpcode =
        kComparisonOpcodes[static_cast<std::size_t>(binaryOperator - OPR_NE)];
      const int jumpList = luaK_condjump(jumpSense, fs, comparisonOpcode, leftOperand, rightOperand);
      result->k = VJMP;
      result->info = jumpList;
      return;
    }

    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);
    const Instruction instruction =
      CREATE_ABC(binaryOperator + OP_ADD, 0, leftOperand, rightOperand);
    const int opcodeIndex = luaK_code(fs, instruction, lexState->lastline);
    result->k = VRELOCABLE;
    result->info = opcodeIndex;
  }

  /**
   * Address: 0x00910590 (FUN_00910590, invertjump)
   *
   * What it does:
   * Inverts one pending conditional-jump lane by toggling the jump's A byte,
   * backing up to the preceding test opcode when the prior instruction carries
   * the Lua "test with following jump" flag.
   */
  void invertjump(FuncState* const fs, expdesc* const expression)
  {
    Instruction* const instructionSlot = LuaResolveControllingInstruction(fs, expression->info);
    const Instruction instruction = *instructionSlot;
    const Instruction invertedCondition = ((instruction & 0xFF000000u) == 0u) ? 0x01000000u : 0u;
    *instructionSlot = (instruction & 0x00FFFFFFu) | invertedCondition;
  }

  /**
   * Address: 0x00910F40 (FUN_00910F40, jumponcond)
   *
   * What it does:
   * Lowers one expression lane into a conditional jump and reuses OP_NOT test
   * instructions in-place when possible.
   */
  extern "C" std::int32_t jumponcond(FuncState* const fs, const int cond, expdesc* const expression)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);

    if (expression->k == VRELOCABLE) {
      const Instruction instruction = fsView->f->code[expression->info];
      if ((instruction & 0x3Fu) == static_cast<Instruction>(OP_NOT)) {
        --fsView->pc;
        return luaK_condjump(NO_REG, fs, 28, static_cast<int>((instruction >> 15) & 0x1FFu), cond == 0);
      }
    }

    discharge2anyreg(fs, expression);
    freeexp(expression, fs);
    return luaK_condjump(NO_REG, fs, 28, expression->info, cond);
  }

  /**
   * Address: 0x009100D0 (FUN_009100D0, need_value)
   *
   * What it does:
   * Walks one jump-list chain and returns non-zero if any reached conditional
   * test node is not an `OP_TESTSET` for `cond`; returns zero when all visited
   * links are matching no-value tests (or list is `NO_JUMP`).
   */
  extern "C" int need_value(FuncState* const fs, int list, const int cond)
  {
    if (list == NO_JUMP) {
      return 0;
    }

    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Instruction* const code = fsView->f->code;

    while (true) {
      Instruction* const jumpInstruction = &code[list];
      Instruction* const controllingInstruction = LuaResolveControllingInstruction(fs, list);

      const Instruction testInstruction = *controllingInstruction;
      if (GET_OPCODE(testInstruction) != OP_TEST || GETARG_C(testInstruction) != cond) {
        return 1;
      }

      const std::int32_t jumpOffset = GETARG_sBx(*jumpInstruction);
      if (jumpOffset == NO_JUMP) {
        return 0;
      }

      list += jumpOffset + 1;
      if (list == NO_JUMP) {
        return 0;
      }
    }
  }

  /**
   * Address: 0x00910FC0 (FUN_00910FC0, luaK_goiftrue)
   *
   * What it does:
   * Forces expression discharge and emits/rewrites jump lanes so control falls
   * through only when expression evaluates to true.
   */
  void luaK_goiftrue(FuncState* const fs, expdesc* const expression)
  {
    luaK_dischargevars(fs, expression);

    switch (expression->k) {
    case VTRUE:
    case VK:
      luaK_concat(fs, &expression->f, NO_JUMP);
      break;

    case VFALSE:
      luaK_concat(fs, &expression->f, luaK_jump(fs));
      break;

    case VJMP:
      invertjump(fs, expression);
      luaK_concat(fs, &expression->f, expression->info);
      break;

    default:
      luaK_concat(fs, &expression->f, jumponcond(fs, 0, expression));
      break;
    }
  }

  /**
   * Address: 0x00911120 (FUN_00911120, codenot)
   *
   * What it does:
   * Applies logical-negation bytecode lowering for one expression lane,
   * handling constant/jump/register forms and swapping true/false jump lists.
   */
  void codenot(FuncState* const fs, expdesc* const expression)
  {
    luaK_dischargevars(fs, expression);

    switch (expression->k) {
    case VNIL:
    case VFALSE:
      expression->k = VTRUE;
      break;

    case VTRUE:
    case VK:
      expression->k = VFALSE;
      break;

    case VJMP:
      invertjump(fs, expression);
      break;

    case VRELOCABLE:
    case VNONRELOC:
      discharge2anyreg(fs, expression);
      freeexp(expression, fs);
      expression->info = luaK_codeABC(fs, OP_NOT, 0, expression->info, 0);
      expression->k = VRELOCABLE;
      break;

    default:
      break;
    }

    const std::int32_t falseList = expression->f;
    expression->f = expression->t;
    expression->t = falseList;
  }

  // ---------------------------------------------------------------------
  // lcode.c - bytecode emission and register allocation.
  //
  // The rest of this module's file-local helpers (getjumpcontrol,
  // patchtestreg, need_value, freereg, freeexp, condjump, code_label,
  // invertjump, jumponcond, codenot, codebinop) sit above; luaK_concat,
  // luaK_fixjump, addk, nil_constant, discharge2reg and discharge2anyreg
  // were recovered into LuaObject.cpp and are declared here.
  // ---------------------------------------------------------------------

  extern "C"
  {
    int addk(LuaPlus::TObject* value, FuncState* fs, LuaPlus::TObject* key);
    int nil_constant(FuncState* fs);
    void discharge2reg(expdesc* e, int reg, FuncState* fs);
    void luaK_fixjump(int to, int from, FuncState* fs);

    std::int32_t luaK_getlabel(FuncState* fs);
    void luaK_checkstack(FuncState* fs, int n);
    void luaK_exp2val(FuncState* fs, expdesc* e);
    std::int32_t luaK_exp2RK(FuncState* fs, expdesc* e);
    void luaK_goiffalse(FuncState* fs, expdesc* e);
  }

  void patchlistaux(
    FuncState* fs,
    std::int32_t list,
    std::int32_t ttarget,
    std::int32_t treg,
    std::int32_t ftarget,
    std::int32_t freg,
    std::int32_t dtarget
  );
  void luaK_dischargejpc(FuncState* fs);
  void exp2reg(FuncState* fs, expdesc* e, std::int32_t reg);

  /**
   * Address: 0x00910070 (FUN_00910070, getjump)
   *
   * IDA signature:
   * Instruction __usercall getjump@<eax>(FuncState *fs@<eax>, int pc@<ecx>);
   *
   * What it does:
   * Turns the relative sBx displacement stored in the jump at `pc` into an
   * absolute destination. A displacement of NO_JUMP is returned unchanged - a
   * jump that points at itself is how a jump list marks its end.
   */
  [[nodiscard]] std::int32_t getjump(FuncState* const fs, const std::int32_t pc) noexcept
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    const std::int32_t offset = GETARG_sBx(fsView->f->code[pc]);
    if (offset == NO_JUMP) {
      return NO_JUMP;
    }
    return (pc + 1) + offset;
  }

  /**
   * Address: 0x00910180 (FUN_00910180, patchlistaux)
   *
   * IDA signature:
   * void __usercall patchlistaux(int list@<edx>, FuncState *fs@<ebx>, int ttarget,
   *                              int treg, int ftarget, int freg, int dtarget);
   *
   * What it does:
   * Walks one jump list and retargets every link. Plain jumps go to `dtarget`;
   * jumps controlled by an OP_TEST are split by the test's C field, so the ones
   * that fire on a true result land on `ttarget` (loading their value into
   * `treg`) and the ones that fire on false land on `ftarget` / `freg`.
   */
  void patchlistaux(
    FuncState* const fs,
    std::int32_t list,
    const std::int32_t ttarget,
    const std::int32_t treg,
    const std::int32_t ftarget,
    const std::int32_t freg,
    const std::int32_t dtarget
  )
  {
    while (list != NO_JUMP) {
      const std::int32_t next = getjump(fs, list);
      Instruction* const controllingInstruction = LuaResolveControllingInstruction(fs, list);

      if (GET_OPCODE(*controllingInstruction) != OP_TEST) {
        luaK_fixjump(dtarget, list, fs);
      } else if (GETARG_C(*controllingInstruction) != 0) {
        LuaPatchTestRegisterField(treg, controllingInstruction);
        luaK_fixjump(ttarget, list, fs);
      } else {
        LuaPatchTestRegisterField(freg, controllingInstruction);
        luaK_fixjump(ftarget, list, fs);
      }

      list = next;
    }
  }

  /**
   * Address: 0x009102C0 (FUN_009102C0, dischargejpc)
   *
   * What it does:
   * Retargets every jump that was left pending on `fs->jpc` to the instruction
   * about to be emitted, then empties the pending list.
   */
  void luaK_dischargejpc(FuncState* const fs)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    patchlistaux(fs, fsView->jpc, fsView->pc, NO_REG, fsView->pc, NO_REG, fsView->pc);
    fsView->jpc = NO_JUMP;
  }

  /**
   * Address: 0x00910600 (FUN_00910600, luaK_code)
   *
   * IDA signature:
   * int __cdecl luaK_code(FuncState *fs, Instruction i, int line);
   *
   * What it does:
   * Appends one instruction plus its source line to the prototype being built,
   * growing the code and lineinfo arrays on demand, and returns its pc.
   */
  extern "C" std::int32_t luaK_code(FuncState* const fs, const Instruction i, const int line)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Proto* const f = fsView->f;

    // `pc` will change, so resolve everything still waiting on it first.
    luaK_dischargejpc(fs);

    if (fsView->pc + 1 > f->sizecode) {
      f->code = static_cast<Instruction*>(luaM_growaux(
        fsView->L,
        f->code,
        &f->sizecode,
        static_cast<int>(sizeof(Instruction)),
        MAX_INT,
        "code size overflow"
      ));
    }
    f->code[fsView->pc] = i;

    if (fsView->pc + 1 > f->sizelineinfo) {
      f->lineinfo = static_cast<int*>(luaM_growaux(
        fsView->L,
        f->lineinfo,
        &f->sizelineinfo,
        static_cast<int>(sizeof(int)),
        MAX_INT,
        "code size overflow"
      ));
    }
    f->lineinfo[fsView->pc] = line;

    return fsView->pc++;
  }

  /**
   * Address: 0x009106B0 (FUN_009106B0, luaK_codeABC)
   *
   * What it does:
   * Packs `o/a/b/c` into an iABC instruction and emits it at the lexer's
   * current line.
   */
  extern "C" std::int32_t
  luaK_codeABC(FuncState* const fs, const int o, const int a, const int b, const int c)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);
    return luaK_code(fs, CREATE_ABC(o, a, b, c), lexState->lastline);
  }

  /**
   * Address: 0x009106E0 (FUN_009106E0, luaK_codeABx)
   *
   * What it does:
   * Packs `o/a/bx` into an iABx instruction and emits it at the lexer's current
   * line.
   */
  extern "C" std::int32_t
  luaK_codeABx(FuncState* const fs, const int o, const int a, const unsigned int bc)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);
    return luaK_code(fs, CREATE_ABx(o, a, bc), lexState->lastline);
  }

  /**
   * Address: 0x009105E0 (FUN_009105E0, luaK_fixline)
   *
   * What it does:
   * Rewrites the source line recorded for the instruction emitted last.
   */
  extern "C" void luaK_fixline(FuncState* const fs, const int line)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    fsView->f->lineinfo[fsView->pc - 1] = line;
  }

  /**
   * Address: 0x00910060 (FUN_00910060, luaK_getlabel)
   *
   * What it does:
   * Marks the next instruction slot as a jump target - which blocks the
   * peephole optimisations that assume straight-line flow - and returns it.
   */
  extern "C" std::int32_t luaK_getlabel(FuncState* const fs)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    fsView->lasttarget = fsView->pc;
    return fsView->pc;
  }

  /**
   * Address: 0x009107A0 (FUN_009107A0, luaK_jump)
   *
   * What it does:
   * Emits an unconditional jump with an as-yet unknown destination and hands
   * back its pc, folding any pending jumps into the same list.
   */
  extern "C" std::int32_t luaK_jump(FuncState* const fs)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);

    const std::int32_t jpc = fsView->jpc; // save list of jumps to here
    fsView->jpc = NO_JUMP;

    std::int32_t j = luaK_code(
      fs,
      CREATE_ABx(OP_JMP, 0, static_cast<std::uint32_t>(NO_JUMP + LUA_MAXARG_sBx)),
      lexState->lastline
    );
    luaK_concat(fs, &j, jpc); // keep them on hold
    return j;
  }

  /**
   * Address: 0x00910840 (FUN_00910840, luaK_patchtohere)
   *
   * What it does:
   * Defers `list` until the next instruction is emitted, at which point
   * luaK_code's dischargejpc pass will point it here.
   */
  extern "C" void luaK_patchtohere(FuncState* const fs, const std::int32_t list)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    luaK_getlabel(fs);
    luaK_concat(fs, &fsView->jpc, list);
  }

  /**
   * Address: 0x009115E0 (FUN_009115E0, luaK_patchlist)
   *
   * What it does:
   * Points every jump in `list` at `target`, or holds them on the pending list
   * when `target` is the instruction about to be emitted.
   */
  extern "C" void luaK_patchlist(FuncState* const fs, const std::int32_t list, const std::int32_t target)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    if (target == fsView->pc) {
      luaK_patchtohere(fs, list);
    } else {
      patchlistaux(fs, list, target, NO_REG, target, NO_REG, target);
    }
  }

  /**
   * Address: 0x00910340 (FUN_00910340, luaK_checkstack)
   *
   * What it does:
   * Raises the prototype's recorded stack requirement to cover `n` more
   * registers, refusing anything that would exceed the Lua register limit.
   */
  extern "C" void luaK_checkstack(FuncState* const fs, const int n)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);

    const std::int32_t newstack = fsView->freereg + n;
    if (newstack > fsView->f->maxstacksize) {
      if (newstack >= MAXSTACK) {
        luaX_syntaxerror(lexState, "function or expression too complex");
      }
      fsView->f->maxstacksize = static_cast<lu_byte>(newstack);
    }
  }

  /**
   * Address: 0x00910380 (FUN_00910380, luaK_reserveregs)
   *
   * What it does:
   * Claims the next `n` registers for the expression being compiled.
   */
  extern "C" void luaK_reserveregs(FuncState* const fs, const int n)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    luaK_checkstack(fs, n);
    fsView->freereg += n;
  }

  /**
   * Address: 0x00910490 (FUN_00910490, luaK_stringK)
   *
   * What it does:
   * Interns one string into the prototype's constant table and returns its
   * index.
   */
  extern "C" std::int32_t luaK_stringK(FuncState* const fs, TString* const s)
  {
    LuaPlus::TObject o;
    o.tt = static_cast<int>(s->tt);
    o.value.p = s;
    return addk(&o, fs, &o);
  }

  /**
   * Address: 0x009104C0 (FUN_009104C0, luaK_numberK)
   *
   * What it does:
   * Interns one number into the prototype's constant table and returns its
   * index.
   */
  extern "C" std::int32_t luaK_numberK(FuncState* const fs, const float r)
  {
    LuaPlus::TObject o;
    o.tt = LUA_TNUMBER;
    o.value.n = r;
    return addk(&o, fs, &o);
  }

  /**
   * Address: 0x00910710 (FUN_00910710, luaK_nil)
   *
   * What it does:
   * Nils out `n` registers starting at `from`, extending the preceding
   * OP_LOADNIL instead of emitting a second one whenever the two ranges touch.
   */
  extern "C" void luaK_nil(FuncState* const fs, const int from, const int n)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);

    if (fsView->pc > fsView->lasttarget) { // no jumps to current position?
      Instruction* const previous = &fsView->f->code[fsView->pc - 1];
      if (GET_OPCODE(*previous) == OP_LOADNIL) {
        const std::int32_t pfrom = GETARG_A(*previous);
        const std::int32_t pto = GETARG_B(*previous);
        if (pfrom <= from && from <= pto + 1) { // can connect both?
          if (from + n - 1 > pto) {
            SETARG_B(*previous, from + n - 1);
          }
          return;
        }
      }
    }

    luaK_codeABC(fs, OP_LOADNIL, from, from + n - 1, 0);
  }

  /**
   * Address: 0x00910540 (FUN_00910540, luaK_setcallreturns)
   *
   * What it does:
   * Rewrites the result count of a pending call expression. Asking for exactly
   * one result also settles the expression into the register the call already
   * writes to.
   */
  extern "C" void luaK_setcallreturns(FuncState* const fs, expdesc* const e, const int nresults)
  {
    if (e->k != VCALL) {
      return;
    }

    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Instruction* const call = &fsView->f->code[e->info];
    SETARG_C(*call, nresults + 1);
    if (nresults == 1) { // `regular' expression?
      e->k = VNONRELOC;
      e->info = GETARG_A(*call);
    }
  }

  /**
   * Address: 0x00910860 (FUN_00910860, luaK_dischargevars)
   *
   * What it does:
   * Turns a variable reference into a value: locals are already in a register,
   * upvalues/globals/table fields become the instruction that fetches them, and
   * a pending call is trimmed to a single result.
   */
  extern "C" void luaK_dischargevars(FuncState* const fs, expdesc* const e)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);

    switch (e->k) {
    case VLOCAL:
      e->k = VNONRELOC;
      break;

    case VUPVAL:
      e->info = luaK_code(fs, CREATE_ABC(OP_GETUPVAL, 0, e->info, 0), lexState->lastline);
      e->k = VRELOCABLE;
      break;

    case VGLOBAL:
      e->info = luaK_code(fs, CREATE_ABx(OP_GETGLOBAL, 0, static_cast<std::uint32_t>(e->info)), lexState->lastline);
      e->k = VRELOCABLE;
      break;

    case VINDEXED:
      freereg(fs, e->aux);
      freereg(fs, e->info);
      e->info = luaK_codeABC(fs, OP_GETTABLE, 0, e->info, e->aux);
      e->k = VRELOCABLE;
      break;

    case VCALL:
      luaK_setcallreturns(fs, e, 1);
      break;

    default:
      break; // there is one value available (somewhere)
    }
  }

  /**
   * Address: 0x00910AD0 (FUN_00910AD0, exp2reg)
   *
   * IDA signature:
   * int __usercall exp2reg@<eax>(FuncState *fs@<eax>, expdesc *e, int reg);
   *
   * What it does:
   * Settles an expression into `reg`. When the expression carries jump lists,
   * the true and false sides are patched to land on a pair of OP_LOADBOOL
   * labels so that whichever path runs leaves the value in `reg`.
   */
  void exp2reg(FuncState* const fs, expdesc* const e, const std::int32_t reg)
  {
    discharge2reg(e, reg, fs);
    if (e->k == VJMP) {
      luaK_concat(fs, &e->t, e->info); // put this jump in `t' list
    }

    if (e->t != e->f) { // expression has jumps
      std::int32_t p_f = NO_JUMP; // position of an eventual LOAD false
      std::int32_t p_t = NO_JUMP; // position of an eventual LOAD true

      if (need_value(fs, e->t, 1) != 0 || need_value(fs, e->f, 0) != 0) {
        const std::int32_t fj = (e->k != VJMP) ? luaK_jump(fs) : NO_JUMP;
        p_f = code_label(reg, fs, 0, 1);
        p_t = code_label(reg, fs, 1, 0);
        luaK_patchtohere(fs, fj);
      }

      const std::int32_t finalLabel = luaK_getlabel(fs); // position after whole expression
      patchlistaux(fs, e->f, p_f, NO_REG, finalLabel, reg, p_f);
      patchlistaux(fs, e->t, finalLabel, reg, p_t, NO_REG, p_t);
    }

    e->f = NO_JUMP;
    e->t = NO_JUMP;
    e->info = reg;
    e->k = VNONRELOC;
  }

  /**
   * Address: 0x00910C00 (FUN_00910C00, luaK_exp2nextreg)
   *
   * What it does:
   * Settles an expression into a freshly reserved register.
   */
  extern "C" void luaK_exp2nextreg(FuncState* const fs, expdesc* const e)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    luaK_dischargevars(fs, e);
    freeexp(e, fs);
    luaK_checkstack(fs, 1);
    exp2reg(fs, e, fsView->freereg++);
  }

  /**
   * Address: 0x00910C80 (FUN_00910C80, luaK_exp2anyreg)
   *
   * What it does:
   * Settles an expression into whichever register is cheapest - the one it
   * already occupies when that is legal, otherwise a fresh one - and returns it.
   */
  extern "C" std::int32_t luaK_exp2anyreg(FuncState* const fs, expdesc* const e)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    luaK_dischargevars(fs, e);

    if (e->k == VNONRELOC) {
      if (e->t == e->f) { // exp is not a test?
        return e->info;   // result is already in a register
      }
      if (e->info >= fsView->nactvar) { // reg. is not a local?
        exp2reg(fs, e, e->info);        // put value on it
        return e->info;
      }
    }

    luaK_exp2nextreg(fs, e); // default
    return e->info;
  }

  /**
   * Address: 0x00910CD0 (FUN_00910CD0, luaK_exp2val)
   *
   * What it does:
   * Reduces an expression to a value, forcing it into a register only when it
   * still carries jump lists.
   */
  extern "C" void luaK_exp2val(FuncState* const fs, expdesc* const e)
  {
    if (e->t != e->f) {
      luaK_exp2anyreg(fs, e);
    } else {
      luaK_dischargevars(fs, e);
    }
  }

  /**
   * Address: 0x00910CF0 (FUN_00910CF0, luaK_exp2RK)
   *
   * What it does:
   * Produces an RK operand: a constant index biased by MAXSTACK when the value
   * is a constant that still fits the 9-bit field, otherwise a register.
   */
  extern "C" std::int32_t luaK_exp2RK(FuncState* const fs, expdesc* const e)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    luaK_exp2val(fs, e);

    if (e->k == VNIL) {
      if (fsView->nk + MAXSTACK <= MAXARG_C) { // constant fits in argC?
        e->info = nil_constant(fs);
        e->k = VK;
        return e->info + MAXSTACK;
      }
    } else if (e->k == VK) {
      if (e->info + MAXSTACK <= MAXARG_C) { // constant fits in argC?
        return e->info + MAXSTACK;
      }
    }

    return luaK_exp2anyreg(fs, e); // not a constant in the right range
  }

  /**
   * Address: 0x00910D70 (FUN_00910D70, luaK_storevar)
   *
   * What it does:
   * Emits the store that writes `ex` back through the variable reference in
   * `var` - a register move for locals, SETUPVAL / SETGLOBAL / SETTABLE
   * otherwise - and releases the value's register afterwards.
   */
  extern "C" void luaK_storevar(FuncState* const fs, expdesc* const var, expdesc* const ex)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);

    switch (var->k) {
    case VLOCAL:
      freeexp(ex, fs);
      exp2reg(fs, ex, var->info);
      return;

    case VUPVAL: {
      const std::int32_t e = luaK_exp2anyreg(fs, ex);
      luaK_code(fs, CREATE_ABC(OP_SETUPVAL, e, var->info, 0), lexState->lastline);
      break;
    }

    case VGLOBAL: {
      const std::int32_t e = luaK_exp2anyreg(fs, ex);
      luaK_code(fs, CREATE_ABx(OP_SETGLOBAL, e, static_cast<std::uint32_t>(var->info)), lexState->lastline);
      break;
    }

    case VINDEXED: {
      const std::int32_t e = luaK_exp2RK(fs, ex);
      luaK_codeABC(fs, OP_SETTABLE, var->info, var->aux, e);
      break;
    }

    default:
      break; // invalid var kind to store
    }

    freeexp(ex, fs);
  }

  /**
   * Address: 0x00910E60 (FUN_00910E60, luaK_self)
   *
   * What it does:
   * Compiles the `obj:method` form: OP_SELF drops the method and the receiver
   * into two adjacent fresh registers, ready for the call that follows.
   */
  extern "C" void luaK_self(FuncState* const fs, expdesc* const e, expdesc* const key)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);

    luaK_exp2anyreg(fs, e);
    freeexp(e, fs);

    const std::int32_t func = fsView->freereg;
    luaK_reserveregs(fs, 2);
    const std::int32_t rkKey = luaK_exp2RK(fs, key);
    luaK_codeABC(fs, OP_SELF, func, e->info, rkKey);
    freeexp(key, fs);

    e->info = func;
    e->k = VNONRELOC;
  }

  /**
   * Address: 0x00911070 (FUN_00911070, luaK_goiffalse)
   *
   * What it does:
   * Emits the jumps that make control fall through only when the expression is
   * false, collecting the true-side exits on `e->t`.
   */
  extern "C" void luaK_goiffalse(FuncState* const fs, expdesc* const e)
  {
    luaK_dischargevars(fs, e);

    std::int32_t pc = NO_JUMP; // pc of last jump
    switch (e->k) {
    case VNIL:
    case VFALSE:
      pc = NO_JUMP; // always false; do nothing
      break;

    case VTRUE:
      pc = luaK_jump(fs); // always jump
      break;

    case VJMP:
      pc = e->info;
      break;

    default:
      pc = jumponcond(fs, 1, e);
      break;
    }

    luaK_concat(fs, &e->t, pc); // insert last jump in `t' list
  }

  /**
   * Address: 0x009111F0 (FUN_009111F0, luaK_indexed)
   *
   * What it does:
   * Folds a key expression into the table reference it indexes, producing a
   * VINDEXED lane that dischargevars/storevar later turn into GETTABLE or
   * SETTABLE.
   */
  extern "C" void luaK_indexed(FuncState* const fs, expdesc* const t, expdesc* const k)
  {
    t->aux = luaK_exp2RK(fs, k);
    t->k = VINDEXED;
  }

  /**
   * Address: 0x00911210 (FUN_00911210, luaK_prefix)
   *
   * What it does:
   * Applies a unary operator. Negating a numeric constant is folded at compile
   * time into a new constant; everything else becomes OP_UNM, and `not` is
   * handled by codenot.
   */
  extern "C" void luaK_prefix(FuncState* const fs, const std::int32_t op, expdesc* const e)
  {
    if (op != OPR_MINUS) {
      codenot(fs, e);
      return;
    }

    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);

    luaK_exp2val(fs, e);
    LuaPlus::TObject* const constants = fsView->f->k;
    if (e->k == VK && constants[e->info].tt == LUA_TNUMBER) {
      e->info = luaK_numberK(fs, -constants[e->info].value.n);
      return;
    }

    luaK_exp2anyreg(fs, e);
    freeexp(e, fs);
    e->info = luaK_code(fs, CREATE_ABC(OP_UNM, 0, e->info, 0), lexState->lastline);
    e->k = VRELOCABLE;
  }

  /**
   * Address: 0x009112D0 (FUN_009112D0, luaK_infix)
   *
   * What it does:
   * Prepares the left operand once the binary operator is known: `and` / `or`
   * emit their short-circuit jumps here, concat needs its operand stacked, and
   * everything else only needs an RK operand.
   */
  extern "C" void luaK_infix(FuncState* const fs, const std::int32_t op, expdesc* const v)
  {
    switch (op) {
    case OPR_AND:
      luaK_goiftrue(fs, v);
      luaK_patchtohere(fs, v->t);
      v->t = NO_JUMP;
      break;

    case OPR_OR:
      luaK_goiffalse(fs, v);
      luaK_patchtohere(fs, v->f);
      v->f = NO_JUMP;
      break;

    case OPR_CONCAT:
      luaK_exp2nextreg(fs, v); // operand must be on the `stack'
      break;

    default:
      luaK_exp2RK(fs, v);
      break;
    }
  }

  /**
   * Address: 0x009113F0 (FUN_009113F0, luaK_posfix)
   *
   * What it does:
   * Finishes a binary operator now that both operands exist. `and` / `or` merge
   * the two jump lists, adjacent concats fuse into the single OP_CONCAT run the
   * VM expects, and the rest go through codebinop.
   */
  extern "C" void
  luaK_posfix(FuncState* const fs, const std::int32_t op, expdesc* const e1, expdesc* const e2)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);

    switch (op) {
    case OPR_AND:
      luaK_dischargevars(fs, e2);
      luaK_concat(fs, &e1->f, e2->f);
      e1->k = e2->k;
      e1->info = e2->info;
      e1->aux = e2->aux;
      e1->t = e2->t;
      break;

    case OPR_OR:
      luaK_dischargevars(fs, e2);
      luaK_concat(fs, &e1->t, e2->t);
      e1->k = e2->k;
      e1->info = e2->info;
      e1->aux = e2->aux;
      e1->f = e2->f;
      break;

    case OPR_CONCAT: {
      luaK_exp2val(fs, e2);
      Proto* const f = fsView->f;
      if (e2->k == VRELOCABLE && GET_OPCODE(f->code[e2->info]) == OP_CONCAT) {
        // `e1 .. (a .. b)` - widen the existing run instead of nesting.
        freeexp(e1, fs);
        SETARG_B(f->code[e2->info], e1->info);
        e1->k = e2->k;
        e1->info = e2->info;
      } else {
        luaK_exp2nextreg(fs, e2); // operand must be on the `stack'
        freeexp(e2, fs);
        freeexp(e1, fs);
        e1->info = luaK_code(fs, CREATE_ABC(OP_CONCAT, 0, e1->info, e2->info), lexState->lastline);
        e1->k = VRELOCABLE;
      }
      break;
    }

    default: {
      const std::int32_t o1 = luaK_exp2RK(fs, e1);
      const std::int32_t o2 = luaK_exp2RK(fs, e2);
      freeexp(e2, fs);
      freeexp(e1, fs);
      codebinop(o2, op, o1, e1, fs);
      break;
    }
    }
  }

  /**
   * Address: 0x00913F90 (FUN_00913F90, luaD_protectedparser)
   *
   * IDA signature:
   * int __cdecl luaD_protectedparser(lua_State *L, ZIO *z, int bin);
   *
   * What it does:
   * Compiles one chunk and releases the scratch buffer afterwards, whether the
   * parse finished or threw. Lives here rather than with the rest of ldo.c
   * because SParser and f_parser do.
   */
  extern "C" std::int32_t luaD_protectedparser(lua_State* const L, LuaUndumpZioRuntimeView* const z, const int bin)
  {
    SParser parser;
    parser.z = z;
    parser.bin = bin;
    parser.buff.buffer = nullptr;
    parser.buff.buffsize = 0;

    // The original frees the buffer from a __finally; the guard is the same
    // thing said in C++.
    struct BufferGuard
    {
      lua_State* state;
      Mbuffer* buffer;

      ~BufferGuard()
      {
        (void)luaM_realloc(state, buffer->buffer, static_cast<lu_mem>(buffer->buffsize), 0u);
      }
    } const guard{L, &parser.buff};

    f_parser(&parser, L);
    return 0;
  }

  /**
   * Address: 0x0091ACA0 (FUN_0091ACA0, codestring)
   *
   * What it does:
   * Interns one parser string token into the function constant table and emits
   * a `VK` expression descriptor lane targeting that constant index.
   */
  extern "C" void codestring(TString* const stringToken, LexState* const ls, expdesc* const outExpression)
  {
    outExpression->info = luaK_stringK(ls->fs, stringToken);
    outExpression->t = NO_JUMP;
    outExpression->f = NO_JUMP;
    outExpression->k = VK;
  }

  // ---------------------------------------------------------------------
  // lparser.c - token checks and expression parsing.
  //
  // error_expected / check / check_match are file-local in the original and
  // this build inlined every call, so they have no address of their own; the
  // bodies below are what those inlined sequences expand to, and their two
  // message strings sit at 0x00E4A5C3 and 0x00E4A5D1.
  // ---------------------------------------------------------------------

  /**
   * What it does:
   * Reports "`<token>' expected" against the current lexer position.
   */
  extern "C" void error_expected(LexState* const ls, const std::int32_t token)
  {
    luaX_syntaxerror(ls, luaO_pushfstring(ls->L, "`%s' expected", luaX_token2str(ls, token)));
  }

  /**
   * What it does:
   * Consumes the expected token, or reports it as missing.
   */
  extern "C" void check(LexState* const ls, const std::int32_t c)
  {
    if (ls->t.token != c) {
      error_expected(ls, c);
    }
    next(ls);
  }

  /**
   * What it does:
   * Consumes a closing token. When the construct it closes was opened on an
   * earlier line, the message names that line so the reader can find it.
   */
  extern "C" void
  check_match(LexState* const ls, const std::int32_t what, const std::int32_t who, const std::int32_t where)
  {
    if (testnext(ls, what) != 0) {
      return;
    }

    if (where == ls->linenumber) {
      error_expected(ls, what);
      return;
    }

    luaX_syntaxerror(
      ls,
      luaO_pushfstring(
        ls->L,
        "`%s' expected (to close `%s' at line %d)",
        luaX_token2str(ls, what),
        luaX_token2str(ls, who),
        where
      )
    );
  }

  /**
   * Address: 0x0091B4F0 (FUN_0091B4F0, luaY_index)
   *
   * IDA signature:
   * void __usercall luaY_index(LexState *ls@<eax>, expdesc *v@<edi>);
   *
   * What it does:
   * Parses the `[ exp ]` of a bracketed table access, leaving the key in `v`.
   */
  extern "C" void luaY_index(LexState* const ls, expdesc* const v)
  {
    next(ls); // skip the '['
    subexpr(ls, v, -1);
    luaK_exp2val(ls->fs, v);
    check(ls, ']');
  }

  /**
   * Address: 0x0091B550 (FUN_0091B550, recfield)
   *
   * IDA signature:
   * void __usercall recfield(LexState *ls@<eax>, ConsControl *cc);
   *
   * What it does:
   * Parses one `key = value` entry of a table constructor and emits its
   * SETTABLE. Both key and value are evaluated into scratch registers that are
   * released again afterwards, so a long constructor does not grow the frame.
   */
  extern "C" void recfield(LexState* const ls, ConsControl* const cc)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    const std::int32_t reg = fsView->freereg;

    expdesc key;
    expdesc val;

    if (ls->t.token == TK_NAME) {
      luaX_checklimit(ls, cc->nh, MAX_INT, "items in a constructor");
      ++cc->nh;
      codestring(str_checkname(ls), ls, &key);
    } else {
      luaY_index(ls, &key);
    }

    check(ls, '=');
    luaK_exp2RK(fs, &key);
    subexpr(ls, &val, -1);
    const std::int32_t rkValue = luaK_exp2RK(fs, &val);
    const std::int32_t rkKey = luaK_exp2RK(fs, &key);
    luaK_codeABC(fs, OP_SETTABLE, cc->t->info, rkKey, rkValue);

    fsView->freereg = reg; // free registers
  }

  /**
   * Address: 0x0091B710 (FUN_0091B710, constructor)
   *
   * IDA signature:
   * void __usercall constructor(expdesc *t@<eax>, LexState *ls@<ecx>);
   *
   * What it does:
   * Parses a table constructor. List entries accumulate in registers and are
   * flushed to the table every LFIELDS_PER_FLUSH values; record entries emit
   * their store immediately. The final OP_NEWTABLE is back-patched with the
   * sizes actually seen, so the table is allocated once at the right size.
   *
   * This build also accepts a leading `&<n>` (and a second `&<n>`) after the
   * opening brace, which forces the hash and array size hints - a FAF
   * extension with no equivalent in stock Lua.
   */
  extern "C" void constructor(expdesc* const t, LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    const int line = ls->linenumber;
    const int pc = luaK_codeABC(fs, OP_NEWTABLE, 0, 0, 0);

    ConsControl cc;
    cc.na = 0;
    cc.nh = 0;
    cc.tostore = 0;
    cc.t = t;
    cc.v.k = VVOID;
    cc.v.info = 0;
    cc.v.t = NO_JUMP;
    cc.v.f = NO_JUMP;

    t->t = NO_JUMP;
    t->f = NO_JUMP;
    t->k = VRELOCABLE;
    t->info = pc;

    luaK_exp2nextreg(ls->fs, t); // fix it at stack top (for gc optimization)
    check(ls, '{');

    std::int32_t forcedHashSize = 0;
    std::int32_t forcedArraySize = 0;
    if (ls->t.token == '&') {
      next(ls);
      if (ls->t.token != TK_NUMBER) {
        luaX_syntaxerror(ls, luaO_pushfstring(ls->L, "size expected following & (line %d)", ls->linenumber));
      }
      forcedHashSize = static_cast<std::int32_t>(ls->t.seminfo.r);
      next(ls);

      if (ls->t.token == '&') {
        next(ls);
        if (ls->t.token != TK_NUMBER) {
          luaX_syntaxerror(ls, luaO_pushfstring(ls->L, "size expected following & (line %d)", ls->linenumber));
        }
        forcedArraySize = static_cast<std::int32_t>(ls->t.seminfo.r);
        next(ls);
      }
    }

    for (;;) {
      if (ls->t.token == ';') {
        next(ls);
      }
      if (ls->t.token == '}') {
        break;
      }

      // closelistfield: settle the value parsed last, and flush a full batch.
      if (cc.v.k != VVOID) {
        luaK_exp2nextreg(fs, &cc.v);
        cc.v.k = VVOID;
        if (cc.tostore == LFIELDS_PER_FLUSH) {
          luaK_codeABx(fs, OP_SETLIST, cc.t->info, static_cast<std::uint32_t>(cc.na - 1));
          cc.tostore = 0; // no more items pending
          fsView->freereg = cc.t->info + 1; // free registers
        }
      }

      // `[key]=v` and `name=v` are record entries; anything else is a list
      // entry. Telling `name=v` from a bare `name` needs one token of
      // lookahead.
      const std::int32_t token = ls->t.token;
      bool isRecordField = (token == '[');
      if (!isRecordField && token == TK_NAME) {
        ls->lookahead.token = luaX_lex(ls, &ls->lookahead.seminfo);
        isRecordField = (ls->lookahead.token == '=');
      }

      if (isRecordField) {
        recfield(ls, &cc);
      } else {
        subexpr(ls, &cc.v, -1);
        luaX_checklimit(ls, cc.na++, LUA_MAXARG_Bx, "items in a constructor");
        ++cc.tostore;
      }

      if (ls->t.token != ',' && ls->t.token != ';') {
        break;
      }
      next(ls);
    }

    check_match(ls, '}', '{', line);
    lastlistfield(fs, &cc);

    if (forcedArraySize > cc.na) {
      cc.na = forcedArraySize;
    }
    if (forcedHashSize > cc.nh) {
      cc.nh = forcedHashSize;
    }

    Instruction* const newTable = &fsView->f->code[pc];
    if (cc.na > 0) {
      SETARG_B(*newTable, static_cast<std::int32_t>(luaO_int2fb(static_cast<unsigned int>(cc.na))));
    }
    SETARG_C(*newTable, luaO_log2(static_cast<unsigned int>(cc.nh)) + 1);
  }

  /**
   * Address: 0x0091BF10 (FUN_0091BF10, prefixexp)
   *
   * IDA signature:
   * void __usercall prefixexp(LexState *ls@<eax>, expdesc *v@<ebx>);
   *
   * What it does:
   * Parses what a suffixed expression starts from - either a parenthesised
   * expression or a single variable name.
   */
  extern "C" void prefixexp(LexState* const ls, expdesc* const v)
  {
    if (ls->t.token == '(') {
      const std::int32_t line = ls->linenumber;
      next(ls);
      subexpr(ls, v, -1);
      check_match(ls, ')', '(', line);
      luaK_dischargevars(ls->fs, v);
      return;
    }

    if (ls->t.token != TK_NAME) {
      luaX_syntaxerror(ls, "unexpected symbol");
    }
    singlevaraux(ls->fs, str_checkname(ls), v, 1);
  }

  /**
   * Address: 0x0091BDA0 (FUN_0091BDA0, funcargs)
   *
   * IDA signature:
   * void __usercall funcargs(LexState *ls@<eax>, expdesc *f);
   *
   * What it does:
   * Parses a call's arguments in any of the three forms Lua accepts - `(...)`,
   * a table constructor, or a string literal - and emits the OP_CALL. The
   * whole argument block collapses back to one register, which the call's
   * result then occupies.
   */
  extern "C" void funcargs(LexState* const ls, expdesc* const f)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    const std::int32_t line = ls->linenumber;

    expdesc args;
    switch (ls->t.token) {
    case '(':
      // A call whose '(' opens on the next line reads as a fresh statement to
      // a human, so refuse it rather than silently pairing them up.
      if (line != ls->lastline) {
        luaX_syntaxerror(ls, "ambiguous syntax (function call x new statement)");
      }
      next(ls);
      if (ls->t.token == ')') { // arg list is empty?
        args.k = VVOID;
      } else {
        explist1(ls, &args);
        luaK_setcallreturns(fs, &args, LUA_MULTRET);
      }
      check_match(ls, ')', '(', line);
      break;

    case '{':
      constructor(&args, ls);
      break;

    case TK_STRING:
      codestring(ls->t.seminfo.ts, ls, &args);
      next(ls); // must use `seminfo' before `next'
      break;

    default:
      luaX_syntaxerror(ls, "function arguments expected");
      break;
    }

    const std::int32_t base = f->info; // base register for call
    std::int32_t nparams = LUA_MULTRET; // open call
    if (args.k != VCALL) {
      if (args.k != VVOID) {
        luaK_exp2nextreg(fs, &args); // close last argument
      }
      nparams = fsView->freereg - (base + 1);
    }

    f->info = luaK_codeABC(fs, OP_CALL, base, nparams + 1, 2);
    f->t = NO_JUMP;
    f->f = NO_JUMP;
    f->k = VCALL;
    luaK_fixline(fs, line); // call `instruction' uses the line where it was called
    fsView->freereg = base + 1; // call removes function and arguments and leaves (unless changed) one result
  }

  /**
   * Address: 0x0091BFB0 (FUN_0091BFB0, primaryexp)
   *
   * IDA signature:
   * unsigned int __usercall primaryexp@<eax>(expdesc *v@<eax>, LexState *ls@<esi>);
   *
   * What it does:
   * Parses a prefix expression followed by any run of suffixes: `.name`,
   * `[key]`, `:method(args)`, and calls. Each suffix consumes the expression
   * built so far and replaces it, so `a.b[c]:d(e)` folds left to right.
   */
  extern "C" void primaryexp(expdesc* const v, LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    prefixexp(ls, v);

    for (;;) {
      switch (ls->t.token) {
      case '.': // field
        luaY_field(ls, v);
        break;

      case '[': { // `[' exp1 `]'
        expdesc key;
        luaK_exp2anyreg(fs, v);
        luaY_index(ls, &key);
        luaK_indexed(fs, v, &key);
        break;
      }

      case ':': { // `:' NAME funcargs
        expdesc key;
        next(ls);
        codestring(str_checkname(ls), ls, &key);
        luaK_self(fs, v, &key);
        funcargs(ls, v);
        break;
      }

      case '(':
      case TK_STRING:
      case '{': // funcargs
        luaK_exp2nextreg(fs, v);
        funcargs(ls, v);
        break;

      default:
        return; // should be follow
      }
    }
  }

  /**
   * Address: 0x0091C2D0 (FUN_0091C2D0, simpleexp)
   *
   * What it does:
   * Parses one simple expression token lane (literals/function/table/primary
   * expression) and materializes resulting `expdesc`.
   */
  void simpleexp(LexState* const ls, expdesc* const outExpression)
  {
    switch (ls->t.token) {
    case '{':
      constructor(outExpression, ls);
      return;

    case TK_FALSE:
      outExpression->t = NO_JUMP;
      outExpression->f = NO_JUMP;
      outExpression->k = VFALSE;
      outExpression->info = 0;
      next(ls);
      return;

    case TK_FUNCTION:
      next(ls);
      body(ls, outExpression, 0, ls->linenumber);
      return;

    case TK_NIL:
      outExpression->t = NO_JUMP;
      outExpression->f = NO_JUMP;
      outExpression->k = VNIL;
      outExpression->info = 0;
      next(ls);
      return;

    case TK_TRUE:
      outExpression->t = NO_JUMP;
      outExpression->f = NO_JUMP;
      outExpression->k = VTRUE;
      outExpression->info = 0;
      next(ls);
      return;

    case TK_NUMBER:
      outExpression->info = luaK_numberK(ls->fs, ls->t.seminfo.r);
      outExpression->t = NO_JUMP;
      outExpression->f = NO_JUMP;
      outExpression->k = VK;
      next(ls);
      return;

    case TK_STRING:
      codestring(ls->t.seminfo.ts, ls, outExpression);
      next(ls);
      return;

    default:
      primaryexp(outExpression, ls);
      return;
    }
  }

  /**
   * Address: 0x0091C680 (FUN_0091C680, subexpr)
   *
   * What it does:
   * Parses unary and binary expressions with Lua's precedence and
   * associativity rules, returning the first operator left for its caller.
   */
  extern "C" std::int32_t subexpr(
    LexState* const ls,
    expdesc* const expression,
    const std::int32_t limit
  )
  {
    if (++ls->nestlevel > 200) {
      luaX_syntaxerror(ls, "too many syntax levels");
    }

    std::int32_t unaryOperator = OPR_NOUNOPR;
    if (ls->t.token == '-') {
      unaryOperator = OPR_MINUS;
    } else if (ls->t.token == TK_NOT) {
      unaryOperator = OPR_NOT;
    }

    if (unaryOperator != OPR_NOUNOPR) {
      next(ls);
      (void)subexpr(ls, expression, UNARY_PRIORITY);
      luaK_prefix(ls->fs, unaryOperator, expression);
    } else {
      simpleexp(ls, expression);
    }

    std::int32_t binaryOperator = GetBinaryOperatorFromToken(ls->t.token);
    while (
      binaryOperator != OPR_NOBINOPR
      && static_cast<std::int32_t>(
        kBinaryOperatorPriorities[static_cast<std::size_t>(binaryOperator)].first
      ) > limit
    ) {
      next(ls);
      luaK_infix(ls->fs, binaryOperator, expression);

      expdesc rightExpression;
      const std::int32_t nextOperator = subexpr(
        ls,
        &rightExpression,
        static_cast<std::int32_t>(
          kBinaryOperatorPriorities[static_cast<std::size_t>(binaryOperator)].second
        )
      );
      luaK_posfix(ls->fs, binaryOperator, expression, &rightExpression);
      binaryOperator = nextOperator;
    }

    --ls->nestlevel;
    return binaryOperator;
  }

  /**
   * Address: 0x0091CE70 (FUN_0091CE70)
   *
   * What it does:
   * Parses one expression, emits it into the next free register, and returns
   * the original expression-kind lane.
   */
  [[maybe_unused]] std::int32_t ParseExpressionToNextRegisterAndReturnKind(
    LexState* const ls
  )
  {
    expdesc expression{};
    subexpr(ls, &expression, -1);
    const std::int32_t kind = expression.k;
    luaK_exp2nextreg(ls->fs, &expression);
    return kind;
  }

  /**
   * Address: 0x0091BD30 (FUN_0091BD30, explist1)
   *
   * What it does:
   * Parses one comma-separated expression list, flushing each prior expression
   * to the next register lane before parsing the next element.
   */
  std::int32_t explist1(LexState* const ls, expdesc* const expression)
  {
    std::int32_t expressionCount = 1;
    subexpr(ls, expression, -1);

    while (ls->t.token == ',') {
      ls->lastline = ls->linenumber;
      if (ls->lookahead.token == TK_EOS) {
        ls->t.token = luaX_lex(ls, &ls->t.seminfo);
      } else {
        ls->t.token = ls->lookahead.token;
        ls->t.seminfo = ls->lookahead.seminfo;
        ls->lookahead.token = TK_EOS;
      }

      luaK_exp2nextreg(ls->fs, expression);
      subexpr(ls, expression, -1);
      ++expressionCount;
    }

    return expressionCount;
  }

  /**
   * Address: 0x0091D490 (FUN_0091D490, ifstat)
   *
   * What it does:
   * Parses an `if` statement chain, stitches each `ELSEIF`/`ELSE` branch into
   * one jump list, and validates the closing `END` token against the opening
   * `IF` line.
   */
  void ifstat(LexState* const ls, const std::int32_t line)
  {
    FuncState* const fs = ls->fs;
    expdesc v{};
    std::int32_t escapelist = NO_JUMP;

    test_then_block(ls, &v); // IF cond THEN block

    while (ls->t.token == TK_ELSEIF) {
      luaK_concat(fs, &escapelist, luaK_jump(fs));
      luaK_patchtohere(fs, v.f);

      test_then_block(ls, &v); // ELSEIF cond THEN block
    }

    if (ls->t.token == TK_ELSE) {
      luaK_concat(fs, &escapelist, luaK_jump(fs));
      luaK_patchtohere(fs, v.f);

      next(ls);
      block(ls);
    } else {
      luaK_concat(fs, &escapelist, v.f);
    }

    luaK_patchtohere(fs, escapelist);
    check_match(ls, TK_END, TK_IF, line);
  }

  struct LuaParserGlobalStateRuntimeView
  {
    std::uint8_t reserved00_24[0x24];
    lu_mem gcThreshold; // +0x24
    CFunction panic;    // +0x28
    lu_mem totalBytes;  // +0x2C
  };

  static_assert(
    offsetof(LuaParserGlobalStateRuntimeView, gcThreshold) == 0x24,
    "LuaParserGlobalStateRuntimeView::gcThreshold offset must be 0x24"
  );
  static_assert(
    offsetof(LuaParserGlobalStateRuntimeView, panic) == 0x28,
    "LuaParserGlobalStateRuntimeView::panic offset must be 0x28"
  );
  static_assert(
    offsetof(LuaParserGlobalStateRuntimeView, totalBytes) == 0x2C,
    "LuaParserGlobalStateRuntimeView::totalBytes offset must be 0x2C"
  );

  /**
   * Address: 0x00913F00 (FUN_00913F00, f_parser)
   *
   * What it does:
   * Runs parser GC gate, parses binary/text Lua chunk into one top-level
   * `Proto`, wraps it into one new Lua closure, and pushes that closure on
   * the VM stack.
   */
  extern "C" void f_parser(SParser* const parser, lua_State* const state)
  {
    auto* const globalState = reinterpret_cast<LuaParserGlobalStateRuntimeView*>(state->l_G);
    if (globalState->totalBytes >= globalState->gcThreshold && globalState->panic == nullptr) {
      luaC_collectgarbage(state);
    }

    Proto* const parsedProto = (parser->bin != 0)
      ? luaU_undump(state, static_cast<LuaUndumpZioRuntimeView*>(parser->z), &parser->buff)
      : luaY_parser(state, static_cast<LuaUndumpZioRuntimeView*>(parser->z), &parser->buff);

    LClosure* const closure = luaF_newLclosure(state, 0, &state->_gt);
    const int closureTypeTag = static_cast<int>(reinterpret_cast<const CClosure*>(closure)->tt);
    closure->p = parsedProto;

    LuaPlus::TObject* const top = state->top;
    top->tt = closureTypeTag;
    top->value.p = closure;

    const auto freeBytes = reinterpret_cast<const std::uint8_t*>(state->stack_last) -
      reinterpret_cast<const std::uint8_t*>(state->top);
    if (freeBytes <= static_cast<std::ptrdiff_t>(sizeof(LuaPlus::TObject))) {
      luaD_growstack(state, 1);
    }
    ++state->top;
  }

  /**
   * Address: 0x0091C8B0 (FUN_0091C8B0, check_conflict)
   *
   * What it does:
   * Rewrites indexed-assignment lanes that alias the RHS local register and
   * emits one `OP_MOVE` spill when conflicts are found.
   */
  [[maybe_unused]] void check_conflict(LHS_assign* const lhs, LexState* const ls, expdesc* const value)
  {
    constexpr std::int32_t VINDEXED = 0x08;

    auto* const funcState = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    const std::int32_t extraRegister = funcState->freereg;
    bool hasConflict = false;

    for (LHS_assign* node = lhs; node != nullptr; node = node->prev) {
      expdesc& lhsExpression = node->v;
      if (lhsExpression.k != VINDEXED) {
        continue;
      }

      if (lhsExpression.info == value->info) {
        lhsExpression.info = extraRegister;
        hasConflict = true;
      }

      if (lhsExpression.aux == value->info) {
        lhsExpression.aux = extraRegister;
        hasConflict = true;
      }
    }

    if (hasConflict) {
      luaK_codeABC(ls->fs, OP_MOVE, funcState->freereg, value->info, 0);
      luaK_reserveregs(ls->fs, 1);
    }
  }

  /**
   * Address: 0x0091D8B0 (FUN_0091D8B0, funcstat)
   *
   * What it does:
   * Parses one `function` statement, building destination/value expressions,
   * stores parsed closure into the destination variable, and applies source
   * line fixup to generated bytecode.
   */
  void funcstat(LexState* const ls, const int line)
  {
    expdesc bodyExpression{};
    expdesc variableExpression{};

    ls->lastline = ls->linenumber;
    if (ls->lookahead.token == TK_EOS) {
      ls->t.token = luaX_lex(ls, &ls->t.seminfo);
    } else {
      ls->t.token = ls->lookahead.token;
      ls->t.seminfo = ls->lookahead.seminfo;
      ls->lookahead.token = TK_EOS;
    }

    const int needsSelf = funcname(&variableExpression, ls);
    body(ls, &bodyExpression, needsSelf, line);
    luaK_storevar(ls->fs, &variableExpression, &bodyExpression);
    luaK_fixline(ls->fs, line);
  }

  /**
   * Address: 0x0091D930 (FUN_0091D930, exprstat)
   *
   * What it does:
   * Parses one statement-headed primary expression and routes it as either a
   * call statement (discarding returns) or an assignment chain root.
   */
  void exprstat(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    LHS_assign lhs{};
    primaryexp(&lhs.v, ls);

    if (lhs.v.k == VCALL) {
      luaK_setcallreturns(fs, &lhs.v, 0);
      return;
    }

    lhs.prev = nullptr;
    assignment(ls, &lhs, 1);
  }

  /**
   * Address: 0x0091B2F0 (FUN_0091B2F0, open_func)
   *
   * What it does:
   * Opens one nested parser function scope by allocating a fresh `Proto`,
   * wiring lexical parent links, and resetting all function-state counters.
   */
  [[maybe_unused]] void open_func(LexState* const ls, FuncState* const fs)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Proto* const functionProto = luaF_newproto(ls->L);

    fsView->f = functionProto;
    fsView->prev = ls->fs;
    fsView->lexState = ls;
    fsView->L = ls->L;
    ls->fs = fs;

    fsView->pc = 0;
    fsView->lasttarget = 0;
    fsView->jpc = LUA_MULTRET;
    fsView->freeRegisterIndex = 0;
    fsView->nk = 0;
    fsView->np = 0;
    fsView->nlocvars = 0;
    fsView->nactvar = 0;
    fsView->bl = nullptr;

    fsView->h = luaH_new(ls->L, 0, 0);
    functionProto->source = ls->source;
    functionProto->maxstacksize = 2;
  }

  /**
   * Address: 0x0091B350 (FUN_0091B350, close_func)
   *
   * What it does:
   * Finalizes one parser function scope by emitting the implicit `return`,
   * shrinking the finished prototype arrays to the recorded counts, and
   * restoring the parent `FuncState` on the lexical state stack.
   */
  FuncState* close_func(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Proto* const f = fsView->f;

    removevars(ls, 0);
    luaK_codeABC(fs, OP_RETURN, 0, 1, 0);

    f->code = static_cast<Instruction*>(
      luaM_realloc(
        ls->L,
        f->code,
        static_cast<lu_mem>(sizeof(Instruction) * f->sizecode),
        static_cast<lu_mem>(sizeof(Instruction) * fsView->pc)
      )
    );
    f->sizecode = fsView->pc;

    f->lineinfo = static_cast<int*>(
      luaM_realloc(
        ls->L,
        f->lineinfo,
        static_cast<lu_mem>(sizeof(int) * f->sizelineinfo),
        static_cast<lu_mem>(sizeof(int) * fsView->pc)
      )
    );
    f->sizelineinfo = fsView->pc;

    f->k = static_cast<LuaPlus::TObject*>(
      luaM_realloc(
        ls->L,
        f->k,
        static_cast<lu_mem>(sizeof(LuaPlus::TObject) * f->sizek),
        static_cast<lu_mem>(sizeof(LuaPlus::TObject) * fsView->nk)
      )
    );
    f->sizek = fsView->nk;

    f->p = static_cast<Proto**>(
      luaM_realloc(
        ls->L,
        f->p,
        static_cast<lu_mem>(sizeof(Proto*) * f->sizep),
        static_cast<lu_mem>(sizeof(Proto*) * fsView->np)
      )
    );
    f->sizep = fsView->np;

    f->locvars = static_cast<LocVar*>(
      luaM_realloc(
        ls->L,
        f->locvars,
        static_cast<lu_mem>(sizeof(LocVar) * f->sizelocvars),
        static_cast<lu_mem>(sizeof(LocVar) * fsView->nlocvars)
      )
    );
    f->sizelocvars = fsView->nlocvars;

    f->upvalues = static_cast<TString**>(
      luaM_realloc(
        ls->L,
        f->upvalues,
        static_cast<lu_mem>(sizeof(TString*) * f->sizeupvalues),
        static_cast<lu_mem>(sizeof(TString*) * f->nups)
      )
    );
    f->sizeupvalues = f->nups;

    ls->fs = fsView->prev;
    return fsView->prev;
  }
  // ---------------------------------------------------------------------
  // lparser.c - blocks, statements and the parser entry point.
  //
  // enterblock / leaveblock / block_follow / new_localvar / cond are
  // file-local in the original and were inlined at every use here, so they
  // carry no address of their own.
  // ---------------------------------------------------------------------

  /**
   * What it does:
   * Pushes one lexical block onto the FuncState chain, remembering how many
   * locals were active outside it.
   */
  void enterblock(FuncState* const fs, BlockCntRuntimeView* const bl, const std::int32_t isbreakable)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    bl->breaklist = NO_JUMP;
    bl->continuelist = NO_JUMP;
    bl->isbreakable = isbreakable;
    bl->nactvar = fsView->nactvar;
    bl->upval = 0;
    bl->previous = fsView->bl;
    fsView->bl = bl;
  }

  /**
   * What it does:
   * Pops the innermost block: its locals go out of scope, any upvalue closed
   * over inside it is closed, and the jumps that left it via `break` land here.
   */
  void leaveblock(FuncState* const fs)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    BlockCntRuntimeView* const bl = fsView->bl;

    fsView->bl = bl->previous;
    removevars(reinterpret_cast<LexState*>(fsView->lexState), bl->nactvar);
    if (bl->upval != 0) {
      luaK_codeABC(fs, OP_CLOSE, bl->nactvar, 0, 0);
    }
    fsView->freereg = fsView->nactvar; // free registers
    luaK_patchtohere(fs, bl->breaklist);
  }

  /**
   * What it does:
   * True for the tokens that can only appear after a block has ended.
   */
  [[nodiscard]] constexpr bool block_follow(const std::int32_t token) noexcept
  {
    switch (token) {
    case TK_ELSE:
    case TK_ELSEIF:
    case TK_END:
    case TK_UNTIL:
    case TK_EOS:
      return true;
    default:
      return false;
    }
  }

  /**
   * Address: 0x0091C820 (FUN_0091C820, block)
   *
   * What it does:
   * Parses a scoped statement list.
   */
  extern "C" void block(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    BlockCntRuntimeView bl;
    enterblock(fs, &bl, 0);
    chunk(ls);
    leaveblock(fs);
  }

  /**
   * Address: 0x0091ACF0 (FUN_0091ACF0, luaI_registerlocalvar)
   *
   * IDA signature:
   * int __usercall luaI_registerlocalvar@<eax>(LexState *ls@<ecx>, TString *varname);
   *
   * What it does:
   * Appends one entry to the prototype's local-variable debug table and returns
   * its index.
   */
  extern "C" int luaI_registerlocalvar(LexState* const ls, TString* const varname)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    Proto* const f = fsView->f;

    if (fsView->nlocvars + 1 > f->sizelocvars) {
      f->locvars = static_cast<LocVar*>(luaM_growaux(
        ls->L, f->locvars, &f->sizelocvars, static_cast<int>(sizeof(LocVar)), MAX_INT, ""));
    }
    f->locvars[fsView->nlocvars].varname = varname;
    return fsView->nlocvars++;
  }

  /**
   * What it does:
   * Declares the n'th local of a group that is not active yet - `local a, b, c`
   * registers all three before any of them becomes visible.
   */
  void new_localvar(LexState* const ls, TString* const name, const int n)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);
    luaX_checklimit(ls, fsView->nactvar + n + 1, MAXVARS, "local variables");
    fsView->actvar[fsView->nactvar + n] = luaI_registerlocalvar(ls, name);
  }

  /**
   * Address: 0x0091AE00 (FUN_0091AE00, new_localvarstr)
   *
   * IDA signature:
   * void __usercall new_localvarstr(const char *name@<edx>, LexState *ls@<edi>, int n);
   *
   * What it does:
   * Declares a compiler-generated local - the hidden `arg`, `self`, and the
   * `(for ...)` control variables - from a C string.
   */
  extern "C" void new_localvarstr(const char* const name, LexState* const ls, const int n)
  {
    TString* const ts = luaS_newlstr(ls->L, name, std::strlen(name));
    new_localvar(ls, ts, n);
  }

  /**
   * Address: 0x0091B140 (FUN_0091B140, code_params)
   *
   * IDA signature:
   * void __usercall code_params(LexState *ls@<eax>, int nparams@<edx>, int dots@<ebx>);
   *
   * What it does:
   * Turns the parsed parameter names into the function's active locals and
   * records how many there are. A vararg function also gets the hidden `arg`
   * table, which occupies one more register.
   */
  extern "C" void code_params(LexState* const ls, const int nparams, const int dots)
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(ls->fs);

    adjustlocalvars(ls, nparams);
    luaX_checklimit(ls, fsView->nactvar, MAXPARAMS, "parameters");
    fsView->f->numparams = static_cast<lu_byte>(fsView->nactvar);
    fsView->f->is_vararg = static_cast<lu_byte>(dots);
    if (dots != 0) {
      new_localvarstr("arg", ls, 0);
      adjustlocalvars(ls, 1);
    }
    luaK_reserveregs(ls->fs, fsView->nactvar); // reserve register for parameters
  }

  /**
   * Address: 0x0091BAD0 (FUN_0091BAD0, parlist)
   *
   * What it does:
   * Parses a parameter list, with an optional trailing `...`.
   */
  void parlist(LexState* const ls)
  {
    int nparams = 0;
    int dots = 0;

    if (ls->t.token != ')') { // is `parlist' not empty?
      while (ls->t.token == TK_NAME) {
        new_localvar(ls, str_checkname(ls), nparams++);
        if (!testnext(ls, ',')) {
          code_params(ls, nparams, dots);
          return;
        }
      }

      if (ls->t.token != TK_DOTS) {
        luaX_syntaxerror(ls, "<name> or `...' expected");
      }
      dots = 1;
      next(ls);
    }

    code_params(ls, nparams, dots);
  }

  /**
   * Address: 0x0091BC70 (FUN_0091BC70, body)
   *
   * What it does:
   * Parses a function body into a nested prototype and leaves an OP_CLOSURE
   * expression behind. `needself` adds the implicit `self` of `a:b()` form.
   */
  extern "C" void body(LexState* const ls, expdesc* const e, const int needself, const int line)
  {
    FuncStateRuntimeView new_fs;
    auto* const newFuncState = reinterpret_cast<FuncState*>(&new_fs);
    open_func(ls, newFuncState);
    new_fs.f->lineDefined = line;

    check(ls, '(');
    if (needself != 0) {
      new_localvarstr("self", ls, 0);
      adjustlocalvars(ls, 1);
    }
    parlist(ls);
    check(ls, ')');
    chunk(ls);
    check_match(ls, TK_END, TK_FUNCTION, line);
    close_func(ls);
    pushclosure(e, ls, newFuncState);
  }

  /**
   * What it does:
   * Parses a loop or branch condition and emits the jumps that skip the body
   * when it is false. `nil` is folded to `false` so the constant path is used.
   */
  extern "C" void cond(LexState* const ls, expdesc* const v)
  {
    subexpr(ls, v, -1);
    if (v->k == VNIL) {
      v->k = VFALSE; // `falses' are all equal here
    }
    luaK_goiftrue(ls->fs, v);
    luaK_patchtohere(ls->fs, v->t);
  }

  /**
   * Address: 0x0091D410 (FUN_0091D410, test_then_block)
   *
   * What it does:
   * Parses one `<cond> THEN <block>` arm of an if/elseif chain.
   */
  extern "C" void test_then_block(LexState* const ls, expdesc* const v)
  {
    next(ls); // skip IF or ELSEIF
    cond(ls, v);
    check(ls, TK_THEN);
    block(ls); // `then' part
  }

  /**
   * Address: 0x0091CA90 (FUN_0091CA90, whilestat)
   *
   * What it does:
   * Parses `while cond do block end`. The condition is compiled first, lifted
   * back out of the instruction stream, and re-emitted after the body - so the
   * loop costs one jump on entry and none per iteration, instead of a jump back
   * and forth every time round. That rotation is why the condition has a size
   * limit and why the true/false jump lists have to be relocated by hand.
   */
  extern "C" void whilestat(LexState* const ls, const std::int32_t line)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    Instruction codeexp[MAXEXPWHILE];
    expdesc v;
    BlockCntRuntimeView bl;

    next(ls); // skip WHILE

    const std::int32_t whileinit = luaK_jump(fs);
    const std::int32_t expinit = luaK_getlabel(fs);
    subexpr(ls, &v, -1);
    if (v.k == VK) {
      v.k = VTRUE; // `while true' - the condition is not worth testing
    }
    const std::int32_t lineexp = ls->linenumber;
    luaK_goiffalse(fs, &v);
    luaK_concat(fs, &v.f, fsView->jpc);
    fsView->jpc = NO_JUMP;

    const std::int32_t sizeexp = fsView->pc - expinit; // size of expression code
    if (sizeexp > MAXEXPWHILE) {
      luaX_syntaxerror(ls, "`while' condition too complex");
    }
    for (std::int32_t i = 0; i < sizeexp; ++i) { // save `exp' code
      codeexp[i] = fsView->f->code[expinit + i];
    }
    fsView->pc = expinit; // remove `exp' code

    enterblock(fs, &bl, 1);
    check(ls, TK_DO);
    const std::int32_t blockinit = luaK_getlabel(fs);
    block(ls);
    luaK_patchtohere(fs, whileinit); // initial jump jumps to here
    luaK_patchtohere(fs, bl.continuelist);

    // move `exp' back to code
    if (v.t != NO_JUMP) {
      v.t += fsView->pc - expinit;
    }
    if (v.f != NO_JUMP) {
      v.f += fsView->pc - expinit;
    }
    for (std::int32_t i = 0; i < sizeexp; ++i) {
      luaK_code(fs, codeexp[i], lineexp);
    }

    check_match(ls, TK_END, TK_WHILE, line);
    leaveblock(fs);
    luaK_patchlist(fs, v.t, blockinit); // true conditions go back to loop
    luaK_patchtohere(fs, v.f);          // false conditions finish the loop
  }

  /**
   * Address: 0x0091CD40 (FUN_0091CD40, repeatstat)
   *
   * What it does:
   * Parses `repeat block until cond`. The body runs before the test, so the
   * false branch jumps back to the top.
   */
  extern "C" void repeatstat(LexState* const ls, const std::int32_t line)
  {
    FuncState* const fs = ls->fs;
    const std::int32_t repeat_init = luaK_getlabel(fs);
    expdesc v;
    BlockCntRuntimeView bl;

    enterblock(fs, &bl, 1);
    next(ls); // skip REPEAT
    block(ls);
    luaK_patchtohere(fs, bl.continuelist);
    check_match(ls, TK_UNTIL, TK_REPEAT, line);

    cond(ls, &v);
    luaK_patchlist(fs, v.f, repeat_init);
    leaveblock(fs);
  }

  /**
   * Address: 0x0091CEA0 (FUN_0091CEA0, forbody)
   *
   * IDA signature:
   * void __usercall forbody(LexState *ls@<eax>, int base, int line, int nvars, int isnum);
   *
   * What it does:
   * Parses the `do block end` shared by both `for` forms and closes the loop -
   * OP_FORLOOP for the numeric form, OP_TFORLOOP plus a jump for the generic
   * one.
   */
  extern "C" void
  forbody(LexState* const ls, const int base, const int line, const int nvars, const int isnum)
  {
    FuncState* const fs = ls->fs;
    BlockCntRuntimeView bl;

    adjustlocalvars(ls, nvars); // scope for all variables
    check(ls, TK_DO);
    enterblock(fs, &bl, 1);
    const std::int32_t prep = luaK_getlabel(fs);
    block(ls);
    luaK_patchtohere(fs, bl.continuelist);
    luaK_patchtohere(fs, prep - 1);

    const std::int32_t endfor = (isnum != 0)
      ? luaK_codeABx(fs, OP_FORLOOP, base, static_cast<std::uint32_t>(NO_JUMP + LUA_MAXARG_sBx))
      : luaK_codeABC(fs, OP_TFORLOOP, base, 0, nvars - 3);
    luaK_fixline(fs, line); // pretend that `OP_FOR' starts the loop

    luaK_patchlist(fs, (isnum != 0) ? endfor : luaK_jump(fs), prep);
    leaveblock(fs);
  }

  /**
   * Address: 0x0091CFC0 (FUN_0091CFC0, fornum)
   *
   * What it does:
   * Parses `for name = init, limit [, step] do`. The three control values live
   * in hidden locals; the initial value is pre-decremented by one step so the
   * loop opcode can increment first and test afterwards.
   */
  extern "C" void fornum(LexState* const ls, TString* const varname, const std::int32_t line)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    const int base = fsView->freereg;
    expdesc v;

    new_localvar(ls, varname, 0);
    new_localvarstr("(for limit)", ls, 1);
    new_localvarstr("(for step)", ls, 2);

    check(ls, '=');
    subexpr(ls, &v, -1); // initial value
    luaK_exp2nextreg(ls->fs, &v);
    check(ls, ',');
    subexpr(ls, &v, -1); // limit
    luaK_exp2nextreg(ls->fs, &v);

    if (testnext(ls, ',')) {
      subexpr(ls, &v, -1); // optional step
      luaK_exp2nextreg(ls->fs, &v);
    } else { // default step = 1
      luaK_codeABx(fs, OP_LOADK, fsView->freereg, static_cast<std::uint32_t>(luaK_numberK(fs, 1.0f)));
      luaK_reserveregs(fs, 1);
    }

    luaK_codeABC(fs, OP_SUB, fsView->freereg - 3, fsView->freereg - 3, fsView->freereg - 1);
    luaK_jump(fs);
    forbody(ls, base, line, 3, 1);
  }

  /**
   * Address: 0x0091D120 (FUN_0091D120, forlist)
   *
   * What it does:
   * Parses `for a, b, ... in explist do`. Two hidden locals hold the iterator
   * function and its state, followed by the visible control variables.
   */
  extern "C" void forlist(LexState* const ls, TString* const indexname)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    const int base = fsView->freereg;
    expdesc e;

    new_localvarstr("(for generator)", ls, 0);
    new_localvarstr("(for state)", ls, 1);
    new_localvar(ls, indexname, 2);

    int nvars = 3;
    while (testnext(ls, ',')) {
      new_localvar(ls, str_checkname(ls), nvars++);
    }

    check(ls, TK_IN);
    const std::int32_t line = ls->linenumber;
    adjust_assign(ls, nvars, &e, explist1(ls, &e));
    luaK_checkstack(fs, 3); // extra space to call generator
    luaK_codeABx(fs, OP_TFORPREP, base, static_cast<std::uint32_t>(NO_JUMP + LUA_MAXARG_sBx));
    forbody(ls, base, line, nvars, 0);
  }

  /**
   * Address: 0x0091D300 (FUN_0091D300, forstat)
   *
   * What it does:
   * Parses either `for` form; the token after the first name decides which.
   * The whole loop sits in its own block so the control variables disappear
   * with it.
   */
  extern "C" void forstat(LexState* const ls, const std::int32_t line)
  {
    FuncState* const fs = ls->fs;
    BlockCntRuntimeView bl;
    enterblock(fs, &bl, 0); // scope for loop and control variables

    next(ls); // skip `for'
    TString* const varname = str_checkname(ls); // first variable name

    switch (ls->t.token) {
    case '=':
      fornum(ls, varname, line);
      break;

    case ',':
    case TK_IN:
      forlist(ls, varname);
      break;

    default:
      luaX_syntaxerror(ls, "`=' or `in' expected");
      break;
    }

    check_match(ls, TK_END, TK_FOR, line);
    leaveblock(fs);
  }

  /**
   * Address: 0x0091D590 (FUN_0091D590, localfunc)
   *
   * What it does:
   * Parses `local function f() ... end`. The local is declared before the body
   * is compiled, so the function can call itself by name.
   */
  extern "C" void localfunc(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    expdesc v;
    expdesc b;

    new_localvar(ls, str_checkname(ls), 0);
    v.k = VLOCAL;
    v.info = fsView->freereg;
    v.t = NO_JUMP;
    v.f = NO_JUMP;
    luaK_reserveregs(fs, 1);
    adjustlocalvars(ls, 1);

    body(ls, &b, 0, ls->linenumber);
    luaK_storevar(fs, &v, &b);

    // debug information will only see the variable after this point
    fsView->f->locvars[fsView->actvar[fsView->nactvar - 1]].startpc = fsView->pc;
  }

  /**
   * Address: 0x0091D6B0 (FUN_0091D6B0, localstat)
   *
   * What it does:
   * Parses `local a, b, c [= explist]`. The names are only made visible after
   * the initialisers are compiled, so `local x = x` reads the outer `x`.
   */
  extern "C" void localstat(LexState* const ls)
  {
    int nvars = 0;
    int nexps = 0;
    expdesc e;

    do {
      new_localvar(ls, str_checkname(ls), nvars++);
    } while (testnext(ls, ','));

    if (testnext(ls, '=')) {
      nexps = explist1(ls, &e);
    } else {
      e.k = VVOID;
      nexps = 0;
    }

    adjust_assign(ls, nvars, &e, nexps);
    adjustlocalvars(ls, nvars);
  }

  /**
   * Address: 0x0091D980 (FUN_0091D980, retstat)
   *
   * What it does:
   * Parses `return [explist]`. A lone call in tail position becomes
   * OP_TAILCALL when tail calls are enabled, so recursion through it does not
   * grow the C stack.
   */
  extern "C" void retstat(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    expdesc e;

    next(ls); // skip RETURN

    std::int32_t first = 0; // registers with returned values
    std::int32_t nret = 0;
    if (!block_follow(ls->t.token) && ls->t.token != ';') { // there are return values
      nret = explist1(ls, &e);
      if (e.k == VCALL) {
        luaK_setcallreturns(fs, &e, LUA_MULTRET);
        if (lua::enable_tailcalls != 0 && nret == 1) { // tail call?
          Instruction& call = fsView->f->code[e.info];
          call = (call & ~static_cast<Instruction>(0x3Fu)) | static_cast<Instruction>(OP_TAILCALL);
        }
        first = fsView->nactvar;
        nret = LUA_MULTRET; // return all values
      } else if (nret == 1) { // only one single value?
        first = luaK_exp2anyreg(fs, &e);
      } else {
        luaK_exp2nextreg(fs, &e); // values must go to the `stack'
        first = fsView->nactvar;  // return all `active' values
      }
    }

    luaK_codeABC(fs, OP_RETURN, first, nret + 1, 0);
  }

  /**
   * What it does:
   * Walks out `levels` enclosing loops for `break`/`continue`, collecting
   * whether any block on the way holds an upvalue. Returns the loop that was
   * landed on, or null when there is none.
   */
  struct LoopExitTarget
  {
    BlockCntRuntimeView* loop;      // the loop reached, or null
    BlockCntRuntimeView* lastLoop;  // the loop reached one level in
    std::int32_t upvalAtLevel;      // upvalues seen before the final level
  };

  [[nodiscard]] LoopExitTarget FindEnclosingLoop(FuncState* const fs, std::int32_t levels) noexcept
  {
    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    LoopExitTarget target{nullptr, nullptr, 0};

    BlockCntRuntimeView* bl = fsView->bl;
    std::int32_t upval = 0;
    for (;;) {
      --levels;
      target.upvalAtLevel = upval;
      if (bl != nullptr) {
        while (bl->isbreakable == 0) {
          upval |= bl->upval;
          bl = bl->previous;
          if (bl == nullptr) {
            break;
          }
        }
        if (bl != nullptr) {
          if (levels <= 0) {
            break;
          }
          target.lastLoop = bl;
          bl = bl->previous;
        }
      }
      if (levels <= 0) {
        break;
      }
    }

    target.loop = bl;
    return target;
  }

  /**
   * What it does:
   * Parses the optional loop count that this build accepts after `break` and
   * `continue`, so `break 2` leaves two loops at once.
   */
  [[nodiscard]] std::int32_t ReadLoopLevelCount(LexState* const ls)
  {
    next(ls);
    if (ls->t.token != TK_NUMBER) {
      return 1;
    }

    next(ls);
    const float r = ls->t.seminfo.r;
    if (r != std::floor(r)) {
      luaX_syntaxerror(ls, "loop block number must be integer");
    }

    const std::int32_t levels = static_cast<std::int32_t>(r);
    if (levels < 1 || levels > MAXEXPWHILE) {
      luaX_syntaxerror(ls, "loop block number out of range");
    }
    return levels;
  }

  /**
   * Address: 0x0091DAA0 (FUN_0091DAA0, breakstat)
   *
   * What it does:
   * Parses `break [n]` and adds the jump to the target loop's break list, which
   * leaveblock will later point past the loop.
   */
  extern "C" void breakstat(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    const std::int32_t levels = ReadLoopLevelCount(ls);

    const LoopExitTarget target = FindEnclosingLoop(fs, levels);
    if (target.loop == nullptr) {
      luaX_syntaxerror(ls, "no loop to break");
    }

    if (target.upvalAtLevel != 0) {
      luaK_codeABC(fs, OP_CLOSE, target.loop->nactvar, 0, 0);
    }
    luaK_concat(fs, &target.loop->breaklist, luaK_jump(fs));
  }

  /**
   * Address: 0x0091DBF0 (FUN_0091DBF0, continuestat)
   *
   * What it does:
   * Parses `continue [n]`, the loop-restart statement this build adds. The jump
   * joins the target loop's continue list, which each loop patches to its own
   * step. The OP_CLOSE it emits closes over the loop one level in, not the
   * target - which only matters for `continue n` with n above 1.
   */
  extern "C" void continuestat(LexState* const ls)
  {
    FuncState* const fs = ls->fs;
    const std::int32_t levels = ReadLoopLevelCount(ls);

    const LoopExitTarget target = FindEnclosingLoop(fs, levels);
    if (target.loop == nullptr) {
      luaX_syntaxerror(ls, "no loop to continue");
    }

    if (target.upvalAtLevel != 0) {
      luaK_codeABC(fs, OP_CLOSE, target.lastLoop->nactvar, 0, 0);
    }
    luaK_concat(fs, &target.loop->continuelist, luaK_jump(fs));
  }

  /**
   * Address: 0x0091C910 (FUN_0091C910, assignment)
   *
   * What it does:
   * Parses the rest of an assignment. It recurses across the comma-separated
   * targets so that the stores happen right to left, after every value has been
   * evaluated.
   */
  extern "C" void assignment(LexState* const ls, LHS_assign* const lh, const std::int32_t nvars)
  {
    expdesc e;

    if (lh->v.k < VLOCAL || lh->v.k > VINDEXED) {
      luaX_syntaxerror(ls, "syntax error");
    }

    if (testnext(ls, ',')) { // assignment -> `,' primaryexp assignment
      LHS_assign nv;
      nv.prev = lh;
      primaryexp(&nv.v, ls);
      if (nv.v.k == VLOCAL) {
        check_conflict(lh, ls, &nv.v);
      }
      assignment(ls, &nv, nvars + 1);
    } else { // assignment -> `=' explist1
      check(ls, '=');
      const std::int32_t nexps = explist1(ls, &e);
      if (nexps != nvars) {
        adjust_assign(ls, nvars, &e, nexps);
        if (nexps > nvars) {
          // remove extra values
          reinterpret_cast<FuncStateRuntimeView*>(ls->fs)->freereg -= nexps - nvars;
        }
      } else {
        luaK_setcallreturns(ls->fs, &e, 1); // close last expression
        luaK_storevar(ls->fs, &lh->v, &e);
        return; // avoid default
      }
    }

    // default assignment
    e.k = VNONRELOC;
    e.info = reinterpret_cast<FuncStateRuntimeView*>(ls->fs)->freereg - 1;
    e.t = NO_JUMP;
    e.f = NO_JUMP;
    luaK_storevar(ls->fs, &lh->v, &e);
  }

  /**
   * Address: 0x0091DD60 (FUN_0091DD60, statement)
   *
   * What it does:
   * Parses one statement. Returns non-zero for the two that must end a block -
   * `return` and `break`.
   */
  std::int32_t statement(LexState* const ls)
  {
    const std::int32_t line = ls->linenumber; // may be needed for error messages

    switch (ls->t.token) {
    case TK_IF:
      ifstat(ls, line);
      return 0;

    case TK_WHILE:
      whilestat(ls, line);
      return 0;

    case TK_DO:
      next(ls); // skip DO
      block(ls);
      check_match(ls, TK_END, TK_DO, line);
      return 0;

    case TK_FOR:
      forstat(ls, line);
      return 0;

    case TK_REPEAT:
      repeatstat(ls, line);
      return 0;

    case TK_FUNCTION:
      funcstat(ls, line);
      return 0;

    case TK_LOCAL:
      next(ls); // skip LOCAL
      if (testnext(ls, TK_FUNCTION)) { // local function?
        localfunc(ls);
      } else {
        localstat(ls);
      }
      return 0;

    case TK_RETURN:
      retstat(ls);
      return 1; // must be last statement

    case TK_BREAK:
      breakstat(ls);
      return 1; // must be last statement

    case TK_CONTINUE:
      continuestat(ls);
      return 1; // must be last statement

    default:
      exprstat(ls);
      return 0;
    }
  }

  /**
   * Address: 0x0091DEB0 (FUN_0091DEB0, chunk)
   *
   * What it does:
   * Parses a statement list, stopping at the token that closes the enclosing
   * construct or after a statement that has to come last. The nesting counter
   * bounds recursion so a pathological source cannot run the C stack out.
   */
  extern "C" void chunk(LexState* const ls)
  {
    if (++ls->nestlevel > LUA_MAXPARSERLEVEL) {
      luaX_syntaxerror(ls, "too many syntax levels");
    }

    while (!block_follow(ls->t.token)) {
      const std::int32_t islast = statement(ls);
      testnext(ls, ';');

      // statements only produce values through their side effects, so every
      // register above the active locals is free again
      reinterpret_cast<FuncStateRuntimeView*>(ls->fs)->freereg =
        reinterpret_cast<FuncStateRuntimeView*>(ls->fs)->nactvar;

      if (islast != 0) {
        break;
      }
    }

    --ls->nestlevel;
  }

  /**
   * Address: 0x00918150 (FUN_00918150, luaX_setinput)
   *
   * What it does:
   * Points the lexer at a stream and reads the first character. A leading `#!`
   * line is skipped, so a chunk can be a shell script.
   */
  extern "C" void
  luaX_setinput(lua_State* const L, LexState* const ls, LuaUndumpZioRuntimeView* const z, TString* const source)
  {
    ls->L = L;
    ls->linenumber = 1;
    ls->lastline = 1;
    ls->lookahead.token = TK_EOS; // no look-ahead token
    ls->z = z;
    ls->fs = nullptr;
    ls->source = source;

    nextchar(ls); // read first char
    if (ls->current == '#') {
      do { // skip first line
        nextchar(ls);
      } while (ls->current != '\n' && ls->current != kLuaEndOfStream);
    }
  }

  /**
   * Address: 0x0091DF80 (FUN_0091DF80, luaY_parser)
   *
   * What it does:
   * Compiles one chunk of Lua source into a prototype - the entry point the
   * loader calls once it has ruled out a precompiled chunk.
   */
  extern "C" Proto* luaY_parser(lua_State* const L, LuaUndumpZioRuntimeView* const z, Mbuffer* const buff)
  {
    LexState lexstate;
    FuncStateRuntimeView funcstate;

    lexstate.buff = buff;
    lexstate.nestlevel = 0;
    luaX_setinput(L, &lexstate, z, luaS_newlstr(L, z->name, std::strlen(z->name)));

    open_func(&lexstate, reinterpret_cast<FuncState*>(&funcstate));
    next(&lexstate); // read first token
    chunk(&lexstate);
    if (lexstate.t.token != TK_EOS) {
      luaX_syntaxerror(&lexstate, "<eof> expected");
    }
    close_func(&lexstate);

    return funcstate.f;
  }

} // namespace

extern "C"
{
  /**
   * Address: 0x009290F0 (FUN_009290F0, luaU_undump)
   * IDA signature:
   * Proto *__usercall luaU_undump@<eax>(lua_State *L, ZIO *Z, Mbuffer *buff);
   *
   * What it does:
   * Initializes the binary-chunk load state, normalizes the chunk source label
   * (`@`/`=` prefix strip, or `"binary string"` for a raw `\x1B` signature),
   * validates the chunk header, and returns the top-level `Proto`. Delegates to
   * the recovered header validator and recursive proto reader in LuaObject.cpp.
   */
  Proto* luaU_undump(lua_State* const state, LuaUndumpZioRuntimeView* const stream, Mbuffer* const buffer)
  {
    const char* sourceName = stream->name;
    const char firstChar = *sourceName;
    if (firstChar == '@' || firstChar == '=') {
      ++sourceName;
    } else if (firstChar == '\x1B') {
      sourceName = "binary string";
    }

    LuaPlus::LuaLoadStateRuntimeView loadState{};
    loadState.state = state;
    // The ZIO object is shared; only its leading {n, p} pair is touched by the
    // loader, which is layout-identical to LuaZioRuntimeView.
    loadState.stream = reinterpret_cast<LuaPlus::LuaZioRuntimeView*>(stream);
    loadState.scratchBuffer = buffer;
    loadState.chunkName = sourceName;

    LuaPlus::LuaLoadChunkHeader(&loadState);
    return LuaPlus::LuaLoadProtoObject(&loadState, nullptr);
  }
}
