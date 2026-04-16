#include "LuaRuntimeTypes.h"

#include <cctype>

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
    BlockCntRuntimeView* previous;
    std::uint8_t reserved04To0B[0x08];
    std::int32_t nactvar;
    std::int32_t upval;
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

  struct LuaUndumpLoadStateRuntimeView
  {
    lua_State* state;
    LuaUndumpZioRuntimeView* stream;
    Mbuffer* buffer;
    const char* sourceName;
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
  static_assert(offsetof(BlockCntRuntimeView, nactvar) == 0x0C, "BlockCntRuntimeView::nactvar offset must be 0x0C");
  static_assert(offsetof(BlockCntRuntimeView, upval) == 0x10, "BlockCntRuntimeView::upval offset must be 0x10");
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
  static_assert(offsetof(LuaUndumpZioRuntimeView, name) == 0x10, "LuaUndumpZioRuntimeView::name offset must be 0x10");
  static_assert(sizeof(LuaUndumpLoadStateRuntimeView) == 0x10, "LuaUndumpLoadStateRuntimeView size must be 0x10");

  constexpr std::int32_t NO_JUMP = -1;
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
  constexpr std::int32_t NO_REG = 0xFF;
  constexpr std::int32_t OP_MOVE = 0x00;
  constexpr std::int32_t OP_GETUPVAL = 0x04;
  constexpr std::int32_t OP_NOT = 0x16;
  constexpr std::int32_t OP_RETURN = 0x1F;
  constexpr std::int32_t OP_CLOSURE = 0x26;
  constexpr std::int32_t OP_EQ = 0x17;
  constexpr std::int32_t OP_LT = 0x18;
  constexpr std::int32_t OP_LE = 0x19;
  constexpr std::int32_t OP_TESTSET = 0x1C;
  constexpr std::int32_t MAXSTACK = 0xFA;
  constexpr std::int32_t LUA_MAXARG_Bx = 0x3FFFF;
  constexpr std::int32_t OPR_BAND = 0x00;
  constexpr std::int32_t OPR_BOR = 0x01;
  constexpr std::int32_t OPR_BSHL = 0x02;
  constexpr std::int32_t OPR_BSHR = 0x03;
  constexpr std::int32_t OPR_ADD = 0x04;
  constexpr std::int32_t OPR_SUB = 0x05;
  constexpr std::int32_t OPR_MULT = 0x06;
  constexpr std::int32_t OPR_DIV = 0x07;
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
  constexpr std::int32_t TK_AND = 0x101;
  constexpr std::int32_t TK_FALSE = 0x108;
  constexpr std::int32_t TK_ELSE = 0x105;
  constexpr std::int32_t TK_ELSEIF = 0x106;
  constexpr std::int32_t TK_END = 0x107;
  constexpr std::int32_t TK_FUNCTION = 0x10A;
  constexpr std::int32_t TK_IF = 0x10B;
  constexpr std::int32_t TK_NIL = 0x10E;
  constexpr std::int32_t TK_OR = 0x110;
  constexpr std::int32_t TK_THEN = 0x113;
  constexpr std::int32_t TK_TRUE = 0x114;
  constexpr std::int32_t TK_CONCAT = 0x118;
  constexpr std::int32_t TK_EQ = 0x11A;
  constexpr std::int32_t TK_GE = 0x11B;
  constexpr std::int32_t TK_LE = 0x11C;
  constexpr std::int32_t TK_NE = 0x11D;
  constexpr std::int32_t TK_NUMBER = 0x11E;
  constexpr std::int32_t TK_STRING = 0x11F;
  constexpr std::int32_t TK_BSHL = 0x120;
  constexpr std::int32_t TK_BSHR = 0x121;
  constexpr std::int32_t TK_EOS = 0x122;
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
  [[maybe_unused]] [[nodiscard]] std::int32_t
  LuaPatchTestRegisterField(std::int32_t registerIndex, Instruction* const instructionSlot) noexcept
  {
    if (registerIndex == NO_REG) {
      registerIndex = static_cast<std::int32_t>((*instructionSlot >> 15) & 0x1FFu);
    }

    const std::int32_t patchedAField = registerIndex << 24;
    *instructionSlot = static_cast<Instruction>(
      (static_cast<std::uint32_t>(*instructionSlot) & 0x00FFFFFFu) | static_cast<std::uint32_t>(patchedAField)
    );
    return patchedAField;
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

  extern "C"
  {
    void next(LexState* ls);
    void cond(LexState* ls, expdesc* v);
    void check(LexState* ls, std::int32_t c);
    void block(LexState* ls);
    void check_match(LexState* ls, std::int32_t what, std::int32_t who, std::int32_t where);
    void subexpr(LexState* ls, expdesc* expression, std::int32_t limit);
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
    Proto* luaY_parser(lua_State* L, void* z, Mbuffer* buff);
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
    char* luaZ_openspace(lua_State* L, Mbuffer* buff, std::size_t n);
    void LuaUndumpLoadChunkHeader(LuaUndumpLoadStateRuntimeView* loadState);
    Proto* LuaUndumpLoadTopLevelProto(LuaUndumpLoadStateRuntimeView* loadState, int parentProtoIndex);
    void luaG_runerror(lua_State* L, const char* format, ...);
    int luaK_exp2anyreg(FuncState* fs, expdesc* e);
    void luaK_indexed(FuncState* fs, expdesc* t, expdesc* k);
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
  [[maybe_unused]] std::size_t ReadIdentifierName(const char firstCharacter, LexState* const lexState)
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
  [[maybe_unused]] void lastlistfield(FuncState* const functionState, ConsControl* const constructorState)
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
   * Address: 0x0091AC60 (lparser.c::str_checkname, file-local in original Lua)
   *
   * What it does:
   * Asserts the current lexer token is `TK_NAME` (`0x104`), captures the
   * semantic-info `TString*`, advances to the next token, and returns the
   * captured identifier. Recovered as a free function here because callers
   * (e.g., `singlevar`) live in our recovered LuaParser.cpp.
   */
  extern "C" TString* str_checkname(LexState* const ls)
  {
    constexpr std::int32_t kTkName = 0x104;
    if (ls->t.token != kTkName) {
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
  [[maybe_unused]] void codebinop(
    const int leftOperandRegister,
    const int binaryOperator,
    int rightOperandRegister,
    expdesc* const result,
    FuncState* const fs
  )
  {
    int lhsRegister = leftOperandRegister;
    if (binaryOperator > OPR_POW) {
      int jumpSense = 1;
      if (binaryOperator < OPR_GT) {
        jumpSense = (binaryOperator != OPR_NE) ? 1 : 0;
      } else {
        const int swapped = rightOperandRegister;
        rightOperandRegister = lhsRegister;
        lhsRegister = swapped;
      }

      int comparisonOpcode = OP_EQ;
      if (binaryOperator == (OPR_NE + 2) || binaryOperator == OPR_GT) {
        comparisonOpcode = OP_LT;
      } else if (binaryOperator == (OPR_NE + 3) || binaryOperator == (OPR_GT + 1)) {
        comparisonOpcode = OP_LE;
      }

      const int jumpList = luaK_condjump(jumpSense, fs, comparisonOpcode, rightOperandRegister, lhsRegister);
      result->k = VJMP;
      result->info = jumpList;
      return;
    }

    auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
    auto* const lexState = reinterpret_cast<LexState*>(fsView->lexState);
    const Instruction instruction = static_cast<Instruction>(
      (binaryOperator + 12) | ((leftOperandRegister | (rightOperandRegister << 9)) << 6)
    );
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
      const std::int32_t opcode = static_cast<std::int32_t>(testInstruction & 0x3Fu);
      const std::int32_t jumpCondition = static_cast<std::int32_t>((testInstruction >> 6) & 0x1FFu);
      if (opcode != OP_TESTSET || jumpCondition != cond) {
        return 1;
      }

      const std::int32_t jumpOffset = static_cast<std::int32_t>((*jumpInstruction >> 6) & 0x3FFFFu) - 0x1FFFF;
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

    next(ls);
    cond(ls, &v);
    check(ls, TK_THEN);
    block(ls);

    while (ls->t.token == TK_ELSEIF) {
      luaK_concat(fs, &escapelist, luaK_jump(fs));
      luaK_patchtohere(fs, v.f);

      next(ls);
      cond(ls, &v);
      check(ls, TK_THEN);
      block(ls);
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
  void f_parser(SParser* const parser, lua_State* const state)
  {
    auto* const globalState = reinterpret_cast<LuaParserGlobalStateRuntimeView*>(state->l_G);
    if (globalState->totalBytes >= globalState->gcThreshold && globalState->panic == nullptr) {
      luaC_collectgarbage(state);
    }

    Proto* const parsedProto = (parser->bin != 0)
      ? luaU_undump(state, static_cast<LuaUndumpZioRuntimeView*>(parser->z), &parser->buff)
      : luaY_parser(state, parser->z, &parser->buff);

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
} // namespace

extern "C"
{
  /**
   * Address: 0x00928ED0 (FUN_00928ED0, LoadChunk)
   *
   * What it does:
   * Reads and validates the binary chunk header (signature byte, version,
   * format word, endianness/size flags) from the load stream. The full
   * binary-bytecode loader is not yet recovered (FUN_00928ED0 is 512 bytes
   * of bit-twiddling); this stub raises a runtime error so callers see a
   * clear failure if pre-compiled bytecode is ever loaded. Lua source
   * loading goes through `luaY_parser`, not this path.
   */
  void LuaUndumpLoadChunkHeader(LuaUndumpLoadStateRuntimeView* const loadState)
  {
    luaG_runerror(loadState->state, "binary chunk loading not implemented in %s", loadState->sourceName);
  }

  /**
   * Address: 0x00928C10 (FUN_00928C10, LoadFunction)
   *
   * What it does:
   * Recursively reads one `Proto` (line numbers, locals, upvalues, code,
   * constants, nested protos) from the binary chunk stream. Not yet recovered
   * (FUN_00928C10 is 447 bytes); raises a runtime error if reached. Compiled
   * Lua source goes through `luaY_parser` instead, so this path is dormant
   * unless a `.luac` chunk is fed to `lua_load`.
   */
  Proto* LuaUndumpLoadTopLevelProto(LuaUndumpLoadStateRuntimeView* const loadState, int)
  {
    luaG_runerror(loadState->state, "binary chunk loading not implemented in %s", loadState->sourceName);
    return nullptr;
  }

  /**
   * Address: 0x009290F0 (FUN_009290F0, luaU_undump)
   *
   * What it does:
   * Initializes binary-chunk load state, normalizes chunk source labels
   * (`@`, `=`, binary-signature), then loads and returns top-level `Proto`.
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

    LuaUndumpLoadStateRuntimeView loadState{};
    loadState.state = state;
    loadState.stream = stream;
    loadState.buffer = buffer;
    loadState.sourceName = sourceName;

    LuaUndumpLoadChunkHeader(&loadState);
    return LuaUndumpLoadTopLevelProto(&loadState, 0);
  }
}
