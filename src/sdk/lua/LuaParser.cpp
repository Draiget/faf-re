#include "LuaRuntimeTypes.h"

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

  struct FuncStateRuntimeView
  {
    Proto* functionProto;
    std::uint8_t reserved04To23[0x20];
    std::int32_t freeRegisterIndex;
    std::uint8_t reserved28To2B[0x04];
    std::int32_t nestedProtoCount;
    std::uint8_t reserved30To33[0x04];
    std::int32_t activeVariableCount;
    expdesc upvalues[0x20];
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
  static_assert(
    offsetof(FuncStateRuntimeView, functionProto) == 0x00, "FuncStateRuntimeView::functionProto offset must be 0x00"
  );
  static_assert(
    offsetof(FuncStateRuntimeView, nestedProtoCount) == 0x2C,
    "FuncStateRuntimeView::nestedProtoCount offset must be 0x2C"
  );
  static_assert(
    offsetof(FuncStateRuntimeView, freeRegisterIndex) == 0x24,
    "FuncStateRuntimeView::freeRegisterIndex offset must be 0x24"
  );
  static_assert(
    offsetof(FuncStateRuntimeView, activeVariableCount) == 0x34,
    "FuncStateRuntimeView::activeVariableCount offset must be 0x34"
  );
  static_assert(offsetof(FuncStateRuntimeView, upvalues) == 0x38, "FuncStateRuntimeView::upvalues offset must be 0x38");
  static_assert(offsetof(LuaUndumpZioRuntimeView, name) == 0x10, "LuaUndumpZioRuntimeView::name offset must be 0x10");
  static_assert(sizeof(LuaUndumpLoadStateRuntimeView) == 0x10, "LuaUndumpLoadStateRuntimeView size must be 0x10");

  constexpr std::int32_t NO_JUMP = -1;
  constexpr std::int32_t VNIL = 0x01;
  constexpr std::int32_t VTRUE = 0x02;
  constexpr std::int32_t VFALSE = 0x03;
  constexpr std::int32_t VK = 0x04;
  constexpr std::int32_t VLOCAL = 0x05;
  constexpr std::int32_t VJMP = 0x09;
  constexpr std::int32_t VRELOCABLE = 0x0A;
  constexpr std::int32_t VNONRELOC = 0x0B;
  constexpr std::int32_t VCALL = 0x0C;
  constexpr std::int32_t OP_MOVE = 0x00;
  constexpr std::int32_t OP_GETUPVAL = 0x04;
  constexpr std::int32_t OP_NOT = 0x16;
  constexpr std::int32_t OP_CLOSURE = 0x26;
  constexpr std::int32_t MAXSTACK = 0xFA;
  constexpr std::int32_t LUA_MAXARG_Bx = 0x3FFFF;
  constexpr std::int32_t TK_FALSE = 0x108;
  constexpr std::int32_t TK_ELSE = 0x105;
  constexpr std::int32_t TK_ELSEIF = 0x106;
  constexpr std::int32_t TK_END = 0x107;
  constexpr std::int32_t TK_FUNCTION = 0x10A;
  constexpr std::int32_t TK_IF = 0x10B;
  constexpr std::int32_t TK_NIL = 0x10E;
  constexpr std::int32_t TK_THEN = 0x113;
  constexpr std::int32_t TK_TRUE = 0x114;
  constexpr std::int32_t TK_NUMBER = 0x11E;
  constexpr std::int32_t TK_STRING = 0x11F;
  constexpr std::int32_t TK_EOS = 0x122;

  void next(LexState* ls);
  void cond(LexState* ls, expdesc* v);
  void check(LexState* ls, std::int32_t c);
  void block(LexState* ls);
  void check_match(LexState* ls, std::int32_t what, std::int32_t who, std::int32_t where);
  void subexpr(LexState* ls, expdesc* expression, std::int32_t limit);
  void assignment(LexState* ls, LHS_assign* lhs, std::int32_t nvars);

  extern "C"
  {
    std::int32_t luaK_jump(FuncState* fs);
    void luaK_concat(FuncState* fs, std::int32_t* l1, std::int32_t l2);
    void luaK_patchtohere(FuncState* fs, std::int32_t list);
    void luaK_reserveregs(FuncState* fs, int n);
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
    LClosure* luaF_newLclosure(lua_State* L, int nelems, LuaPlus::TObject* e);
    Proto* luaU_undump(lua_State* state, LuaUndumpZioRuntimeView* stream, Mbuffer* buffer);
    Proto* luaY_parser(lua_State* L, void* z, Mbuffer* buff);
    std::int32_t luaX_lex(LexState* ls, SemInfo* seminfo);
    std::int32_t funcname(expdesc* outExpression, LexState* ls);
    void luaK_storevar(FuncState* fs, expdesc* outVariableExpression, expdesc* valueExpression);
    void luaK_fixline(FuncState* fs, int line);
    void codestring(TString* stringToken, LexState* ls, expdesc* outExpression);
    void constructor(expdesc* outExpression, LexState* ls);
    void body(LexState* ls, expdesc* outExpression, int needself, int line);
    void primaryexp(expdesc* outExpression, LexState* ls);
    void LuaUndumpLoadChunkHeader(LuaUndumpLoadStateRuntimeView* loadState);
    Proto* LuaUndumpLoadTopLevelProto(LuaUndumpLoadStateRuntimeView* loadState, int parentProtoIndex);
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
    Proto* const parentProto = parentView->functionProto;
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
    parentProto->p[parentView->nestedProtoCount++] = childView->functionProto;

    outExpression->t = -1;
    outExpression->f = -1;
    outExpression->k = VRELOCABLE;
    outExpression->info = luaK_codeABx(ls->fs, OP_CLOSURE, 0, static_cast<unsigned int>(parentView->nestedProtoCount - 1));

    const int upvalueCount = static_cast<int>(childView->functionProto->nups);
    for (int index = 0; index < upvalueCount; ++index) {
      const expdesc& upvalue = childView->upvalues[index];
      const std::int32_t opcode = (upvalue.k == VLOCAL) ? OP_MOVE : OP_GETUPVAL;
      luaK_codeABC(ls->fs, opcode, 0, upvalue.info, 0);
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
      if (expression->k == VNONRELOC) {
        auto* const fsView = reinterpret_cast<FuncStateRuntimeView*>(fs);
        if (expression->info >= fsView->activeVariableCount && expression->info < MAXSTACK) {
          --fsView->freeRegisterIndex;
        }
      }
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
} // namespace

extern "C"
{
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
