// Engine addition (dedicated-server plan WPL.24): lists the calls and constructions whose
// result could depend on the order their arguments are evaluated in.
//
// clang evaluates call arguments right to left under the Microsoft ABI (the Windows builds)
// and left to right under System V (Linux). A call with two or more arguments that each call
// a function with side effects (not a const member function, not on the pure list below) can
// then compute different values on the two platforms - an RNG draw in each argument is the
// classic case. This tool walks one translation unit with libclang and prints one line per
// such call:
//
//   <file>:<line>:<col> <callee> | arg<i>: <callees in that argument> | ...
//
// Usage: faf-argorder-scan <source> -- <compiler arguments...>
//
// Built against the system's libclang-18 (only the shared library is installed, no headers,
// so the stable C API's few declarations are spelled out below).

#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

extern "C" {
enum CXCursorKind { CXCursor_FunctionDecl = 8, CXCursor_CXXMethod = 21, CXCursor_Constructor = 24,
                    CXCursor_Destructor = 25, CXCursor_ConversionFunction = 26, CXCursor_FunctionTemplate = 30,
                    CXCursor_CallExpr = 103 };
enum CXChildVisitResult { CXChildVisit_Break, CXChildVisit_Continue, CXChildVisit_Recurse };
struct CXCursor { CXCursorKind kind; int xdata; const void* data[3]; };
struct CXString { const void* data; unsigned private_flags; };
struct CXSourceLocation { const void* ptr_data[2]; unsigned int_data; };
using CXIndex = void*;
using CXTranslationUnit = struct CXTranslationUnitImpl*;
using CXFile = void*;
using CXClientData = void*;
using CXCursorVisitor = CXChildVisitResult (*)(CXCursor cursor, CXCursor parent, CXClientData data);

CXIndex clang_createIndex(int excludeDeclarationsFromPCH, int displayDiagnostics);
void clang_disposeIndex(CXIndex index);
CXTranslationUnit clang_parseTranslationUnit(CXIndex index, const char* source, const char* const* args, int numArgs,
                                             void* unsavedFiles, unsigned numUnsaved, unsigned options);
void clang_disposeTranslationUnit(CXTranslationUnit unit);
CXCursor clang_getTranslationUnitCursor(CXTranslationUnit unit);
unsigned clang_visitChildren(CXCursor parent, CXCursorVisitor visitor, CXClientData data);
CXCursorKind clang_getCursorKind(CXCursor cursor);
CXCursor clang_getCursorReferenced(CXCursor cursor);
unsigned clang_Cursor_isNull(CXCursor cursor);
unsigned clang_CXXMethod_isConst(CXCursor cursor);
unsigned clang_CXXMethod_isStatic(CXCursor cursor);
int clang_Cursor_getNumArguments(CXCursor cursor);
CXCursor clang_Cursor_getArgument(CXCursor cursor, unsigned index);
CXSourceLocation clang_getCursorLocation(CXCursor cursor);
void clang_getSpellingLocation(CXSourceLocation location, CXFile* file, unsigned* line, unsigned* column, unsigned* offset);
CXString clang_getFileName(CXFile file);
CXString clang_getCursorSpelling(CXCursor cursor);
CXString clang_getCursorDisplayName(CXCursor cursor);
CXCursor clang_getCursorSemanticParent(CXCursor cursor);
const char* clang_getCString(CXString string);
void clang_disposeString(CXString string);
unsigned clang_getNumDiagnostics(CXTranslationUnit unit);
}

namespace
{
  std::string Take(const CXString text)
  {
    const char* const raw = clang_getCString(text);
    std::string out = raw != nullptr ? raw : "";
    clang_disposeString(text);
    return out;
  }

  /// `Class::name` of a function declaration.
  std::string QualifiedName(const CXCursor declaration)
  {
    std::string name = Take(clang_getCursorSpelling(declaration));
    const CXCursor parent = clang_getCursorSemanticParent(declaration);
    if (!clang_Cursor_isNull(parent)) {
      const std::string owner = Take(clang_getCursorSpelling(parent));
      if (!owner.empty()) {
        name = owner + "::" + name;
      }
    }
    return name;
  }

  /// Functions without side effects that are not const members (accessors on non-const
  /// objects pick the non-const overload; math is pure).
  bool IsPureName(const std::string& qualified, const std::string& plain)
  {
    static const std::set<std::string> kPure = {
      "begin", "end", "cbegin", "cend", "rbegin", "rend", "size", "empty", "data", "c_str", "length", "capacity",
      "front", "back", "at", "operator[]", "operator*", "operator->", "get", "move", "forward", "addressof",
      "sqrt", "sqrtf", "fabs", "fabsf", "abs", "min", "max", "clamp", "floor", "ceil", "floorf", "ceilf",
      "sin", "cos", "sinf", "cosf", "atan2", "atan2f", "operator+", "operator-", "operator/", "operator==",
      "operator!=", "operator<", "operator>", "operator<=", "operator>=", "operator!", "operator&", "operator|",
      "strlen", "strcmp", "wcslen", "view", "to_std", "Get", "IsNil", "operator bool",
    };
    if (kPure.count(plain) != 0) {
      return true;
    }
    (void)qualified;
    return false;
  }

  struct ArgumentScan
  {
    std::vector<std::string> sideEffectCallees;
  };

  CXChildVisitResult VisitArgument(const CXCursor cursor, CXCursor, const CXClientData data)
  {
    auto& scan = *static_cast<ArgumentScan*>(data);
    if (clang_getCursorKind(cursor) == CXCursor_CallExpr) {
      const CXCursor callee = clang_getCursorReferenced(cursor);
      if (!clang_Cursor_isNull(callee)) {
        const CXCursorKind kind = clang_getCursorKind(callee);
        const std::string plain = Take(clang_getCursorSpelling(callee));
        const bool constMember =
          (kind == CXCursor_CXXMethod || kind == CXCursor_ConversionFunction) && clang_CXXMethod_isConst(callee) != 0;
        // A construction counts only when the constructor can have effects beyond the new
        // object: copies and moves of values do not.
        const bool construction = kind == CXCursor_Constructor;
        if (!constMember && !construction && !IsPureName(QualifiedName(callee), plain)) {
          scan.sideEffectCallees.push_back(QualifiedName(callee));
        }
      }
    }
    return CXChildVisit_Recurse;
  }

  std::set<std::string> gReported;

  CXChildVisitResult VisitAll(const CXCursor cursor, CXCursor, CXClientData)
  {
    if (clang_getCursorKind(cursor) == CXCursor_CallExpr) {
      const int count = clang_Cursor_getNumArguments(cursor);
      if (count >= 2) {
        std::vector<ArgumentScan> scans(static_cast<std::size_t>(count));
        int withEffects = 0;
        for (int index = 0; index < count; ++index) {
          const CXCursor argument = clang_Cursor_getArgument(cursor, static_cast<unsigned>(index));
          ArgumentScan& scan = scans[static_cast<std::size_t>(index)];
          // The argument expression itself, then everything below it.
          (void)VisitArgument(argument, cursor, &scan);
          (void)clang_visitChildren(argument, &VisitArgument, &scan);
          if (!scan.sideEffectCallees.empty()) {
            ++withEffects;
          }
        }
        if (withEffects >= 2) {
          CXFile file = nullptr;
          unsigned line = 0;
          unsigned column = 0;
          clang_getSpellingLocation(clang_getCursorLocation(cursor), &file, &line, &column, nullptr);
          const std::string path = file != nullptr ? Take(clang_getFileName(file)) : "?";
          std::string text = path + ":" + std::to_string(line) + ":" + std::to_string(column);
          const CXCursor callee = clang_getCursorReferenced(cursor);
          text += " " + (clang_Cursor_isNull(callee) ? std::string("?") : QualifiedName(callee));
          for (int index = 0; index < count; ++index) {
            const ArgumentScan& scan = scans[static_cast<std::size_t>(index)];
            if (scan.sideEffectCallees.empty()) {
              continue;
            }
            text += " | arg" + std::to_string(index) + ":";
            for (const std::string& name : scan.sideEffectCallees) {
              text += " " + name;
            }
          }
          if (gReported.insert(text).second) {
            std::printf("%s\n", text.c_str());
          }
        }
      }
    }
    return CXChildVisit_Recurse;
  }
} // namespace

int main(int argc, char** argv)
{
  if (argc < 3 || std::strcmp(argv[2], "--") != 0) {
    std::fprintf(stderr, "usage: %s <source> -- <compiler arguments...>\n", argv[0]);
    return 2;
  }
  std::vector<const char*> args;
  for (int index = 3; index < argc; ++index) {
    args.push_back(argv[index]);
  }
  const CXIndex index = clang_createIndex(0, 0);
  const CXTranslationUnit unit =
    clang_parseTranslationUnit(index, argv[1], args.data(), static_cast<int>(args.size()), nullptr, 0, 0);
  if (unit == nullptr) {
    std::fprintf(stderr, "%s: parse failed\n", argv[1]);
    clang_disposeIndex(index);
    return 1;
  }
  (void)clang_visitChildren(clang_getTranslationUnitCursor(unit), &VisitAll, nullptr);
  clang_disposeTranslationUnit(unit);
  clang_disposeIndex(index);
  return 0;
}
