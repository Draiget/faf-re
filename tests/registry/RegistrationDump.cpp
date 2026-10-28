// Engine addition (dedicated-server plan WPL.4, WPR.11, WPL.18): prints what the
// engine's static initialisers registered, in registration order:
//
//   - every Lua init-form set and its forms (name and group), in the order
//     RunInits adds them to a Lua state (so the order of the Lua tables they fill);
//   - every reflection type in gpg::GetRTypeVec() order;
//   - every console command (CON_GetCommandList, sorted by name).
//
// Linked against all of an executable's engine objects in that executable's
// order, it shows that executable's static-init result: splitting a source
// file must leave the output unchanged. Built from the simulation's objects
// only, on Windows and Linux, it compares the two platforms (WPL.18).
//
// Usage: faf_registration_dump [out.txt]   (default: stdout)

#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaInitForm.h"

int main(int argc, char** argv)
{
  std::FILE* out = stdout;
  if (argc > 1) {
    out = std::fopen(argv[1], "w");
    if (out == nullptr) {
      std::fprintf(stderr, "cannot write %s\n", argv[1]);
      return 2;
    }
  }

  int sets = 0;
  int forms = 0;
  for (moho::CScrLuaInitFormSet* set = moho::CScrLuaInitFormSet::GetFirst(); set != nullptr; set = set->GetNext()) {
    std::fprintf(out, "set %s\n", set->mSetName != nullptr ? set->mSetName : "(null)");
    ++sets;
    for (const moho::CScrLuaInitForm* form = set->mForms; form != nullptr; form = form->mNextInSet) {
      std::fprintf(
        out, "  form %s [%s]\n", form->mName != nullptr ? form->mName : "(null)",
        form->mGroupName != nullptr ? form->mGroupName : "(null)"
      );
      ++forms;
    }
  }

  // Types finalised during static init (LookupRType), in type-index order.
  int types = 0;
  for (const gpg::RType* const type : gpg::GetRTypeVec()) {
    std::fprintf(out, "type %d %s\n", types, type != nullptr ? type->GetName() : "(null)");
    ++types;
  }

  // Types pre-registered (keyed by type_info address, so listed by name).
  std::vector<std::string> preregistered;
  for (const auto& entry : gpg::GetRTypePreregisteredMap()) {
    preregistered.emplace_back(entry.second != nullptr ? entry.second->GetName() : "(null)");
  }
  std::sort(preregistered.begin(), preregistered.end());
  for (const std::string& name : preregistered) {
    std::fprintf(out, "pretype %s\n", name.c_str());
  }

  msvc8::string commands;
  moho::CON_GetCommandList(commands, false);
  std::fprintf(out, "commands\n%s\n", commands.c_str());

  std::fprintf(
    stderr, "%d Lua init sets, %d forms, %d reflection types, %zu pre-registered\n", sets, forms, types,
    preregistered.size()
  );
  if (out != stdout) {
    std::fclose(out);
  }
  return 0;
}
