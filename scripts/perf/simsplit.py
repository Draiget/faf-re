"""Split a thread's sampled time into Lua and engine categories.

usage: python scripts/perf/simsplit.py [--thread sim] [-n N] <win.json...>

Each sampled call chain (leaf first) is put in exactly one category:
  wait                   the leaf is a wait (the thread was idle)
  lua gc: mark|weak|sweep|finalizers|other
                         anywhere under the Lua 5.0 collector (luaC_collectgarbage and friends);
                         the sub-phase is the leafmost collector function on the chain
  lua interpreter        the Lua VM is the leafmost of (VM, binding) on the chain: bytecode,
                         table and string work, calls into Lua from the engine
  lua binding glue       inside a Lua C function (moho::cfunc_*) or the Lua API / LuaPlus it uses
                         to read arguments and push results
  engine from lua        engine code a Lua C function called (attributed to that function)
  engine: <phase>        everything else, by the leafmost phase marker on the chain
Prints the categories, the bindings by total cost (glue + engine below them), and the phases.
Windows come from sampler64.py.
"""
import collections
import json
import re
import sys

WAITS = ("NtWaitFor", "ZwWaitFor", "NtDelayExecution", "ZwDelayExecution", "NtUserMsgWaitForMultipleObjectsEx",
         "NtWaitForAlertByThreadId", "ZwWaitForAlertByThreadId", "NtRemoveIoCompletion")

GC_PHASES = [
    ("finalizers", ("luaC_callGCTM", "do1gcTM", "LuaPlusGCFunction")),
    ("weak", ("cleartablekeys", "cleartablevalues")),
    ("sweep", ("sweeplist", "sweepstrings", "luaC_sweep", "freeobj", "checkSizes")),
    ("mark", ("reallymarkobject", "marktmu", "traversetable", "traverseproto", "traverseclosure",
              "traversestack", "propagatemarks", "markroot", "luaC_separateudata", "`mark'", " mark")),
]
GC_ROOTS = ("luaC_collectgarbage", "luaC_checkGC")
VM = ("luaV_execute", "luaD_precall", "luaD_call", "luaD_rawrunprotected", "lua_resume", "luaD_poscall",
      "luaV_gettable", "luaV_settable", "luaD_callhook")
BINDING = re.compile(r"(^|::)cfunc_\w+")
LUA_API = re.compile(r"^(lua_|luaL_|luaH_|luaS_|luaM_|luaV_|luaD_|luaO_|luaF_|luaT_|LuaPlus::|moho::SCR_|"
                     r"moho::LuaState|`anonymous namespace'::Lua|moho::CScrLuaBinder)")

PHASES = [
    ("sync", ("moho::Sim::Sync",)),
    ("pose/animation", ("CAniActor::", "CAniPose", "Manipulator::")),
    ("collision", ("Collide", "CColPrimitive", "CollisionResult", "ComputeBoxBoxContact", "Wm3::Intr")),
    ("projectiles", ("moho::Projectile::",)),
    ("weapons", ("moho::UnitWeapon::", "CWeapon", "CFireWeaponTask", "CAimManipulator")),
    ("target acquisition", ("CAcquireTargetTask", "LAiAttackerImpl", "GetBlipsInRange", "UpdateBlipsInRange",
                            "EntitiesAroundPoint", "CAiAttackerImpl", "CollectEntitiesInBox")),
    ("pathfinding", ("PathQueue", "AStarSearch", "PathTables")),
    ("motion/steering", ("CUnitMotion", "CAiSteering", "CAiNavigator", "CAiPathNavigator", "Unit::MotionTick",
                         "EntityOccupationManager", "COGrid")),
    ("intel/recon", ("CAiReconDBImpl", "ReconBlip", "RefreshReconArmyRange", "CIntel", "CInfluenceMap")),
    ("effects", ("CEffectManagerImpl", "CEfx")),
    ("coords", ("Entity::AdvanceCoords",)),
    ("economy", ("ProcessArmyEconomy", "CEconomy", "HandleResourceManagement")),
    ("formations", ("CAiFormation",)),
    ("allocation", ("operator new", "malloc", "RtlAllocateHeap", "operator delete", "RtlFreeHeap", "free")),
]


def thread_of(w, which):
    names = w["names"]
    want = {"main": ("WinMain", "moho::WIN_AppExecute"), "sim": ("moho::Sim::AdvanceBeat",)}.get(which)
    if want is None:
        return which
    best = (0, None)
    for t, k, v in w["incl"]:
        if names[k] in want and v > best[0]:
            best = (v, str(t))
    return best[1]


def contains(name, needles):
    return any(n in name for n in needles)


def classify(ch):
    """Returns (category, binding-or-None)."""
    if contains(ch[0], WAITS):
        return "wait", None
    for f in ch:
        for phase, needles in GC_PHASES:
            if contains(f, needles):
                return "lua gc: " + phase, None
        if contains(f, GC_ROOTS):
            return "lua gc: other", None
    vm = next((i for i, f in enumerate(ch) if contains(f, VM)), None)
    binding = next((i for i, f in enumerate(ch) if BINDING.search(f)), None)
    if binding is not None and (vm is None or binding < vm):
        name = ch[binding]
        if all(LUA_API.search(f) or BINDING.search(f) for f in ch[:binding + 1]):
            return "lua binding glue", name
        return "engine from lua", name
    if vm is not None:
        return "lua interpreter", None
    for i, f in enumerate(ch):
        for phase, needles in PHASES:
            if contains(f, needles):
                return "engine: " + phase, None
    return "engine: other", None


def main():
    args = sys.argv[1:]
    which, n = "sim", 25
    if "--thread" in args:
        i = args.index("--thread")
        which = args[i + 1]
        del args[i:i + 2]
    if "-n" in args:
        i = args.index("-n")
        n = int(args[i + 1])
        del args[i:i + 2]
    cats, bindings, binding_engine = collections.Counter(), collections.Counter(), collections.Counter()
    other_leaves = collections.Counter()
    total = 0
    for path in args:
        w = json.load(open(path))
        names = w["names"]
        tid = thread_of(w, which)
        for t, c, v in w["chains"]:
            if str(t) != tid:
                continue
            ch = [names[k] for k in c]
            cat, binding = classify(ch)
            cats[cat] += v
            total += v
            if cat == "engine: other":
                other_leaves[ch[0]] += v
            if binding:
                bindings[binding] += v
                if cat == "engine from lua":
                    binding_engine[(binding, ch[0])] += v
    busy = total - cats["wait"]
    print("samples %d, busy %d (%.1f%%)" % (total, busy, 100.0 * busy / max(total, 1)))
    print("-- categories (%% of busy)")
    for k, v in sorted(cats.items(), key=lambda kv: -kv[1]):
        if k != "wait":
            print("%6.2f%%  %s" % (100.0 * v / max(busy, 1), k))
    print("-- Lua C functions by total cost (glue + engine below them, %% of busy)")
    for k, v in bindings.most_common(n):
        print("%6.2f%%  %s" % (100.0 * v / max(busy, 1), k[:120]))
    print("-- leaves of engine: other")
    for k, v in other_leaves.most_common(n):
        print("%6.2f%%  %s" % (100.0 * v / max(busy, 1), k[:120]))
    print("-- engine leaves under Lua C functions")
    for (b, leaf), v in binding_engine.most_common(n):
        print("%6.2f%%  %s  <-  %s" % (100.0 * v / max(busy, 1), leaf[:80], b[:60]))


if __name__ == "__main__":
    main()
