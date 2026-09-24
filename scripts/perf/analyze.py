"""Two-axis attribution of sim-thread samples: WHAT (innermost recognizable subsystem) x WHO (beat context).

usage: analyze.py <window.json>...
"""
import collections
import json
import os
import sys

TABLES = os.environ.get("FAF_PERF_TABLES", os.path.join(os.environ.get("TEMP", "."), "faf_perf"))
NAMES = json.load(open(os.path.join(TABLES, "symnames.json")))


def unqualify(name):
    """Drops the engine namespace, so `moho::Sim::AdvanceBeat` and `Sim::AdvanceBeat` match alike.

    Which spelling symnames.json holds depends on where the source index finds the anchor (a
    header declaration inside `namespace moho`, or an out-of-line `Sim::` definition)."""
    for prefix in ("moho::", "Moho::"):
        if name.startswith(prefix):
            return name[len(prefix):]
    return name


def nm(i):
    return i if isinstance(i, str) else unqualify(NAMES[i][1] or "")


def pth(i):
    return "" if isinstance(i, str) else NAMES[i][2]


GC = ("luaC_collectgarbage", "mark", "propagatemarks", "traversetable", "sweeplist", "sweepstrings", "luaC_sweep",
      "luaC_callGCTM", "reallymarkobject", "checkSizes", "luaC_separateudata", "LuaPlusGCFunction", "markobject",
      "traverseproto", "traverseclosure", "traversestack", "freeobj", "luaF_freeproto", "luaH_free")

WHAT = [
    ("idle wait (beat/vsync)", lambda n, p: n in ("boost::detail::condition_impl::do_wait", "gpg::gal::DeviceD3D9::Present")),
    ("Lua GC", lambda n, p: n in GC),
    ("allocator", lambda n, p: n in ("malloc_0", "free", "operatornew", "realloc_0", "AllocateSmallBlocksAmount",
                                     "msvc8::detail::allocate_checked", "operator delete", "operatordelete")
     ),
    ("Lua VM + LuaPlus", lambda n, p: p.startswith("src/sdk/lua/") or n.startswith(("lua", "LuaPlus::"))),
    ("spatial query (COGrid)", lambda n, p: any(s in n for s in ("COGrid::", "EntityOccupationManager", "GatherUnmarked",
                                                                  "EntitiesAroundPoint", "CollectEntitiesInBox"))),
    ("collision math", lambda n, p: any(s in n for s in ("CollideBox", "ComputeBoxBoxContactManifold",
                                                          "ProjectBoxOntoAxis", "CColPrimitive", "Collide"))),
    ("path search", lambda n, p: any(s in n for s in ("PathQueue", "ClusterMap", "HaStar", "PathTables", "CAiPathFinder",
                                                       "ExpandCellNeighbours", "EnumerateAdjacentCells", "Cluster"))),
    ("anim/pose", lambda n, p: any(s in n for s in ("CAniPose", "CAniActor", "Manipulator", "NormalizeQuat",
                                                     "CalculateAttachedTransform", "CAniSkel"))),
    ("recon/intel", lambda n, p: any(s in n for s in ("Recon", "CIntel", "VisionDB", "CInfluenceMap", "Blip"))),
    ("weapons/targeting", lambda n, p: any(s in n for s in ("CAcquireTargetTask", "UnitWeapon", "CAiAttacker",
                                                             "CAiTarget", "FindBestEnemy", "CFireWeaponTask"))),
    ("patrol scan", lambda n, p: "CUnitPatrolTask" in n),
    ("steering/nav", lambda n, p: any(s in n for s in ("CAiSteering", "CAiNavigator", "CAiPathNavigator", "CAiPathSpline"))),
    ("motion", lambda n, p: any(s in n for s in ("CUnitMotion", "MotionTick", "CalcMove", "DoCollisionsFor"))),
    ("effects/decals", lambda n, p: any(s in n for s in ("CEffectManager", "CEfx", "CDecalBuffer", "IEffect"))),
    ("sync publish", lambda n, p: any(s in n for s in ("::Sync", "FinalizeSyncDispatch", "SSyncData"))),
    ("coords commit", lambda n, p: "AdvanceCoords" in n or "UpdateCollision" in n),
    ("economy", lambda n, p: any(s in n for s in ("CEconomy", "HandleResourceManagement", "SEcon"))),
    ("events", lambda n, p: "Broadcaster" in n),
    ("command queue/tasks", lambda n, p: any(s in n for s in ("CUnitCommand", "CCommandTask", "IAiCommandDispatch",
                                                               "CUnit", "Task::Execute"))),
    ("engine cfunc (called from Lua)", lambda n, p: "cfunc_" in n),
    ("CRT/string/math", lambda n, p: any(s in n for s in ("std::", "strcmp", "STR_", "memcpy", "memset", "sqrt",
                                                           "runtime::", "hash_value"))),
]

WHO = [  # rootmost match wins
    ("forced GC (every 70 ticks)", lambda n: n == "lua_setgcthreshold"),
    ("Lua coroutines (ForkThread)", lambda n: n == "CLuaTask::Execute"),
    ("stage A: entity tick", lambda n: n in ("Entity::TaskTick", "Unit::MotionTick",
                                             "Projectile::MotionTick") or n.endswith("::MotionTick")),
    ("stage B: unit commands", lambda n: any(s in n for s in ("IAiCommandDispatch", "CUnitPatrolTask::Execute",
                                                               "CCommandTask", "CUnitMoveTask", "CUnitBuildTask"))),
    ("army tick: AI stages/econ/path", lambda n: n == "CArmyImpl::OnTick"),
    ("recon/blips", lambda n: any(s in n for s in ("ReconRefresh", "ReconTick", "RefreshBlips"))),
    ("effects/decals tick", lambda n: n in ("CEffectManagerImpl::Tick", "CDecalBuffer::CleanupTick",
                                            "CEffectManagerImpl::PurgeDestroyedEffects")),
    ("coords commit", lambda n: n == "Entity::AdvanceCoords"),
    ("sync publish", lambda n: n in ("Sim::Sync", "CSimDriver::FinalizeSyncDispatchLocked")),
    ("AdvanceBeat (other)", lambda n: n == "Sim::AdvanceBeat"),
]

windows = [json.load(open(p)) for p in sys.argv[1:]]
chains = collections.Counter()
for w in windows:
    for t, c, v in w.get("chains", []):
        chains[(int(t), tuple(c))] += v
adv = next(i for i, n in enumerate(NAMES) if unqualify(n[1] or "") == "Sim::AdvanceBeat")
per = collections.Counter()
for (t, c), v in chains.items():
    if adv in c:
        per[t] += v
sim_tid = per.most_common(1)[0][0]

for w in windows:
    s1 = w.get("sim_end") or {}
    s0 = w.get("sim_start") or {}
    if s0 and s1:
        print("window %d: %.1f ticks/s, units %s, projectiles %s, blips %s" % (
            w["window"], (s1["tick"] - s0["tick"]) / 60.0, s1.get("families", {}).get("unit"),
            s1.get("families", {}).get("projectile"), s1.get("families", {}).get("blip")))

what_c = collections.Counter()
who_c = collections.Counter()
grid = collections.Counter()
total = 0
unknown_leaf = collections.Counter()
for (t, c), v in chains.items():
    if t != sim_tid:
        continue
    total += v
    names = [nm(f) for f in c]
    paths = [pth(f) for f in c]
    what = None
    if names[0].startswith("mod:") and len(names) > 1 and names[1] in ("boost::detail::condition_impl::do_wait", "gpg::gal::DeviceD3D9::Present"):
        what = "idle wait (beat/vsync)"
    elif names[0].startswith("mod:") and len(names) > 1 and names[1] in ("malloc_0", "free", "operatornew", "realloc_0", "AllocateSmallBlocksAmount", "ReleaseHeapRecord"):
        what = "allocator"
    for n, p in ([] if what else zip(names, paths)):
        for label, pred in WHAT:
            if pred(n, p):
                what = label
                break
        if what:
            break
    if what is None:
        what = "other"
        unknown_leaf[names[0]] += v
    who = None
    for n in reversed(names):
        hit = next((label for label, pred in WHO[:-1] if pred(n)), None)
        if hit:
            who = hit
            break
    if who is None:
        who = "AdvanceBeat (other)" if "Sim::AdvanceBeat" in names else "outside AdvanceBeat"
    what_c[what] += v
    who_c[who] += v
    grid[(who, what)] += v


def p(v):
    return "%5.1f%%" % (100.0 * v / total)


print("\nSIM THREAD samples:", total)
print("\n== WHO (beat context, rootmost marker)")
for k, v in who_c.most_common():
    print(" ", p(v), k)
print("\n== WHAT (innermost recognizable subsystem)")
for k, v in what_c.most_common():
    print(" ", p(v), k)
print("\n== WHO x WHAT (cells >= 0.7%)")
for (who, what), v in sorted(grid.items(), key=lambda kv: -kv[1]):
    if v / total >= 0.007:
        print(" ", p(v), "%-34s | %s" % (who, what))
print("\n== 'other' leaves")
for k, v in unknown_leaf.most_common(15):
    print(" ", p(v), k)
