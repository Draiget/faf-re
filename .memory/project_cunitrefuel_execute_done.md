---
name: project-cunitrefuel-execute-done
description: CUnitRefuel::Execute is already fully recovered at 0x00621490; its entire remaining closure is seven std::string CRT emissions. The goal's named target is met.
metadata:
  type: project
---

The standing goal asks "can we recover `CUnitRefuel::Execute`?" - it is
**already recovered**, at `moho/unit/tasks/CUnitRefuel.cpp:416`, annotated
`0x00621490 (?TaskTick@CUnitRefuel@Moho@@UAE?AW4ETaskStatus@2@XZ)`.

The body is a real refuel/rearm state machine, not a stub: dead-unit and
platform guards (a platform that dies, lifts off, sets down, submerges, or
takes any command of its own kills the refuel task of everything docked on
it), the submerged-platform path that detaches an attached unit before
tearing down, and separate carrier and non-carrier state branches driving
`TransportHasAvailableStorage`, `IssueCarrierLandTask` and the
`UNITSTATE_ForceSpeedThrough` mask.

## The closure is entirely CRT strings

Unrecovered closure under `Execute`: **7 fns / 411 instrs**, all
`std::string`:

    0x00405C20  111  std::string::_Copy
    0x004056B0   96  std::string::assign(const string&, uint, uint)
    0x004059E0   88  std::string::string(const char*, uint)   <- see below
    0x00405AB0   54  std::string::erase(uint, uint)
    0x00405E00   25  std::_Allocate_char
    0x00405550   23  std::string::string(const char*)         <- recorded bbe9358
    0x00402370   14  std::string::~string

So nothing engine-side is missing beneath it. There is no unit-task
blocker left here.

## Two of the seven should stay unrecorded

  - **0x004059E0** is exported as the `(const char*, size_t)` ctor but its
    body reads `this->_Myres` *before* initialising it and has a
    source-aliases-own-buffer guard. That is `assign` behaviour, not
    construction - likely ICF folding the ctor onto assign. Do not staple
    it onto `msvc8::string::string(const char*, size_t)` without checking
    its hash against 0x004056B0 first.
  - **0x00402370** is `~string`. `msvc8::string` **deliberately has no
    destructor** - see the rationale at `String.h:48` and `String.h:599`.
    Do not add one to give this address a home.

## Consequence for the goal

The named target is met. What remains under the goal's second clause
("recover related sources for units meanwhile") is open-ended, so pick
unit-side work by evidence rather than expecting `CUnitRefuel` to yield
more - it is done. See [[project-icf-twin-pool]] for the candidate screen
and [[project-gal-effect-api-gate]] for what is blocking the render side.
