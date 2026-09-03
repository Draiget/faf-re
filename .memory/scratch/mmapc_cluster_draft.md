# UICommandGraph::mMapC (HashListNode2C) find/insert cluster - research draft

Status: RESEARCH ONLY. No src/sdk files were edited. All addresses below were read
fresh from `decomp/recovery/disasm/fa_full_2026_03_26/FUN_<addr>.c` / `.asm` /
`.meta.json` / `.xrefs.txt` in this session. Every callsite/register claim was
traced through the raw `.asm`, not just the IDA-decompiled `.c` (which drops
register arguments at several of these sites - flagged explicitly below).

## 0. Executive summary - what's wrong in the progress DB right now

| Token | DB status today | Reality (this session) |
|---|---|---|
| `FUN_0082C750` | `recovered`, cites `CrtRuntimeHelpers.cpp` | **FAKE.** `grep -r 0082C750 src/sdk` = zero hits. Needs full recovery: `FindHashListNode2C`. |
| `FUN_00830700` | `recovered`, cites `CrtRuntimeHelpers.cpp` | **FAKE.** `grep -r 00830700\|830700 src/sdk` = zero hits. This is `ConstructHashListNode2C`, a hard dependency of item 2. |
| `FUN_0082D960` | `recovered`, no `source_paths` field at all | **FAKE.** `grep -r 0082D960\|82D960 src/sdk` = zero hits. This is `HashKeyPairScramble`, the shared pair-key mix+scramble helper `FindHashListNode2C` calls. |
| `FUN_0082DB00` | `external_dependency`, note claims "no Moho/gpg engine references" | **WRONG CLASSIFICATION.** It operates directly on `HashTable<HashListNode2C>::mBuckets` (an engine `HashBucketVector`). It's the mMapC-table's own duplicate instantiation of the already-recovered `EnsureHashBucketVectorLength` (0x0082D820). Not external at all. |
| `FUN_00831BA0` | `blocked`, `blocker_type=needs_callsite_evidence` | **Already correctly caught** by a prior session's DB-integrity revert (2026-08-19 note explicitly documents the same fake-CrtRuntimeHelpers pattern). No action needed here beyond the real recovery below. |
| `FUN_0082F5D0` | `recovered` in `CrtRuntimeHelpers.cpp` as `RuntimeThrowListTooLongS()` | **REAL FILE, WRONG BODY.** The existing recovery models this as an unconditional `[[noreturn]]` throw-with-no-params. The actual disassembly is a guarded increment-and-store (`CheckedIncrementListSize` analogue) that only throws conditionally. The current recovery captured only the cold exception sub-path and dropped the function's primary behavior. It also has **zero callers anywhere in src/sdk** (confirmed by grep) - dead AND wrong. |
| `FUN_0082F7A0` | `recovered` in `CWldSession.cpp` as `GrowHashBucketVectorByFillRef()`, doc-comment claims "confirmed instruction-for-instruction" match to `GrowHashBucketVector` | **WRONG-BODY CITATION.** The real 0x0082F7A0 is a 236-instruction, SEH-protected, independently-compiled duplicate of the grow algorithm (own throw helper `sub_8307F0`, own copy/fill/allocate primitives `sub_831910/831960/831C20/832710/832BE0`). The existing recovery models it as a 4-line forward to the already-recovered `GrowHashBucketVector` - that is not what the binary does at this address. See Section 6. |
| `FUN_0082F750` | `recovered` in `LegacyContainerRuntime.cpp` as `MoveDwordTailLaneC()` | **VERIFIED CORRECT.** Cross-checked line-by-line against the raw asm; matches exactly. No action needed. |

Net: of the 8 tokens touched by this cluster, **4 are fake/wrong** (0082C750,
00830700, 0082D960, 0082F5D0), **1 is misclassified** (0082DB00), **1 has a
wrong-body citation on a real file** (0082F7A0), **1 is already correctly
blocked** (00831BA0), and **1 is genuinely correct** (0082F750).

## 1. Required prerequisite: `HashListNode2C` must become a bespoke struct

Today (`CWldSession.cpp:1488-1497`):

```cpp
template <std::size_t kNodeSize>
struct HashListNode
{
  HashListNode* mNext;
  HashListNode* mPrev;
  std::uint8_t mPayload[kNodeSize - 8];
};

using HashListNode2C = HashListNode<0x2C>;
using HashListNode10 = HashListNode<0x10>;
```

`HashListNode2C` has no named fields - every access would need raw payload
reinterpretation. `HashListNode88` (the sibling this cluster mirrors) is **not**
built off this template; it is a bespoke struct with named `mKey`/`mKeyHigh`/`mDraw`
fields. Now that mMapC's fields are known with high confidence (task-provided +
independently confirmed against 0x0082C750/0x0082C480's disassembly - both index
`node[2]`/`node[3]` as two key dwords immediately after the mNext/mPrev header,
and 0x0082B490 confirms `+0x10` is `mEdge`), `HashListNode2C` should graduate to a
bespoke struct exactly like `HashListNode88`, leaving `HashListNode10 =
HashListNode<0x10>` on the generic template untouched (mMapD is out of scope here).

**Proposed replacement** (drop `HashListNode2C` from the template, replace with):

```cpp
/**
 * mMapC's node. Mirrors HashListNode88's shape: mNext/mPrev intrusive link
 * header, two key dwords, then the payload. Unlike HashListNode88 (single
 * dword key), mMapC keys by a lexicographically-compared (fromNode,toNode)
 * pointer pair - mKeyLow/mKeyHigh duplicate mEdge.mFromNode/mEdge.mToNode at
 * a DIFFERENT absolute offset (mKeyLow@0x08 vs mEdge.mFromNode@0x18), exactly
 * mirroring how HashListNode88::mKey duplicates (but is stored separately
 * from) mDraw.mCommandId. CommandGraphEdge is fully POD (no owned resources),
 * so unlike HashListNode88 this node needs no DestroyPayload().
 */
struct HashListNode2C
{
  HashListNode2C* mNext;              // +0x00
  HashListNode2C* mPrev;              // +0x04
  UICommandGraphDrawNode* mKeyLow;    // +0x08 - duplicates mEdge.mFromNode
  UICommandGraphDrawNode* mKeyHigh;   // +0x0C - duplicates mEdge.mToNode
  CommandGraphEdge mEdge;             // +0x10 (0x1C bytes, total 0x2C)
};
static_assert(sizeof(HashListNode2C) == 0x2C, "UICommandGraph::HashListNode2C size must be 0x2C");
static_assert(offsetof(HashListNode2C, mKeyLow) == 0x08, "UICommandGraph::HashListNode2C::mKeyLow offset must be 0x08");
static_assert(offsetof(HashListNode2C, mKeyHigh) == 0x0C, "UICommandGraph::HashListNode2C::mKeyHigh offset must be 0x0C");
static_assert(offsetof(HashListNode2C, mEdge) == 0x10, "UICommandGraph::HashListNode2C::mEdge offset must be 0x10");
```

This also means the class-level `static_assert(sizeof(UICommandGraph::HashListNode2C) == 0x2C, ...)`
already at line 2227 stays valid unchanged (good - no size regression), and
`AllocateMapCListSentinel`/`InitMapCBuckets`/`InitMapC`/`ResetHashBucketVectorToNineSlots`
(already recovered, generic-template-based today) keep compiling since they only
touch `mNext`/`mPrev` through `AllocateSelfLinkedNode<TNode>`, which is field-name-
agnostic.

**Confidence: high.** Field offsets independently confirmed three separate ways
(0x0082C750's `v6[2]`/`v6[3]` dword-index reads, 0x0082C480's identical indexing,
and 0x0082B490's `add eax, 0x10` return-adjustment). Not a guess.

## 2. `HashListNode2CValue` - the insert-side "value" composite

Mirrors `HashListNode88Value`. Confirmed from `FUN_00826960`'s own stack layout
(`v9[2]` immediately followed by `v10[28]` = 8+28=0x24 bytes contiguous, passed as
one pointer into `FUN_0082B490`→`FUN_0082C480`→`FUN_00830700`'s `qmemcpy(node+2, a3, 0x24)`):

```cpp
/**
 * The value portion of one HashListNode2C - everything after the intrusive
 * mNext/mPrev link header, mirroring HashListNode88Value. Built by
 * FindOrInsertMapCEdge on a miss: mKeyLow/mKeyHigh get the search
 * (fromNode,toNode) pair, mEdge is left default-constructed (all fields
 * zero/null per CommandGraphEdge's own default member initializers) -
 * confirmed from FUN_0082B490's disassembly at 0x0082B4AD-0x0082B4DD, which
 * builds this composite as {fromNode, toNode, <28 zeroed bytes>} with no
 * write into the edge's mFromNode/mToNode at construction time (those get
 * populated by FUN_00826960's own caller-side code after the call returns,
 * only `if (!edge->mToNode)`).
 */
struct HashListNode2CValue
{
  UICommandGraphDrawNode* mKeyLow;   // +0x00
  UICommandGraphDrawNode* mKeyHigh;  // +0x04
  CommandGraphEdge mEdge;            // +0x08 (0x1C bytes, total 0x24)
};
```

## 3. Token-by-token

### 3.1 `FUN_0082C750` -> `FindHashListNode2C`

- **Address:** 0x0082C750-0x0082C7FF (175 bytes, 70 instructions).
- **Callsite evidence (class 1, code xref):** exactly one caller, `FUN_0082B490` at
  0x0082B49F (`call sub_82C750`), confirmed via both `FUN_0082C750.xrefs.txt` and
  `FUN_0082C750.meta.json`. `FUN_0082B490` is item 3 below (itself needs a chain
  back to a recovered caller - see 3.3's reachability note).
- **Registers (raw asm, not the IDA `.c` prototype):** `a1@EBX` = `HashTable<HashListNode2C>*`
  (uses `a1[8]`=mBucketMask, `a1[9]`=mBucketCount, `a1[5]`=mBuckets.mStart,
  `a1[2]`=mListHead - all consistent with the already-established dword-index
  layout used by `FindHashListNode88`). `a2@EDI` = pointer to the 2-dword
  `{fromNode,toNode}` key pair. `a3` = a **stack-passed** output slot (`retn 4`
  confirms one stack dword popped).
- **Hash formula - VERIFIED, not the guessed formula:** `sub_82D960(a2)` is a
  **real call**, not inlined (unlike the 88-family's scramble, which is inlined at
  every site). Disassembly of `FUN_0082D960` (0x0082D960-0x0082D9A5, 20
  instructions):
  ```
  mov eax,[ecx]        ; lhs = key[0]  (fromNode)
  mov ecx,[ecx+4]       ; rhs = key[1]  (toNode)
  mov edx,ecx
  imul ecx, 0x1EEF        ; rhs * 7919
  xor edx,eax               ; rhs ^ lhs
  imul eax, 0x0F17            ; lhs * 3863
  imul edx, 0xD259              ; (rhs^lhs) * 53849
  add edx,ecx; add edx,eax        ; mixed = 3863*lhs + 7919*rhs + 53849*(lhs^rhs)
  push 0x1F31D(=127773); push edx
  call __imp_ldiv
  imul eax,0xB14(=2836); imul edx,0x41A7(=16807)
  sub edx,eax                        ; 16807*rem - 2836*quot
  mov eax,edx; jns +0x5; add eax,0x7FFFFFFF   ; wrap if negative
  retn
  ```
  This is **exactly** the formula quoted in the task prompt
  (`3863*lhs + 7919*rhs + 53849*(lhs^rhs)` -> `ldiv(_, 127773)` -> Park-Miller tail),
  confirmed instruction-for-instruction, not merely plausible. One difference from
  `HashKeyToBucketIndex`'s single-dword scramble: **no `^0xDEADBEEF` XOR step** -
  confirmed absent from the disassembly.
- **Control flow (verified against `FUN_0082C750.asm`):**
  1. `bucketIndex = HashKeyPairScramble(key.low,key.high) & table.mBucketMask`, with
     the same `if (mBucketCount <= bucketIndex) bucketIndex += (uint32)-1 - (mBucketMask>>1)`
     wraparound `HashKeyToBucketIndex` already implements.
  2. Empty bucket -> return `table.mListHead` (sentinel).
  3. Walk forward while `node < key` lexicographically (two-dword compare, see
     below), reaching bucket end -> sentinel.
  4. On loop exit, if `key == node` (i.e. `node <= key` also holds) -> found;
     else -> sentinel.
  5. Lexicographic predicate reverse-engineered from the raw compare instructions
     and proven equivalent by case analysis: `(aLow,aHigh) <= (bLow,bHigh)` iff
     `aLow < bLow || (aLow==bLow && aHigh<=bHigh)`. Matches `std::pair<uint32,uint32>`'s
     built-in lexicographic `operator<=`/`operator>=` exactly - used in the draft
     below for readability, verified equivalent to the raw boolean, not a behavior
     change.
  6. **Return convention:** the raw asm writes the result through the stack `a3`
     outparam and also echoes `a3` in EAX (`*a3=result; return a3;`), the *same*
     outparam-echo idiom the ALREADY-RECOVERED `FindHashListNode88` (0x0082C240) uses
     at the raw-asm level (`_DWORD *a1@<ebx>` outparam, `*a1=a3[2]; return a1;`).
     Since that sibling's existing recovery already normalizes this to a direct
     `HashListNode88*` return (no outparam in the modern signature), the draft
     below does the same for consistency.

**Draft (declaration, private section, after `HashKeyPairToBucketIndex` below):**

```cpp
/**
 * Address: 0x0082C750 (FUN_0082C750, sub_82C750)
 *
 * IDA signature:
 * _DWORD *__userpurge sub_82C750@<eax>(_DWORD *a1@<ebx>, unsigned int *a2@<edi>, _DWORD *a3);
 *
 * What it does:
 * mMapC analogue of FindHashListNode88: finds the node whose
 * (mKeyLow,mKeyHigh) pair exactly matches (fromNode,toNode) lexicographically
 * within its hash bucket, or returns the table's list sentinel on a miss.
 */
[[nodiscard]] static HashListNode2C* FindHashListNode2C(
  HashTable<HashListNode2C>& table, UICommandGraphDrawNode* fromNode, UICommandGraphDrawNode* toNode
) noexcept;
```

**Draft (definition):**

```cpp
/**
 * Address: 0x0082C750 (FUN_0082C750, sub_82C750)
 */
UICommandGraph::HashListNode2C* UICommandGraph::FindHashListNode2C(
  HashTable<HashListNode2C>& table, UICommandGraphDrawNode* const fromNode, UICommandGraphDrawNode* const toNode
) noexcept
{
  const std::pair searchKey{
    reinterpret_cast<std::uint32_t>(fromNode), reinterpret_cast<std::uint32_t>(toNode)
  };
  const auto nodeKey = [](const HashListNode2C* const n) {
    return std::pair{reinterpret_cast<std::uint32_t>(n->mKeyLow), reinterpret_cast<std::uint32_t>(n->mKeyHigh)};
  };

  const std::uint32_t bucketIndex = HashKeyPairToBucketIndex(table, searchKey.first, searchKey.second);
  auto* const bucketSlots = reinterpret_cast<HashListNode2C**>(table.mBuckets.mStart);
  HashListNode2C* node = bucketSlots[bucketIndex];
  HashListNode2C* const bucketEnd = bucketSlots[bucketIndex + 1u];

  if (node == bucketEnd) {
    return table.mListHead;
  }
  while (nodeKey(node) < searchKey) {
    node = node->mNext;
    if (node == bucketEnd) {
      return table.mListHead;
    }
  }
  return (searchKey >= nodeKey(node)) ? node : table.mListHead;
}
```

**Evidence class:** (1) direct code xref, single caller `FUN_0082B490` @0x0082B49F.
`FUN_0082B490` itself is `blocked` today (depends_on `FUN_0082C480`) - see 3.3 for
its own reachability chain back to a recovered caller (`FUN_00826960` -> ... ->
`FUN_00826140`, none recovered yet). **This means FindHashListNode2C cannot be
promoted to `recovered` in isolation** per the callsite-verification rule's
"caller must be recovered or paired in the same pass" clause - it should land
paired with 0082C480/0082B490 in one commit, or `FUN_00826960`/`FUN_00826140`
need recovering first. Flagging this explicitly per CLAUDE.md.

### 3.2 `FUN_0082C480` -> `InsertOrFindHashListNode2C`

- **Address:** 0x0082C480-0x0082C750 (720 bytes, 244 instructions).
- **Callsite evidence:** exactly one caller, `FUN_0082B490` @0x0082B4FC (confirmed
  via `.xrefs.txt`/`.meta.json`).
- **Structure:** line-by-line confirmed structurally identical to the already-
  recovered `InsertOrFindHashListNode88` (0x0082BFB0): same load-factor test
  (`mBucketCount <= mListSize>>2`), same incremental split-one-bucket rehash
  shape, same backward-walk-then-insert-or-find tail. Differences, all confirmed:
  1. **Key compare is lexicographic pair, not single dword** (same predicate as
     3.1).
  2. **Rehash-loop's raw-hash test inlines the scramble formula directly**
     (`ldiv(3863*node->mKeyLow + 7919*node->mKeyHigh + 53849*(...), 127773)` at
     0x0082C516-0x0082C550) - confirmed it does **NOT** call `sub_82D960` at this
     site, unlike `FindHashListNode2C`. Same again at the final bucket-index calc
     (0x0082C62E-0x0082C671). Both inlined occurrences match `HashKeyPairScramble`'s
     formula exactly (verified same immediates: 0x1EEF/0x0F17/0xD259/0x41A7/0xB14/0x1F31D).
  3. **Grow-branch calls `sub_82DB00`, not the mMapAB0-family's `EnsureHashBucketVectorLength`
     (0x0082D820).** Register-traced precisely (see 3.2.1 below): this is a
     **separate, binary-distinct duplicate instantiation** of the exact same
     algorithm, not literally the same function. See Section 5.
  4. **Node construction calls `sub_830700`, not `ConstructHashListNode88`.**
     Confirmed at 0x0082C6C6-0x0082C6C9: `push ebx(=valueSource); push edx(=insertionPoint->mPrev);
     push edi(=insertionPoint); call sub_830700` - i.e.
     `sub_830700(next=insertionPoint, prev=insertionPoint->mPrev, valueSource)`,
     the *exact* calling convention `ConstructHashListNode88(next, prev, valueSource)`
     already uses. See Section 4.2.
  5. **List-size increment calls `sub_82F5D0`, not `CheckedIncrementListSize`
     (0x0082F050).** Same duplicate-instantiation pattern, different overflow
     threshold constant (`0x071C71C7` vs `0x01FFFFFF`). Note: `0x071C71C7` =
     `floor(UINT_MAX/36)` exactly, but `HashListNode2C` is 0x2C=44 bytes, not 36 -
     `floor(UINT_MAX/44)` = 97612893 ≠ 119304647, so this is **not** simply
     "UINT_MAX / sizeof(node)". The constant is verified exact from the
     disassembly; its derivation is not fully explained and should not be
     assumed. See Section 5.
  6. **Return convention differs from the 88-family:** the 88-version returns the
     node pointer directly via EAX plus a separate by-ref `outInserted` bool. The
     2C-version instead writes **both** into one caller-supplied 5-byte struct
     via a hidden-pointer-style `a2` outparam (`*(DWORD*)a2=node; *(BYTE*)(a2+4)=flag;
     return a2;`), confirmed at both return sites (0x0082C710-0x0082C720 "found" path,
     0x0082C73D-0x0082C74D "inserted" path). The draft below normalizes this to
     match `InsertOrFindHashListNode88`'s already-established modern shape (return
     node* directly, bool via out-ref) - purely an ABI-surface normalization, the
     underlying logic is unchanged.
- **3.2.1 - the `sub_82DB00` register trace (proving it's `EnsureHashBucketVectorLength`,
  not `ConstructHashListNode2C` as the task's speculative hypothesis suggested):**
  ```
  lea ecx, [esi+10h]      ; ecx = &table.mBuckets   (set ONCE, ~15 instructions before the call,
                            ;   never touched again before the call - confirmed by scanning every
                            ;   intervening instruction in FUN_0082C480.asm)
  ...
  mov edx, [esi+8]         ; edx = table.mListHead
  lea eax, [eax+eax-3]      ; eax = 2*bucketVectorLength - 3 = newMask
  mov [esi+20h], eax         ; table.mBucketMask = newMask
  push edx                    ; STACK arg = fillValue = table.mListHead
  add eax, 2                   ; eax = newMask + 2 = requiredLength
  call sub_82DB00
  ```
  i.e. `sub_82DB00(requiredLength=EAX, buckets=ECX, fillValue=stack)` -
  register-for-register the same three logical parameters as the already-recovered
  `EnsureHashBucketVectorLength(HashBucketVector& buckets, uint32 requiredLength, void* fillValue)`,
  just in different registers. **This directly refutes the "maybe it's
  ConstructHashListNode2C" hypothesis in the task prompt** - that's `sub_830700`
  instead (proven independently in 3.2 point 4 and Section 4.2).

**Draft (declaration):**

```cpp
/**
 * Address: 0x0082C480 (FUN_0082C480, sub_82C480)
 *
 * What it does:
 * mMapC's hash-bucket insert lane: structurally identical to
 * InsertOrFindHashListNode88 (incremental split-one-bucket rehash, backward-
 * walk-then-insert-or-find), but keyed by the lexicographic (mKeyLow,mKeyHigh)
 * pair and using mMapC's own duplicate helper family
 * (EnsureHashBucketVectorLengthForMapC, ConstructHashListNode2C,
 * CheckedIncrementListSizeForMapC) instead of mMapAB0's.
 */
static HashListNode2C*
  InsertOrFindHashListNode2C(HashTable<HashListNode2C>& table, HashListNode2CValue& valueSource, bool& outInserted);
```

**Draft (definition):**

```cpp
/**
 * Address: 0x0082C480 (FUN_0082C480, sub_82C480)
 */
UICommandGraph::HashListNode2C* UICommandGraph::InsertOrFindHashListNode2C(
  HashTable<HashListNode2C>& table, HashListNode2CValue& valueSource, bool& outInserted
)
{
  if (table.mBucketCount <= (table.mListSize >> 2u)) {
    const std::uint32_t bucketVectorLength =
      table.mBuckets.mStart ? static_cast<std::uint32_t>(table.mBuckets.mFinish - table.mBuckets.mStart) : 0u;

    if ((bucketVectorLength - 1u) > table.mBucketCount) {
      if (table.mBucketMask < table.mBucketCount) {
        table.mBucketMask = 2u * table.mBucketMask + 1u;
      }
    } else {
      const std::uint32_t newMask = 2u * bucketVectorLength - 3u;
      table.mBucketMask = newMask;
      EnsureHashBucketVectorLengthForMapC(table.mBuckets, newMask + 2u, table.mListHead);
    }

    auto* const rehashBucketSlots = reinterpret_cast<HashListNode2C**>(table.mBuckets.mStart);
    const std::uint32_t splitBucketIndex = table.mBucketCount - (table.mBucketMask >> 1u) - 1u;
    HashListNode2C* node = rehashBucketSlots[splitBucketIndex];
    HashListNode2C* const splitBucketEnd = rehashBucketSlots[splitBucketIndex + 1u];

    if (splitBucketEnd != node) {
      for (;;) {
        // Inlined independently here in the binary - does NOT call HashKeyPairScramble/
        // sub_82D960 (confirmed absent from 0x0082C516-0x0082C550's disassembly).
        const std::uint32_t rehashedIndex =
          HashKeyPairScramble(
            reinterpret_cast<std::uint32_t>(node->mKeyLow), reinterpret_cast<std::uint32_t>(node->mKeyHigh)
          ) & table.mBucketMask;

        if (rehashedIndex == splitBucketIndex) {
          node = node->mNext;
        } else {
          HashListNode2C* const next = node->mNext;
          if (next != table.mListHead) {
            if (rehashBucketSlots[splitBucketIndex] == node) {
              std::uint32_t walkIndex = splitBucketIndex;
              for (;;) {
                rehashBucketSlots[walkIndex] = next;
                if (walkIndex == 0u) {
                  break;
                }
                --walkIndex;
                if (rehashBucketSlots[walkIndex] != node) {
                  break;
                }
              }
            }
            HashListNode2C* const sentinel = table.mListHead;
            HashListNode2C* const oldTail = sentinel->mPrev;
            node->mPrev->mNext = next;
            next->mPrev = node->mPrev;
            node->mNext = sentinel;
            node->mPrev = oldTail;
            oldTail->mNext = node;
            sentinel->mPrev = node;
          }
          std::uint32_t cascadeIndex = table.mBucketCount;
          while (cascadeIndex > splitBucketIndex && rehashBucketSlots[cascadeIndex] == table.mListHead) {
            rehashBucketSlots[cascadeIndex] = node;
            --cascadeIndex;
          }
          if (next == table.mListHead) {
            break;
          }
          node = next;
        }
      }
    }
    ++table.mBucketCount;
  }

  const std::pair searchKey{
    reinterpret_cast<std::uint32_t>(valueSource.mKeyLow), reinterpret_cast<std::uint32_t>(valueSource.mKeyHigh)
  };
  const auto nodeKey = [](const HashListNode2C* const n) {
    return std::pair{reinterpret_cast<std::uint32_t>(n->mKeyLow), reinterpret_cast<std::uint32_t>(n->mKeyHigh)};
  };

  const std::uint32_t bucketIndex = HashKeyPairToBucketIndex(table, searchKey.first, searchKey.second);
  auto* const bucketSlots = reinterpret_cast<HashListNode2C**>(table.mBuckets.mStart);
  HashListNode2C* insertionPoint = bucketSlots[bucketIndex + 1u];

  if (bucketSlots[bucketIndex] != insertionPoint) {
    bool reachedBegin = false;
    for (;;) {
      insertionPoint = insertionPoint->mPrev;
      if (nodeKey(insertionPoint) <= searchKey) {
        break;
      }
      if (bucketSlots[bucketIndex] == insertionPoint) {
        reachedBegin = true;
        break;
      }
    }

    if (!reachedBegin) {
      if (nodeKey(insertionPoint) >= searchKey) {
        outInserted = false;
        return insertionPoint;
      }
      insertionPoint = insertionPoint->mNext;
    }
  }

  HashListNode2C* const newNode = ConstructHashListNode2C(insertionPoint, insertionPoint->mPrev, valueSource);
  CheckedIncrementListSizeForMapC(1u, table.mListSize);

  HashListNode2C* const oldPrev = newNode->mPrev;
  insertionPoint->mPrev = newNode;
  oldPrev->mNext = newNode;

  if (bucketSlots[bucketIndex] == insertionPoint) {
    std::uint32_t cascadeIndex = bucketIndex;
    for (;;) {
      bucketSlots[cascadeIndex] = newNode;
      if (cascadeIndex == 0u) {
        break;
      }
      --cascadeIndex;
      if (bucketSlots[cascadeIndex] != insertionPoint) {
        break;
      }
    }
  }

  outInserted = true;
  return newNode;
}
```

**Confidence note:** the OUTER shape (load-factor test, grow/rehash trigger,
backward-walk insert, cascade fixups, tail linking) was verified **line-by-line**
against both the `.c` and `.asm`. The rehash inner-loop's bucket-slot cascade
(`rehashBucketSlots[walkIndex]` walk-back block) was verified as **structurally
parallel** to `InsertOrFindHashListNode88`'s equivalent block (same variable
roles, same branch shape) but not re-derived instruction-by-instruction the way
the tail insert logic was - flagging this at "high but not exhaustive" confidence
per the task's request to flag uncertainty rather than guess silently.

**Evidence class:** (1) direct code xref, single caller `FUN_0082B490` @0x0082B4FC.
Same paired-recovery caveat as 3.1 applies.

### 3.3 `FUN_0082B490` -> `FindOrInsertMapCEdge`

- **Address:** 0x0082B490-0x0082B50D (125 bytes, 42 instructions).
- **Callsite evidence:** exactly one caller, `FUN_00826960` @0x00826996 (confirmed
  via `.xrefs.txt`/`.meta.json`). `FUN_00826960` is itself `blocked` today, called
  from `FUN_00826140` (also not recovered) - so this chain needs `FUN_00826960`
  and/or `FUN_00826140` recovered in the same pass (or first) for the
  "caller must be recovered" rule to clear. Flagging per CLAUDE.md - do not
  promote 0082B490 to `recovered` without also landing a real recovered caller.
- **Register args - the task's hint confirmed precisely.** Raw asm
  (`FUN_0082B490.asm`) at entry:
  ```
  mov edi, eax     ; edi = a1 (EAX incoming)  -- the KEY POINTER
  lea eax, [esp+5Ch+var_4C]
  mov ebx, ecx      ; ebx = a2 (ECX incoming)  -- the TABLE POINTER (&mMapC)
  push eax
  call sub_82C750     ; sub_82C750(a1=ebx=table, a2=edi=key, a3=stack outslot)
  ```
  So `FUN_0082B490`'s own two register args are **EAX = pointer to a
  `{fromNode,toNode}` dword pair** (its real "key" argument) and **ECX =
  `&mMapC`**. The task's framing ("called with essentially `&mMapC` as its sole
  visible argument in the decompile") is exactly right - IDA's decompile of the
  *caller* (`FUN_00826960`) shows only `sub_82B490(a3 + 3456)` (one visible arg,
  the ECX-carried table pointer) and drops the EAX-carried key pointer entirely.
- **Confirming what builds the EAX key pointer, in `FUN_00826960`'s own raw asm**
  (0x00826984-0x00826996):
  ```
  lea ecx, [ebx+0D80h]        ; ecx = this + 0xD80 = &mMapC       (0xD80 = 3456 decimal, matches the task's framing)
  lea eax, [esp+6Ch+a2]        ; eax = &(local 2-dword scratch buffer)
  mov [esp+6Ch+a2], esi         ; buffer[0] = esi = FUN_00826960's own EDX-arg (its "a2")
  mov [esp+6Ch+var_54], edi      ; buffer[1] = edi = FUN_00826960's own ECX-arg (its "a1")
  call sub_82B490
  ```
  i.e. the key buffer is `{fromNode = FUN_00826960's a2(EDX-arg), toNode =
  FUN_00826960's a1(ECX-arg)}`. Confirmed downstream: right after the call,
  `*(edge+8) = a2; *(edge+12) = a1;` (only `if (!edge->mToNode)`, i.e. only on a
  fresh/miss edge) - and `CommandGraphEdge::mFromNode`/`mToNode` sit at exactly
  `+0x08`/`+0x0C` **within CommandGraphEdge**, matching `mKeyLow`/`mKeyHigh`'s
  absolute node offsets. Fully self-consistent.
- **Control flow:**
  1. `found = FindHashListNode2C(table, key.fromNode, key.toNode)`.
  2. If found != sentinel -> return `&found->mEdge` (see return-convention proof
     below), skip everything else.
  3. On miss: build `{mKeyLow=fromNode, mKeyHigh=toNode, mEdge=CommandGraphEdge{}}`
     (all-zero edge payload - confirmed by the raw `xorps xmm0,xmm0` + `xor eax,eax`
     + `rep movsd` zero-fill at 0x0082B4B2-0x0082B4EE, no field of the freshly-built
     edge is set to `fromNode`/`toNode` at this point - that happens later, in
     `FUN_00826960`, only when the miss path is taken).
  4. `InsertOrFindHashListNode2C(table, value, inserted)`, discard `inserted`
     (never read afterward - same pattern the sibling `FindOrInsertCommandGraphDrawNode`
     already uses for its own `inserted` flag).
  5. **Return convention - confirmed precisely:** after the `sub_82C480` call,
     `mov eax,[eax]` dereferences its combined `{node*,bool}` outparam down to just
     the node pointer, then **both** exit paths (early "found" jump target and the
     fall-through "inserted" path) converge on:
     ```
     pop edi; pop esi; add eax, 0x10; pop ebx; add esp,0x50; retn
     ```
     `add eax, 0x10` is applied unconditionally on both paths, and `HashListNode2C::mEdge`
     sits at `+0x10`. **This proves `FindOrInsertMapCEdge` returns `CommandGraphEdge*`
     (specifically `&node->mEdge`), not `HashListNode2C*`** - exactly matching the
     task's hypothesis, now confirmed at the instruction level rather than inferred
     from the caller's field reads alone.

**Draft (declaration):**

```cpp
/**
 * Address: 0x0082B490 (FUN_0082B490, sub_82B490)
 *
 * What it does:
 * mMapC's public find-or-insert entry point: looks (fromNode,toNode) up via
 * FindHashListNode2C first; on a miss, builds a default (all-zero payload)
 * CommandGraphEdge keyed by (fromNode,toNode) and inserts via
 * InsertOrFindHashListNode2C. Always returns &node->mEdge (confirmed from the
 * unconditional `add eax, 0x10` applied on both the found and inserted return
 * paths), never the owning HashListNode2C*.
 *
 * The binary's own two register arguments are EAX = pointer to a caller-built
 * {fromNode,toNode} dword pair (dropped from the IDA decompile of its caller,
 * FUN_00826960 - confirmed from FUN_00826960's own disassembly instead), ECX =
 * &mMapC (this + 0xD80).
 */
[[nodiscard]] static CommandGraphEdge*
  FindOrInsertMapCEdge(UICommandGraphDrawNode* fromNode, UICommandGraphDrawNode* toNode, HashTable<HashListNode2C>& table);
```

**Draft (definition):**

```cpp
/**
 * Address: 0x0082B490 (FUN_0082B490, sub_82B490)
 */
UICommandGraph::CommandGraphEdge* UICommandGraph::FindOrInsertMapCEdge(
  UICommandGraphDrawNode* const fromNode, UICommandGraphDrawNode* const toNode, HashTable<HashListNode2C>& table
)
{
  HashListNode2C* const found = FindHashListNode2C(table, fromNode, toNode);
  if (found != table.mListHead) {
    return &found->mEdge;
  }

  HashListNode2CValue insertValue{};
  insertValue.mKeyLow = fromNode;
  insertValue.mKeyHigh = toNode;
  // insertValue.mEdge left default-constructed: all-zero payload, matching the
  // binary's explicit zero-fill at 0x0082B4B2-0x0082B4EE. mEdge.mFromNode/mToNode
  // are populated by the caller (FUN_00826960) only on a genuine miss.

  bool inserted = false;
  HashListNode2C* const resultNode = InsertOrFindHashListNode2C(table, insertValue, inserted);
  return &resultNode->mEdge;
}
```

**Evidence class:** (1) direct code xref, single caller `FUN_00826960` @0x00826996.
`FUN_00826960` itself is not recovered - same paired-recovery caveat as above,
stated explicitly rather than silently promoting this to `recovered`.

## 4. Supporting leaf helpers (fake-citation cleanup)

### 4.1 `FUN_0082D960` -> `HashKeyPairScramble`

Full disassembly already reproduced in 3.1. Real address, real distinct binary
function (unlike the 88-family's inlined-everywhere scramble). Only one *real*
caller in this cluster: `FUN_0082C750`. `meta.json` lists a second caller,
`FUN_0082D924` @0x0082D924, but **that address has no owning function in any
export in this namespace** (`owner_ea: null`, and no `FUN_0082D924.*` files exist -
it falls in an unclassified byte gap between `FUN_0082D914` and `FUN_0082D940`).
Not resolved this session; flagging as an open item, not blocking recovery of
this helper (the one *real*, exported caller is sufficient evidence).

```cpp
/**
 * Address: 0x0082D960 (FUN_0082D960, sub_82D960)
 *
 * IDA signature:
 * int __thiscall sub_82D960(_DWORD *this);
 *
 * What it does:
 * mMapC's pair-key mix step: folds two key dwords into one via
 * `3863*lhs + 7919*rhs + 53849*(lhs^rhs)`, then applies the same Park-Miller
 * scramble tail HashKeyToBucketIndex's single-dword version uses - EXCEPT
 * this one does NOT XOR with 0xDEADBEEF first (confirmed absent from this
 * function's disassembly). Only FindHashListNode2C calls this directly;
 * InsertOrFindHashListNode2C inlines the identical formula independently at
 * its own two use sites instead (confirmed from its own disassembly).
 */
[[nodiscard]] static std::uint32_t HashKeyPairScramble(std::uint32_t lhs, std::uint32_t rhs) noexcept;
```

```cpp
UICommandGraph HashKeyPairScramble impl:

std::uint32_t UICommandGraph::HashKeyPairScramble(const std::uint32_t lhs, const std::uint32_t rhs) noexcept
{
  const std::ldiv_t split =
    std::ldiv(static_cast<long>(3863u * lhs + 7919u * rhs + 53849u * (lhs ^ rhs)), 127773L);
  long scrambled = 16807L * split.rem - 2836L * split.quot;
  if (scrambled < 0) {
    scrambled += 0x7FFFFFFFL;
  }
  return static_cast<std::uint32_t>(scrambled);
}
```

Plus the (not-a-distinct-binary-function, intent-first-lifted) wrapper used at
every mMapC call site:

```cpp
/**
 * Not a distinct binary function - masks HashKeyPairScramble's result against
 * the table's bucket mask and applies the same wraparound adjustment
 * HashKeyToBucketIndex uses. Inlined independently at every mMapC call site
 * (0x0082C750 calls HashKeyPairScramble then inlines this; 0x0082C480 inlines
 * the whole thing, twice); lifted into one named helper here per the
 * intent-first helper contract, mirroring HashKeyToBucketIndex.
 */
[[nodiscard]] static std::uint32_t HashKeyPairToBucketIndex(
  const HashTable<HashListNode2C>& table, std::uint32_t lhs, std::uint32_t rhs
) noexcept;
```
```cpp
std::uint32_t UICommandGraph::HashKeyPairToBucketIndex(
  const HashTable<HashListNode2C>& table, const std::uint32_t lhs, const std::uint32_t rhs
) noexcept
{
  std::uint32_t bucketIndex = HashKeyPairScramble(lhs, rhs) & table.mBucketMask;
  if (table.mBucketCount <= bucketIndex) {
    bucketIndex += static_cast<std::uint32_t>(-1) - (table.mBucketMask >> 1u);
  }
  return bucketIndex;
}
```

**Evidence class:** (1) direct code xref from `FUN_0082C750` @0x0082C75E.

### 4.2 `FUN_00830700` -> `ConstructHashListNode2C`

```
_DWORD *__stdcall sub_830700(int a1, int a2, const void *a3)
{
  result = sub_831BA0(1u);                    // AllocateHashListNode2CStorage(1)
  if (result) *result = a1;                      // node->mNext = a1
  if (result != -4) result[1] = a2;                // node->mPrev = a2
  if (result != -8) qmemcpy(result+2, a3, 0x24);     // node->mKeyLow.. = *valueSource (0x24 bytes)
  return result;
}
```
`if (result != -4/-8)` are compiler-generated partial-construction/SEH-unwind
sentinel checks, the same idiom `ConstructHashListNode88`'s try/catch cleanup
funclet already encodes explicitly. `0x24` = `sizeof(HashListNode2CValue)`
(4+4+0x1C), confirmed exact match.

**Callsite evidence:** register-traced at `FUN_0082C480` 0x0082C6C6-0x0082C6C9:
`push ebx(=a3, the outer function's own valueSource ptr); push edx(=insertionPoint->mPrev);
push edi(=insertionPoint); call sub_830700` = `sub_830700(next=insertionPoint,
prev=insertionPoint->mPrev, valueSource)` - the *exact* same calling convention
`ConstructHashListNode88(next, prev, valueSource)` already uses. `meta.json` also
lists 3 other callers (`FUN_0082DA20`, `FUN_0082F510`, `FUN_00832300`) - not
investigated this session, out of scope for this cluster, noted for completeness.

```cpp
/**
 * Address: 0x00830700 (FUN_00830700, sub_830700)
 *
 * IDA signature:
 * _DWORD *__stdcall sub_830700(int a1, int a2, const void *a3);
 *
 * What it does:
 * Allocates one HashListNode2C, links it via the caller-supplied next/prev,
 * and copies valueSource's 0x24-byte value portion (mKeyLow/mKeyHigh/mEdge)
 * into place. CommandGraphEdge is fully POD (no owned resources), so the
 * binary's raw `qmemcpy(node+2, value, 0x24)` is expressed here as a typed
 * member-wise copy rather than a literal memcpy - compiles to the identical
 * instruction sequence for a POD type.
 */
[[nodiscard]] static HashListNode2C* ConstructHashListNode2C(
  HashListNode2C* next, HashListNode2C* prev, HashListNode2CValue& valueSource
);
```
```cpp
UICommandGraph::HashListNode2C* UICommandGraph::ConstructHashListNode2C(
  HashListNode2C* const next, HashListNode2C* const prev, HashListNode2CValue& valueSource
)
{
  auto* const node = static_cast<HashListNode2C*>(AllocateHashListNode2CStorage(1));
  node->mNext = next;
  node->mPrev = prev;
  node->mKeyLow = valueSource.mKeyLow;
  node->mKeyHigh = valueSource.mKeyHigh;
  node->mEdge = valueSource.mEdge;
  return node;
}
```

**Confidence flag:** the binary's `if (result != -4)` / `if (result != -8)` guards
suggest the original had a try/catch around at least the value-copy step (matching
`ConstructHashListNode88`'s explicit `try { ... } catch (...) { ::operator delete(node); throw; }`).
Since `CommandGraphEdge`'s copy cannot itself throw (fully POD, no allocations),
a try/catch here would be dead code with no observable effect - the draft above
omits it, but this is a minor simplification worth the orchestrator's own
judgment call (the sibling keeps its try/catch even though HashListNode88Value's
copy *can* throw via `RelocateDrawNode`'s heap-lane allocations, which is the
real reason that one needs it and this one doesn't).

### 4.3 `FUN_00831BA0` -> `AllocateHashListNode2CStorage`

Already correctly `blocked` (`blocker_type=needs_callsite_evidence`) after a
prior session's DB-integrity revert - no DB correction needed, just the real
recovery, now unblocked by 4.2's real callsite:

```
void *__fastcall sub_831BA0(unsigned int a1)
{
  if (0xFFFFFFFF / a1 < 0x2C) throw std::bad_alloc();   // 0x2C = sizeof(HashListNode2C)
  return operator new(44 * a1);                            // 44 = 0x2C decimal
}
```

```cpp
/**
 * Address: 0x00831BA0 (FUN_00831BA0, sub_831BA0)
 *
 * What it does:
 * Overflow-checked `operator new` for `count` HashListNode2C (0x2C-byte)
 * slots; throws `std::bad_alloc` when `count` would overflow the byte count.
 * mMapC's own duplicate instantiation of the same `std::_Allocate<T>` shape
 * AllocateHashListNode88Storage already uses for HashListNode88.
 */
[[nodiscard]] static void* AllocateHashListNode2CStorage(std::size_t count);
```
```cpp
void* UICommandGraph::AllocateHashListNode2CStorage(const std::size_t count)
{
  if ((0xFFFFFFFFu / static_cast<std::uint32_t>(count)) < sizeof(HashListNode2C)) {
    throw std::bad_alloc();
  }
  return ::operator new(sizeof(HashListNode2C) * count);
}
```

**Evidence class:** (1) direct code xref from `FUN_00830700` @its call to `sub_831BA0(1u)`.

## 5. `FUN_0082DB00` -> `EnsureHashBucketVectorLengthForMapC` (misclassification fix)

Register-traced fully in 3.2.1. `FUN_0082DB00` (0x0082DB00-0x0082DB6E, 110 bytes,
53 instructions) has the **identical branch structure** to the already-recovered
`EnsureHashBucketVectorLength` (0x0082D820, also 110 bytes/53 instructions - same
size, different SHA256, i.e. a genuine separate compile, not an ICF fold):

```
int __userpurge sub_82DB00@<eax>(unsigned int a1@<eax>, int a2@<ecx>, char a3)
{
  result = *(a2+4);                                   // buckets.mStart
  currentLength = result ? (*(a2+8)-result)>>2 : 0;      // (mFinish-mStart)>>2
  if (currentLength >= a1) {                               // requiredLength
    if (result && a1 < currentLength)
      return sub_82F750(result + 4*a1, *(a2+8));               // truncate
  } else {
    return sub_82F7A0(*(a2+8), a1-currentLength, &a3);           // grow
  }
  return result;
}
```
matches `EnsureHashBucketVectorLength`'s shape exactly (truncate-in-place vs.
grow branches on the same threshold test). Its only two callees, `FUN_0082F7A0`
and `FUN_0082F750`, are both **engine-internal bucket-vector helpers** (see
Section 6) - not `__imp_*`, not wx/Lua/boost/CRT. The existing DB note
("all-external-callees... no Moho/gpg engine references") is simply wrong; it
appears to have been generated by a heuristic that didn't recognize
`HashBucketVector`-shaped field offsets as engine data.

`FUN_0082F750` is already correctly recovered as `MoveDwordTailLaneC` (verified
in Section 6.1) but lives in an **anonymous namespace** in
`LegacyContainerRuntime.cpp` (`namespace { ... }` at line 9), so it has internal
linkage and is not directly callable from `CWldSession.cpp`. At this specific
call site the truncate branch is provably a no-op copy (source pointer read
fresh from the struct always equals the value passed in, so `MoveDwordTailToGapAndCommitEnd`'s
copy loop never executes - see 6.1), so the draft below just does the equivalent
plain pointer write rather than adding a cross-TU dependency for a degenerate case.

```cpp
/**
 * Address: 0x0082DB00 (FUN_0082DB00, sub_82DB00)
 *
 * What it does:
 * mMapC's own duplicate instantiation of EnsureHashBucketVectorLength
 * (binary-separate from the mMapAB0 copy at 0x0082D820 - same algorithm,
 * different compiled address, confirmed by register-level argument tracing
 * of InsertOrFindHashListNode2C's call site). Grows via
 * GrowHashBucketVectorForMapC when short, truncates in place when already
 * longer.
 *
 * PRIOR MISCLASSIFICATION: marked `external_dependency` in the progress DB
 * ("all-external-callees... no Moho/gpg engine references"). Wrong - it
 * operates directly on HashTable<HashListNode2C>::mBuckets, an engine-owned
 * HashBucketVector, exactly mirroring the already-recovered
 * EnsureHashBucketVectorLength. Its callees (FUN_0082F7A0, FUN_0082F750) are
 * engine-internal bucket-vector helpers, not third-party imports.
 */
static void** EnsureHashBucketVectorLengthForMapC(HashBucketVector& buckets, std::uint32_t requiredLength, void* fillValue);
```
```cpp
void** UICommandGraph::EnsureHashBucketVectorLengthForMapC(
  HashBucketVector& buckets, const std::uint32_t requiredLength, void* const fillValue
)
{
  const std::uint32_t currentLength =
    buckets.mStart ? static_cast<std::uint32_t>(buckets.mFinish - buckets.mStart) : 0u;

  if (currentLength >= requiredLength) {
    if (buckets.mStart != nullptr && requiredLength < currentLength) {
      // The binary calls sub_82F750/MoveDwordTailLaneC here; at this call site its
      // source pointer always equals the freshly-read mFinish value, so its copy
      // loop is provably unreachable (see Section 6.1) and it degenerates to this
      // plain pointer write. MoveDwordTailLaneC itself lives in an anonymous
      // namespace in LegacyContainerRuntime.cpp (internal linkage) - not directly
      // callable cross-TU without a hoist, which isn't needed for this degenerate case.
      buckets.mFinish = buckets.mStart + requiredLength;
    }
    return buckets.mStart;
  }

  return GrowHashBucketVectorForMapC(buckets, buckets.mFinish, requiredLength - currentLength, fillValue);
}
```

**Evidence class:** (1) direct code xref from `FUN_0082C480` @0x0082C4D4 (register-
traced, not just the IDA decompile's misleading 1-arg display).

## 6. `FUN_0082F7A0` -> needs a DEDICATED recovery pass (do not trust existing citation)

Currently recovered as `UICommandGraph::GrowHashBucketVectorByFillRef` in
`CWldSession.cpp` (~line 5012-5019):

```cpp
void** UICommandGraph::GrowHashBucketVectorByFillRef(
  HashBucketVector& buckets, void** const insertPosition, const std::uint32_t insertCount, void* const* const fillValueRef
)
{
  return GrowHashBucketVector(buckets, insertPosition, insertCount, *fillValueRef);
}
```

with a doc comment claiming this is "confirmed instruction-for-instruction
against 0x0082F7A0's disassembly (same capacity check, same in-place-shift vs
1.5x-reallocate branches)".

**That claim does not hold up.** `FUN_0082F7A0` (0x0082F7A0-0x0082FA11) is 625
bytes / 236 instructions, has its own SEH exception frame (`data_refs` shows
`SEH_82F7A0` -> `stru_EEBEB0`), its own "vector<T> too long" throw call
(`sub_8307F0`, a **separate** duplicate of `ThrowHashBucketVectorTooLong`, not a
call to the shared one), and 5 more sub-callees resolved this session:

| Callee | Role (verified) |
|---|---|
| `sub_832BE0` (0x00832BE0) | `std::copy(first,last,dest)` - forward element copy |
| `sub_832710` (0x00832710) | `std::fill_n(dest,count,*value)` - scalar broadcast fill |
| `sub_831960` (0x00831960) | `std::copy_backward`-equivalent (iterates source downward) |
| `sub_831C20` (0x00831C20) | overflow-checked `operator new(4*count)` - a **third** duplicate instantiation of the `allocate_dword_slots_checked` shape already noted in `GrowHashBucketVector`'s own doc comment (that comment cites `FUN_00831B40` as the "canonical" one; this is yet another sibling at 0x00831C20) |
| `sub_8307F0` (0x008307F0) | `[[noreturn]]` "vector<T> too long" throw - own duplicate of `ThrowHashBucketVectorTooLong` |
| `sub_831910` (0x00831910) | **UNRESOLVED.** IDA's decompile (`LOBYTE(this)=0; return sub_832BE0(a3,this,this);`) looks like a decompiler-garbled partial-byte-write artifact - passing the same value for both `sub_832BE0` args would make its copy loop a no-op, which doesn't fit its call site's apparent purpose. Needs raw-asm-level (not decompiled-C) re-derivation before `FUN_0082F7A0` can be fully trusted end-to-end. |

The growth algorithm's *shape* (capacity check, in-place-shift-then-fill vs.
1.5x-reallocate branches, same threshold arithmetic) is confirmed structurally
identical to `GrowHashBucketVector` by manual comparison of the two `.c` decompiles
- so `GrowHashBucketVectorForMapC` almost certainly **is** logically the mMapC
duplicate of `GrowHashBucketVector`, matching the same "duplicated-per-table-
instantiation" pattern established everywhere else in this cluster. But the
existing recovered body (a 4-line forward call) is not what's at this address,
and one callee (`sub_831910`) is not yet fully understood. **Recommend treating
`FUN_0082F7A0` as still-open** rather than relying on the current
`GrowHashBucketVectorByFillRef` citation, and giving it its own dedicated
bottom-up pass (resolve `sub_831910` from raw asm first, then write a real
`GrowHashBucketVectorForMapC` matching this session's confirmed callee roles).
Not attempted in this draft beyond the mapping table above, per this task's
scope (research + the 3 named tokens) and to avoid guessing at `sub_831910`'s
exact behavior.

### 6.1 `FUN_0082F5D0` -> needs correction, not just a citation fix

Currently recovered in `CrtRuntimeHelpers.cpp` as:

```cpp
[[noreturn]] void RuntimeThrowListTooLongS()
{
  RuntimeThrowContainerTooLong("list<T> too long");
}
```

Actual disassembly (`FUN_0082F5D0.c`, cross-checked against `.asm`):

```c
int __fastcall sub_82F5D0(unsigned int a1, int a2)
{
  v2 = *(_DWORD *)(a2 + 8);
  if ( 119304647 - v2 < a1 )              // 119304647 = 0x071C71C7 = floor(UINT_MAX/36)
  {
    ... build "list<T> too long" logic_error, throw (length_error vftable) ...
  }
  result = a1 + v2;
  *(_DWORD *)(a2 + 8) = result;
  return result;
}
```

This is **not** an unconditional throw - it is `CheckedIncrementListSize`'s
mMapC-table duplicate (guard-then-increment-then-store), using a different
overflow threshold constant (`0x071C71C7` vs. the mMapAB0 copy's `0x01FFFFFF` at
0x0082F050). `0x071C71C7` = `floor(UINT_MAX/36)` exactly, but note this is
**not** `UINT_MAX/sizeof(HashListNode2C)` (`HashListNode2C` is 0x2C=44 bytes;
`floor(UINT_MAX/44)`=97612893, a different number) - the constant is verified
exact from the disassembly, but its derivation/rationale is not established and
should not be assumed to be size-derived. The current recovery captured
only the cold exception sub-path and silently dropped the function's actual
primary behavior. It's also **dead** right now - `grep -rn RuntimeThrowListTooLongS src/sdk`
finds only its own declaration/definition, zero callers - so this wrong body has
not (yet) caused an observable bug, but it will as soon as anything real calls
`CheckedIncrementListSizeForMapC` and someone reaches for the existing symbol
instead. `a2@<ecx>`'s effective address resolves to `&table.mListSize` (traced:
`FUN_0082C480` passes `edx = esi+4`, i.e. `table+4`, and the callee itself adds
`+8` before dereferencing, landing on `table+0xC` = `mListSize`'s real offset -
a compiler-quirk two-step rather than passing `&mListSize` directly, functionally
identical either way).

```cpp
/**
 * Address: 0x0082F5D0 (FUN_0082F5D0, sub_82F5D0)
 *
 * What it does:
 * mMapC's own duplicate instantiation of CheckedIncrementListSize, using a
 * different max-size guard constant (0x071C71C7 = floor(UINT_MAX/36), vs. the
 * mMapAB0 copy's 0x01FFFFFF - NOT simply UINT_MAX/sizeof(HashListNode2C);
 * that would be 97612893, not 119304647, so the derivation is unexplained).
 * Throws the same "list<T> too long" diagnostic on overflow, otherwise adds
 * `count` to `sizeField` and returns the new value.
 *
 * PRIOR MISRECOVERY: this address is currently modeled in
 * CrtRuntimeHelpers.cpp as `RuntimeThrowListTooLongS()`, an unconditional
 * throw with no parameters and no increment logic - it captured only this
 * function's cold exception sub-path and dropped its actual (guard-then-
 * increment) primary behavior. That symbol also has zero callers anywhere in
 * src/sdk - dead and wrong; should be replaced by this, not kept alongside it.
 */
static std::uint32_t CheckedIncrementListSizeForMapC(std::uint32_t count, std::uint32_t& sizeField);
```
```cpp
std::uint32_t UICommandGraph::CheckedIncrementListSizeForMapC(const std::uint32_t count, std::uint32_t& sizeField)
{
  if ((0x071C71C7u - sizeField) < count) {
    RuntimeThrowContainerTooLong("list<T> too long");
  }
  sizeField += count;
  return sizeField;
}
```

**Evidence class:** (1) direct code xref from `FUN_0082C480` @0x0082C6D8 (the live
call site; the earlier @0x0082C5A8 call is unreachable dead code - `cmp edx,edx; jz`
is a tautology, always taken, so the `xor ecx,ecx; call sub_82F5D0` right before it
never executes - confirmed by reading the raw asm, not just the decompiled C which
doesn't make the always-true branch obvious).

## 7. Open items / confidence flags (do not silently resolve these)

1. **`FUN_0082D924`** (second listed caller of `HashKeyPairScramble`/`FUN_0082D960`)
   has no owning function in this namespace's exports (`owner_ea: null`, falls in
   an unclassified byte gap 0x0082D915-0x0082D93F). Not resolved. Doesn't block
   4.1 (the one real, exported caller `FUN_0082C750` is sufficient evidence), but
   worth a follow-up IDA pass to check whether it's a second real hash-table
   instantiation (mMapD?) our exports simply missed.
2. **`FUN_0082F7A0`'s `sub_831910` callee** - decompiled shape looks like a
   `LOBYTE`-clearing artifact that doesn't self-evidently make sense; needs
   raw-instruction re-derivation, not decompiled-C, before trusting a full
   `GrowHashBucketVectorForMapC` recovery. See Section 6.
3. **Paired-recovery requirement:** none of `FUN_0082C750`/`FUN_0082C480`/
   `FUN_0082B490` currently have a *recovered* caller above them
   (`FUN_00826960` and `FUN_00826140` are both still `blocked`). Per CLAUDE.md's
   callsite-verification rule, these three should land in the same commit as
   each other at minimum, and ideally paired with enough of `FUN_00826960` to
   give the whole chain a real recovered caller - otherwise they satisfy
   evidence-class (1) in isolation but not the "reachable from a recovered
   caller" refinement. Flagging rather than silently promoting to `recovered`.
4. **`ConstructHashListNode2C`'s try/catch** - omitted in the draft since
   `CommandGraphEdge`'s copy can't throw (fully POD); the binary's `if (result !=
   -4/-8)` guards suggest a try/catch shape was present in source regardless.
   Orchestrator's call on whether to keep a (dead but faithful) try/catch for
   consistency with `ConstructHashListNode88`, or omit it as done here since it
   cannot execute.
5. **`HashListNode2C` struct-layout change** (Section 1) is a prerequisite edit
   to the class declaration, not additive - it replaces `using HashListNode2C =
   HashListNode<0x2C>;` entirely. Should be reviewed carefully since
   `AllocateMapCListSentinel`/`InitMapCBuckets`/`InitMapC`/
   `ResetHashBucketVectorToNineSlots`/`PrepareForRebuild` (all already recovered
   and presumably building today) depend on this type and were checked to keep
   compiling (they only touch `mNext`/`mPrev` via the generic
   `AllocateSelfLinkedNode<TNode>`), but this needs a real build check, not just
   my read-through.
