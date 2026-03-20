#pragma once

namespace moho
{
  enum class SiloType : int;

  class IAiSiloBuild
  {
    // Primary vftable (12 entries)
  public:
    /**
     * In binary: dtor
     *
     * Address: 0x5CE860
     * VFTable SLOT: 0
     */
    virtual ~IAiSiloBuild() = default;

    // Slot 1. Refreshes cached stockpile slots from owner weapon records.
    virtual void RefreshSlotsFromOwner() = 0; // 0xA82547

    // Slot 2. Returns true if active queue/type matches the requested silo type.
    virtual bool IsActiveType(SiloType type) const = 0; // 0xA82547

    // Slot 3. Returns true when built + queued has reached desired count.
    virtual bool IsSufficient(SiloType type) const = 0; // 0xA82547

    // Slot 4. Counts queued entries for the given silo type.
    virtual int GetQueuedCount(SiloType type) const = 0; // 0xA82547

    // Slot 5. Returns stockpiled built count for the given silo type.
    virtual int GetBuiltCount(SiloType type) const = 0; // 0xA82547

    // Slot 6. Returns desired target count for the given silo type.
    virtual int GetDesiredCount(SiloType type) const = 0; // 0xA82547

    // Slot 7. Adjusts built counter for the given silo type.
    virtual void AddToBuilt(SiloType type, int delta) = 0; // 0xA82547

    // Slot 8. Attempts to enqueue another stockpile build.
    virtual bool TryEnqueue(SiloType type) = 0; // 0xA82547

    // Slot 9. Silo build state-machine tick.
    virtual bool Tick() = 0; // 0xA82547

    // Slot 10. SSE-heavy helper used by Tick.
    virtual int EvalVectorHelperA(int arg) = 0; // 0xA82547

    // Slot 11. SSE-heavy helper used by Tick.
    virtual int EvalVectorHelperB(int arg) = 0; // 0xA82547
  };
} // namespace moho
