# Particle pool statistics

The client writes one `Particle pools:` summary when a successfully created
world session ends. It covers the normal particle, refraction and trail lanes.
There is no new setting; pool sizes, admission order and drawing are unchanged.

## Reading the summary

- `peak buffers particles=used/capacity trails=used/capacity`: the greatest
  number of descriptors unavailable from each free pool during this session,
  and that pool's greatest realized capacity. These are independent peaks,
  not necessarily observed in the same frame. One descriptor can contain many
  particles or segments. This is not a live-particle count, VRAM measurement,
  or count of GPU draw calls.
- `pool drops particles=... trail_segments=...`: pending input actually
  discarded when its descriptor pool is empty. A failed acquire with no
  discarded input adds nothing. One trail segment counts once, not once per
  vertex. An already consumed particle-upload prefix is excluded.
- `upload discards pending_particles=... pending_trail_segments=...`: pending
  input discarded after a missing buffer or null upload lock, separately from
  capacity rejection. That path can also invalidate earlier live intervals;
  those older records are not included in this pending-input count. Exceptions
  are not converted into drops, and mirror/gather fallback is not a drop.
- `saturated=1` means a cumulative count reached its unsigned 64-bit limit and
  was clamped instead of wrapping. Normally this is zero.

Ordinary expiry, buffer reuse, bucket cleanup and intentionally suppressed
effects are not counted as pool drops. The counters do not measure sim-side
culling, effects outside these render pools, or all possible visual loss.

## Session and resource lifetime

Collection starts after successful world-session construction and ends after
the final driver sync drain, before teardown clears render buckets. Repeated
teardown does not print the same session twice. A session with no activity
still has a summary. The existing logger handles the output; if it throws,
the summary may be missing or incomplete; teardown continues without retry.

Pool storage can survive into the next session. Its realized capacity and any
already unavailable descriptors are sampled, rather than inferred from the
current setting. Device reset does not end collection. A replay timeline seek
clears buckets but stays in the same statistics session: subsequently rendered
effects contribute again. Use a fresh playback without seeks for comparable
whole-replay measurements. A full session restart starts a new summary.

The sidecar is owned by the same main/render thread as the existing pools.
It adds fixed scalar storage, constant-time updates per successful acquisition
or discard, and one end-of-session log. It adds no per-particle loop, pool scan,
hot-path allocation, lock or atomic operation. Host checks are not measurements
of native GPU cost, frame times or real-game saturation.

## Tests

The standalone GoogleTest projects are `tests/particles/upload_host` and
`tests/particles/stats_host`. Their READMEs give the dependency and CMake/CTest
commands and describe the source-bound functions and host adapters. Native
Windows builds, graphics devices and real replay measurements are separate
integration checks.
