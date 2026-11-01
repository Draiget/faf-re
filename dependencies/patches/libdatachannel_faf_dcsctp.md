# FAF libdatachannel dcSCTP patch

Baseline: upstream `libdatachannel-0.24.6.tar.gz` from GitHub tags (`22a66aebebd8dae561d8e5181da96f2fcc203e067c5b2186c07b39af913464c0`). `cmake/FafDependencies.cmake` downloads it, checks the hash, extracts it to `dependencies/libdatachannel` and applies this patch.

## Patch scope

Adds an alternative high-performance SCTP transport backend powered by `dcSCTP` (extracted from Google WebRTC) alongside upstream `usrsctp`.

| File | Change |
|---|---|
| `include/rtc/configuration.hpp` | Adds `SctpBackend` enum (`UsrSctp = 0`, `DcSctp = 1`) and `sctpBackend` configuration option to `rtc::Configuration` |
| `src/impl/sctptransport.hpp` | Declares `rtc::SctpBackend mBackend` and `std::shared_ptr<DcSctpBackend> mDcSctp`, exposing helper callbacks `triggerRecv`, `triggerChangeState`, and `triggerOutgoing` |
| `src/impl/sctptransport.cpp` | Dispatches lifecycle and stream/message transmission (`connect`, `close`, `closeStream`, `send`, `incoming`, stats) to `mDcSctp` when `sctpBackend == SctpBackend::DcSctp` |
| `src/impl/dcsctpbackend.hpp` | Header for `DcSctpBackend` implementing SCTP transport using `dcSCTP` |
| `src/impl/dcsctpbackend.cpp` | Implementation of `DcSctpBackend` and `dcsctp::DcSctpSocketCallbacks`, mapping timers to `ThreadPool::Instance()`, zero-lock buffer dispatch, and DSCP packet forwarding |
