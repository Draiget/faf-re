#pragma once

// This header used to declare free register_/cleanup_ wrapper functions for
// the CUnitMotionConstruct/CUnitMotionSerializer reflection singletons.
// Those wrappers fabricated an eager Init() dispatch not present in the real
// binary (see CUnitMotionSerHelpers.cpp) -- the singletons now construct and
// tear down through their own real gpg::SerHelperBase ctor/dtor, declared in
// moho/unit/CUnitMotionConstruct.h and moho/unit/CUnitMotionSerializer.h.
