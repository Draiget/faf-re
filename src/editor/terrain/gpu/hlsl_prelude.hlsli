// HLSL side of the kernel language (docs/projects/editor/GPU_COMPUTE.md). scripts/gen_gpu_shaders.py puts this file in front of every kernel it embeds; the C++ test shim
// (hlsl_cpp_shim.h) defines the SAME macro names for g++ / MSVC. A kernel therefore never writes cbuffer, register(), StructuredBuffer, [numthreads], SV_ or groupshared itself.
//
// Resource slots: constant buffer b0 (one per kernel), shader resource views t0..t15, unordered access views u0..u7, samplers s0 (linear, clamp) and s1 (point, clamp).
// The SRV slot numbers are shared between buffers and textures (SRV_BUFFER(.., 0) and SRV_TEX(.., 0) would collide), the same for UAVs.

#define CBUFFER(Type, name, slot) cbuffer name##_cb : register(b##slot) { Type name; };
#define SRV_BUFFER(T, name, slot) StructuredBuffer<T> name : register(t##slot);
#define UAV_BUFFER(T, name, slot) RWStructuredBuffer<T> name : register(u##slot);
#define SRV_TEX(name, slot) Texture2D<float> name : register(t##slot);
#define UAV_TEX(name, slot) RWTexture2D<float> name : register(u##slot);
#define SAMPLER(name, slot) SamplerState name : register(s##slot);
#define GROUPSHARED(T, name, n) groupshared T name[n];
#define NUMTHREADS(x, y, z) [numthreads(x, y, z)]
#define KERNEL_IDS uint3 dtid : SV_DispatchThreadID, uint3 gtid : SV_GroupThreadID, uint3 gid : SV_GroupID, uint gidx : SV_GroupIndex

// Kernels with group shared memory split their body into phases at top level: PHASES_BEGIN, code, BARRIER(0); code, ..., PHASES_END. Every phase is its own scope (a local does not
// live across a BARRIER, on the GPU as in the emulation).
#define PHASES_BEGIN {
// (BARRIER takes one dummy argument: the HLSL compiler's preprocessor rejects a macro with an empty parameter list, error X1500 at the #define)
#define BARRIER(unused) GroupMemoryBarrierWithGroupSync(); } {
#define PHASES_END }

#define UNROLL [unroll]
#define LOOP [loop]
#define OUT(T) out T
#define INOUT(T) inout T
#define FN
