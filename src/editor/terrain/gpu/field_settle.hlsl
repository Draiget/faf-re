// Op settle (EdFieldEro2.cpp OpSettle), one iteration: sediment settles in hollows. Low ground rises towards the mean of its in-bounds neighbours (eight of them, the order of the CPU op) where it
// is flat enough: fill = rate * min(cap, max(0, mean - c)) * (1 - smoothstep(slopeLo, slopeHi, |gradient|)) * mask; the rise of all iterations is summed into `dep` (the op's deposit output).
// The host runs it `iterations` times over a ping-pong pair of fields. Same arithmetic as the CPU op, in the same order.
#include "filt_common.hlsli"
#include "field_settle_params.hlsli"

CBUFFER(SettleParams, P, 0)
SRV_BUFFER(float, cur, 0)
SRV_BUFFER(float, mask, 1)
UAV_BUFFER(float, nxt, 0)
UAV_BUFFER(float, dep, 1)

DEFINE_GRADIENT_AT(cur)

static const int kSettleDx[8] = {-1, 1, 0, 0, -1, 1, -1, 1};
static const int kSettleDz[8] = {0, 0, -1, 1, -1, -1, 1, 1};

NUMTHREADS(16, 16, 1)
void CSMain(KERNEL_IDS)
{
    if (dtid.x >= P.w || dtid.y >= P.h) return;
    int x = int(dtid.x);
    int z = int(dtid.y);
    int w = int(P.w);
    int h = int(P.h);
    uint i = dtid.y * P.w + dtid.x;
    float c = cur[i];
    float sum = 0.0f;
    int cnt = 0;
    UNROLL for (int k = 0; k < 8; ++k)
    {
        int nx = x + kSettleDx[k];
        int nz = z + kSettleDz[k];
        if (nx < 0 || nz < 0 || nx >= w || nz >= h) continue;
        sum += cur[uint(nz) * P.w + uint(nx)];
        ++cnt;
    }
    float mean = c;
    if (cnt > 0) mean = sum / float(cnt);
    float gx;
    float gz;
    GradientAt(x, z, gx, gz);
    float wgt = 1.0f - SmoothStep(P.slopeLo, P.slopeHi, sqrt(gx * gx + gz * gz));
    if (P.hasMask != 0u) wgt *= saturate(mask[i]);
    float fill = P.rate * min(P.cap, max(0.0f, mean - c)) * wgt;
    nxt[i] = c + fill;
    dep[i] = dep[i] + fill;
}
