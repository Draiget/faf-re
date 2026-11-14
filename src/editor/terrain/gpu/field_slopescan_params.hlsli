// Constant buffer of field_slopescan.hlsl (op slope_limit).
#ifndef GPU_FIELD_SLOPESCAN_PARAMS_HLSLI
#define GPU_FIELD_SLOPESCAN_PARAMS_HLSLI

struct SlopeScanParams
{
    uint lines;        // number of lines scanned (one thread each)
    uint len;          // samples per line
    uint stride;       // distance between two samples of a line in the buffer
    uint lineStride;   // distance between the first samples of two lines
    float lim;         // largest height difference between neighbouring samples
    float inSign;      // the scan works on inSign * source (-1: the upper envelope is the lower envelope of the negated field; 1 for a second scan of an already signed field)
    float pad0;
    float pad1;
};

#endif
