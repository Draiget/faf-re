// Engine addition (dedicated-server plan WPL.11), see Libm.h. Ported from musl 1.2.5
// (src/math/exp.c, exp_data.c, log.c, log_data.c, asin.c); the tables are musl's, unchanged.
//
// exp, log and their data:
//   Copyright (c) 2018, Arm Limited.
//   SPDX-License-Identifier: MIT
//
//   Permission is hereby granted, free of charge, to any person obtaining a copy of this
//   software and associated documentation files (the "Software"), to deal in the Software
//   without restriction, including without limitation the rights to use, copy, modify, merge,
//   publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons
//   to whom the Software is furnished to do so, subject to the following conditions:
//
//   The above copyright notice and this permission notice shall be included in all copies or
//   substantial portions of the Software.
//
//   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
//   INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
//   PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE
//   FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
//   OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
//   DEALINGS IN THE SOFTWARE.
//
// asin (origin: FreeBSD /usr/src/lib/msun/src/e_asin.c):
//   Copyright (C) 1993 by Sun Microsystems, Inc. All rights reserved.
//
//   Developed at SunSoft, a Sun Microsystems, Inc. business.
//   Permission to use, copy, modify, and distribute this
//   software is freely granted, provided that this notice
//   is preserved.

#include "legacy/math/Libm.h"

#include <bit>
#include <cmath>
#include <cstdint>
#include <limits>

#include <emmintrin.h>

namespace msvc8::libm
{
  namespace
  {
    [[nodiscard]] double AsDouble(const std::uint64_t bits) noexcept { return std::bit_cast<double>(bits); }
    [[nodiscard]] std::uint64_t AsBits(const double value) noexcept { return std::bit_cast<std::uint64_t>(value); }

    /// The correctly rounded square root (`sqrtsd`): a library sqrt on x86 can be an x87
    /// `fsqrt` that rounds under the caller's precision control.
    [[nodiscard]] double Sqrt(const double value) noexcept
    {
      return _mm_cvtsd_f64(_mm_sqrt_sd(_mm_setzero_pd(), _mm_set_sd(value)));
    }

    /// The quiet NaN `(x - x) / (x - x)` gives: `x` itself for a NaN, the hardware's default
    /// NaN otherwise (musl's __math_invalid).
    [[nodiscard]] double Invalid(const double x) noexcept
    {
      const double difference = x - x;
      return difference / difference;
    }

    constexpr int kExpTableBits = 7;
    constexpr std::uint64_t kExpTableSize = 1u << kExpTableBits;
    constexpr double kInvLn2N = 0x1.71547652b82fep0 * kExpTableSize;
    constexpr double kNegLn2HiN = -0x1.62e42fefa0000p-8;
    constexpr double kNegLn2LoN = -0x1.cf79abc9e3b3ap-47;
    constexpr double kShift = 0x1.8p52;

    constexpr int kLogTableBits = 7;
    constexpr std::uint64_t kLogTableSize = 1u << kLogTableBits;
    constexpr double kLn2Hi = 0x1.62e42fefa3800p-1;
    constexpr double kLn2Lo = 0x1.ef35793c76730p-45;

    struct SLogEntry
    {
      double first;  // kLogTable: 1/c; kLogTable2: c rounded to double
      double second; // kLogTable: log(c); kLogTable2: c minus that
    };

    constexpr double kExpPoly[4] = {0x1.ffffffffffdbdp-2, 0x1.555555555543cp-3, 0x1.55555cf172b91p-5, 0x1.1111167a4d017p-7};
    // 2^(k/N) ~= H[k]*(1 + T[k]): [2k] = bits of T[k], [2k+1] = bits of H[k] - (k << 52)/N.
    constexpr std::uint64_t kExpTable[2 * kExpTableSize] = {
      0x0, 0x3ff0000000000000,
      0x3c9b3b4f1a88bf6e, 0x3feff63da9fb3335,
      0xbc7160139cd8dc5d, 0x3fefec9a3e778061,
      0xbc905e7a108766d1, 0x3fefe315e86e7f85,
      0x3c8cd2523567f613, 0x3fefd9b0d3158574,
      0xbc8bce8023f98efa, 0x3fefd06b29ddf6de,
      0x3c60f74e61e6c861, 0x3fefc74518759bc8,
      0x3c90a3e45b33d399, 0x3fefbe3ecac6f383,
      0x3c979aa65d837b6d, 0x3fefb5586cf9890f,
      0x3c8eb51a92fdeffc, 0x3fefac922b7247f7,
      0x3c3ebe3d702f9cd1, 0x3fefa3ec32d3d1a2,
      0xbc6a033489906e0b, 0x3fef9b66affed31b,
      0xbc9556522a2fbd0e, 0x3fef9301d0125b51,
      0xbc5080ef8c4eea55, 0x3fef8abdc06c31cc,
      0xbc91c923b9d5f416, 0x3fef829aaea92de0,
      0x3c80d3e3e95c55af, 0x3fef7a98c8a58e51,
      0xbc801b15eaa59348, 0x3fef72b83c7d517b,
      0xbc8f1ff055de323d, 0x3fef6af9388c8dea,
      0x3c8b898c3f1353bf, 0x3fef635beb6fcb75,
      0xbc96d99c7611eb26, 0x3fef5be084045cd4,
      0x3c9aecf73e3a2f60, 0x3fef54873168b9aa,
      0xbc8fe782cb86389d, 0x3fef4d5022fcd91d,
      0x3c8a6f4144a6c38d, 0x3fef463b88628cd6,
      0x3c807a05b0e4047d, 0x3fef3f49917ddc96,
      0x3c968efde3a8a894, 0x3fef387a6e756238,
      0x3c875e18f274487d, 0x3fef31ce4fb2a63f,
      0x3c80472b981fe7f2, 0x3fef2b4565e27cdd,
      0xbc96b87b3f71085e, 0x3fef24dfe1f56381,
      0x3c82f7e16d09ab31, 0x3fef1e9df51fdee1,
      0xbc3d219b1a6fbffa, 0x3fef187fd0dad990,
      0x3c8b3782720c0ab4, 0x3fef1285a6e4030b,
      0x3c6e149289cecb8f, 0x3fef0cafa93e2f56,
      0x3c834d754db0abb6, 0x3fef06fe0a31b715,
      0x3c864201e2ac744c, 0x3fef0170fc4cd831,
      0x3c8fdd395dd3f84a, 0x3feefc08b26416ff,
      0xbc86a3803b8e5b04, 0x3feef6c55f929ff1,
      0xbc924aedcc4b5068, 0x3feef1a7373aa9cb,
      0xbc9907f81b512d8e, 0x3feeecae6d05d866,
      0xbc71d1e83e9436d2, 0x3feee7db34e59ff7,
      0xbc991919b3ce1b15, 0x3feee32dc313a8e5,
      0x3c859f48a72a4c6d, 0x3feedea64c123422,
      0xbc9312607a28698a, 0x3feeda4504ac801c,
      0xbc58a78f4817895b, 0x3feed60a21f72e2a,
      0xbc7c2c9b67499a1b, 0x3feed1f5d950a897,
      0x3c4363ed60c2ac11, 0x3feece086061892d,
      0x3c9666093b0664ef, 0x3feeca41ed1d0057,
      0x3c6ecce1daa10379, 0x3feec6a2b5c13cd0,
      0x3c93ff8e3f0f1230, 0x3feec32af0d7d3de,
      0x3c7690cebb7aafb0, 0x3feebfdad5362a27,
      0x3c931dbdeb54e077, 0x3feebcb299fddd0d,
      0xbc8f94340071a38e, 0x3feeb9b2769d2ca7,
      0xbc87deccdc93a349, 0x3feeb6daa2cf6642,
      0xbc78dec6bd0f385f, 0x3feeb42b569d4f82,
      0xbc861246ec7b5cf6, 0x3feeb1a4ca5d920f,
      0x3c93350518fdd78e, 0x3feeaf4736b527da,
      0x3c7b98b72f8a9b05, 0x3feead12d497c7fd,
      0x3c9063e1e21c5409, 0x3feeab07dd485429,
      0x3c34c7855019c6ea, 0x3feea9268a5946b7,
      0x3c9432e62b64c035, 0x3feea76f15ad2148,
      0xbc8ce44a6199769f, 0x3feea5e1b976dc09,
      0xbc8c33c53bef4da8, 0x3feea47eb03a5585,
      0xbc845378892be9ae, 0x3feea34634ccc320,
      0xbc93cedd78565858, 0x3feea23882552225,
      0x3c5710aa807e1964, 0x3feea155d44ca973,
      0xbc93b3efbf5e2228, 0x3feea09e667f3bcd,
      0xbc6a12ad8734b982, 0x3feea012750bdabf,
      0xbc6367efb86da9ee, 0x3fee9fb23c651a2f,
      0xbc80dc3d54e08851, 0x3fee9f7df9519484,
      0xbc781f647e5a3ecf, 0x3fee9f75e8ec5f74,
      0xbc86ee4ac08b7db0, 0x3fee9f9a48a58174,
      0xbc8619321e55e68a, 0x3fee9feb564267c9,
      0x3c909ccb5e09d4d3, 0x3feea0694fde5d3f,
      0xbc7b32dcb94da51d, 0x3feea11473eb0187,
      0x3c94ecfd5467c06b, 0x3feea1ed0130c132,
      0x3c65ebe1abd66c55, 0x3feea2f336cf4e62,
      0xbc88a1c52fb3cf42, 0x3feea427543e1a12,
      0xbc9369b6f13b3734, 0x3feea589994cce13,
      0xbc805e843a19ff1e, 0x3feea71a4623c7ad,
      0xbc94d450d872576e, 0x3feea8d99b4492ed,
      0x3c90ad675b0e8a00, 0x3feeaac7d98a6699,
      0x3c8db72fc1f0eab4, 0x3feeace5422aa0db,
      0xbc65b6609cc5e7ff, 0x3feeaf3216b5448c,
      0x3c7bf68359f35f44, 0x3feeb1ae99157736,
      0xbc93091fa71e3d83, 0x3feeb45b0b91ffc6,
      0xbc5da9b88b6c1e29, 0x3feeb737b0cdc5e5,
      0xbc6c23f97c90b959, 0x3feeba44cbc8520f,
      0xbc92434322f4f9aa, 0x3feebd829fde4e50,
      0xbc85ca6cd7668e4b, 0x3feec0f170ca07ba,
      0x3c71affc2b91ce27, 0x3feec49182a3f090,
      0x3c6dd235e10a73bb, 0x3feec86319e32323,
      0xbc87c50422622263, 0x3feecc667b5de565,
      0x3c8b1c86e3e231d5, 0x3feed09bec4a2d33,
      0xbc91bbd1d3bcbb15, 0x3feed503b23e255d,
      0x3c90cc319cee31d2, 0x3feed99e1330b358,
      0x3c8469846e735ab3, 0x3feede6b5579fdbf,
      0xbc82dfcd978e9db4, 0x3feee36bbfd3f37a,
      0x3c8c1a7792cb3387, 0x3feee89f995ad3ad,
      0xbc907b8f4ad1d9fa, 0x3feeee07298db666,
      0xbc55c3d956dcaeba, 0x3feef3a2b84f15fb,
      0xbc90a40e3da6f640, 0x3feef9728de5593a,
      0xbc68d6f438ad9334, 0x3feeff76f2fb5e47,
      0xbc91eee26b588a35, 0x3fef05b030a1064a,
      0x3c74ffd70a5fddcd, 0x3fef0c1e904bc1d2,
      0xbc91bdfbfa9298ac, 0x3fef12c25bd71e09,
      0x3c736eae30af0cb3, 0x3fef199bdd85529c,
      0x3c8ee3325c9ffd94, 0x3fef20ab5fffd07a,
      0x3c84e08fd10959ac, 0x3fef27f12e57d14b,
      0x3c63cdaf384e1a67, 0x3fef2f6d9406e7b5,
      0x3c676b2c6c921968, 0x3fef3720dcef9069,
      0xbc808a1883ccb5d2, 0x3fef3f0b555dc3fa,
      0xbc8fad5d3ffffa6f, 0x3fef472d4a07897c,
      0xbc900dae3875a949, 0x3fef4f87080d89f2,
      0x3c74a385a63d07a7, 0x3fef5818dcfba487,
      0xbc82919e2040220f, 0x3fef60e316c98398,
      0x3c8e5a50d5c192ac, 0x3fef69e603db3285,
      0x3c843a59ac016b4b, 0x3fef7321f301b460,
      0xbc82d52107b43e1f, 0x3fef7c97337b9b5f,
      0xbc892ab93b470dc9, 0x3fef864614f5a129,
      0x3c74b604603a88d3, 0x3fef902ee78b3ff6,
      0x3c83c5ec519d7271, 0x3fef9a51fbc74c83,
      0xbc8ff7128fd391f0, 0x3fefa4afa2a490da,
      0xbc8dae98e223747d, 0x3fefaf482d8e67f1,
      0x3c8ec3bc41aa2008, 0x3fefba1bee615a27,
      0x3c842b94c3a9eb32, 0x3fefc52b376bba97,
      0x3c8a64a931d185ee, 0x3fefd0765b6e4540,
      0xbc8e37bae43be3ed, 0x3fefdbfdad9cbe14,
      0x3c77893b4d91cd9d, 0x3fefe7c1819e90d8,
      0x3c5305c14160cc89, 0x3feff3c22b8f71f1,
    };
    constexpr double kLogPoly1[11] = {
      -0x1p-1,
      0x1.5555555555577p-2,
      -0x1.ffffffffffdcbp-3,
      0x1.999999995dd0cp-3,
      -0x1.55555556745a7p-3,
      0x1.24924a344de3p-3,
      -0x1.fffffa4423d65p-4,
      0x1.c7184282ad6cap-4,
      -0x1.999eb43b068ffp-4,
      0x1.78182f7afd085p-4,
      -0x1.5521375d145cdp-4,
    };
    constexpr double kLogPoly[5] = {-0x1.0000000000001p-1, 0x1.555555551305bp-2, -0x1.fffffffeb459p-3, 0x1.999b324f10111p-3, -0x1.55575e506c89fp-3};
    constexpr SLogEntry kLogTable[kLogTableSize] = {
      {0x1.734f0c3e0de9fp+0, -0x1.7cc7f79e69000p-2},
      {0x1.713786a2ce91fp+0, -0x1.76feec20d0000p-2},
      {0x1.6f26008fab5a0p+0, -0x1.713e31351e000p-2},
      {0x1.6d1a61f138c7dp+0, -0x1.6b85b38287800p-2},
      {0x1.6b1490bc5b4d1p+0, -0x1.65d5590807800p-2},
      {0x1.69147332f0cbap+0, -0x1.602d076180000p-2},
      {0x1.6719f18224223p+0, -0x1.5a8ca86909000p-2},
      {0x1.6524f99a51ed9p+0, -0x1.54f4356035000p-2},
      {0x1.63356aa8f24c4p+0, -0x1.4f637c36b4000p-2},
      {0x1.614b36b9ddc14p+0, -0x1.49da7fda85000p-2},
      {0x1.5f66452c65c4cp+0, -0x1.445923989a800p-2},
      {0x1.5d867b5912c4fp+0, -0x1.3edf439b0b800p-2},
      {0x1.5babccb5b90dep+0, -0x1.396ce448f7000p-2},
      {0x1.59d61f2d91a78p+0, -0x1.3401e17bda000p-2},
      {0x1.5805612465687p+0, -0x1.2e9e2ef468000p-2},
      {0x1.56397cee76bd3p+0, -0x1.2941b3830e000p-2},
      {0x1.54725e2a77f93p+0, -0x1.23ec58cda8800p-2},
      {0x1.52aff42064583p+0, -0x1.1e9e129279000p-2},
      {0x1.50f22dbb2bddfp+0, -0x1.1956d2b48f800p-2},
      {0x1.4f38f4734ded7p+0, -0x1.141679ab9f800p-2},
      {0x1.4d843cfde2840p+0, -0x1.0edd094ef9800p-2},
      {0x1.4bd3ec078a3c8p+0, -0x1.09aa518db1000p-2},
      {0x1.4a27fc3e0258ap+0, -0x1.047e65263b800p-2},
      {0x1.4880524d48434p+0, -0x1.feb224586f000p-3},
      {0x1.46dce1b192d0bp+0, -0x1.f474a7517b000p-3},
      {0x1.453d9d3391854p+0, -0x1.ea4443d103000p-3},
      {0x1.43a2744b4845ap+0, -0x1.e020d44e9b000p-3},
      {0x1.420b54115f8fbp+0, -0x1.d60a22977f000p-3},
      {0x1.40782da3ef4b1p+0, -0x1.cc00104959000p-3},
      {0x1.3ee8f5d57fe8fp+0, -0x1.c202956891000p-3},
      {0x1.3d5d9a00b4ce9p+0, -0x1.b81178d811000p-3},
      {0x1.3bd60c010c12bp+0, -0x1.ae2c9ccd3d000p-3},
      {0x1.3a5242b75dab8p+0, -0x1.a45402e129000p-3},
      {0x1.38d22cd9fd002p+0, -0x1.9a877681df000p-3},
      {0x1.3755bc5847a1cp+0, -0x1.90c6d69483000p-3},
      {0x1.35dce49ad36e2p+0, -0x1.87120a645c000p-3},
      {0x1.34679984dd440p+0, -0x1.7d68fb4143000p-3},
      {0x1.32f5cceffcb24p+0, -0x1.73cb83c627000p-3},
      {0x1.3187775a10d49p+0, -0x1.6a39a9b376000p-3},
      {0x1.301c8373e3990p+0, -0x1.60b3154b7a000p-3},
      {0x1.2eb4ebb95f841p+0, -0x1.5737d76243000p-3},
      {0x1.2d50a0219a9d1p+0, -0x1.4dc7b8fc23000p-3},
      {0x1.2bef9a8b7fd2ap+0, -0x1.4462c51d20000p-3},
      {0x1.2a91c7a0c1babp+0, -0x1.3b08abc830000p-3},
      {0x1.293726014b530p+0, -0x1.31b996b490000p-3},
      {0x1.27dfa5757a1f5p+0, -0x1.2875490a44000p-3},
      {0x1.268b39b1d3bbfp+0, -0x1.1f3b9f879a000p-3},
      {0x1.2539d838ff5bdp+0, -0x1.160c8252ca000p-3},
      {0x1.23eb7aac9083bp+0, -0x1.0ce7f57f72000p-3},
      {0x1.22a012ba940b6p+0, -0x1.03cdc49fea000p-3},
      {0x1.2157996cc4132p+0, -0x1.f57bdbc4b8000p-4},
      {0x1.201201dd2fc9bp+0, -0x1.e370896404000p-4},
      {0x1.1ecf4494d480bp+0, -0x1.d17983ef94000p-4},
      {0x1.1d8f5528f6569p+0, -0x1.bf9674ed8a000p-4},
      {0x1.1c52311577e7cp+0, -0x1.adc79202f6000p-4},
      {0x1.1b17c74cb26e9p+0, -0x1.9c0c3e7288000p-4},
      {0x1.19e010c2c1ab6p+0, -0x1.8a646b372c000p-4},
      {0x1.18ab07bb670bdp+0, -0x1.78d01b3ac0000p-4},
      {0x1.1778a25efbcb6p+0, -0x1.674f145380000p-4},
      {0x1.1648d354c31dap+0, -0x1.55e0e6d878000p-4},
      {0x1.151b990275fddp+0, -0x1.4485cdea1e000p-4},
      {0x1.13f0ea432d24cp+0, -0x1.333d94d6aa000p-4},
      {0x1.12c8b7210f9dap+0, -0x1.22079f8c56000p-4},
      {0x1.11a3028ecb531p+0, -0x1.10e4698622000p-4},
      {0x1.107fbda8434afp+0, -0x1.ffa6c6ad20000p-5},
      {0x1.0f5ee0f4e6bb3p+0, -0x1.dda8d4a774000p-5},
      {0x1.0e4065d2a9fcep+0, -0x1.bbcece4850000p-5},
      {0x1.0d244632ca521p+0, -0x1.9a1894012c000p-5},
      {0x1.0c0a77ce2981ap+0, -0x1.788583302c000p-5},
      {0x1.0af2f83c636d1p+0, -0x1.5715e67d68000p-5},
      {0x1.09ddb98a01339p+0, -0x1.35c8a49658000p-5},
      {0x1.08cabaf52e7dfp+0, -0x1.149e364154000p-5},
      {0x1.07b9f2f4e28fbp+0, -0x1.e72c082eb8000p-6},
      {0x1.06ab58c358f19p+0, -0x1.a55f152528000p-6},
      {0x1.059eea5ecf92cp+0, -0x1.63d62cf818000p-6},
      {0x1.04949cdd12c90p+0, -0x1.228fb8caa0000p-6},
      {0x1.038c6c6f0ada9p+0, -0x1.c317b20f90000p-7},
      {0x1.02865137932a9p+0, -0x1.419355daa0000p-7},
      {0x1.0182427ea7348p+0, -0x1.81203c2ec0000p-8},
      {0x1.008040614b195p+0, -0x1.0040979240000p-9},
      {0x1.fe01ff726fa1ap-1, 0x1.feff384900000p-9},
      {0x1.fa11cc261ea74p-1, 0x1.7dc41353d0000p-7},
      {0x1.f6310b081992ep-1, 0x1.3cea3c4c28000p-6},
      {0x1.f25f63ceeadcdp-1, 0x1.b9fc114890000p-6},
      {0x1.ee9c8039113e7p-1, 0x1.1b0d8ce110000p-5},
      {0x1.eae8078cbb1abp-1, 0x1.58a5bd001c000p-5},
      {0x1.e741aa29d0c9bp-1, 0x1.95c8340d88000p-5},
      {0x1.e3a91830a99b5p-1, 0x1.d276aef578000p-5},
      {0x1.e01e009609a56p-1, 0x1.07598e598c000p-4},
      {0x1.dca01e577bb98p-1, 0x1.253f5e30d2000p-4},
      {0x1.d92f20b7c9103p-1, 0x1.42edd8b380000p-4},
      {0x1.d5cac66fb5ccep-1, 0x1.606598757c000p-4},
      {0x1.d272caa5ede9dp-1, 0x1.7da76356a0000p-4},
      {0x1.cf26e3e6b2ccdp-1, 0x1.9ab434e1c6000p-4},
      {0x1.cbe6da2a77902p-1, 0x1.b78c7bb0d6000p-4},
      {0x1.c8b266d37086dp-1, 0x1.d431332e72000p-4},
      {0x1.c5894bd5d5804p-1, 0x1.f0a3171de6000p-4},
      {0x1.c26b533bb9f8cp-1, 0x1.067152b914000p-3},
      {0x1.bf583eeece73fp-1, 0x1.147858292b000p-3},
      {0x1.bc4fd75db96c1p-1, 0x1.2266ecdca3000p-3},
      {0x1.b951e0c864a28p-1, 0x1.303d7a6c55000p-3},
      {0x1.b65e2c5ef3e2cp-1, 0x1.3dfc33c331000p-3},
      {0x1.b374867c9888bp-1, 0x1.4ba366b7a8000p-3},
      {0x1.b094b211d304ap-1, 0x1.5933928d1f000p-3},
      {0x1.adbe885f2ef7ep-1, 0x1.66acd2418f000p-3},
      {0x1.aaf1d31603da2p-1, 0x1.740f8ec669000p-3},
      {0x1.a82e63fd358a7p-1, 0x1.815c0f51af000p-3},
      {0x1.a5740ef09738bp-1, 0x1.8e92954f68000p-3},
      {0x1.a2c2a90ab4b27p-1, 0x1.9bb3602f84000p-3},
      {0x1.a01a01393f2d1p-1, 0x1.a8bed1c2c0000p-3},
      {0x1.9d79f24db3c1bp-1, 0x1.b5b515c01d000p-3},
      {0x1.9ae2505c7b190p-1, 0x1.c2967ccbcc000p-3},
      {0x1.9852ef297ce2fp-1, 0x1.cf635d5486000p-3},
      {0x1.95cbaeea44b75p-1, 0x1.dc1bd3446c000p-3},
      {0x1.934c69de74838p-1, 0x1.e8c01b8cfe000p-3},
      {0x1.90d4f2f6752e6p-1, 0x1.f5509c0179000p-3},
      {0x1.8e6528effd79dp-1, 0x1.00e6c121fb800p-2},
      {0x1.8bfce9fcc007cp-1, 0x1.071b80e93d000p-2},
      {0x1.899c0dabec30ep-1, 0x1.0d46b9e867000p-2},
      {0x1.87427aa2317fbp-1, 0x1.13687334bd000p-2},
      {0x1.84f00acb39a08p-1, 0x1.1980d67234800p-2},
      {0x1.82a49e8653e55p-1, 0x1.1f8ffe0cc8000p-2},
      {0x1.8060195f40260p-1, 0x1.2595fd7636800p-2},
      {0x1.7e22563e0a329p-1, 0x1.2b9300914a800p-2},
      {0x1.7beb377dcb5adp-1, 0x1.3187210436000p-2},
      {0x1.79baa679725c2p-1, 0x1.377266dec1800p-2},
      {0x1.77907f2170657p-1, 0x1.3d54ffbaf3000p-2},
      {0x1.756cadbd6130cp-1, 0x1.432eee32fe000p-2},
    };
    constexpr SLogEntry kLogTable2[kLogTableSize] = {
      {0x1.61000014fb66bp-1, 0x1.e026c91425b3cp-56},
      {0x1.63000034db495p-1, 0x1.dbfea48005d41p-55},
      {0x1.650000d94d478p-1, 0x1.e7fa786d6a5b7p-55},
      {0x1.67000074e6fadp-1, 0x1.1fcea6b54254cp-57},
      {0x1.68ffffedf0faep-1, -0x1.c7e274c590efdp-56},
      {0x1.6b0000763c5bcp-1, -0x1.ac16848dcda01p-55},
      {0x1.6d0001e5cc1f6p-1, 0x1.33f1c9d499311p-55},
      {0x1.6efffeb05f63ep-1, -0x1.e80041ae22d53p-56},
      {0x1.710000e86978p-1, 0x1.bff6671097952p-56},
      {0x1.72ffffc67e912p-1, 0x1.c00e226bd8724p-55},
      {0x1.74fffdf81116ap-1, -0x1.e02916ef101d2p-57},
      {0x1.770000f679c9p-1, -0x1.7fc71cd549c74p-57},
      {0x1.78ffffa7ec835p-1, 0x1.1bec19ef50483p-55},
      {0x1.7affffe20c2e6p-1, -0x1.07e1729cc6465p-56},
      {0x1.7cfffed3fc9p-1, -0x1.08072087b8b1cp-55},
      {0x1.7efffe9261a76p-1, 0x1.dc0286d9df9aep-55},
      {0x1.81000049ca3e8p-1, 0x1.97fd251e54c33p-55},
      {0x1.8300017932c8fp-1, -0x1.afee9b630f381p-55},
      {0x1.850000633739cp-1, 0x1.9bfbf6b6535bcp-55},
      {0x1.87000204289c6p-1, -0x1.bbf65f3117b75p-55},
      {0x1.88fffebf57904p-1, -0x1.9006ea23dcb57p-55},
      {0x1.8b00022bc04dfp-1, -0x1.d00df38e04b0ap-56},
      {0x1.8cfffe50c1b8ap-1, -0x1.8007146ff9f05p-55},
      {0x1.8effffc918e43p-1, 0x1.3817bd07a7038p-55},
      {0x1.910001efa5fc7p-1, 0x1.93e9176dfb403p-55},
      {0x1.9300013467bb9p-1, 0x1.f804e4b980276p-56},
      {0x1.94fffe6ee076fp-1, -0x1.f7ef0d9ff622ep-55},
      {0x1.96fffde3c12d1p-1, -0x1.082aa962638bap-56},
      {0x1.98ffff4458a0dp-1, -0x1.7801b9164a8efp-55},
      {0x1.9afffdd982e3ep-1, -0x1.740e08a5a9337p-55},
      {0x1.9cfffed49fb66p-1, 0x1.fce08c19bep-60},
      {0x1.9f00020f19c51p-1, -0x1.a3faa27885b0ap-55},
      {0x1.a10001145b006p-1, 0x1.4ff489958da56p-56},
      {0x1.a300007bbf6fap-1, 0x1.cbeab8a2b6d18p-55},
      {0x1.a500010971d79p-1, 0x1.8fecadd78793p-55},
      {0x1.a70001df52e48p-1, -0x1.f41763dd8abdbp-55},
      {0x1.a90001c593352p-1, -0x1.ebf0284c27612p-55},
      {0x1.ab0002a4f3e4bp-1, -0x1.9fd043cff3f5fp-57},
      {0x1.acfffd7ae1ed1p-1, -0x1.23ee7129070b4p-55},
      {0x1.aefffee510478p-1, 0x1.a063ee00edea3p-57},
      {0x1.b0fffdb650d5bp-1, 0x1.a06c8381f0ab9p-58},
      {0x1.b2ffffeaaca57p-1, -0x1.9011e74233c1dp-56},
      {0x1.b4fffd995badcp-1, -0x1.9ff1068862a9fp-56},
      {0x1.b7000249e659cp-1, 0x1.aff45d0864f3ep-55},
      {0x1.b8ffff987164p-1, 0x1.cfe7796c2c3f9p-56},
      {0x1.bafffd204cb4fp-1, -0x1.3ff27eef22bc4p-57},
      {0x1.bcfffd2415c45p-1, -0x1.cffb7ee3bea21p-57},
      {0x1.beffff86309dfp-1, -0x1.14103972e0b5cp-55},
      {0x1.c0fffe1b57653p-1, 0x1.bc16494b76a19p-55},
      {0x1.c2ffff1fa57e3p-1, -0x1.4feef8d30c6edp-57},
      {0x1.c4fffdcbfe424p-1, -0x1.43f68bcec4775p-55},
      {0x1.c6fffed54b9f7p-1, 0x1.47ea3f053e0ecp-55},
      {0x1.c8fffeb998fd5p-1, 0x1.383068df992f1p-56},
      {0x1.cb0002125219ap-1, -0x1.8fd8e64180e04p-57},
      {0x1.ccfffdd94469cp-1, 0x1.e7ebe1cc7ea72p-55},
      {0x1.cefffeafdc476p-1, 0x1.ebe39ad9f88fep-55},
      {0x1.d1000169af82bp-1, 0x1.57d91a8b95a71p-56},
      {0x1.d30000d0ff71dp-1, 0x1.9c1906970c7dap-55},
      {0x1.d4fffea790fc4p-1, -0x1.80e37c558fe0cp-58},
      {0x1.d70002edc87e5p-1, -0x1.f80d64dc10f44p-56},
      {0x1.d900021dc82aap-1, -0x1.47c8f94fd5c5cp-56},
      {0x1.dafffd86b0283p-1, 0x1.c7f1dc521617ep-55},
      {0x1.dd000296c4739p-1, 0x1.8019eb2ffb153p-55},
      {0x1.defffe54490f5p-1, 0x1.e00d2c652cc89p-57},
      {0x1.e0fffcdabf694p-1, -0x1.f8340202d69d2p-56},
      {0x1.e2fffdb52c8ddp-1, 0x1.b00c1ca1b0864p-56},
      {0x1.e4ffff24216efp-1, 0x1.2ffa8b094ab51p-56},
      {0x1.e6fffe88a5e11p-1, -0x1.7f673b1efbe59p-58},
      {0x1.e9000119eff0dp-1, -0x1.4808d5e0bc801p-55},
      {0x1.eafffdfa51744p-1, 0x1.80006d54320b5p-56},
      {0x1.ed0001a127fa1p-1, -0x1.002f860565c92p-58},
      {0x1.ef00007babcc4p-1, -0x1.540445d35e611p-55},
      {0x1.f0ffff57a8d02p-1, -0x1.ffb3139ef9105p-59},
      {0x1.f30001ee58ac7p-1, 0x1.a81acf2731155p-55},
      {0x1.f4ffff5823494p-1, 0x1.a3f41d4d7c743p-55},
      {0x1.f6ffffca94c6bp-1, -0x1.202f41c987875p-57},
      {0x1.f8fffe1f9c441p-1, 0x1.77dd1f477e74bp-56},
      {0x1.fafffd2e0e37ep-1, -0x1.f01199a7ca331p-57},
      {0x1.fd0001c77e49ep-1, 0x1.181ee4bceacb1p-56},
      {0x1.feffff7e0c331p-1, -0x1.e05370170875ap-57},
      {0x1.00ffff465606ep+0, -0x1.a7ead491c0adap-55},
      {0x1.02ffff3867a58p+0, -0x1.77f69c3fcb2ep-54},
      {0x1.04ffffdfc0d17p+0, 0x1.7bffe34cb945bp-54},
      {0x1.0700003cd4d82p+0, 0x1.20083c0e456cbp-55},
      {0x1.08ffff9f2cbe8p+0, -0x1.dffdfbe37751ap-57},
      {0x1.0b000010cda65p+0, -0x1.13f7faee626ebp-54},
      {0x1.0d00001a4d338p+0, 0x1.07dfa79489ff7p-55},
      {0x1.0effffadafdfdp+0, -0x1.7040570d66bcp-56},
      {0x1.110000bbafd96p+0, 0x1.e80d4846d0b62p-55},
      {0x1.12ffffae5f45dp+0, 0x1.dbffa64fd36efp-54},
      {0x1.150000dd59ad9p+0, 0x1.a0077701250aep-54},
      {0x1.170000f21559ap+0, 0x1.dfdf9e2e3deeep-55},
      {0x1.18ffffc275426p+0, 0x1.10030dc3b7273p-54},
      {0x1.1b000123d3c59p+0, 0x1.97f7980030188p-54},
      {0x1.1cffff8299eb7p+0, -0x1.5f932ab9f8c67p-57},
      {0x1.1effff48ad4p+0, 0x1.37fbf9da75bebp-54},
      {0x1.210000c8b86a4p+0, 0x1.f806b91fd5b22p-54},
      {0x1.2300003854303p+0, 0x1.3ffc2eb9fbf33p-54},
      {0x1.24fffffbcf684p+0, 0x1.601e77e2e2e72p-56},
      {0x1.26ffff52921d9p+0, 0x1.ffcbb767f0c61p-56},
      {0x1.2900014933a3cp+0, -0x1.202ca3c02412bp-56},
      {0x1.2b00014556313p+0, -0x1.2808233f21f02p-54},
      {0x1.2cfffebfe523bp+0, -0x1.8ff7e384fdcf2p-55},
      {0x1.2f0000bb8ad96p+0, -0x1.5ff51503041c5p-55},
      {0x1.30ffffb7ae2afp+0, -0x1.10071885e289dp-55},
      {0x1.32ffffeac5f7fp+0, -0x1.1ff5d3fb7b715p-54},
      {0x1.350000ca66756p+0, 0x1.57f82228b82bdp-54},
      {0x1.3700011fbf721p+0, 0x1.000bac40dd5ccp-55},
      {0x1.38ffff9592fb9p+0, -0x1.43f9d2db2a751p-54},
      {0x1.3b00004ddd242p+0, 0x1.57f6b707638e1p-55},
      {0x1.3cffff5b2c957p+0, 0x1.a023a10bf1231p-56},
      {0x1.3efffeab0b418p+0, 0x1.87f6d66b152bp-54},
      {0x1.410001532aff4p+0, 0x1.7f8375f198524p-57},
      {0x1.4300017478b29p+0, 0x1.301e672dc5143p-55},
      {0x1.44fffe795b463p+0, 0x1.9ff69b8b2895ap-55},
      {0x1.46fffe80475ep+0, -0x1.5c0b19bc2f254p-54},
      {0x1.48fffef6fc1e7p+0, 0x1.b4009f23a2a72p-54},
      {0x1.4afffe5bea704p+0, -0x1.4ffb7bf0d7d45p-54},
      {0x1.4d000171027dep+0, -0x1.9c06471dc6a3dp-54},
      {0x1.4f0000ff03ee2p+0, 0x1.77f890b85531cp-54},
      {0x1.5100012dc4bd1p+0, 0x1.004657166a436p-57},
      {0x1.530001605277ap+0, -0x1.6bfcece233209p-54},
      {0x1.54fffecdb704cp+0, -0x1.902720505a1d7p-55},
      {0x1.56fffef5f54a9p+0, 0x1.bbfe60ec96412p-54},
      {0x1.5900017e61012p+0, 0x1.87ec581afef9p-55},
      {0x1.5b00003c93e92p+0, -0x1.f41080abf0ccp-54},
      {0x1.5d0001d4919bcp+0, -0x1.8812afb254729p-54},
      {0x1.5efffe7b87a89p+0, -0x1.47eb780ed6904p-54},
    };

    [[nodiscard]] std::uint32_t Top12(const double x) noexcept { return static_cast<std::uint32_t>(AsBits(x) >> 52); }

    /// exp's overflow and underflow ranges: `scale * (1 + tmp)` without an intermediate rounding
    /// past the exponent range. `ki`'s sign says which side (musl's specialcase).
    [[nodiscard]] double ExpSpecialCase(const double tmp, std::uint64_t sbits, const std::uint64_t ki) noexcept
    {
      if ((ki & 0x80000000u) == 0) {
        // k > 0: the exponent of scale might have overflowed by <= 460.
        sbits -= 1009ull << 52;
        const double scale = AsDouble(sbits);
        return 0x1p1009 * (scale + scale * tmp);
      }
      // k < 0: special care in the subnormal range.
      sbits += 1022ull << 52;
      const double scale = AsDouble(sbits);
      double y = scale + scale * tmp;
      if (y < 1.0) {
        // Round y to the right precision before scaling it into the subnormal range, to avoid
        // the double rounding.
        double lo = scale - y + scale * tmp;
        const double hi = 1.0 + y;
        lo = 1.0 - hi + y + lo;
        y = (hi + lo) - 1.0;
        if (y == 0.0) {
          y = 0.0; // no -0.0 under downward rounding
        }
      }
      return 0x1p-1022 * y;
    }
  } // namespace

  double exp(const double x) noexcept
  {
    std::uint32_t abstop = Top12(x) & 0x7ffu;
    if (abstop - Top12(0x1p-54) >= Top12(512.0) - Top12(0x1p-54)) {
      if (abstop - Top12(0x1p-54) >= 0x80000000u) {
        return 1.0 + x; // tiny x; 0 is a common input
      }
      if (abstop >= Top12(1024.0)) {
        if (AsBits(x) == AsBits(-std::numeric_limits<double>::infinity())) {
          return 0.0;
        }
        if (abstop >= Top12(std::numeric_limits<double>::infinity())) {
          return 1.0 + x; // +inf, NaN
        }
        return (AsBits(x) >> 63) != 0 ? 0.0 : std::numeric_limits<double>::infinity();
      }
      abstop = 0; // large x: the special case below
    }

    // exp(x) = 2^(k/N) * exp(r), with exp(r) in [2^(-1/2N), 2^(1/2N)];
    // x = ln2/N*k + r, with int k and r in [-ln2/2N, ln2/2N].
    const double z = kInvLn2N * x;
    double kd = z + kShift;
    const std::uint64_t ki = AsBits(kd);
    kd -= kShift;
    const double r = x + kd * kNegLn2HiN + kd * kNegLn2LoN;
    // 2^(k/N) ~= scale * (1 + tail).
    const std::uint64_t idx = 2 * (ki % kExpTableSize);
    const std::uint64_t top = ki << (52 - kExpTableBits);
    const double tail = AsDouble(kExpTable[idx]);
    const std::uint64_t sbits = kExpTable[idx + 1] + top; // a valid scale when -1023*N < k < 1024*N
    // exp(x) = 2^(k/N) * exp(r) ~= scale + scale * (tail + exp(r) - 1).
    const double r2 = r * r;
    const double tmp = tail + r + r2 * (kExpPoly[0] + r * kExpPoly[1]) + r2 * r2 * (kExpPoly[2] + r * kExpPoly[3]);
    if (abstop == 0) {
      return ExpSpecialCase(tmp, sbits, ki);
    }
    const double scale = AsDouble(sbits);
    return scale + scale * tmp;
  }

  double log(const double x) noexcept
  {
    std::uint64_t ix = AsBits(x);
    const std::uint32_t top = static_cast<std::uint32_t>(ix >> 48);
    constexpr std::uint64_t kNearOneLow = std::bit_cast<std::uint64_t>(1.0 - 0x1p-4);
    constexpr std::uint64_t kNearOneHigh = std::bit_cast<std::uint64_t>(1.0 + 0x1.09p-4);
    if (ix - kNearOneLow < kNearOneHigh - kNearOneLow) {
      // Close to 1.0.
      if (ix == AsBits(1.0)) {
        return 0.0;
      }
      const double r = x - 1.0;
      const double r2 = r * r;
      const double r3 = r * r2;
      const double* const b = kLogPoly1;
      double y = r3 * (b[1] + r * b[2] + r2 * b[3] +
                       r3 * (b[4] + r * b[5] + r2 * b[6] + r3 * (b[7] + r * b[8] + r2 * b[9] + r3 * b[10])));
      // Worst-case error is around 0.507 ULP.
      double w = r * 0x1p27;
      const double rhi = r + w - w;
      const double rlo = r - rhi;
      w = rhi * rhi * b[0]; // b[0] == -0.5
      const double hi = r + w;
      double lo = r - hi + w;
      lo += b[0] * rlo * (rhi + r);
      y += lo;
      y += hi;
      return y;
    }
    if (top - 0x0010u >= 0x7ff0u - 0x0010u) {
      // x < 0x1p-1022, inf or NaN.
      if (ix * 2 == 0) {
        return -std::numeric_limits<double>::infinity();
      }
      if (ix == AsBits(std::numeric_limits<double>::infinity())) {
        return x;
      }
      if ((top & 0x8000u) != 0 || (top & 0x7ff0u) == 0x7ff0u) {
        return Invalid(x);
      }
      // Subnormal: normalize.
      ix = AsBits(x * 0x1p52);
      ix -= 52ull << 52;
    }

    // x = 2^k z, z in [OFF, 2*OFF) and exact; the range is split into N subintervals, the ith
    // holding z with c near its center.
    constexpr std::uint64_t kOff = 0x3fe6000000000000ull;
    const std::uint64_t tmp = ix - kOff;
    const int i = static_cast<int>((tmp >> (52 - kLogTableBits)) % kLogTableSize);
    const int k = static_cast<int>(static_cast<std::int64_t>(tmp) >> 52); // arithmetic shift
    const std::uint64_t iz = ix - (tmp & 0xfffull << 52);
    const double invc = kLogTable[i].first;
    const double logc = kLogTable[i].second;
    const double z = AsDouble(iz);

    // log(x) = log1p(z/c - 1) + log(c) + k*Ln2; r ~= z/c - 1, |r| < 1/(2*N). No fma: the
    // rounding error is 0x1p-55/N + 0x1p-66.
    const double r = (z - kLogTable2[i].first - kLogTable2[i].second) * invc;
    const double kd = static_cast<double>(k);

    // hi + lo = r + log(c) + k*Ln2.
    const double w = kd * kLn2Hi + logc;
    const double hi = w + r;
    const double lo = w - hi + r + kd * kLn2Lo;

    // log(x) = lo + (log1p(r) - r) + hi.
    const double r2 = r * r;
    const double* const a = kLogPoly;
    return lo + r2 * a[0] + r * r2 * (a[1] + r * a[2] + r2 * (a[3] + r * a[4])) + hi;
  }

  namespace
  {
    constexpr double kPio2Hi = 1.57079632679489655800e+00; // 0x3FF921FB, 0x54442D18
    constexpr double kPio2Lo = 6.12323399573676603587e-17; // 0x3C91A626, 0x33145C07
    // Coefficients of R(x^2), a rational approximation of (asin(x) - x) / x^3.
    constexpr double kPS0 = 1.66666666666666657415e-01;
    constexpr double kPS1 = -3.25565818622400915405e-01;
    constexpr double kPS2 = 2.01212532134862925881e-01;
    constexpr double kPS3 = -4.00555345006794114027e-02;
    constexpr double kPS4 = 7.91534994289814532176e-04;
    constexpr double kPS5 = 3.47933107596021167570e-05;
    constexpr double kQS1 = -2.40339491173441421878e+00;
    constexpr double kQS2 = 2.02094576023350569471e+00;
    constexpr double kQS3 = -6.88283971605453293030e-01;
    constexpr double kQS4 = 7.70381505559019352791e-02;

    [[nodiscard]] double AsinRational(const double z) noexcept
    {
      const double p = z * (kPS0 + z * (kPS1 + z * (kPS2 + z * (kPS3 + z * (kPS4 + z * kPS5)))));
      const double q = 1.0 + z * (kQS1 + z * (kQS2 + z * (kQS3 + z * kQS4)));
      return p / q;
    }
  } // namespace

  double asin(double x) noexcept
  {
    const std::uint32_t hx = static_cast<std::uint32_t>(AsBits(x) >> 32);
    const std::uint32_t ix = hx & 0x7fffffffu;
    if (ix >= 0x3ff00000u) {
      // |x| >= 1 or NaN.
      const std::uint32_t lx = static_cast<std::uint32_t>(AsBits(x));
      if (((ix - 0x3ff00000u) | lx) == 0) {
        return x * kPio2Hi + 0x1p-120f; // asin(+-1) = +-pi/2, inexact
      }
      return 0.0 / (x - x);
    }
    if (ix < 0x3fe00000u) {
      // |x| < 0.5; 0x1p-1022 <= |x| < 0x1p-26 returns x (no underflow).
      if (ix < 0x3e500000u && ix >= 0x00100000u) {
        return x;
      }
      return x + x * AsinRational(x * x);
    }
    // 1 > |x| >= 0.5.
    const double z = (1.0 - std::fabs(x)) * 0.5;
    const double s = Sqrt(z);
    const double r = AsinRational(z);
    if (ix >= 0x3fef3333u) {
      // |x| > 0.975.
      x = kPio2Hi - (2.0 * (s + s * r) - kPio2Lo);
    } else {
      // f + c = sqrt(z).
      const double f = AsDouble(AsBits(s) & 0xffffffff00000000ull);
      const double c = (z - f * f) / (s + f);
      x = 0.5 * kPio2Hi - (2.0 * s * r - (kPio2Lo - 2.0 * c) - (0.5 * kPio2Hi - 2.0 * f));
    }
    return (hx >> 31) != 0 ? -x : x;
  }
} // namespace msvc8::libm
