"""Test the checked-out ZIP offset helper against a small stream mock.

This is a host-side source-body test, not a Windows or complete-engine test.
"""

import argparse
import hashlib
import subprocess
import tempfile
from pathlib import Path


def read_helper(source):
    marker = "bool ReadZipDirectory(gpg::Stream& stream, moho::CZipFileEntry& entry)"
    start = source.index(marker)
    end = source.index("{", start) + 1
    depth = 1
    while depth:
        if source[end] == "{":
            depth += 1
        elif source[end] == "}":
            depth -= 1
        end += 1
    return source[start:end]


parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument(
    "source",
    type=Path,
    nargs="?",
    default=Path(__file__).resolve().parents[2] / "src/moho/misc/CZipFile.cpp",
    help="Path to src/moho/misc/CZipFile.cpp",
)
parser.add_argument("--compiler", default="g++")
parser.add_argument("--ubsan", action="store_true")
args = parser.parse_args()
fn = read_helper(args.source.read_text())

pre=r'''
#include <bit>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cassert>
#include <limits>
#include <array>
#include <iostream>
constexpr std::uint32_t kInvalidZipOffset=0xffffffffU,kZipLocalFileHeaderMagic=0x04034b50U;
namespace moho {
#pragma pack(push,1)
struct SZipLocalFileHeader {std::uint32_t mSignature;std::uint16_t mVersionNeeded,mGeneralPurposeFlags,mCompressionMethod,mDosTime,mDosDate;std::uint32_t mCrc32,mCompressedSize,mUncompressedSize;std::uint16_t mFileNameLength,mExtraFieldLength;};
#pragma pack(pop)
struct CZipFileEntry {std::uint32_t mLocalHeaderOffset;std::int32_t mCachedDataOffset=-1;};
}
namespace gpg {
struct Stream {
 enum SeekOrigin {OriginBegin,OriginCurr};
 std::uint64_t pos=0,local=0;unsigned reads=0,seeks=0;std::int64_t lastSeek=-1;unsigned failRead=0;moho::SZipLocalFileHeader header{};
 explicit Stream(std::uint32_t at):local(at){header.mSignature=kZipLocalFileHeaderMagic;}
 std::uint64_t Seek(SeekOrigin origin,std::int64_t n){assert(n>=0);lastSeek=n;++seeks;pos=(origin==OriginBegin?0:pos)+static_cast<std::uint64_t>(n);return pos;}
 std::size_t Read(char* dst,std::size_t n){++reads;if(reads==failRead)return 0;assert(pos>=local);auto off=pos-local;assert(off+n<=sizeof(header));std::memcpy(dst,reinterpret_cast<const char*>(&header)+off,n);pos+=n;return n;}
};}
'''
tail=r'''
static unsigned cases=0;
static void cached(std::uint32_t bits){
 moho::CZipFileEntry e{0x123U,std::bit_cast<std::int32_t>(bits)};gpg::Stream s(0x123);assert(bits!=0xffffffffU);
 assert(ReadZipDirectory(s,e));assert(s.pos==bits&&s.lastSeek==static_cast<std::int64_t>(bits));assert(s.reads==0&&s.seeks==1);++cases;
}
static void fresh(std::uint32_t local,std::uint16_t name,std::uint16_t extra){
 moho::CZipFileEntry e{local,-1};gpg::Stream s(local);s.header.mFileNameLength=name;s.header.mExtraFieldLength=extra;
 auto expected=std::uint64_t(local)+sizeof(s.header)+name+extra;
 assert(ReadZipDirectory(s,e)&&s.pos==expected);assert(e.mLocalHeaderOffset==local);assert(s.reads==2);auto r=s.reads;
 if(expected<0xffffffffULL){assert(static_cast<std::uint32_t>(e.mCachedDataOffset)==expected);}else{assert(e.mCachedDataOffset==-1);}
 assert(ReadZipDirectory(s,e)&&s.pos==expected);
 assert(s.reads==(expected<0xffffffffULL?r:r+2));++cases;
}
int main(){
 static_assert(sizeof(std::int32_t)==sizeof(std::uint32_t));
 fresh(0x80000000U-30U,0,0);
 for(auto bits:std::array<std::uint32_t,9>{0U,1U,30U,0x7ffffffeU,0x7fffffffU,0x80000000U,0x80000001U,0xffffff00U,0xfffffffeU})cached(bits);
 for(auto target:std::array<std::uint64_t,9>{30ULL,0x7ffffffeULL,0x7fffffffULL,0x80000000ULL,0xffffff00ULL,0xfffffffeULL,0xffffffffULL,0x100000000ULL,0x100000001ULL})fresh(static_cast<std::uint32_t>(target-30),0,0);
 fresh(0xfffffffeU,65535,65535);fresh(0,65535,65535);
 std::uint32_t state=0x432195adU;
 for(unsigned i=0;i<200000;++i){state=state*1664525U+1013904223U;if(state!=0xffffffffU)cached(state);if(i<10000&&state!=0xffffffffU)fresh(state,static_cast<std::uint16_t>(state),static_cast<std::uint16_t>(state>>16));}
 for(unsigned fail=0;fail<=2;++fail){moho::CZipFileEntry e{0x80000000U,-1};gpg::Stream s(e.mLocalHeaderOffset);if(fail)s.failRead=fail;else s.header.mSignature=0;assert(!ReadZipDirectory(s,e));assert(e.mLocalHeaderOffset==0xffffffffU&&e.mCachedDataOffset==-1);auto reads=s.reads,seeks=s.seeks;assert(!ReadZipDirectory(s,e));assert(s.reads==reads&&s.seeks==seeks);++cases;}
 for(auto bits:std::array<std::uint32_t,3>{0U,0x80000000U,0xffffffffU}){moho::CZipFileEntry e{0xffffffffU,std::bit_cast<std::int32_t>(bits)};gpg::Stream s(0);assert(!ReadZipDirectory(s,e)&&s.reads==0&&s.seeks==0);++cases;}
 std::cout<<"PASS "<<cases<<" exact-body synthetic helper scenarios; pointer_width="<<8*sizeof(void*)<<"\n";
}
'''

with tempfile.TemporaryDirectory(prefix="zip-offset-test-") as directory:
    work = Path(directory)
    source_file = work / "boundary_test.cpp"
    executable = work / "boundary_test"
    source_file.write_text(pre + fn + tail)
    command = [args.compiler, "-std=c++20", "-O2", "-Wall", "-Wextra", "-Werror"]
    if args.ubsan:
        command.extend(["-fsanitize=undefined", "-fno-sanitize-recover=undefined"])
    command.extend([str(source_file), "-o", str(executable)])
    subprocess.run(command, check=True)
    subprocess.run([str(executable)], check=True)
    print("helper SHA-256:", hashlib.sha256(fn.encode()).hexdigest(), flush=True)
