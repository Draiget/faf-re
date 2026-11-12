#!/bin/bash
# Packs the Linux download, faf-engine-<tag>-linux-x64.tar.gz, from a faf_client build made with the
# pinned toolchain (tools/linux/toolchain.sh --client, which also installs patchelf). The nightly's
# Linux job runs it; it runs as well in tools/linux/Dockerfile's image.
#
#   tools/release/linux/package.sh <build dir> <tag> <out dir>
#
# The download must run on glibc 2.34 (issue #394): the engine is checked to need nothing newer, and
# Microsoft's DXC libraries, built on glibc 2.38, get libfaf-glibc-compat.so (glibc_compat.c) and
# weak GLIBC_2.35+ requirements (elf_glibc_versions.py). The step fails when any file still needs a
# newer glibc, or when DXC needs a function from a newer glibc that the compat library lacks.
# tools/release/linux/check-package.sh then loads the result on several distributions.
set -euo pipefail

build="$1"
tag="$2"
out="$3"
glibc_max=2.34
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
llvm=/usr/lib/llvm-18/bin

stage="$(mktemp -d)/pkg"
mkdir -p "$stage" "$out"
install -m 0755 "$build/faf_client" "$stage/ForgedAlliance"
install -m 0755 "$root/dependencies/dxc-linux/lib/libdxcompiler.so" "$root/dependencies/dxc-linux/lib/libdxil.so" "$stage/"
cp -r "$root/data/fafengine" "$stage/"
install -m 0755 "$here/faf-launch" "$stage/faf-launch"
{ echo "FAF engine $tag (Linux x64), built $(date +%F)"; echo; cat "$root/tools/release/INSTALL_linux-x64.txt"; } > "$stage/INSTALL.txt"

# The engine itself must not need more than glibc 2.34.
python3 "$here/elf_glibc_versions.py" --max "$glibc_max" --report "$stage/ForgedAlliance"
"$llvm/llvm-readelf" -d "$stage/ForgedAlliance" | grep NEEDED

# DXC: its few newer glibc functions come from the compat library when glibc lacks them.
"$llvm/clang" -O2 -fPIC -shared -fno-builtin -Wall -Werror -Wl,-z,defs -Wl,--as-needed \
  -Wl,-soname,libfaf-glibc-compat.so -o "$stage/libfaf-glibc-compat.so" "$here/glibc_compat.c"
for lib in libdxcompiler.so libdxil.so; do
  patchelf --add-needed libfaf-glibc-compat.so "$stage/$lib"
  # The compat library sits next to them; a library loaded by path does not search there by itself.
  existing="$(patchelf --print-rpath "$stage/$lib")"
  patchelf --set-rpath "\$ORIGIN${existing:+:$existing}" "$stage/$lib"
done
python3 "$here/elf_glibc_versions.py" --max "$glibc_max" --weaken "$stage/libdxcompiler.so" "$stage/libdxil.so"
python3 "$here/elf_glibc_versions.py" --max "$glibc_max" --report \
  "$stage/libdxcompiler.so" "$stage/libdxil.so" "$stage/libfaf-glibc-compat.so"
# Every symbol bound to a weakened (newer) version must be one the compat library defines.
provided="$(nm -D --defined-only "$stage/libfaf-glibc-compat.so" | awk '{print $3}' | sort -u)"
for lib in libdxcompiler.so libdxil.so; do
  needed="$(objdump -T "$stage/$lib" | awk '/\*UND\*/ && /\(GLIBC_[0-9.]+\)/ {
      v = $0; sub(/.*\(GLIBC_/, "", v); sub(/\).*/, "", v); split(v, p, ".");
      if (p[1] > 2 || (p[1] == 2 && p[2] > 34)) print $NF }' | sort -u)"
  for symbol in $needed; do
    if ! grep -qx "$symbol" <<<"$provided"; then
      echo "package: $lib needs $symbol from a glibc newer than $glibc_max, and libfaf-glibc-compat.so lacks it" >&2
      exit 1
    fi
  done
  echo "$lib: $(wc -w <<<"$needed") symbols from glibc > $glibc_max, all in libfaf-glibc-compat.so: $(tr '\n' ' ' <<<"$needed")"
done

find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
chmod 0755 "$stage/ForgedAlliance" "$stage/faf-launch" "$stage"/*.so
tar --sort=name --owner=0 --group=0 --numeric-owner -czf "$out/faf-engine-$tag-linux-x64.tar.gz" -C "$stage" .
echo "package: $out/faf-engine-$tag-linux-x64.tar.gz"
