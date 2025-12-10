#!/bin/bash
set -e

DATE=$(date +%Y-%m-%d_%H%M)
OUTDIR="64kformat_${DATE}"
ARCHIVE="${OUTDIR}.7z"

rm -rf build
mkdir -p build
cd build
psp-cmake -DBUILD_PRX=1 -DENC_PRX=1 ..
make
cd ..

rm -rf "$OUTDIR"
mkdir -p "${OUTDIR}/PSP/GAME/64kformat"
cp build/EBOOT.PBP "${OUTDIR}/PSP/GAME/64kformat/"

rm -f "$ARCHIVE"
7z a "$ARCHIVE" "$OUTDIR"

echo "created: $ARCHIVE"
