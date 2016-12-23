#!/bin/sh -e

DIR=${1:-.}
: ${HASH_BITS:=256}
: ${HASH:=sha512}
: ${HASH_CMD:=${HASH}sum}
: ${HASH_BYTES:=$((HASH_BITS / 8 * 2))}
: ${BLOCK_SIZE:=32768}

echo "DIRSIGNATURE.v1 $HASH/$HASH_BITS block_size=$BLOCK_SIZE"

exec 3>&1
final_hash=$({
    cd $DIR
    find ./ -type d | tr '/' '\0' | LC_ALL=C sort | tr '\0' '/' | while read dir; do
        echo "/${dir#./}"
        ls -A1 "$dir" | LC_ALL=C sort | while read file; do
            if [ -L "$dir/$file" ]; then
                echo "  $file s $(readlink "$dir/$file")"
            elif [ -f "$dir/$file" ]; then
                size="$(stat "$dir/$file" --format %s)"
                if [ -x "$dir/$file" ]; then
                    echo -n "  $file x $size"
                else
                    echo -n "  $file f $size"
                fi
                for ((i = 0; i < size; i += BLOCK_SIZE)); do
                    dd if="$dir/$file" skip=$((i / BLOCK_SIZE)) bs=$BLOCK_SIZE count=1 status=none | $HASH_CMD
                done | cut -c1-$HASH_BYTES | tr '\n' ' ' | sed 's/ $//;s/^/ /'
                echo
            fi
        done
    done
} | tee -a /proc/self/fd/3 | $HASH_CMD | cut -c1-$HASH_BYTES)

echo $final_hash >> /proc/self/fd/3
