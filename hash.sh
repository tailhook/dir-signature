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
    find ./ -type d | sort | while read dir; do
        echo "/${dir#./}"
        ls -1 "$dir" | sort | while read file; do
            if [ -L "$dir/$file" ]; then
                echo "  $file s $(readlink "$dir/$file")"
            elif [ -f "$dir/$file" ]; then
                size="$(stat "$dir/$file" --format %s)"
                echo -n "  $file f $size "
                for ((i = 0; i < size; i += BLOCK_SIZE)); do
                    dd if="$dir/$file" skip=$((i / BLOCK_SIZE)) bs=$BLOCK_SIZE count=1 status=none | $HASH_CMD
                done | cut -c1-$HASH_BYTES | tr '\n' ' '
                echo
            fi
        done
    done
} | tee -a /proc/self/fd/3 | $HASH_CMD | cut -c1-$HASH_BYTES)

echo $final_hash >> /proc/self/fd/3
