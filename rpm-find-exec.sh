#!/bin/bash
# Produces a csv list of all executable files and the packages that they belong to 
# including the details of whether they have been built using security hardened
# options.

for file in "$@"; do
    for data in `rpm -qp --queryformat '[%{NAME} %{FILEMODES:perms} %{FILENAMES}\n]' $file | grep -E "^.* -..x..x..x " | awk '{ print sprintf("%s:%s", $1, $3)}'| grep -v lib`; do

        split=`echo $data | sed -e 's/\:/ /'`
        set -- $split
        rv=`rpm2cpio $file | cpio --to-stdout -iv .$2 2>/dev/null | ./checksec`
        if test $? -eq 0; then 
            echo $(basename $file),$2,$rv
        fi
    done
done
