#!/bin/bash
# Produces a csv list of all executable files and the packages that they belong to 
# including the details of whether they have been built using security hardened
# options.

for file in "$@"; do
    for data in `rpm -qp --queryformat '[%{NAME} %{FILEMODES:perms} %{FILENAMES}\n]' $file | grep -E "^.* -..x..x..x " | awk '{ print sprintf("%s:%s", $1, $3)}'`; do

	split=`echo $data | sed -e 's/\:/ /'`
	set -- $split
        echo $2 | grep -E "/lib.*" >> /dev/null
        is_lib=$? 
        echo $2 | grep -E "/usr/share.*" >> /dev/null
        is_shared=$?
        if  test $is_shared -eq 1 && test $is_lib -eq 1 && test -x $2 && test -f $2; then 
            rv=`rpm2cpio $file | cpio --to-stdout -iv .$2 2>/dev/null | ./checksec`
            if test $? -eq 0; then 
                echo $(basename $file),$2,$rv
            fi
        fi
    done
done
