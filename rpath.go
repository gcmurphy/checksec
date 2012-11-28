package main

import "debug/elf"

func rpath(file *elf.File) string {

    if haveDynTag(file, elf.DT_RPATH) {
        return ENABLED
    }
    return DISABLED
}
