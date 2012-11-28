package main

import "debug/elf"

func runpath(file *elf.File) string {

    if haveDynTag(file, elf.DT_RUNPATH) {
        return ENABLED
    }
    return DISABLED
}
