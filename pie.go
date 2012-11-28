package main

import "debug/elf"

func pie(file *elf.File) string {

    if file.Type == elf.ET_DYN {
        return ENABLED
    }
    return DISABLED
}
