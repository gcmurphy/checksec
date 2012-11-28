package main

//#include <sys/types.h>
//#include <elf.h>
//int64_t GNU_STACK = PT_GNU_STACK;
import "C"
import "debug/elf"

func nx(file *elf.File) string {

    rv := ENABLED
    for _, prog := range file.Progs {

        if int64(prog.Type) == int64(C.GNU_STACK) {
            if prog.Flags&elf.PF_X == elf.PF_X {
                rv = DISABLED
            }
        }
    }
    return rv
}
