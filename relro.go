package main

//#include <sys/types.h>
//#include <elf.h>
//int64_t GNU_RELRO = PT_GNU_RELRO;
import "C"
import "debug/elf"

func relro(file *elf.File) string {

    haveRelro := false

    for _, prog := range file.Progs {
        if int64(prog.Type) == int64(C.GNU_RELRO) {
            haveRelro = true
            break
        }
    }

    if haveDynTag(file, elf.DT_BIND_NOW) && haveRelro {
        return ENABLED
    }

    if haveRelro {
        return PARTIAL
    }
    return DISABLED

}
