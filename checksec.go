package main

//#include "os_spec.h"
import "C"

import (
    "bytes"
    "debug/elf"
    "encoding/binary"
    "fmt"
    "io"
    "os"
)

const (
    DISABLED  = "Disabled"
    ENABLED   = "Enabled"
    PARTIAL   = "Partial"
    NX        = "NX"
    CANARY    = "CANARY"
    RELRO     = "RELRO"
    RPATH     = "RPATH"
    RUNPATH   = "RUNPATH"
    PIE       = "PIE"
    SEP       = ","
    STACK_CHK = "__stack_chk_fail"
)

func tagExists(file *elf.File, tag elf.DynTag) bool {

    section := file.Section(".dynamic")
    reader := io.NewSectionReader(section, 0, int64(section.Size))

    switch(file.Machine){

        case elf.EM_X86_64: 
            for {
                var entry elf.Dyn64
                if err := binary.Read(reader, binary.LittleEndian, &entry); err != io.EOF {
                    if elf.DynTag(entry.Tag) == tag {
                        return true
                    }
                } else {
                    break;
                }
            }

        case elf.EM_386:
            for {
                var entry elf.Dyn32
                if err := binary.Read(reader, binary.LittleEndian, &entry); err != io.EOF {
                    if elf.DynTag(entry.Tag) == tag {
                        return true
                    }
                } else {
                    break;
                }
            }
    }
    return false  
}

func nx(progs []*elf.Prog) string {

    rv := ENABLED
    for _, prog := range progs {

        if int64(prog.Type) == int64(C.GNU_STACK) {
            if prog.Flags&elf.PF_X == elf.PF_X {
                rv = DISABLED
            }
        }
    }
    return rv
}

func canary(file *elf.File) string {

    symbols, _ := file.Symbols()
    for _, sym := range symbols {
        if bytes.HasPrefix([]byte(sym.Name), []byte(STACK_CHK)) {
            return  ENABLED
        }
    }

    importedSymbols, _ := file.ImportedSymbols()
    for _, imp := range importedSymbols {
        if bytes.HasPrefix([]byte(imp.Name), []byte(STACK_CHK)) {
            return ENABLED
        }
    }

    return DISABLED 
}

func relro(file *elf.File) string {

    haveRelro   := false

    for _, prog := range file.Progs {
        if int64(prog.Type) == int64(C.GNU_RELRO) {
            haveRelro = true
            break
        }
    }

    if tagExists(file, elf.DT_BIND_NOW) && haveRelro {
        return ENABLED
    }

    if haveRelro {
        return PARTIAL
    }

    return DISABLED
}

func checksec(file *elf.File) {

    var status string

    // NX Enabled
    status = nx(file.Progs)
    fmt.Print(NX, "=", status, SEP)

    // Stack protection enabled
    status = canary(file)
    fmt.Print(CANARY, "=", status, SEP)

    // RELRO
    status = relro(file)
    fmt.Print(RELRO, "=", status, SEP)

    // PIE
    status = DISABLED
    if file.Type == elf.ET_DYN {
        status = ENABLED
    }
    fmt.Print(PIE, "=", status, SEP)

    // RPATH
    status = DISABLED
    if tagExists(file, elf.DT_RPATH) {
        status = ENABLED
    }
    fmt.Print(RPATH, "=", status, SEP)

    // RUNPATH
    status = DISABLED
    if tagExists(file, elf.DT_RUNPATH) {
        status = ENABLED
    }
    fmt.Print(RUNPATH, "=", status)
    fmt.Println()
}

func main() {

    // cat <bin> | ./a.out 
    if len(os.Args) == 1 {

        var buf bytes.Buffer
        if _, err := io.Copy(&buf, os.Stdin); err != nil {
            fmt.Println(err)
            os.Exit(1)
        }

        data := buf.Bytes()
        if len(data) > 0 {
            file, e := elf.NewFile(bytes.NewReader(data))
            if e != nil {
                fmt.Println("Not an ELF binary")
                os.Exit(1)
            }
            checksec(file)
        }

    // FILE [FILE]*
    } else {

        for _, arg := range os.Args[1:] {

            file, e := elf.Open(arg)
            if e != nil {
                fmt.Println(e)
                os.Exit(1)
            }
            checksec(file)
            file.Close()
        }
    }
}

