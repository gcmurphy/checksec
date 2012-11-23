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

func dyn(section *elf.Section, tag elf.DynTag) *elf.Dyn64 {

    if section == nil {
        return nil;
    }

    var entry elf.Dyn64
    sectionReader := io.NewSectionReader(section, 0, int64(section.Size))
    for {

        err := binary.Read(sectionReader, binary.LittleEndian, &entry)
        if err != nil {
            if err != io.EOF {
                fmt.Println(err)
            }
            break
        }

        if elf.DynTag(entry.Tag) == tag {
            return &entry
        }
    }

    return nil
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

func relro(progs []*elf.Prog, dynamic *elf.Section) string {

    haveRelro   := false
    haveBindNow := false

    for _, prog := range progs {
        if int64(prog.Type) == int64(C.GNU_RELRO) {
            haveRelro = true
            break
        }
    }

    if dynamic != nil { 
        haveBindNow = (dyn(dynamic, elf.DT_BIND_NOW) != nil)
    }

    if haveBindNow && haveRelro {
        return ENABLED
    }

    if haveRelro {
        return PARTIAL
    }

    return DISABLED
}

func checksec(file *elf.File) {

    var status string
    dynamic := file.Section(".dynamic")

    // NX Enabled
    status = nx(file.Progs)
    fmt.Print(NX, "=", status, SEP)

    // Stack protection enabled
    status = canary(file)
    fmt.Print(CANARY, "=", status, SEP)

    // RELRO
    status = relro(file.Progs, dynamic)
    fmt.Print(RELRO, "=", status, SEP)

    // PIE
    status = DISABLED
    if file.Type == elf.ET_DYN {
        status = ENABLED
    }
    fmt.Print(PIE, "=", status, SEP)

    // RPATH
    status = DISABLED
    if rpath := dyn(dynamic, elf.DT_RPATH); rpath != nil {
        status = ENABLED
    }
    fmt.Print(RPATH, "=", status, SEP)

    // RUNPATH
    status = DISABLED
    if runpath := dyn(dynamic, elf.DT_RUNPATH); runpath != nil {
        status = ENABLED
    }
    fmt.Print(RUNPATH, "=", status)
    fmt.Println()
}

func main() {

    // cat <bin> | ./a.out 
    if len(os.Args) == 1 {

        var buf bytes.Buffer
        var kb [1024]byte
        for {

            nbytes, err := os.Stdin.Read(kb[:])
            if nbytes > 0 {
                buf.Write(kb[0:nbytes])
            }
            if err == io.EOF {
                break
            }
            if err != nil {
                fmt.Println(err)
                os.Exit(1)
            }
        }

        data := buf.Bytes()
        if len(data) > 0 {
            file, e := elf.NewFile(bytes.NewReader(data))
            if e != nil {
                fmt.Println(e)
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

