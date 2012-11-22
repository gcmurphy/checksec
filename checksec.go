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
    IS_GOOD   = "(good)"
    IS_OK     = "(alright)"
    IS_BAD    = "(bad)"
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

func dyn(s *elf.Section, tag elf.DynTag) *elf.Dyn64 {

    var entry elf.Dyn64
    sectionReader := io.NewSectionReader(s, 0, int64(s.Size))
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

func canary(symbols []elf.Symbol) string {

    rv := DISABLED
    for _, sym := range symbols {

        if bytes.HasPrefix([]byte(sym.Name), []byte(STACK_CHK)) {
            rv = ENABLED
            break
        }
    }
    return rv
}

func relro(progs []*elf.Prog, dynamic *elf.Section) string {

    haveRelro := false
    haveBindNow := false

    for _, prog := range progs {
        if int64(prog.Type) == int64(C.GNU_RELRO) {
            haveRelro = true
            break
        }
    }

    haveBindNow = (dyn(dynamic, elf.DT_BIND_NOW) != nil)

    if haveBindNow && haveRelro {
        return ENABLED
    }

    if haveRelro {
        return PARTIAL
    }

    return DISABLED

}

func printResult(expected, actual, name string) {

    fmt.Printf("%s=%s", name, actual)
    if expected != actual {

        if actual == PARTIAL {
            fmt.Print(IS_OK)

        } else {
            fmt.Print(IS_BAD)
        }

    } else {
        fmt.Print(IS_GOOD)
    }
}

func checksec(file *elf.File) {

    var status string

    dynamic := file.Section(".dynamic")
    symbols, _ := file.Symbols()

    // NX Enabled
    status = nx(file.Progs)
    printResult(ENABLED, status, NX)
    fmt.Print(SEP)

    // Stack protection enabled
    status = canary(symbols)
    printResult(ENABLED, status, CANARY)
    fmt.Print(SEP)

    // RELRO
    status = relro(file.Progs, dynamic)
    printResult(ENABLED, status, RELRO)
    fmt.Print(SEP)

    // PIE
    status = DISABLED
    if file.Type == elf.ET_DYN {
        status = ENABLED
    }
    printResult(ENABLED, status, PIE)
    fmt.Print(SEP)

    // RPATH
    status = DISABLED
    if rpath := dyn(dynamic, elf.DT_RPATH); rpath != nil {
        status = ENABLED
    }
    printResult(DISABLED, status, RPATH)
    fmt.Print(SEP)

    // RUNPATH
    status = DISABLED
    if runpath := dyn(dynamic, elf.DT_RUNPATH); runpath != nil {
        status = ENABLED
    }
    printResult(DISABLED, status, RUNPATH)
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

