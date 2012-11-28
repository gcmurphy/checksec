package main

import (
    "bytes"
    "debug/elf"
    "fmt"
    "io"
    "os"
)

const (
    INVALID  = "Not an ELF binary"
    DISABLED = "Disabled"
    ENABLED  = "Enabled"
    PARTIAL  = "Partial"
    SEP      = ","
)

type checker func(file *elf.File) string

var checks = []struct {
    name string
    run  checker
}{
    {"NX", nx},
    {"CANARY", canary},
    {"RELRO", relro},
    {"PIE", pie},
    {"RPATH", rpath},
    {"RUNPATH", runpath},
}

func checksec(file *elf.File) {

    for n, check := range checks {
        fmt.Print(check.name, "=", check.run(file))
        if n < len(checks)-1 {
            fmt.Print(SEP)
        }
    }
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
                fmt.Println(INVALID)
                os.Exit(1)
            }
            checksec(file)
        }

        // FILE [FILE]*
    } else {

        for _, arg := range os.Args[1:] {

            file, e := elf.Open(arg)
            if e != nil {
                fmt.Printf("%s,%s\n", arg, INVALID)

            } else {
                fmt.Print(arg, SEP)
                checksec(file)
                file.Close()
            }
        }
    }
}
