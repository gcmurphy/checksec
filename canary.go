package main

import (
    "bytes"
    "debug/elf"
)

const STACK_CHK = "__stack_chk_fail"

func canary(file *elf.File) string {

    if symbols, e := file.Symbols(); e == nil {
        for _, sym := range symbols {
            if bytes.HasPrefix([]byte(sym.Name), []byte(STACK_CHK)) {
                return ENABLED
            }
        }
    }

    if importedSymbols, e := file.ImportedSymbols(); e == nil {
        for _, imp := range importedSymbols {
            if bytes.HasPrefix([]byte(imp.Name), []byte(STACK_CHK)) {
                return ENABLED
            }
        }
    }

    return DISABLED
}
