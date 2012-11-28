package main

import (
    "debug/elf"
    "encoding/binary"
    "io"
)

func haveDynTag(file *elf.File, tag elf.DynTag) bool {

    if section := file.Section(".dynamic"); section != nil {

        reader := io.NewSectionReader(section, 0, int64(section.Size))
        switch file.Machine {

        case elf.EM_X86_64:
            for {
                var entry elf.Dyn64
                if err := binary.Read(reader, binary.LittleEndian, &entry); err != io.EOF {
                    if elf.DynTag(entry.Tag) == tag {
                        return true
                    }
                } else {
                    break
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
                    break
                }
            }
        }
    }
    return false
}
