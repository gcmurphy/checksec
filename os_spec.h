/* So you probably need this for things to work */ 
#ifndef os_spec_h
#define os_spec_h

#include <sys/types.h>
#include <elf.h>

int64_t GNU_RELRO = PT_GNU_RELRO;
int64_t GNU_STACK = PT_GNU_STACK;

#endif /* os_spec_h */

