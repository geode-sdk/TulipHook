#include "dobby/dobby_internal.h"

void GenRelocateCode(void *buffer, void* relocated_mem, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch, void (*writer)(void*, void const*, size_t));

void GenRelocateCodeAndBranch(void *buffer, void* relocated_mem, CodeMemBlock *origin, CodeMemBlock *relocated, void (*writer)(void*, void const*, size_t));
