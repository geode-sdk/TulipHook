#include "dobby/dobby_internal.h"

void GenRelocateCode(void *buffer, void* relocated_mem, CodeMemBlock *origin, CodeMemBlock *relocated, bool branch);

void GenRelocateCodeAndBranch(void *buffer, void* relocated_mem, CodeMemBlock *origin, CodeMemBlock *relocated);
