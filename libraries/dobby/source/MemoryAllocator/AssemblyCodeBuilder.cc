#include "MemoryAllocator/AssemblyCodeBuilder.h"

#include "dobby/dobby_internal.h"
#include "PlatformUnifiedInterface/ExecMemory/CodePatchTool.h"

AssemblyCode *AssemblyCodeBuilder::FinalizeFromTurboAssembler(AssemblerBase *assembler, void (*writer)(void*, void const*, size_t)) {
  auto buffer = (CodeBufferBase *)assembler->GetCodeBuffer();
  auto realized_addr = (addr_t)assembler->GetRealizedAddress();
#if defined(TEST_WITH_UNICORN)
  // impl: unicorn emulator map memory
  realized_addr = 0;
#endif
  if (!realized_addr) {
      return nullptr;
  }

  // Realize the buffer code to the executable memory address, remove the external label, etc
  (*writer)((void *)realized_addr, buffer->GetBuffer(), buffer->GetBufferSize());

  auto block = new AssemblyCode(realized_addr, buffer->GetBufferSize());
  return block;
}