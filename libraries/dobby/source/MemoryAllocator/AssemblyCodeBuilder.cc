#include "MemoryAllocator/AssemblyCodeBuilder.h"

#include "dobby/dobby_internal.h"
#include "PlatformUnifiedInterface/CodePatchTool.h"

AssemblyCode *AssemblyCodeBuilder::FinalizeFromTurboAssembler(AssemblerBase *assembler) {
  auto buffer = (CodeBufferBase *)assembler->GetCodeBuffer();
  auto realized_addr = (addr_t)assembler->GetRealizedAddress();

  // Realize the buffer code to the executable memory address, remove the external label, etc
  std::memcpy((void *)realized_addr, buffer->GetBuffer(), buffer->GetBufferSize());

  auto block = new AssemblyCode(realized_addr, buffer->GetBufferSize());
  return block;
}