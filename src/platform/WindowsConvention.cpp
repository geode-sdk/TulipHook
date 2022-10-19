#include <platform/WindowsConvention.hpp>
#include <Platform.hpp>
#include <AbstractFunction.hpp>
#include <sstream>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

/**
 * Get stack size for function (divided by 4)
 * This assumes all parameters are pushed through stack, subtract if some 
 * are passed through ecx or other instead
 * @returns Stack size (divided by 4)
 */
static size_t stackSizeFromFunction(
	AbstractFunction const& function,
	bool floatsThroughXmm = false
) {
	size_t size = 0;
	size_t paramCount = 0;
	// on x86, returning structs over the size of 8 causes a pointer 
	// to the struct to be pushed as the first parameter through the 
	// stack
	if (function.m_return.m_size > 4 * 2) {
		size += 1;
		paramCount += 1;
	}
	for (auto& param : function.m_parameters) {
		// in some cconvs floats 0..3 are passed through xmm0..xmm3
		if (
			floatsThroughXmm &&
			param.m_kind == AbstractTypeKind::FloatingPoint &&
			paramCount < 4
		) {
			paramCount += 1;
			continue;
		}
		// C++ integer division is rounded down, so for example 
		// (1 + 3) / 4 = 1
		// (4 + 3) / 4 = 4
		// (8 + 3) / 4 = 8
		size += (param.m_size + 3) / 4;
		paramCount += 1;
	}
	return size;
}

static bool registerPassable(AbstractFunction const& function, size_t paramIndex) {
	if (paramIndex < function.m_parameters.size()) {
		return function.m_parameters.at(paramIndex).m_kind == AbstractTypeKind::Primitive;
	}
	return false;
}

static void pushParameter(std::ostringstream& out, size_t paramSize, size_t at) {
	// all struct members need to be pushed separately
	// push adds 4 to esp so we use the same offset for all of them
	for (auto i = 0; i < (paramSize + 3) / 4; i++) {
		out << "push [esp + " << at << "]; ";
	}
}

std::string CdeclConvention::generateFromDefault(AbstractFunction const& function) {
	// it's the same conv as default
	return "ret 0";
}
std::string CdeclConvention::generateToDefault(AbstractFunction const& function) {
	// it's the same conv as default
	return "";
}
CdeclConvention::~CdeclConvention() {}

std::string ThiscallConvention::generateFromDefault(AbstractFunction const& function) {
	std::ostringstream out;

	// stack size (divided by 4)
	auto size = stackSizeFromFunction(function);

	// clean up stack from the ones we added
	out << "add esp, " << (size * 4) << "; ";
	// `this` is originally in ecx, so 
	out << "ret " << ((size - 1) * 4);

	return out.str();
}
std::string ThiscallConvention::generateToDefault(AbstractFunction const& function) {
	std::ostringstream out;

	// stack size (divided by 4)
	auto size = stackSizeFromFunction(function);

	// Class::memberFun(this, int, int, int)
	// ecx    <= this
	// 0x4    <= first
	// 0x8    <= second
	// 0xc    <= third
	// converted with
	// push [esp + 0xc]   third
	// push [esp + 0xc]   second
	// push [esp + 0xc]   first
	// push ecx           this

	// repush parameters in same order as pushed
	for (auto i = 1; i < size; i++) {
		out << "push [esp + " << ((size - 1) * 4) << "]; ";
	}
	// the first parameter in __thiscall is always going to be ecx-passable
	// push `this`
	if (size > 0) out << "push ecx ";

	return out.str();
}
ThiscallConvention::~ThiscallConvention() {}

std::string FastcallConvention::generateFromDefault(AbstractFunction const& function) {
	std::ostringstream out;
	
	// stack size (divided by 4)
	auto size = stackSizeFromFunction(function);

	size_t registerCount = 0;

	// first two parameters that can go in ecx and edx go in ecx 
	for (auto& param : function.m_parameters) {
		if (registerCount < 2 && param.m_kind == AbstractTypeKind::Primitive) {
			registerCount += 1;
		}
	}

	// clean up stack from the ones we added
	out << "add esp, " << (size * 4) << "; ";
	// some of the original parameters may be passed through ecx and edx so the 
	// original's stack size may be smaller
	out << "ret " << ((size - registerCount) * 4);

	return out.str();
}
std::string FastcallConvention::generateToDefault(AbstractFunction const& function) {
	std::ostringstream out;

	// stack size (divided by 4)
	auto size = stackSizeFromFunction(function);

	size_t registerCount = 0;

	// first two parameters that can go in ecx and edx go in ecx 
	for (auto& param : function.m_parameters) {
		if (registerCount < 2 && param.m_kind == AbstractTypeKind::Primitive) {
			registerCount += 1;
		}
	}

	// struct Big { int x; int y; int z; }
	// test3(Big, int, float, int, float)
	// 0x4                  <= Big.x
	// 0x8                  <= Big.y
	// 0xc                  <= Big.z
	// ecx                  <= int
	// 0x10                 <= float
	// edx                  <= int
	// 0x14                 <= float
	// 
	// stackSizeFromFunction = 0x1c
	// ----------------------------- offset before / after
	// push [esp + 0x14]    <= float        0x0      0x4
	// push edx             <= int          0x4      0x8
	// push [esp + 0x18]    <= float        0x8      0xc
	// push ecx             <= int          0xc      0x10
	// push [esp + 0x1c]    <= Big.z        0x10     0x14
	// push [esp + 0x1c]    <= Big.y        0x14     0x18
	// push [esp + 0x1c]    <= Big.x        0x18     0x1c

	// repush parameters
	for (auto& param : function.m_parameters) {
		if (registerCount && param.m_kind == AbstractTypeKind::Primitive) {
			if (registerCount == 2) out << "push edx; ";
			if (registerCount == 1) out << "push ecx; ";
			registerCount--;
		} else {
			pushParameter(out, param.m_size, (size - registerCount) * 4);
		}
	}

	return out.str();
}
FastcallConvention::~FastcallConvention() {}

std::string OptcallConvention::generateFromDefault(AbstractFunction const& function) {
	return "";
}
std::string OptcallConvention::generateToDefault(AbstractFunction const& function) {
	// __optcall is like __fastcall, except parameters 0..3 are 
	// passed through xmm0..xmm3 if they are floating-point and 
	// structs are all passed last
	return "";
}
OptcallConvention::~OptcallConvention() {}

std::string MembercallConvention::generateFromDefault(AbstractFunction const& function) {
	return "";
}
std::string MembercallConvention::generateToDefault(AbstractFunction const& function) {
	return "";
}
MembercallConvention::~MembercallConvention() {}

#endif