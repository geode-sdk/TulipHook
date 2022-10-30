#include <platform/WindowsConvention.hpp>
#include <Platform.hpp>
#include <AbstractFunction.hpp>
#include <sstream>
#include <ranges>
#include <variant>

using namespace tulip::hook;

#if defined(TULIP_HOOK_WINDOWS)

enum class Register {
	ECX, EDX,
	XMM0, XMM1, XMM2, XMM3,
};
using Stack = size_t;
using Location = std::variant<Stack, Register>;

class PushParameter final {
public:
	Location m_location;
	AbstractType m_type;
	std::string m_debug = "";

	PushParameter(AbstractType const& type, Location loc, std::string const& c)
	 : m_type(type), m_location(loc), m_debug(c) {}
};

static bool shouldStructReturn(AbstractFunction const& function) {
	return function.m_return.m_size > 4 * 2;
}

// todo: remove
template<class F>
static std::string hexString(F f) {
	std::stringstream stream;
	stream << std::hex << f;
	return stream.str();
}

class PushParameters final {
private:
	std::vector<PushParameter> m_params;
	// size of the original function's stack
	size_t m_originalStackSize = 0x0;
	// size of our converted function's stack
	size_t m_resultStackSize = 0x0;
	// keeps track of where the next parameter 
	// should be pushed on the stack
	size_t m_stackPointer = 0x0;

	static size_t paramSize(AbstractType const& type) {
		// this rounds a number up to the nearest multiple of 4
		return (type.m_size + 3) / 4 * 4;
	}

	static size_t xmmRegisterName(Register reg) {
		switch (reg) {
			default:
			case Register::XMM0: return 0;
			case Register::XMM1: return 1;
			case Register::XMM2: return 2;
			case Register::XMM3: return 3;
		}
	}

	static Register xmmRegisterFromName(size_t num) {
		switch (num) {
			default:
			case 0: return Register::XMM0;
			case 1: return Register::XMM1;
			case 2: return Register::XMM2;
			case 3: return Register::XMM3;
		}
	}

public:
	static PushParameters fromThiscall(AbstractFunction const& function) {
		auto res = PushParameters();
		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), "struct return");
		}
		bool ecxUsed = false;
		// first parameter through ecx
		// this is in practice always 'this' but for the sake of idk i made 
		// it safe anyway (so it should work even if someone applied __thiscall 
		// on a non-member function)
		for (auto& param : function.m_parameters) {
			if (!ecxUsed && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX, "ecx");
				ecxUsed = true;
			}
			// everything else through stack
			else {
				res.push(param);
			}
		}
		return res;
	}

	static PushParameters fromFastcall(AbstractFunction const& function) {
		auto res = PushParameters();
		size_t registersUsed = 0;
		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), Register::ECX, "struct return");
			registersUsed = 1;
		}
		// first two parameters that can go in ecx and edx go in ecx 
		for (auto& param : function.m_parameters) {
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX, "ecx");
				registersUsed = 1;
			}
			else if (registersUsed == 1 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::EDX, "edx");
				registersUsed = 2;
			}
			else {
				res.push(param);
			}
		}
		return res;
	}

	static PushParameters fromOptcall(AbstractFunction const& function) {
		auto res = PushParameters();
		size_t registersUsed = 0;
		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), Register::ECX, "struct return");
			registersUsed = 1;
		}
		// precalc size for structs due to reordering
		size_t stackSize = 0;
		size_t structsSize = 0;
		size_t index = 0;
		for (auto& param : function.m_parameters) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				registersUsed = 1;
			}
			// second primitive through edx
			else if (registersUsed == 1 && param.m_kind == AbstractTypeKind::Primitive) {
				registersUsed = 2;
			}
			// floats 0..3 through xmm0..xmm3
			else if (index < 4 && param.m_kind == AbstractTypeKind::FloatingPoint) {
			}
			// structs at the end
			else if (param.m_kind == AbstractTypeKind::Other) {
				stackSize += paramSize(param);
				structsSize += paramSize(param);
			}
			// rest on stack as normal
			else {
				stackSize += paramSize(param);
			}
			index++;
		}

		index = 0;
		for (auto& param : function.m_parameters) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX, "ecx");
				registersUsed = 1;
			}
			// second primitive through edx
			else if (registersUsed == 1 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::EDX, "edx");
				registersUsed = 2;
			}
			// floats 0..3 through xmm0..xmm3
			else if (index < 4 && param.m_kind == AbstractTypeKind::FloatingPoint) {
				res.push(param, xmmRegisterFromName(index), "float #" + std::to_string(index));
			}
			// structs at the end
			else if (param.m_kind == AbstractTypeKind::Other) {
				res.push(param, stackSize - structsSize);
				structsSize -= paramSize(param);
			}
			// rest on stack as normal
			else {
				res.push(param);
			}
			index++;
		}
		return res;
	}

	static PushParameters fromMembercall(AbstractFunction const& function) {
		auto res = PushParameters();
		size_t registersUsed = 0;
		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), Register::ECX, "struct return");
			registersUsed = 1;
		}
		// precalc size for structs due to reordering
		size_t stackSize = 0;
		size_t structsSize = 0;
		size_t index = 0;
		for (auto& param : function.m_parameters) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				registersUsed = 1;
			}
			// floats 0..3 through xmm0..xmm3
			else if (index < 4 && param.m_kind == AbstractTypeKind::FloatingPoint) {
			}
			// structs at the end
			else if (param.m_kind == AbstractTypeKind::Other) {
				stackSize += paramSize(param);
				structsSize += paramSize(param);
			}
			// rest on stack as normal
			else {
				stackSize += paramSize(param);
			}
			index++;
		}

		index = 0;
		for (auto& param : function.m_parameters) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX, "ecx");
				registersUsed = 1;
			}
			// floats 0..3 through xmm0..xmm3
			else if (index < 4 && param.m_kind == AbstractTypeKind::FloatingPoint) {
				res.push(param, xmmRegisterFromName(index), "float #" + std::to_string(index));
			}
			// structs at the end
			else if (param.m_kind == AbstractTypeKind::Other) {
				res.push(param, stackSize - structsSize);
				structsSize -= paramSize(param);
			}
			// rest on stack as normal
			else {
				res.push(param);
			}
			index++;
		}
		return res;
	}

	// Push through register
	void push(AbstractType const& type, Register reg, std::string const& comment = "") {
		m_params.emplace_back(type, reg, comment);
		m_resultStackSize += paramSize(type);
	}

	// Push through stack at offset
	void push(AbstractType const& type, size_t offset, std::string const& comment = "") {
		m_params.emplace_back(
			type, offset,
			(comment.size() ?
				comment :
				"location (o): 0x" + hexString(offset)
			)
		);
		m_originalStackSize += paramSize(type);
		m_resultStackSize += paramSize(type);
	}

	// Push through stack
	void push(AbstractType const& type, std::string const& comment = "") {
		m_params.emplace_back(
			type, m_stackPointer,
			(comment.size() ?
				comment :
				"location: 0x" + hexString(m_stackPointer)
			)
		);
		m_originalStackSize += paramSize(type);
		m_resultStackSize += paramSize(type);
		m_stackPointer += paramSize(type);
	}

	void generateToDefault(std::ostringstream& out) {
		size_t stackOffset = 0x0;
		for (auto& param : std::ranges::reverse_view(m_params)) {
			if (param.m_debug.size()) {
				out << "/* " << param.m_debug << " */; ";
			}
			// repush from stack
			if (std::holds_alternative<Stack>(param.m_location)) {
				auto offset = std::get<Stack>(param.m_location);
				// push every member of struct
				for (size_t i = 0; i < paramSize(param.m_type); i += 4) {
					out << "push [esp + 0x"
						<< (
							offset + stackOffset + 
							// offset is stored relative to first member, we want 
							// to repush starting from last member since params 
							// are pushed in reverse order
							paramSize(param.m_type)
						)
						<< "]; ";
				}
			}
			// repush from register
			else {
				switch (auto reg = std::get<Register>(param.m_location)) {
					case Register::ECX: out << "push ecx; "; break;
					case Register::EDX: out << "push edx; "; break;
					// xmm registers
					default: {
						// double
						if (param.m_type.m_size == 8) {
							out << "sub esp, 0x8; mov qword [esp], xmm" 
								<< xmmRegisterName(reg) << "; ";
						}
						// float
						else {
							out << "sub esp, 0x4; mov dword [esp], xmm" 
								<< xmmRegisterName(reg) << "; ";
						}
					} break;
				}
			}
			// since we pushed parameters to the stack, we need to take into 
			// account the stack pointer being offset by that amount when 
			// pushing the next parameters
			stackOffset += paramSize(param.m_type);
		}
	}

	void generateFromDefault(std::ostringstream& out) {
		// clean up stack from the ones we added
		out << "add esp, 0x" << m_resultStackSize << "; ";
		// some of the original parameters may be passed through registers so the 
		// original's stack size may be smaller
		out << "ret 0x" << m_originalStackSize;
	}

	std::string generateToDefault() {
		std::ostringstream out;
		out << std::hex;
		this->generateToDefault(out);
		return out.str();
	}

	std::string generateFromDefault() {
		std::ostringstream out;
		out << std::hex;
		this->generateFromDefault(out);
		return out.str();
	}
};

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
	if (shouldStructReturn(function)) {
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
		out << "push [esp + 0x" << at << "]; ";
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
	return PushParameters::fromThiscall(function).generateFromDefault();
}
std::string ThiscallConvention::generateToDefault(AbstractFunction const& function) {
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

	return PushParameters::fromThiscall(function).generateToDefault();
}
ThiscallConvention::~ThiscallConvention() {}

std::string FastcallConvention::generateFromDefault(AbstractFunction const& function) {
	return PushParameters::fromFastcall(function).generateFromDefault();
}
std::string FastcallConvention::generateToDefault(AbstractFunction const& function) {
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

	return PushParameters::fromFastcall(function).generateToDefault();
}
FastcallConvention::~FastcallConvention() {}

std::string OptcallConvention::generateFromDefault(AbstractFunction const& function) {
	return PushParameters::fromOptcall(function).generateFromDefault();
}
std::string OptcallConvention::generateToDefault(AbstractFunction const& function) {
	// __optcall is like __fastcall, except parameters 0..3 are 
	// passed through xmm0..xmm3 if they are floating-point and 
	// structs are all passed last

	// struct Big { int x; int y; int z; }
	//
	// test3(Big, int, int, float, int, float)
	// ===> (int, int, float, int, float, Big)
	//
	// ecx                  <= int
	// edx                  <= int
	// xmm1                 <= float
	// 0x4                  <= int
	// 0x8                  <= float
	// 0xc                  <= Big.x
	// 0x10                 <= Big.y
	// 0x14                 <= Big.z
	// 
	// stackSizeFromFunction = 0x20
	// -----------------------------   stack offset after
	// push [esp + 0x8]      <= float        0x4
	// push [esp + 0xc]      <= int          0x8
	// sub esp, 0x4
	// mov dword [esp], xmm1 <= float        0xc
	// push edx              <= int          0x10
	// push ecx              <= int          0x14
	// push [esp + 0x28]     <= Big.z        0x18
	// push [esp + 0x28]     <= Big.y        0x1c
	// push [esp + 0x28]     <= Big.x        0x20
	
	return PushParameters::fromOptcall(function).generateToDefault();
}
OptcallConvention::~OptcallConvention() {}

std::string MembercallConvention::generateFromDefault(AbstractFunction const& function) {
	return PushParameters::fromMembercall(function).generateFromDefault();
}
std::string MembercallConvention::generateToDefault(AbstractFunction const& function) {
	return PushParameters::fromMembercall(function).generateToDefault();
}
MembercallConvention::~MembercallConvention() {}

#endif