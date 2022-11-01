#include <platform/WindowsConvention.hpp>
#include <Platform.hpp>
#include <AbstractFunction.hpp>
#include <sstream>
#include <ranges>
#include <variant>
#include <optional>
#include <algorithm>

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
	Stack m_resultLocation;
	AbstractType m_type;
	size_t m_originalIndex;

	PushParameter(
		AbstractType const& type,
		Location loc,
		size_t originalIndex
	) : m_type(type),
		m_location(loc),
		m_originalIndex(originalIndex) {}
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
			res.push(AbstractType::from<void*>());
		}
		bool ecxUsed = false;
		// first parameter through ecx
		// this is in practice always 'this' but for the sake of idk i made 
		// it safe anyway (so it should work even if someone applied __thiscall 
		// on a non-member function)
		for (auto& param : function.m_parameters) {
			if (!ecxUsed && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX);
				ecxUsed = true;
			}
			// everything else through stack
			else {
				res.push(param);
			}
		}

		res.reorder();

		return res;
	}

	static PushParameters fromFastcall(AbstractFunction const& function) {
		auto res = PushParameters();
		size_t registersUsed = 0;
		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), Register::ECX);
			registersUsed = 1;
		}
		// first two parameters that can go in ecx and edx go in ecx 
		for (auto& param : function.m_parameters) {
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX);
				registersUsed = 1;
			}
			else if (registersUsed == 1 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::EDX);
				registersUsed = 2;
			}
			else {
				res.push(param);
			}
		}

		res.reorder();

		return res;
	}

	static PushParameters fromOptcall(AbstractFunction const& function) {
		auto res = PushParameters();
		size_t registersUsed = 0;

		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), Register::ECX);
			registersUsed = 1;
		}

		// structs go at the end of the parameter list in optcall
		std::vector<std::pair<size_t, AbstractType>> reordered;
		size_t structsAt = 0;
		size_t origIndex = 0;
		for (auto& param : function.m_parameters) {
			if (param.m_kind == AbstractTypeKind::Other) {
				reordered.push_back({ origIndex, param });
			} else {
				reordered.insert(reordered.begin() + structsAt, { origIndex, param });
				structsAt++;
			}
			origIndex++;
		}

		size_t index = 0;
		for (auto& [oindex, param] : reordered) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX, oindex);
				registersUsed = 1;
			}
			// second primitive through edx
			else if (registersUsed == 1 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::EDX, oindex);
				registersUsed = 2;
			}
			// floats 0..3 through xmm0..xmm3
			else if (index < 4 && param.m_kind == AbstractTypeKind::FloatingPoint) {
				res.push(param, xmmRegisterFromName(index), oindex);
			}
			// rest on stack as normal
			else {
				res.push(param, oindex);
			}
			index++;
		}
		
		// reorder params to be in original order
		res.reorder();
		
		return res;
	}

	static PushParameters fromMembercall(AbstractFunction const& function) {
		auto res = PushParameters();
		size_t registersUsed = 0;

		// structs are returned as pointer through first parameter
		if (shouldStructReturn(function)) {
			res.push(AbstractType::from<void*>(), Register::ECX);
			registersUsed = 1;
		}

		// structs go at the end of the parameter list in optcall
		std::vector<std::pair<size_t, AbstractType>> reordered;
		size_t structsAt = 0;
		size_t origIndex = 0;
		for (auto& param : function.m_parameters) {
			if (param.m_kind == AbstractTypeKind::Other) {
				reordered.push_back({ origIndex, param });
			} else {
				reordered.insert(reordered.begin() + structsAt, { origIndex, param });
				structsAt++;
			}
			origIndex++;
		}

		size_t index = 0;
		for (auto& [oindex, param] : reordered) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive) {
				res.push(param, Register::ECX, oindex);
				registersUsed = 1;
			}
			// floats 0..3 through xmm0..xmm3
			else if (index < 4 && param.m_kind == AbstractTypeKind::FloatingPoint) {
				res.push(param, xmmRegisterFromName(index), oindex);
			}
			// rest on stack as normal
			else {
				res.push(param, oindex);
			}
			index++;
		}
		
		// reorder params to be in original order
		res.reorder();
		
		return res;
	}

	// Push through register
	void push(AbstractType const& type, Register reg, std::optional<size_t> oindex = std::nullopt) {
		m_params.emplace_back(type, reg, oindex.value_or(m_params.size()));
		m_resultStackSize += paramSize(type);
	}

	// Push through stack
	void push(AbstractType const& type, std::optional<size_t> oindex = std::nullopt) {
		m_params.emplace_back(
			type, m_originalStackSize, oindex.value_or(m_params.size())
		);
		m_originalStackSize += paramSize(type);
		m_resultStackSize += paramSize(type);
	}

	// Reorder based on original index of parameters
	void reorder() {
		// params are on the stack in reverse order
		size_t stackLocation = m_resultStackSize;
		for (auto& param : m_params) {
			stackLocation -= paramSize(param.m_type);
			param.m_resultLocation = stackLocation;
		}
		std::sort(
			m_params.begin(), m_params.end(), [](auto a, auto b) -> bool {
				return a.m_originalIndex < b.m_originalIndex;
			}
		);
	}

	std::string generateToDefault() {
		std::ostringstream out;
		out << std::hex;

		size_t stackOffset = 0x0;
		for (auto& param : std::ranges::reverse_view(m_params)) {
			out << "/* " << param.m_originalIndex << " */; ";
			// repush from stack
			if (std::holds_alternative<Stack>(param.m_location)) {
				auto offset = std::get<Stack>(param.m_location);
				// push every member of struct
				for (size_t i = 0; i < paramSize(param.m_type); i += 4) {
					out << "push [esp + 0x"
						<< (
							// we want to repush starting from first member 
							// since the params are already pushed in reverse 
							// order
							offset + stackOffset + paramSize(param.m_type)
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
							out << "sub esp, 0x8; movsd [esp], xmm" 
								<< xmmRegisterName(reg) << "; ";
						}
						// float
						else {
							out << "sub esp, 0x4; movss [esp], xmm" 
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

		return out.str();
	}

	std::string generateFromDefault() {
		std::ostringstream out;
		out << std::hex;

		// clean up stack from the ones we added
		out << "add esp, 0x" << m_resultStackSize << "; ";
		// some of the original parameters may be passed through registers so the 
		// original's stack size may be smaller
		out << "ret 0x" << m_originalStackSize << "; ";

		return out.str();
	}

	std::string generateBackToDefault(size_t additionalOffset) {
		std::ostringstream out;
		out << std::hex;
		
		size_t stackOffset = additionalOffset;
		for (auto& param : std::ranges::reverse_view(m_params)) {
			if (std::holds_alternative<Stack>(param.m_location)) {
				// push all members of struct
				for (size_t i = 0; i < paramSize(param.m_type); i += 4) {
					out
						<< "push [esp + 0x"
						<< param.m_resultLocation + stackOffset + paramSize(param.m_type)
						<< "]; ";
				}
				// we're only pushing parameters on the stack back to the stack
				stackOffset += paramSize(param.m_type);
			}
			else {
				switch (auto reg = std::get<Register>(param.m_location)) {
					case Register::ECX: {
						out << "mov ecx, [esp + 0x"
							<< param.m_resultLocation + stackOffset << "]; ";
					} break;

					case Register::EDX: {
						out << "mov edx, [esp + 0x"
							<< param.m_resultLocation + stackOffset << "]; ";
					} break;

					// xmm registers
					default: {
						// double
						if (param.m_type.m_size == 8) {
							out << "movsd xmm" 
								<< xmmRegisterName(reg) << ", [esp + 0x"
								<< param.m_resultLocation + stackOffset << "]; ";
						}
						// float
						else {
							out << "movss xmm" 
								<< xmmRegisterName(reg) << ", [esp + 0x"
								<< param.m_resultLocation + stackOffset << "]; ";
						}
					} break;
				}
			}
		}
		
		return out.str();
	}

	std::string generateBackFromDefault() {
		return "";
	}
};

std::string CdeclConvention::generateFromDefault(AbstractFunction const& function) {
	// it's the same conv as default
	return "ret 0";
}
std::string CdeclConvention::generateToDefault(AbstractFunction const& function) {
	// it's the same conv as default
	return "";
}
std::string CdeclConvention::generateBackFromDefault(AbstractFunction const& function) {
	// it's the same conv as default
	return "";
}
std::string CdeclConvention::generateBackToDefault(AbstractFunction const& function, size_t stackOffset) {
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
std::string ThiscallConvention::generateBackFromDefault(AbstractFunction const& function) {
	return PushParameters::fromThiscall(function).generateBackFromDefault();
}
std::string ThiscallConvention::generateBackToDefault(AbstractFunction const& function, size_t stackOffset) {
	return PushParameters::fromThiscall(function).generateBackToDefault(stackOffset);
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
std::string FastcallConvention::generateBackFromDefault(AbstractFunction const& function) {
	return PushParameters::fromFastcall(function).generateBackFromDefault();
}
std::string FastcallConvention::generateBackToDefault(AbstractFunction const& function, size_t stackOffset) {
	return PushParameters::fromFastcall(function).generateBackToDefault(stackOffset);
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
std::string OptcallConvention::generateBackFromDefault(AbstractFunction const& function) {
	return PushParameters::fromOptcall(function).generateBackFromDefault();
}
std::string OptcallConvention::generateBackToDefault(AbstractFunction const& function, size_t stackOffset) {
	return PushParameters::fromOptcall(function).generateBackToDefault(stackOffset);
}
OptcallConvention::~OptcallConvention() {}

std::string MembercallConvention::generateFromDefault(AbstractFunction const& function) {
	return PushParameters::fromMembercall(function).generateFromDefault();
}
std::string MembercallConvention::generateToDefault(AbstractFunction const& function) {
	return PushParameters::fromMembercall(function).generateToDefault();
}
std::string MembercallConvention::generateBackFromDefault(AbstractFunction const& function) {
	return PushParameters::fromMembercall(function).generateBackFromDefault();
}
std::string MembercallConvention::generateBackToDefault(AbstractFunction const& function, size_t stackOffset) {
	return PushParameters::fromMembercall(function).generateBackToDefault(stackOffset);
}
MembercallConvention::~MembercallConvention() {}

#endif
