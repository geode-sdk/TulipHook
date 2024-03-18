#include "../assembler/X86Assembler.hpp"

#include <AbstractFunction.hpp>
#include <Platform.hpp>
#include <algorithm>
#include <iostream>
#include <optional>
#include <platform/WindowsConvention.hpp>
#include <variant>

using namespace tulip::hook;

enum class Register {
	EAX,
	ECX,
	EDX,
	XMM0,
	XMM1,
	XMM2,
	XMM3,
	ST0,
};
using Stack = size_t;
using Location = std::variant<Stack, Register>;

class PushParameter final {
public:
	Location location;
	Stack resultLocation = 0;
	Stack originalLocation = 0;
	AbstractType type;
	size_t originalIndex = 0;

	PushParameter(AbstractType const& type, Location loc, size_t originalIndex) :
		type(type),
		location(loc),
		originalIndex(originalIndex) {}
};

static Location returnLocation(AbstractFunction const& function) {
	// other
	switch (function.m_return.m_kind) {
		default:
		case AbstractTypeKind::Primitive: return Register::EAX;
		case AbstractTypeKind::FloatingPoint: return Register::ST0;
		case AbstractTypeKind::Other: return Stack(0x4);
	}
}

static Location optimizedReturnLocation(AbstractFunction const& function) {
	// other
	switch (function.m_return.m_kind) {
		default:
		case AbstractTypeKind::Primitive: return Register::EAX;
		case AbstractTypeKind::FloatingPoint: return Register::XMM0;
		case AbstractTypeKind::Other: return Stack(0x4);
	}
}

class PushParameters final {
private:
	std::vector<PushParameter> m_params;
	Location m_returnValueLocation;
	AbstractType m_returnType;

	// size of the original function's stack
	size_t m_originalStackSize = 0x0;
	// size of our converted function's stack
	size_t m_resultStackSize = 0x0;
	// whether to clean up stack when doing orig -> detour
	bool m_isCallerCleanup = false;

	X86Assembler& a;
	RegMem32 m;

	using enum X86Register;

	PushParameters(X86Assembler& a) :
		a(a) {}

	static size_t paramSize(AbstractType const& type) {
		// this rounds a number up to the nearest multiple of 4
		return (type.m_size + 3) / 4 * 4;
	}

	static X86Register xmmRegisterName(Register reg) {
		switch (reg) {
			default:
			case Register::XMM0: return XMM0;
			case Register::XMM1: return XMM1;
			case Register::XMM2: return XMM2;
			case Register::XMM3: return XMM3;
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
	static PushParameters fromCdecl(X86Assembler& a, AbstractFunction const& function) {
		auto res = PushParameters(a);
		res.m_returnType = function.m_return;

		// structs are returned as pointer through first parameter
		res.m_returnValueLocation = returnLocation(function);
		if (std::holds_alternative<Stack>(res.m_returnValueLocation)) {
			res.push(AbstractType::from<void*>());
		}

		for (auto& param : function.m_parameters) {
			res.push(param);
		}

		res.reorder();
		res.m_isCallerCleanup = true;

		return res;
	}

	static PushParameters fromStdcall(X86Assembler& a, AbstractFunction const& function) {
		auto res = fromCdecl(a, function);

		res.m_isCallerCleanup = false;

		return res;
	}

	static PushParameters fromThiscall(X86Assembler& a, AbstractFunction const& function) {
		auto res = PushParameters(a);
		res.m_returnType = function.m_return;

		// structs are returned as pointer through first parameter
		res.m_returnValueLocation = returnLocation(function);
		if (std::holds_alternative<Stack>(res.m_returnValueLocation)) {
			res.push(AbstractType::from<void*>());
		}

		bool ecxUsed = false;
		// first pointer-like parameter through ecx
		// this is in practice always 'this' but for the sake of uhh idk i made
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

	static PushParameters fromFastcall(X86Assembler& a, AbstractFunction const& function) {
		auto res = PushParameters(a);
		res.m_returnType = function.m_return;
		size_t registersUsed = 0;

		// structs are returned as pointer through first parameter
		res.m_returnValueLocation = returnLocation(function);
		if (std::holds_alternative<Stack>(res.m_returnValueLocation)) {
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

	static PushParameters fromOptcall(X86Assembler& a, AbstractFunction const& function) {
		auto res = PushParameters(a);
		size_t registersUsed = 0;

		// structs are returned as pointer through first parameter
		res.m_returnType = function.m_return;
		res.m_returnValueLocation = optimizedReturnLocation(function);
		if (std::holds_alternative<Stack>(res.m_returnValueLocation)) {
			res.push(AbstractType::from<void*>(), Register::ECX);
			registersUsed = 1;
		}

		// structs go at the end of the parameter list in optcall
		std::vector<std::pair<size_t, AbstractType>> reordered;
		size_t structsAt = 0;
		size_t origIndex = 0;
		for (auto& param : function.m_parameters) {
			if (param.m_kind == AbstractTypeKind::Other && param.m_size > 4) {
				reordered.push_back({origIndex, param});
			}
			else {
				reordered.insert(reordered.begin() + structsAt, {origIndex, param});
				structsAt++;
			}
			origIndex++;
		}

		size_t index = 0;
		for (auto& [oindex, param] : reordered) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive && param.m_size <= sizeof(void*)) {
				res.push(param, Register::ECX, oindex);
				registersUsed = 1;
			}
			// second primitive through edx
			else if (registersUsed == 1 && param.m_kind == AbstractTypeKind::Primitive && param.m_size <= sizeof(void*)) {
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

		// optcall is caller cleanup
		res.m_isCallerCleanup = true;

		return res;
	}

	static PushParameters fromMembercall(X86Assembler& a, AbstractFunction const& function) {
		auto res = PushParameters(a);
		size_t registersUsed = 0;

		// structs are returned as pointer through first parameter
		res.m_returnType = function.m_return;
		res.m_returnValueLocation = optimizedReturnLocation(function);
		if (std::holds_alternative<Stack>(res.m_returnValueLocation)) {
			res.push(AbstractType::from<void*>());
		}

		// structs go at the end of the parameter list like in optcall
		std::vector<std::pair<size_t, AbstractType>> reordered;
		size_t structsAt = 0;
		size_t origIndex = 0;
		for (auto& param : function.m_parameters) {
			if (param.m_kind == AbstractTypeKind::Other) {
				reordered.push_back({origIndex, param});
			}
			else {
				reordered.insert(reordered.begin() + structsAt, {origIndex, param});
				structsAt++;
			}
			origIndex++;
		}

		size_t index = 0;
		for (auto& [oindex, param] : reordered) {
			// first primitive through ecx
			if (registersUsed == 0 && param.m_kind == AbstractTypeKind::Primitive && param.m_size <= sizeof(void*)) {
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
		m_params.emplace_back(type, m_originalStackSize, oindex.value_or(m_params.size()));
		m_originalStackSize += paramSize(type);
		m_resultStackSize += paramSize(type);
	}

	// Reorder based on original index of parameters
	void reorder() {
		size_t stackLocation = 0;
		for (auto& param : m_params) {
			if (std::holds_alternative<Stack>(param.location)) {
				param.originalLocation = stackLocation;
				stackLocation += paramSize(param.type);
			}
		}
		std::sort(m_params.begin(), m_params.end(), [](auto a, auto b) -> bool {
			return a.originalIndex < b.originalIndex;
		});
		stackLocation = 0;
		for (auto& param : m_params) {
			param.resultLocation = stackLocation;
			stackLocation += paramSize(param.type);
		}
	}

	void generateIntoDefault() {
		// allocate space on the stack for our parameters
		if (m_resultStackSize) {
			a.sub(ESP, m_resultStackSize);
		}

		// cdecl parameters are passed in reverse order; however, since we are
		// just moving stuff to from known memory locations to other known
		// memory locations, it doesn't matter the order we iterate the params
		// in (unlike previously when m_params was reversed for this point).
		// what matters is that the correct params end up in the correct places

		// keep track of which offset to place the next parameter at
		// this is the offset from the top of the stack, so we are moving
		// the first parameter first, then the second, etc.
		size_t placeAt = 0x0;

		for (auto& param : m_params) {
			// repush from stack
			if (std::holds_alternative<Stack>(param.location)) {
				auto offset = std::get<Stack>(param.location);

				// push every member of struct
				for (size_t i = 0; i < paramSize(param.type); i += 4) {
					// move value to eax first since we can't have mov [...], [...]

					// push the struct in the same order as it was originally on the stack
					// + 4 is for the return address
					a.mov(EAX, m[ESP + (offset + m_resultStackSize + i + 4)]);

					// push parameters in order
					a.mov(m[ESP + (placeAt + i)], EAX);
				}
			}
			// repush from register
			else {
				switch (auto reg = std::get<Register>(param.location)) {
					case Register::ECX: {
						a.mov(m[ESP + placeAt], ECX);
					} break;
					case Register::EDX: {
						a.mov(m[ESP + placeAt], EDX);
					} break;
					// xmm registers
					default: {
						// double
						if (param.type.m_size == 8) {
							a.movsd(m[ESP + placeAt], xmmRegisterName(reg));
						}
						// float
						else {
							a.movss(m[ESP + placeAt], xmmRegisterName(reg));
						}
					} break;
				}
			}

			// since we pushed parameters to the stack, we need to take into
			// account the stack pointer being offset by that amount when
			// pushing the next parameters
			placeAt += paramSize(param.type);
		}
	}

	void generateDefaultCleanup() {
		// clean up stack from the ones we added
		a.add(ESP, m_resultStackSize);

		// in the original(gd) function, the return for floats is in xmm0
		if (std::holds_alternative<Register>(m_returnValueLocation) && std::get<Register>(m_returnValueLocation) == Register::XMM0) {
			// move the st0 into xmm0
			auto size = m_returnType.m_size;
			a.sub(ESP, size);
			if (size == 4) {
				a.fstps(m[ESP]);
				a.movss(XMM0, m[ESP]);
			}
			else {
				a.fstpd(m[ESP]);
				a.movsd(XMM0, m[ESP]);
			}
			a.add(ESP, size);
		}

		// if the function is caller cleaned, then generateOriginalCleanup
		// or the original GD function cleans it up
		if (m_isCallerCleanup) {
			a.ret();
		}
		// otherwise clean up stack using ret
		// some of the original parameters may be passed through registers so the
		// original's stack size may be smaller
		else {
			a.ret(m_originalStackSize);
		}
	}

	void generateIntoOriginal() {
		if (m_originalStackSize) {
			a.sub(ESP, m_originalStackSize);
		}

		for (auto& param : m_params) {
			auto const resultOffset = m_originalStackSize + param.resultLocation + 4;
			if (std::holds_alternative<Register>(param.location)) {
				auto const reg = std::get<Register>(param.location);
				switch (reg) {
					case Register::ECX: {
						a.mov(ECX, m[ESP + resultOffset]);
					} break;
					case Register::EDX: {
						a.mov(EDX, m[ESP + resultOffset]);
					} break;
					default: {
						if (param.type.m_size == 4) {
							a.movss(xmmRegisterName(reg), m[ESP + resultOffset]);
						}
						else {
							a.movsd(xmmRegisterName(reg), m[ESP + resultOffset]);
						}
					}
				}
			}
			else {
				for (size_t i = 0; i < param.type.m_size; i += 4) {
					a.mov(EAX, m[ESP + (resultOffset + i)]);
					a.mov(m[ESP + (param.originalLocation + i)], EAX);
				}
			}
		}
	}

	void generateOriginalCleanup() {
		// in the default(geode) function, the return for floats is in st0
		if (std::holds_alternative<Register>(m_returnValueLocation) && std::get<Register>(m_returnValueLocation) == Register::XMM0) {
			// move the xmm into st0
			auto size = m_returnType.m_size;
			a.sub(ESP, size);
			if (size == 4) {
				a.movss(m[ESP], XMM0);
				a.flds(m[ESP]);
			}
			else {
				a.movsd(m[ESP], XMM0);
				a.fldd(m[ESP]);
			}
			a.add(ESP, size);
		}

		if (m_isCallerCleanup) {
			// for mat: comment this to make your tests work
			a.add(ESP, m_originalStackSize);
		}
		a.ret();
	}
};

void CdeclConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromCdecl(static_cast<X86Assembler&>(a), function).generateDefaultCleanup();
}

void CdeclConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromCdecl(static_cast<X86Assembler&>(a), function).generateIntoDefault();
}

void CdeclConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromCdecl(static_cast<X86Assembler&>(a), function).generateOriginalCleanup();
}

void CdeclConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromCdecl(static_cast<X86Assembler&>(a), function).generateIntoOriginal();
}

std::shared_ptr<CdeclConvention> CdeclConvention::create() {
	return std::make_shared<CdeclConvention>();
}

CdeclConvention::~CdeclConvention() {}

void ThiscallConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromThiscall(static_cast<X86Assembler&>(a), function).generateDefaultCleanup();
}

void ThiscallConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {
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

	return PushParameters::fromThiscall(static_cast<X86Assembler&>(a), function).generateIntoDefault();
}

void ThiscallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromThiscall(static_cast<X86Assembler&>(a), function).generateOriginalCleanup();
}

void ThiscallConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromThiscall(static_cast<X86Assembler&>(a), function).generateIntoOriginal();
}

std::shared_ptr<ThiscallConvention> ThiscallConvention::create() {
	return std::make_shared<ThiscallConvention>();
}

ThiscallConvention::~ThiscallConvention() {}

void FastcallConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromFastcall(static_cast<X86Assembler&>(a), function).generateDefaultCleanup();
}

void FastcallConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {
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

	return PushParameters::fromFastcall(static_cast<X86Assembler&>(a), function).generateIntoDefault();
}

void FastcallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromFastcall(static_cast<X86Assembler&>(a), function).generateOriginalCleanup();
}

void FastcallConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromFastcall(static_cast<X86Assembler&>(a), function).generateIntoOriginal();
}

std::shared_ptr<FastcallConvention> FastcallConvention::create() {
	return std::make_shared<FastcallConvention>();
}

FastcallConvention::~FastcallConvention() {}

void OptcallConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromOptcall(static_cast<X86Assembler&>(a), function).generateDefaultCleanup();
}

void OptcallConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {
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

	return PushParameters::fromOptcall(static_cast<X86Assembler&>(a), function).generateIntoDefault();
}

void OptcallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromOptcall(static_cast<X86Assembler&>(a), function).generateOriginalCleanup();
}

void OptcallConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromOptcall(static_cast<X86Assembler&>(a), function).generateIntoOriginal();
}

std::shared_ptr<OptcallConvention> OptcallConvention::create() {
	return std::make_shared<OptcallConvention>();
}

OptcallConvention::~OptcallConvention() {}

void MembercallConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromMembercall(static_cast<X86Assembler&>(a), function).generateDefaultCleanup();
}

void MembercallConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromMembercall(static_cast<X86Assembler&>(a), function).generateIntoDefault();
}

void MembercallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromMembercall(static_cast<X86Assembler&>(a), function).generateOriginalCleanup();
}

void MembercallConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromMembercall(static_cast<X86Assembler&>(a), function).generateIntoOriginal();
}

std::shared_ptr<MembercallConvention> MembercallConvention::create() {
	return std::make_shared<MembercallConvention>();
}

MembercallConvention::~MembercallConvention() {}

void StdcallConvention::generateDefaultCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromStdcall(static_cast<X86Assembler&>(a), function).generateDefaultCleanup();
}

void StdcallConvention::generateIntoDefault(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromStdcall(static_cast<X86Assembler&>(a), function).generateIntoDefault();
}

void StdcallConvention::generateOriginalCleanup(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromStdcall(static_cast<X86Assembler&>(a), function).generateOriginalCleanup();
}

void StdcallConvention::generateIntoOriginal(BaseAssembler& a, AbstractFunction const& function) {
	return PushParameters::fromStdcall(static_cast<X86Assembler&>(a), function).generateIntoOriginal();
}

std::shared_ptr<StdcallConvention> StdcallConvention::create() {
	return std::make_shared<StdcallConvention>();
}

StdcallConvention::~StdcallConvention() {}
