#pragma once
#include <vector>
#include "MEMORYAPI.H"
#include "disasm.hpp"

using byte = unsigned char;

class TDetour
{
public:
	TDetour(int target_func, int hook): target{ (PVOID)target_func }, size{}
	{		
		auto next_instr = target;

		while (size < 6)
		{
			next_instr = DetourCopyInstruction(&trampoline[size], next_instr);			
			size = (int)next_instr - (int)target;
		}

		trampoline[size] = 0x68;								// push ...
		*(int*)&trampoline[size + 1] = (int)target + size;		// the address of the next valid instruction in the target
		trampoline[size + 5] = 0xc3;							// return

		DWORD old_protection;
		VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &old_protection);

		*(byte*)target = 0x68;									// push ...
		*(int*)((int)target + 1) = hook;						// the address of the detour
		*(byte*)((int)target + 5) = 0xc3;						// return
		for (auto i = 6; i < size; i++)
		{
			*(byte*)((int)target + i) = 0x90;					//fill the gap with NOPs
		}

		VirtualProtect(target, size, old_protection, 0);	
	}

	~TDetour()
	{
		Remove();
	}
	
	void Remove()
	{
		DWORD old_protection;
		VirtualProtect(target, size, PAGE_EXECUTE_READWRITE, &old_protection);
		
		for (auto i = 0; i < size; i++)
		{
			*(byte*)((int)target + i) = trampoline[i];
		}

		VirtualProtect(target, size, old_protection, 0);
	}

	template<typename T, typename... Args >
	decltype(auto) Call(Args... args)
	{
		return ((T*)&trampoline)(args...);
	}
	
	PVOID target{};
	byte trampoline[32];
	int size;
};