#pragma once

#include "CDataStore.hpp"

//it's a a thiscall
int __fastcall NetClientProcessDetour(int connection, int edx, int tickCount, CDataStore* data)
{
	auto ds = DataStore(data);
	uint16 opcode = ds.Peek<uint16>();

	logger.add("opcode", OpcodesMap[opcode]);	

	//---------------- return to the original function ----------------
	return ((detours["NetClientProcess"])->Call<decltype(NetClientProcessDetour)>)(connection, edx, tickCount, data);
}