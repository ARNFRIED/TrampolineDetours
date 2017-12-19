#pragma once
#include <algorithm>
#include "Structs.h"

inline auto ClntCurMgr() { return *(CurMgr**)0x00B41414; }
inline auto CurrentMap() { return ClntCurMgr() ? ClntCurMgr()->mapId : 0; }

inline auto GetLocalPlayerGuid() { return ClntCurMgr() ? ClntCurMgr()->activePlayer : 0; }

inline auto GetObjectPtr(uint64 guid)
{
	return  ((int(__stdcall*)(uint64))0x00464870)(guid);	//there is already a check for guid == 0 in GetObjectPtr
}

inline auto GetLocalPlayer()
{
	return ClntCurMgr() ? GetObjectPtr(ClntCurMgr()->activePlayer) : 0;
}

inline int PerformanceCount() { return ((int(__cdecl*)())0x0042C010)(); }

inline void FramescriptExecute(const char* text)
{
	((void(__fastcall*)(const char*, const char*))0x00704CD0)(text, text);
}