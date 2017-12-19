#pragma once
#include <map>
#include <string>
#include "Detour.hpp"
#include "Timer.hpp"
#include "WowFuncs.hpp"

volatile bool shouldRemoveEndSceneInjection{};
volatile bool endSceneUnhooked{};
volatile bool should_exit{};
volatile int frameCount{};
std::map<std::string, Detour*> detours{};

//---------------- END SCENE DETOUR ------------------
int __fastcall EndSceneDetour(int s_device, int edx)	//is a __thiscall
{
	if (*(int*)(s_device + 0x3A38))						//is device created?
	{
		if (GetLocalPlayer())							//are we in game?
		{
			if (frameCount == 0)						//do this only in the begin
			{
				FramescriptExecute("DEFAULT_CHAT_FRAME:AddMessage(\"|c00D358F7VanilaCPP|r loaded.\")");
			}
		}

		//---------------------------------
		// Do some stuff here
		//---------------------------------

		frameCount++;
	}

	//------------------------------------------------------------------------------------------------------------------	
	//------------------------------------------------------------------------------------------------------------------	
	//------------------------------------------------------------------------------------------------------------------	
	auto result = ((detours["CGxDeviceD3d__ISceneEnd"])->Call<decltype(EndSceneDetour)>)(s_device, edx);
	
	if (shouldRemoveEndSceneInjection)
	{
		if (GetLocalPlayer())							//are we in game?
		{
			FramescriptExecute("DEFAULT_CHAT_FRAME:AddMessage(\"|c00D358F7VanilaCPP|r unloaded.\")");
		}

		//remove end scene hook
		auto it = detours.find("CGxDeviceD3d__ISceneEnd");
		delete it->second;
		detours.erase(it);		
		endSceneUnhooked = true;
	}	

	return result;
}