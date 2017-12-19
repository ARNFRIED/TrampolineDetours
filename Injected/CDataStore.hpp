#pragma once
#include "Structs.h"

struct CDataStore
{
	int vTable;
	byte* buffer;		//4
	int base;			//8
	int allocated;		//0xC
	int written;		//0x10
	int readed;			//0x14

	CDataStore() :
		vTable{ 0x007FF9E4 },
		buffer{ new byte[0x100] },	//TODO: Optimize this
		base{},
		allocated{ 0x100 },
		written{},
		readed{ -1 }
	{
	}

	~CDataStore()
	{
		delete buffer;
	}
};

class DataStore
{
public:
	DataStore(int opcode)
	{
		Write<int>(opcode);
	}

	DataStore(CDataStore* pdata)
	{
		pointer = pdata;
	}

	~DataStore()
	{

	}

	template<typename T>
	T Read()
	{
		T result = *(T*)(data.buffer + data.readed);
		data.readed += sizeof(T);
		return result;
	}

	template<typename T>
	T Peek()
	{
		T result = *(T*)(pointer->buffer + pointer->readed);
		fake_readed += sizeof(T);
		return result;
	}

	template<typename T>
	void Write(T value)
	{
		// if(data->written + sizeof(T) > data->allocated) --- TODO: See the 3rd vfunc with IDA
		*(T*)(data.buffer + data.written) = value;
		data.written += sizeof(T);
		return;
	}

	auto WritePackedGuid(uint64 guid)
	{
		std::vector<byte> packGUID{};
		packGUID.push_back(0);
		auto g = guid;

		for (int i = 0; g != 0; ++i)
		{
			if ((g & 0xFF) != 0)
			{
				packGUID[0] |= (byte)(1 << i);
				packGUID.push_back((byte)(g & 0xFF));
			}
			g >>= 8;
		}

		for (auto b : packGUID)
		{
			Write<byte>(b);
		}
	}

	auto Send()
	{
		data.readed = 0;
		((void(__thiscall*)(int, CDataStore&))0x005379A0)(*(int*)0x00C28128, data);
	}

private:
	CDataStore* pointer;
	CDataStore data;
	int fake_readed;
};