#pragma once
#pragma warning(disable : 4996) //_CRT_SECURE_NO_WARNINGS

#include <fstream>
#include <iostream>
#include <string>
#include <time.h>
#include<stdarg.h>
#include<iomanip>
#include <chrono>
#include <sstream>

template<typename K, typename V>
inline auto typetostring(const K key, const V value)
{
	std::ostringstream sskey;
	std::ostringstream ssvalue;
	sskey << key;
	ssvalue << value;
	return sskey.str() + " = " + ssvalue.str();
}

std::string time_in_HH_MM_SS_MMM()
{
	using namespace std::chrono;
	
	auto now = system_clock::now();	
	auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;	
	auto timer = system_clock::to_time_t(now);	
	std::tm bt = *std::localtime(&timer);

	std::ostringstream oss{};

	oss << std::put_time(&bt, "%T"); // HH:MM:SS
	oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

	return oss.str();
}

class Log
{
private:
	std::ofstream logFile;
public:
	Log()
	{
		logFile.open("Log.txt", std::ios::out | std::ios::trunc);
	}

	~Log()
	{
		logFile.close();
	}

	template<typename K, typename V>
	void add(const K key, const V value)
	{
		logFile << time_in_HH_MM_SS_MMM() << " -->  ";
		logFile << typetostring(key, value) << "\n";
	}
};

Log logger{};