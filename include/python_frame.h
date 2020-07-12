#pragma once
#include <string>
namespace spiritsaway::cpy_frame
{
	size_t LocateLibPython(pid_t pid, const std::string& hint, std::string* path);
}