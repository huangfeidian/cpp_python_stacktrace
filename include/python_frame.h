#pragma once
#include <string>
#include <ostream>
#include "elf_utils.h"
namespace spiritsaway::cpy_frame
{
	// Maximum number of times to retry checking for Python symbols when -p is used.
#define MAX_ATTACH_RETRIES 1

// Maximum number of times to retry checking for Python symbols when -t is used.
#define MAX_TRACE_RETRIES 50

	std::size_t locate_lib_python(pid_t pid, const std::string& hint, std::string& path);
	

	struct pyframe
	{
		void* addr;
		std::string file;
		std::string name;
		std::size_t line;
		inline bool operator==(const pyframe& other) const
		{
			return file == other.file && line == other.line;
		}

		friend std::ostream& operator<<(std::ostream& os, const pyframe& fr)
		{
			os << "frame file " << fr.file << " name "<<fr.name<<" line " << fr.line << " addr " << fr.addr << std::endl;
			return os;
		}

	};
	using pyframes_t = std::vector<pyframe>;
	struct pyframe_hash
	{
		std::size_t operator()(const pyframes_t& _fr_v) const
		{
			std::size_t hash = 0;
			for (size_t i = 0; i < _fr_v.size(); i++)
			{
				hash ^= std::hash<size_t>()(i);
				hash ^= std::hash<std::string>()(_fr_v[i].file);
			}
			return hash;
		}
	};
	pyframes_t trace_py_frames(pid_t pid, void* frame_addr);

	struct py_thread
	{
		void* id;
		bool is_current;
		pyframes_t frames;
		friend std::ostream& operator<<(std::ostream& os, const py_thread& this_py_thread)
		{
			os << this_py_thread.id;
			if (this_py_thread.is_current)
			{
				os << '*';
			}
			os << ';' << std::endl;
			for (const auto& frame : this_py_thread.frames)
			{
				os << frame << std::endl;
			}
			return os;
		}
	};
	std::vector<py_thread> trace_py_threads(pid_t pid, PyAddresses py_addr, bool enable_py_threads);

	std::vector<py_thread> dump_py_threads(pid_t pid, bool enable_py_threads);
}