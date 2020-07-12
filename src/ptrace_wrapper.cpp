#include <ptrace_wrapper.h>

#include <dirent.h>

#include <cassert>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>

using namespace std;
using namespace spiritsaway::cpy_frame;
using namespace tl;

string ptrace_condition(pid_t pid)
{
	if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
		std::ostringstream ss;
		ss << "Failed to PTRACE_CONT: " << strerror(errno);
		return ss.str();
	}
	else
	{
		return std::string();
	}
}
expected<int, string> ptrace_wait(pid_t pid, int options)
{
	int status;
	std::ostringstream ss;
	for (;;) {
		pid_t progeny = waitpid(pid, &status, options);
		if (progeny == -1) {
			ss << "Failed to waitpid(): " << strerror(errno);
			return make_unexpected(ss.str());
		}
		assert(progeny == pid);
		if (WIFSTOPPED(status)) {
			int signum = WSTOPSIG(status);
			if (signum == SIGTRAP) {
				break;
			}
			else if (signum == SIGCHLD) {
				auto cond_result = ptrace_condition(pid);
				if (cond_result.empty())
				{
					continue;
				}
				else
				{
					return make_unexpected(cond_result);
				}
			}
			ss << "waitpid() indicated a WIFSTOPPED process, but got unexpected "
				"signal "
				<< signum;
			return make_unexpected(ss.str());
		}
		else if (WIFEXITED(status)) {
			ss << "Child process " << pid << " exited with status "
				<< WEXITSTATUS(status);
			return make_unexpected(ss.str());
		}
		else {
			ss << "Child process " << pid
				<< " returned an unexpected waitpid() code: " << status;
			return make_unexpected(ss.str());
		}
	}
	return status;
}

std::string ptrace_attach(pid_t pid)
{
	if (ptrace(PTRACE_ATTACH, pid, 0, 0)) 
	{
		std::ostringstream ss;
		ss << "Failed to attach to PID " << pid << ": " << strerror(errno);
		return ss.str();
	}
	int status;
	if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) 
	{
		std::ostringstream ss;
		ss << "Failed to wait on PID " << pid << ": " << strerror(errno);
		return ss.str();
	}
	return std::string();
}

std::string ptrace_detach(pid_t pid)
{
	if (ptrace(PTRACE_DETACH, pid, 0, 0)) {
		std::ostringstream ss;
		ss << "Failed to detach PID " << pid << ": " << strerror(errno);
		return ss.str();
	}
	return std::string();
}

bool ptrace_peek(pid_t pid, void* addr, long& data)
{
	errno = 0;
	data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
	if (data == -1 && errno != 0)
	{
		return false;
	}
	return true;
}

std::optional<std::string> ptrace_peek_string(pid_t pid, void* addr, std::size_t n_bytes)
{
	ostringstream dump;
	unsigned long off = 0;
	long val;
	while (true)
	{
		if (!ptrace_peek(pid, addr + off, val))
		{
			return {};
		}
		std::string chunk(reinterpret_cast<const char*>(&val), sizeof(val));
		dump << chunk.c_str();
		if (chunk.find_first_of('\0') != string::npos)
		{
			break;
		}
		off += sizeof(val);
	}
	return dump.str();
}


std::unique_ptr<uint8_t[]> ptrace_peek_bytes(pid_t pid, void* addr, std::size_t n_bytes)
{
	// align the buffer to a word size
	if (n_bytes % sizeof(long)) {
		n_bytes = (n_bytes / sizeof(long) + 1) * sizeof(long);
	}
	std::unique_ptr<uint8_t[]> bytes(new uint8_t[n_bytes]);

	size_t off = 0;
	long val;
	while (off < n_bytes) 
	{
		if (!ptrace_peek(pid, addr + off, val))
		{
			return {};
		}
		memmove(bytes.get() + off, &val, sizeof(val));
		off += sizeof(val);
	}
	return bytes;
}

void ptrace_cleanup(pid_t pid)
{
	ptrace_detach(pid);
	return;
}