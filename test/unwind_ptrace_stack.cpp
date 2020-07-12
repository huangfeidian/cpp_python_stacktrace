#include <iostream>
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <cxxabi.h>
#include <cstdio>

int wait4stop(pid_t pid) {
	int status = 99;
	do {
		if (waitpid(pid, &status, 0) == -1 || WIFEXITED(status) || WIFSIGNALED(status))
			return 0;
	} while (!WIFSTOPPED(status));
	return 1;
}

void print_backtrace(unw_cursor_t* cursor)
{
	char symbol_name[512];
	while (unw_step(cursor) > 0) {
		unw_word_t ip, sp, offset;
		unw_get_reg(cursor, UNW_REG_IP, &ip);
		if (ip == 0) {
			std::printf("pc is 0\n");
			break;
		}
		std::printf("0x%lx:", ip);

		if (unw_get_proc_name(cursor, symbol_name, sizeof(symbol_name), &offset) == 0) {
			char* nameptr = symbol_name;
			int status;
			char* demangled = abi::__cxa_demangle(symbol_name, nullptr, nullptr, &status);
			if (status == 0) {
				nameptr = demangled;
			}
			std::printf(" (%s+0x%lx)\n", nameptr, offset);
			std::free(demangled);
		}
		else {
			std::printf(" -- error: unable to obtain symbol name for this frame\n");
		}
	}
}
void get_backtrace(pid_t pid) {
	unw_cursor_t cursor;
	unw_word_t ip, sp, off;

	unw_addr_space_t addr_space = unw_create_addr_space(&_UPT_accessors, __BYTE_ORDER__);
	if (!addr_space)
		std::cerr << "Failed to create address space" << std::endl;


	if (-1 == ptrace(PTRACE_ATTACH, pid, nullptr, nullptr))
	{
		std::cerr << "Failed to ptrace" << std::endl;
		return;
	}


	if (!wait4stop(pid))
	{
		std::cerr << "wait SIGSTOP of ptrace failed" << std::endl;
		ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
		return;
	}

	void* rctx = _UPT_create(pid);

	if (rctx == nullptr)
	{
		std::cerr << "Failed to _UPT_create" << std::endl;
	}
	else
	{
		if (unw_init_remote(&cursor, addr_space, rctx))
		{
			std::cerr << "unw_init_remote failed" << std::endl;
		}
		else
		{
			print_backtrace(&cursor);
		}

		_UPT_resume(addr_space, &cursor, rctx);
		_UPT_destroy(rctx);
	}

	// 然后是将进程结束中断
	ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
}

int main(int argc, char** argv) {
	if (argc < 2)
		std::cerr << "please input pid" << std::endl;

	pid_t pid = std::atoi(argv[1]);
	get_backtrace(pid);
	return 0;
}