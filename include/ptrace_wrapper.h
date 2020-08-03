#pragma once
#include <sys/types.h>
#include <sys/user.h>
#include <unistd.h>
#include <tl/expected.hpp>
#include <memory>

namespace spiritsaway::cpy_frame
{
#ifdef __arm__
	using user_regs_struct = user_regs;
#endif // __arm__
	user_regs_struct ptrace_get_regs(pid_t pid);
	std::string ptrace_peek_string(pid_t, void* addr);
	std::unique_ptr<uint8_t[]> ptrace_peek_bytes(pid_t pid, void* addr, std::size_t n_bytes);
	void ptrace_cleanup(pid_t pid);
	void ptrace_attach(pid_t pid);
	void ptrace_detach(pid_t pid);
	long ptrace_peek(pid_t pid, void* addr);
	void* ptrace_peek_ptr(pid_t pid, void* addr);
	void ptrace_condition(pid_t pid);
	void ptrace_interrupt(pid_t pid);
	long ptrace_call_function(pid_t pid, long);
	void ptrace_poke(pid_t pid, void* addr, void* data);
	void ptrace_set_regs(pid_t pid, user_regs_struct regs);
	void ptrace_single_step(pid_t pid);

}