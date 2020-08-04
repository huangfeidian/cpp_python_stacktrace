

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

#include <ptrace_wrapper.h>
#include <custom_exceptions.h>

using namespace std;
namespace spiritsaway::cpy_frame
{
	user_regs_struct ptrace_get_regs(pid_t pid)
	{
		user_regs_struct regs;
		if (ptrace(PTRACE_GETREGS, pid, 0, &regs)) {
			std::ostringstream ss;
			ss << "Failed to PTRACE_GETREGS: " << strerror(errno);
			throw PtraceException(ss.str());
		}
		return regs;
	}


	void ptrace_condition(pid_t pid)
	{
		if (ptrace(PTRACE_CONT, pid, 0, 0) == -1) {
			std::ostringstream ss;
			ss << "Failed to PTRACE_CONT: " << strerror(errno);
			throw PtraceException(ss.str());
		}

	}
	void ptrace_wait(pid_t pid, int options = 0)
	{
		int status;
		std::ostringstream ss;
		for (;;) {
			pid_t progeny = waitpid(pid, &status, options);
			if (progeny == -1) {
				ss << "Failed to waitpid(): " << strerror(errno);
				throw PtraceException(ss.str());
			}
			assert(progeny == pid);
			if (WIFSTOPPED(status)) {
				int signum = WSTOPSIG(status);
				if (signum == SIGTRAP) {
					break;
				}
				else if (signum == SIGCHLD) {
					ptrace_condition(pid);  // see issue #122
					continue;
				}
				ss << "waitpid() indicated a WIFSTOPPED process, but got unexpected "
					"signal "
					<< signum;
				throw PtraceException(ss.str());
			}
			else if (WIFEXITED(status)) {
				ss << "Child process " << pid << " exited with status "
					<< WEXITSTATUS(status);
				throw TerminateException(ss.str());
			}
			else {
				ss << "Child process " << pid
					<< " returned an unexpected waitpid() code: " << status;
				throw PtraceException(ss.str());
			}
		}
	}
	void ptrace_interrupt(pid_t pid)
	{
		if (ptrace(PTRACE_INTERRUPT, pid, 0, 0)) {
			throw PtraceException("Failed to PTRACE_INTERRUPT");
		}
		ptrace_wait(pid);
	}
	void ptrace_attach(pid_t pid)
	{
		if (ptrace(PTRACE_ATTACH, pid, 0, 0)) {
			std::ostringstream ss;
			ss << "Failed to attach to PID " << pid << ": " << strerror(errno);
			throw PtraceException(ss.str());
		}
		int status;
		if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
			std::ostringstream ss;
			ss << "Failed to wait on PID " << pid << ": " << strerror(errno);
			throw PtraceException(ss.str());
		}
	}

	void ptrace_detach(pid_t pid)
	{
		if (ptrace(PTRACE_DETACH, pid, 0, 0)) {
			std::ostringstream ss;
			ss << "Failed to detach PID " << pid << ": " << strerror(errno);
			throw PtraceException(ss.str());
		}
	}

	long ptrace_peek(pid_t pid, void* addr)
	{
		errno = 0;
		long data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		if (data == -1 && errno != 0)
		{
			std::ostringstream ss;
			ss << "Failed to PTRACE_PEEKDATA (pid " << pid << ", addr "
				<< reinterpret_cast<void*>(addr) << "): " << strerror(errno);
			throw PtraceException(ss.str());
		}
		return data;
	}

	void* ptrace_peek_ptr(pid_t pid, void* addr)
	{
		errno = 0;
		long data = ptrace(PTRACE_PEEKDATA, pid, addr, 0);
		if (data == -1 && errno != 0)
		{
			std::ostringstream ss;
			ss << "Failed to PTRACE_PEEKDATA (pid " << pid << ", addr "
				<< reinterpret_cast<void*>(addr) << "): " << strerror(errno);
			throw PtraceException(ss.str());
		}
		return (void*)data;
	}
	std::string ptrace_peek_string(pid_t pid, void* addr)
	{
		std::ostringstream dump;
		unsigned long off = 0;
		while (true) {
			const long val = ptrace_peek(pid, addr + off);

			// XXX: this can be micro-optimized, c.f.
			// https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord
			const std::string chunk(reinterpret_cast<const char*>(&val), sizeof(val));
			dump << chunk.c_str();
			if (chunk.find_first_of('\0') != std::string::npos) {
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
		while (off < n_bytes) {
			const long val = ptrace_peek(pid, addr + off);
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
	void ptrace_poke(pid_t pid, void* addr, void* data)
	{
		if (ptrace(PTRACE_POKEDATA, pid, addr, (void*)data)) {
			std::ostringstream ss;
			ss << "Failed to PTRACE_POKEDATA at " << reinterpret_cast<void*>(addr)
				<< ": " << strerror(errno);
			throw PtraceException(ss.str());
		}

	}
	void ptrace_set_regs(pid_t pid, user_regs_struct regs)
	{
		if (ptrace(PTRACE_SETREGS, pid, 0, &regs)) {
			std::ostringstream ss;
			ss << "Failed to PTRACE_SETREGS: " << strerror(errno);
			throw PtraceException(ss.str());
		}
	}
	void ptrace_single_step(pid_t pid)
	{
		if (ptrace(PTRACE_SINGLESTEP, pid, 0, 0) == -1) {
			std::ostringstream ss;
			ss << "Failed to PTRACE_SINGLESTEP: " << strerror(errno);
			throw PtraceException(ss.str());
		}
		ptrace_wait(pid);
	}
	static const long syscall_x86 = 0x050f;  // x86 code for SYSCALL

	static unsigned long probe_ = 0;

	static unsigned long AllocPage(pid_t pid)
	{
		user_regs_struct oldregs = ptrace_get_regs(pid);
		// rip 指令为x64架构下的程序计数器 保存的是下一个要执行的指令id
		long orig_code = ptrace_peek(pid, (void*)oldregs.rip);
		ptrace_poke(pid, (void*)oldregs.rip, (void*)syscall_x86);
		// 这个是设置rip为syscall_x86 然后下面的参数是调用syscall 的相关参数
		// 意思就是分配一页内存区域
		user_regs_struct newregs = oldregs;
		newregs.rax = SYS_mmap;
		newregs.rdi = 0;                                   // addr
		newregs.rsi = getpagesize();                       // len
		newregs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
		newregs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;         // flags
		newregs.r8 = -1;                                   // fd
		newregs.r9 = 0;                                    // offset
		ptrace_set_regs(pid, newregs);
		// 设置好所有寄存器之后 单步执行这个系统调用
		ptrace_single_step(pid);
		// x64架构下 如果返回单个整数 结果会存储在rax寄存器里
		unsigned long result = ptrace_get_regs(pid).rax;
		// 再恢复原来的现场
		ptrace_set_regs(pid, oldregs);
		// 重新恢复之前的程序计数器
		ptrace_poke(pid, (void*)oldregs.rip, (void*)orig_code);

		return result;
	}

	static std::vector<pid_t> ListThreads(pid_t pid)
	{
		std::vector<pid_t> result;
		std::ostringstream dirname;
		dirname << "/proc/" << pid << "/task";
		DIR* dir = opendir(dirname.str().c_str());
		if (dir == nullptr) {
			throw PtraceException("Failed to list threads");
		}
		dirent* entry;
		while ((entry = readdir(dir)) != nullptr) {
			std::string name = entry->d_name;
			if (name != "." && name != "..") {
				result.push_back(static_cast<pid_t>(std::stoi(name)));
			}
		}
		return result;
	}

	static void PauseChildThreads(pid_t pid)
	{
		for (auto tid : ListThreads(pid)) {
			if (tid != pid) ptrace_attach(tid);
		}
	}

	static void ResumeChildThreads(pid_t pid)
	{
		for (auto tid : ListThreads(pid)) {
			if (tid != pid) ptrace_detach(tid);
		}
	}

	long ptrace_call_function(pid_t pid, long addr)
	{
		// 这里会预先分配一页内存区，然后内存区的前三个字节里有两个指令
		// 第一条是call rax 就是将rax里的函数指针执行
		// 第二条就是trap 相当于call rax之后进入中断
		if (probe_ == 0) {
			PauseChildThreads(pid);
			probe_ = AllocPage(pid);
			ResumeChildThreads(pid);
			if (probe_ == (unsigned long)MAP_FAILED) {
				return -1;
			}

			long code = 0;
			uint8_t* new_code_bytes = (uint8_t*)&code;
			new_code_bytes[0] = 0xff;  // CALL
			new_code_bytes[1] = 0xd0;  // rax
			new_code_bytes[2] = 0xcc;  // TRAP
			ptrace_poke(pid, (void*)probe_, (void*)code);
		}

		user_regs_struct oldregs = ptrace_get_regs(pid);
		user_regs_struct newregs = oldregs;
		// 这里的操作就是把返回地址寄存器rip的值设置为我们之前定好的prob
		// 同时设置rax为我们要调用的函数指针
		newregs.rax = addr;
		newregs.rip = probe_;
		// 设置好之后 恢复原来程序的执行
		// 恢复之后就会自动的执行addr对应的函数 然后进入中断
		ptrace_set_regs(pid, newregs);
		ptrace_condition(pid);
		ptrace_wait(pid);
		// 这里addr的函数执行完成，对应的返回值会再rax寄存器里
		newregs = ptrace_get_regs(pid);
		// 再恢复原来的现场
		ptrace_set_regs(pid, oldregs);

		// 目前的限制好像是必须调用的是无参数的函数
		return newregs.rax;
	};
}