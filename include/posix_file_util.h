#pragma once

#include <sys/stat.h>
#include <sys/types.h>

#include <string>

namespace spiritsaway::cpy_frame
{
	int OpenRdonly(const char *path);
	void Close(int fd);

	void Fstat(int fd, struct stat *buf);
	void Lstat(const char *path, struct stat *buf);

	void SetNs(int fd);

	std::string ReadLink(const char *path);
	class Namespace 
	{
	public:
		Namespace() = delete;
		explicit Namespace(pid_t pid);
		~Namespace();

		// Get a file descriptor in the namespace
		int Open(const char *path);

	private:
		int out_;  // file descriptor that lets us return to our original namespace
		int in_;   // file descriptor that lets us enter the target namespace
	};
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
	/*  Define setns() if missing from the C library */
#include <error.h>
	static inline int setns(int fd, int nstype)
	{
#ifdef __NR_setns
		return syscall(__NR_setns, fd, nstype);
#elif defined(__NR_set_ns)
		return syscall(__NR_set_ns, fd, nstype);
#else
		errno = ENOSYS;
		return -1;
#endif
	}
#endif
}