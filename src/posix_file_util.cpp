#include <sstream>
#include <string>
#include <cstring>
#include <iostream>

#include <fcntl.h>
#include <limits.h>
#include <unistd.h>

#include <posix_file_util.h>
#include <custom_exceptions.h>


namespace
{
    const char kOurMnt[] = "/proc/self/ns/mnt";

}
namespace spiritsaway::cpy_frame
{
int OpenRdonly(const char *path)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		std::ostringstream ss;
		ss << "Failed to open " << path << ": " << strerror(errno);
		throw FatalException(ss.str());
	}
	return fd;
}


void Close(int fd)
{
	if (fd < 0)
	{
		return;
	}
	while (close(fd) == -1)
		;
}

void Fstat(int fd, struct stat *buf)
{
	if (fstat(fd, buf) < 0)
	{
		std::ostringstream ss;
		ss << "Failed to fstat file descriptor " << fd << ": " << strerror(errno);
		throw FatalException(ss.str());
	}
}

void Lstat(const char *path, struct stat *buf)
{
	if (lstat(path, buf) < 0)
	{
		std::ostringstream ss;
		ss << "Failed to lstat path " << path << ": " << strerror(errno);
		throw FatalException(ss.str());
	}
}

void SetNs(int fd)
{
	if (setns(fd, 0))
	{
		std::ostringstream ss;
		ss << "Failed to setns " << fd << ": " << strerror(errno);
		throw FatalException(ss.str());
	}
}

std::string ReadLink(const char *path)
{
	char buf[PATH_MAX];
	ssize_t nbytes = readlink(path, buf, sizeof(buf));
	if (nbytes < 0)
	{
		std::ostringstream ss;
		ss << "Failed to read symlink " << path << ": " << strerror(errno);
		throw FatalException(ss.str());
	}
	buf[nbytes] = '\0';
	return {buf, static_cast<std::string::size_type>(nbytes)};
}

Namespace::Namespace(pid_t pid) : out_(-1), in_(-1)
{
    struct stat in_st;
    std::ostringstream os;
    os << "/proc/" << pid << "/ns/mnt";
    const std::string their_mnt = os.str();

    struct stat out_st;

    // In the case of no namespace support (ie ancient boxen), still make an
    // attempt to work
    if (lstat(kOurMnt, &out_st) < 0) {
        std::cerr << "Failed to lstat path " << kOurMnt << ": " << strerror(errno);
        out_ = in_ = -1;
        return;
    }

    // Since Linux 3.8 symbolic links are used.
    if (S_ISLNK(out_st.st_mode)) {
        char our_name[PATH_MAX];
        ssize_t ourlen = readlink(kOurMnt, our_name, sizeof(our_name));
        if (ourlen < 0) {
            std::ostringstream ss;
            ss << "Failed to readlink " << kOurMnt << ": " << strerror(errno);
            throw FatalException(ss.str());
        }
        our_name[ourlen] = '\0';

        char their_name[PATH_MAX];
        ssize_t theirlen =
            readlink(their_mnt.c_str(), their_name, sizeof(their_name));
        if (theirlen < 0) {
            std::ostringstream ss;
            ss << "Failed to readlink " << their_mnt.c_str() << ": "
                << strerror(errno);
            throw FatalException(ss.str());
        }
        their_name[theirlen] = '\0';

        if (strcmp(our_name, their_name) != 0) {
            out_ = OpenRdonly(kOurMnt);
            in_ = OpenRdonly(their_mnt.c_str());
        }
    }
    else {
        // Before Linux 3.8 these are hard links.
        out_ = OpenRdonly(kOurMnt);
        Fstat(out_, &out_st);

        in_ = OpenRdonly(os.str().c_str());
        Fstat(in_, &in_st);
        if (out_st.st_ino == in_st.st_ino) {
            Close(out_);
            Close(in_);
            out_ = in_ = -1;
        }
    }
}

int Namespace::Open(const char* path)
{
    if (in_ != -1) {
        SetNs(in_);
        int fd = open(path, O_RDONLY);
        SetNs(out_);
        return fd;
    }
    else {
        return open(path, O_RDONLY);
    }
}

Namespace::~Namespace()
{
    if (out_) {
        Close(out_);
        Close(in_);
    }
}
}