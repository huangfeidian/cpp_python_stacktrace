#include <python_frame.h>
#include <tl/expected.hpp>
#include <sstream>
#include <fstream>

#include <ptrace_wrapper.h>

#include <python2.7/Python.h>
#include <python2.7/frameobject.h>

using namespace spiritsaway::cpy_frame;

// return the aslr address of libpython in dest process
// read the maps file to get so begin address
tl::expected<std::size_t, std::string> locate_lib_python(pid_t pid, const std::string& hint, std::string& path)
{
    std::ostringstream ss;
    ss << "/proc/" << pid << "/maps";
    std::ifstream fp(ss.str());
    std::string line;
    std::string elf_path;
    while (std::getline(fp, line)) {
        if (line.find(hint) != std::string::npos &&
            line.find(" r-xp ") != std::string::npos) {
            size_t pos = line.find('/');
            if (pos == std::string::npos) {
                return tl::make_unexpected("Did not find libpython absolute path");
            }
            path = line.substr(pos);
            pos = line.find('-');
            if (pos == std::string::npos) {
                return tl::make_unexpected("Did not find libpython virtual memory address");
            }
            return std::strtoul(line.substr(0, pos).c_str(), nullptr, 16);
        }
    }
    return 0;
}
unsigned long StringSize(unsigned long addr)
{
    return addr + offsetof(PyStringObject, ob_size);
}

unsigned long ByteData(unsigned long addr)
{
    return addr + offsetof(PyStringObject, ob_sval);
}

std::optional<std::string> StringData(pid_t pid, unsigned long addr)
{
    return ptrace_peek_string(pid, reinterpret_cast<void*>(ByteData(addr)));
}


// Extract the line number from the code object. Python uses a compressed table
// data structure to store line numbers. See:
//
// https://svn.python.org/projects/python/trunk/Objects/lnotab_notes.txt
//
// This is essentially an implementation of PyFrame_GetLineNumber /
// PyCode_Addr2Line.
size_t GetLine(pid_t pid, unsigned long frame, unsigned long f_code)
{
    long f_trace;
    const long f_trace = ptrace_peek(pid, frame + offsetof(_frame, f_trace));
    if (f_trace) {
        return static_cast<size_t>(
            PtracePeek(pid, frame + offsetof(_frame, f_lineno)) &
            std::numeric_limits<decltype(_frame::f_lineno)>::max());
    }

    const int f_lasti = PtracePeek(pid, frame + offsetof(_frame, f_lasti)) &
        std::numeric_limits<int>::max();
    const long co_lnotab =
        PtracePeek(pid, f_code + offsetof(PyCodeObject, co_lnotab));

    int size =
        PtracePeek(pid, StringSize(co_lnotab)) & std::numeric_limits<int>::max();
    int line = PtracePeek(pid, f_code + offsetof(PyCodeObject, co_firstlineno)) &
        std::numeric_limits<int>::max();
    const std::unique_ptr<uint8_t[]> tbl =
        PtracePeekBytes(pid, ByteData(co_lnotab), size);
    size /= 2;  // since we increment twice in each loop iteration
    const uint8_t* p = tbl.get();
    int addr = 0;
    while (--size >= 0) {
        addr += *p++;
        if (addr > f_lasti) {
            break;
        }
        line += *p++;
    }
    return static_cast<size_t>(line);
}
