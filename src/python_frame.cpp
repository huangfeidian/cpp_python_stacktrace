

#include <sstream>
#include <fstream>
#include <iostream>
#include <thread>

#include <python2.7/Python.h>
#include <python2.7/frameobject.h>
#include <sys/ptrace.h>

#include <custom_exceptions.h>
#include <ptrace_wrapper.h>
#include <python_frame.h>
#include <posix_file_util.h>

namespace spiritsaway::cpy_frame
{

#define ENABLE_THREADS 1
    // return the aslr address of libpython in dest process
    // read the maps file to get so begin address
    std::size_t locate_lib_python(pid_t pid, const std::string& hint, std::string& path)
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
                    throw FatalException("Did not find libpython absolute path");
                }
                path = line.substr(pos);
                pos = line.find('-');
                if (pos == std::string::npos) {
                    throw FatalException("Did not find libpython virtual memory address");
                }
                return std::strtoul(line.substr(0, pos).c_str(), nullptr, 16);
            }
        }
        return 0;
    }
    void* StringSize(void* addr)
    {
        return addr + offsetof(PyStringObject, ob_size);
    }

    void* ByteData(void* addr)
    {
        return addr + offsetof(PyStringObject, ob_sval);
    }

    std::string StringData(pid_t pid, void* addr)
    {
        return ptrace_peek_string(pid, ByteData(addr));
    }


    // Extract the line number from the code object. Python uses a compressed table
    // data structure to store line numbers. See:
    //
    // https://svn.python.org/projects/python/trunk/Objects/lnotab_notes.txt
    //
    // This is essentially an implementation of PyFrame_GetLineNumber /
    // PyCode_Addr2Line.
    size_t GetLine(pid_t pid, void* frame, void* f_code)
    {
        const long f_trace = ptrace_peek(pid, frame + offsetof(_frame, f_trace));
        if (f_trace) {
            return static_cast<size_t>(
                ptrace_peek(pid, (frame + offsetof(_frame, f_lineno))) &
                std::numeric_limits<decltype(_frame::f_lineno)>::max());
        }

        const int f_lasti = ptrace_peek(pid, (frame + offsetof(_frame, f_lasti))) &
            std::numeric_limits<int>::max();
        void* co_lnotab = (void*)
            ptrace_peek(pid, (f_code + offsetof(PyCodeObject, co_lnotab)));

        int size =
            ptrace_peek(pid, (void*)(StringSize(co_lnotab))) & std::numeric_limits<int>::max();
        int line = ptrace_peek(pid, (f_code + offsetof(PyCodeObject, co_firstlineno))) &
            std::numeric_limits<int>::max();
        const std::unique_ptr<uint8_t[]> tbl =
            ptrace_peek_bytes(pid, (void*)(ByteData(co_lnotab)), size);
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

    pyframes_t trace_py_frames(pid_t pid, void* frame_addr)
    {
        void* f_back = nullptr;
        pyframes_t result;
        do
        {
            void* f_code = ptrace_peek_ptr(pid, frame_addr + offsetof(_frame, f_code));
            auto co_filename = ptrace_peek_ptr(pid, f_code + offsetof(PyCodeObject, co_filename));
            std::string filename = StringData(pid, co_filename);
            std::string name = StringData(pid, ptrace_peek_ptr(pid, f_code + offsetof(PyCodeObject, co_name)));
            result.push_back({ frame_addr, filename, name, GetLine(pid, frame_addr , f_code) });
            f_back = ptrace_peek_ptr(pid, frame_addr + offsetof(_frame, f_back));
            frame_addr = f_back;
        }
        while (frame_addr);
        return result;
    }

    std::vector<py_thread> trace_py_threads(pid_t pid, PyAddresses addrs, bool enable_py_threads)
    {
        // Pointer to the current interpreter state. Python has a very rarely used
      // feature called "sub-interpreters", Pyflame only supports profiling a single
      // sub-interpreter.
        void* istate = nullptr;

        // First try to get interpreter state via dereferencing
        // _Pypy_threadState_Current. This won't work if the main py_thread doesn't hold
        // the GIL (_Current will be null).
        void* tstate = ptrace_peek_ptr(pid, addrs.tstate_addr);
        std::cout << "tstate phase 1 " << tstate << std::endl;
        void* current_tstate = tstate;
        if (enable_py_threads) {
            if (tstate != nullptr) {
                istate = ptrace_peek_ptr(pid, tstate + offsetof(PyThreadState, interp));
                std::cout << "istate phase 1" << istate << std::endl;
                // Secondly try to get it via the static interp_head symbol, if we managed
                // to find it:
                //  - interp_head is not strictly speaking part of the public API so it
                //    might get removed!
                //  - interp_head is not part of the dynamic symbol table, so e.g. strip
                //    will drop it
            }
            else if (addrs.interp_head_addr != nullptr) {
                istate =
                    ptrace_peek_ptr(pid, addrs.interp_head_addr);
                std::cout << "istate phase 2" << istate << std::endl;

            }
            else if (addrs.interp_head_hint != nullptr) {
                // Finally. check if we have already put a hint into interp_head_hint -
                // currently this can only happen if we called PyInterpreterState_Head.
                istate = addrs.interp_head_hint;
                std::cout << "istate phase 3" << istate << std::endl;

            }
            if (istate != nullptr) {
                tstate = ptrace_peek_ptr(pid, istate + offsetof(PyInterpreterState, tstate_head));
                std::cout << "tstate phase 2 " << tstate << std::endl;

            }
        }

        // Walk the py_thread list.
        std::vector<py_thread> py_threads;
        std::cout << "trace thread tstate " << tstate << std::endl;

        while (tstate != nullptr) {
            std::cout << "trace thread tstate " << tstate << std::endl;
            void* id =
                ptrace_peek_ptr(pid, tstate + offsetof(PyThreadState, thread_id));
            const bool is_current = tstate == current_tstate;

            // Dereference the py_thread's current frame.
            std::cout << "trace thread step 2" << std::endl;
            auto frame_addr = ptrace_peek_ptr(pid, tstate + offsetof(PyThreadState, frame));

            if (frame_addr != nullptr) {
                std::cout << "trace thread step 3" << std::endl;

                py_threads.push_back({ id, is_current, trace_py_frames(pid, frame_addr) });
            }
            std::cout << "trace thread step 4" << std::endl;

            if (enable_py_threads) {
                tstate = ptrace_peek_ptr(pid, tstate + offsetof(PyThreadState, next));
            }
            else {
                tstate = nullptr;
            }
        };

        return py_threads;
    }

    // locate within libpython
    PyAddresses AddressesFromLibPython(pid_t pid, const std::string& libpython,
        Namespace* ns, PyABI* abi)
    {
        std::string elf_path;
        const size_t offset = locate_lib_python(pid, libpython, elf_path);
        if (offset == 0) {
            std::ostringstream ss;
            ss << "Failed to locate libpython named " << libpython;
            throw SymbolException(ss.str());
        }

        ELF pyelf;
        pyelf.Open(elf_path, ns);
        pyelf.Parse();
        const PyAddresses addrs = pyelf.GetAddresses(abi);
        if (addrs.empty()) {
            throw SymbolException("Failed to locate addresses");
        }
        return addrs + offset;
    }

    PyAddresses Addrs(pid_t pid, Namespace* ns, PyABI* abi)
    {
        std::ostringstream ss;
        ss << "/proc/" << pid << "/exe";
        ELF target;
        std::string exe = ReadLink(ss.str().c_str());
        target.Open(exe, ns);
        target.Parse();

        // There's two different cases here. The default way Python is compiled you
        // get a "static" build which means that you get a big several-megabytes
        // Python executable that has all of the symbols statically built in. For
        // instance, this is how Python is built on Debian and Ubuntu. This is the
        // easiest case to handle, since in this case there are no tricks, we just
        // need to find the symbol in the ELF file.
        //
        // There's also a configure option called --enable-shared where you get a
        // small several-kilobytes Python executable that links against a
        // several-megabytes libpython2.7.so. This is how Python is built on Fedora.
        // If that's the case we need to do some fiddly things to find the true symbol
        // location.
        //
        // The code here attempts to detect if the executable links against
        // libpython2.7.so, and if it does the libpython variable will be filled with
        // the full soname. That determines where we need to look to find our symbol
        // table.

        PyAddresses addrs = target.GetAddresses(abi);
        if (addrs) {
            if (addrs.pie) {
                // If Python executable is PIE, add offsets
                std::string elf_path;
                const size_t offset = locate_lib_python(pid, exe, elf_path);
                return addrs + offset;
            }
            else {
                return addrs;
            }
        }

        std::string libpython;
        for (const auto& lib : target.NeededLibs()) {
            if (lib.find("libpython") != std::string::npos) {
                libpython = lib;
                break;
            }
        }
        if (!libpython.empty()) {
            return AddressesFromLibPython(pid, libpython, ns, abi);
        }
        // A process like uwsgi may use dlopen() to load libpython... let's just guess
        // that the DSO is called libpython2.7.so
        //
        // XXX: this won't work if the embedding language is Python 3
        return AddressesFromLibPython(pid, "libpython2.7.so", ns, abi);
    }

    int set_addrs_(pid_t pid_, PyABI* abi, PyAddresses& addrs_)
    {
        Namespace ns(pid_);
        try {
            addrs_ = Addrs(pid_, &ns, abi);
        }
        catch (const SymbolException& exc) {
            return 1;
        }
#if ENABLE_THREADS
        // If we didn't find the interp_head address, but we did find the public
        // PyInterpreterState_Head
        // function, use evil non-portable ptrace tricks to call the function
        if (addrs_.interp_head_addr == 0 &&
            addrs_.interp_head_hint == 0 && addrs_.interp_head_fn_addr != 0) {
            addrs_.interp_head_hint =
               (void*)(ptrace_call_function(pid_, (long)addrs_.interp_head_fn_addr));
        }
#endif
        return 0;
    }

    int detect_python_abi(PyABI abi, PyAddresses& addrs_, pid_t pid)
    {
        // Set up the function pointers. By default, we auto-detect the ABI. If an ABI
     // is explicitly passed to us, then use that one (even though it could be
     // wrong)!
        if (set_addrs_(pid, abi == PyABI::Unknown ? &abi : nullptr, addrs_)) {
            return 1;
        }
        if (abi != PyABI::Py26)
        {
            throw FatalException("only py2.7 is allowed");
        }
        if (addrs_.empty()) {
            throw FatalException("DetectABI(): addrs_ is unexpectedly empty.");
        }
        return 0;
    }

    std::vector<py_thread> dump_py_threads(pid_t pid, bool enable_py_threads)
    {

        if (ptrace(PTRACE_SEIZE, pid, 0, 0))
        {
            std::cerr << "Failed to seize PID " << pid << std::endl;
            throw PtraceException("fail to PTRACE_SEIZE");
        }
        if (ptrace(PTRACE_INTERRUPT, pid, 0, 0))
        {
            std::cerr << "fail to PTRACE_INTERRUPT" << pid << std::endl;
            throw PtraceException("fail to PTRACE_INTERRUPT ");
        }
        std::cout << "suc ptrace target process" << std::endl;
        PyABI abi;
        PyAddresses addrs;
        int max_retry = 50;
        int i = 0;
        for (; i < max_retry; i++)
        {
            if (detect_python_abi(abi, addrs, pid))
            {
                if (i == max_retry - 1)
                {
                    throw PtraceException("fail to detect python abi with max retry");

                }
                ptrace_condition(pid);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                ptrace_interrupt(pid);

            }
            else
            {
                break;
            }

        }
        std::cout << "suc to detect target python abi with iteration " <<i<< std::endl;
        std::cout << addrs << std::endl;
        return trace_py_threads(pid, addrs, enable_py_threads);
    }

}