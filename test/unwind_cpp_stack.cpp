#define UNW_LOCAL_ONLY
#include <cxxabi.h>
#include <libunwind.h>
#include <cstdio>
#include <cstdlib>


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

void backtrace() {
  unw_cursor_t cursor;
  unw_context_t context;
// Initialize cursor to current frame for local unwinding.
  unw_getcontext(&context);
  unw_init_local(&cursor, &context);
// Unwind frames one by one, going up the frame stack.
  print_backtrace(&cursor);
}
namespace ns {
template <typename T, typename U>
void foo(T t, U u) {
  backtrace(); // <-------- backtrace here!
}
}  // namespace ns
template <typename T>
struct Klass {
  T t;
  void bar() {
    ns::foo(t, true);
  }
};
int main(int argc, char** argv) {
  Klass<double> k;
  k.bar();
return 0;
}
