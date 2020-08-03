#include <python_frame.h>
#include <iostream>
using namespace spiritsaway;

int main(int argc, char** argv)
{
	//if (argc != 2)
	//{
	//	std::cerr << "should provide a pid as argument" << std::endl;
	//	return 1;
	//}
	//auto pid = std::strtol(argv[1], nullptr, 10);
	//if (pid <= 0 || pid > std::numeric_limits<pid_t>::max())
	//{
	//	std::cerr << "Error: failed to parse \"" << argv[1] << "\" as a PID.\n\n";
	//}
	auto py_threads = cpy_frame::dump_py_threads(21753, true);
	for (auto one_py_thread : py_threads)
	{
		std::cout << one_py_thread << std::endl;
	}
	return 0;
}