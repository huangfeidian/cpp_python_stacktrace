#pragma once

#include <stdexcept>
#include <string>
namespace spiritsaway::cpy_frame
{
	class PtraceException : public std::runtime_error
	{
	public:
		explicit PtraceException(const std::string &what_arg)
			: std::runtime_error(what_arg)
		{
		}
	};
	class TerminateException : public std::runtime_error
	{
	public:
		explicit TerminateException(const std::string &what_arg)
			: std::runtime_error(what_arg)
		{
		}
	};

	// An unexpected exception, indicating that Pyflame should exit with non-zero
	// status.
	class FatalException : public std::runtime_error
	{
	public:
		explicit FatalException(const std::string &what_arg)
			: std::runtime_error(what_arg)
		{
		}
	};

	class SymbolException : public FatalException
	{
	public:
		explicit SymbolException(const std::string &what_arg)
			: FatalException(what_arg)
		{
		}
	};
} // namespace spiritsaway::cpy_frame