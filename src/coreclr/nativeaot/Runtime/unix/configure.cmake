include(CheckCXXSourceCompiles)
include(CheckCXXSourceRuns)
include(CheckCXXSymbolExists)
include(CheckFunctionExists)
include(CheckIncludeFiles)
include(CheckStructHasMember)
include(CheckTypeSize)
include(CheckLibraryExists)

if(CMAKE_SYSTEM_NAME STREQUAL FreeBSD)
  set(CMAKE_REQUIRED_INCLUDES /usr/local/include)
elseif(NOT CMAKE_SYSTEM_NAME STREQUAL Darwin)
  set(CMAKE_REQUIRED_DEFINITIONS "-D_BSD_SOURCE -D_SVID_SOURCE -D_DEFAULT_SOURCE -D_POSIX_C_SOURCE=200809L")
endif()

list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_FILE_OFFSET_BITS=64)

check_include_files("sys/prctl.h" HAVE_PRCTL_H)
check_include_files("sys/ptrace.h" HAVE_SYS_PTRACE_H)
check_include_files("sys/auxv.h;asm/hwcap.h" HAVE_AUXV_HWCAP_H)

check_library_exists(pthread pthread_create "" HAVE_LIBPTHREAD)
check_library_exists(c pthread_create "" HAVE_PTHREAD_IN_LIBC)

if (HAVE_LIBPTHREAD)
  set(PTHREAD_LIBRARY pthread)
elseif (HAVE_PTHREAD_IN_LIBC)
  set(PTHREAD_LIBRARY c)
endif()

check_library_exists(${PTHREAD_LIBRARY} pthread_attr_get_np "" HAVE_PTHREAD_ATTR_GET_NP)
check_library_exists(${PTHREAD_LIBRARY} pthread_getattr_np "" HAVE_PTHREAD_GETATTR_NP)
check_library_exists(${PTHREAD_LIBRARY} pthread_condattr_setclock "" HAVE_PTHREAD_CONDATTR_SETCLOCK)
check_library_exists(${PTHREAD_LIBRARY} pthread_getthreadid_np "" HAVE_PTHREAD_GETTHREADID_NP)

check_function_exists(clock_nanosleep HAVE_CLOCK_NANOSLEEP)

check_include_files(ucontext.h HAVE_UCONTEXT_H)

if (HAVE_UCONTEXT_H)
  set(UCONTEXT_T_HEADER ucontext.h)
else ()
  set(UCONTEXT_T_HEADER signal.h)
endif ()

check_struct_has_member ("ucontext_t" uc_mcontext.gregs[0] ${UCONTEXT_T_HEADER} HAVE_GREGSET_T)
check_struct_has_member ("ucontext_t" uc_mcontext.__gregs[0] ${UCONTEXT_T_HEADER} HAVE___GREGSET_T)

set(CMAKE_EXTRA_INCLUDE_FILES)
set(CMAKE_EXTRA_INCLUDE_FILES signal.h)
check_type_size(siginfo_t SIGINFO_T)
set(CMAKE_EXTRA_INCLUDE_FILES)

check_cxx_source_compiles("
#include <lwp.h>

int main(int argc, char **argv)
{
    return (int)_lwp_self();
}" HAVE_LWP_SELF)

check_cxx_source_compiles("
#include <sys/prctl.h>

int main(int argc, char **argv)
{
    int flag = (int)PR_SET_PTRACER;
    return 0;
}" HAVE_PR_SET_PTRACER)

check_symbol_exists(
    clock_gettime_nsec_np
    time.h
    HAVE_CLOCK_GETTIME_NSEC_NP)

check_library_exists(c sched_getaffinity "" HAVE_SCHED_GETAFFINITY)

configure_file(${CMAKE_CURRENT_LIST_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)
