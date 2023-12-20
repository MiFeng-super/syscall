#include <iostream>
#include <syscall_def.hpp>

using namespace std;

int main(int argc, char** argv)
{
    syscall::initialize();

    const auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());

    std::cout << std::hex << syscall::ZwClose(hProcess);

    syscall::destroy();

    return 0;
}
