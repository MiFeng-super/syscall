# syscall
Windows syscall

## 特性

* 可以直接调用当前系统中的所有 Zw 函数，您只需定义所需调用的函数
* 仅需要两个头文件

## 实现

### ssdt index 的获取

通过读取磁盘中的ntdll.dll文件，解析导出表以获取SSDT索引。

### 系统调用

* 在X86架构的Windows系统下，通过使用sysenter指令进入内核
* 在X64架构的Windows系统下，通过使用syscall指令进入内核

## 使用

您只需将syscall添加到您的项目中，并包含`syscall_def.hpp`头文件。在`syscall_def.hpp`中定义所需调用的函数。

```C++
namespace syscall 
{
    SYSCALL_INFO_BEGIN
    {
        SYSCALL_INFO(ZwClose),
        SYSCALL_INFO(ZwOpenProcess),
    };

    SYSCALL_FUNC(0xC00000BBL /* STATUS_NOT_SUPPORTED */, NTSTATUS, ZwClose);
    SYSCALL_FUNC(0xC00000BBL /* STATUS_NOT_SUPPORTED */, NTSTATUS, ZwOpenProcess);
}
```

```c++
#include <iostream>
#include <syscall_def.hpp>

int main(int argc, char** argv)
{
    syscall::initialize();

    const auto hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());

    std::cout << std::hex << syscall::ZwClose(hProcess);

    syscall::destroy();

    return 0;
}
```

