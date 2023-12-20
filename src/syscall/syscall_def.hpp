#pragma once

#include <syscall.hpp>

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