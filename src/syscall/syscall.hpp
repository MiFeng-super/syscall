#pragma once

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <windows.h>


#define SYSCALL_INFO_BEGIN \
     inline std::unordered_map<uint32_t, void*> detail::funcInfo = 

#define SYSCALL_INFO(funcName) \
    std::pair<uint32_t, void*>{ detail::hash_const("" #funcName ""), nullptr }

#define SYSCALL_FUNC(Default, ReturnT, funcName) \
    template<typename... Args> \
    ReturnT funcName (Args... args) { \
        if (const auto func = detail::getFuncAddress(detail::hash_const("" #funcName ""))) \
        {\
            return detail::nativeCall<ReturnT>(func, args...);\
        }\
        if constexpr (!std::is_same_v<void, ReturnT>) \
        {\
            return Default;\
        }\
    } 


#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_Start() X64_Start_with_CS(0x33)
#define X64_End() X64_End_with_CS(0x23)

#define _RAX  0
#define _RCX  1
#define _RDX  2
#define _RBX  3
#define _RSP  4
#define _RBP  5
#define _RSI  6
#define _RDI  7
#define _R8   8
#define _R9   9
#define _R10 10
#define _R11 11
#define _R12 12
#define _R13 13
#define _R14 14
#define _R15 15

#define X64_Push(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x50 | ((r) & 7))
#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm

union reg64
{
	DWORD64 v;
	DWORD dw[2];
};

namespace syscall 
{
    namespace detail
    {
        inline bool     isArch64;
        inline bool     isWow64;
        inline HANDLE   hHeap = nullptr;

        extern std::unordered_map<uint32_t, void*> funcInfo;

        struct hash_const
        {
            uint32_t result;
            template <uint32_t len>
            constexpr __forceinline hash_const(const char(&e)[len]) : hash_const(e, std::make_index_sequence<len - 1>()) {}
            template <uint32_t len>
            constexpr __forceinline hash_const(const wchar_t(&e)[len]) : hash_const(e, std::make_index_sequence<len - 1>()) {}
            template <typename T, uint32_t len>
            constexpr __forceinline hash_const(const T(&e)[len]) : hash_const(e, std::make_index_sequence<len>()) {}
            template <typename T, uint32_t... ids>
            constexpr __forceinline hash_const(const T e, std::index_sequence<ids...>) : hash_const(0, e[ids]...) {}
            template <typename T, typename... T_>
            constexpr __forceinline hash_const(uint32_t result_, const T elem, const T_... elems) : hash_const(((result_ >> 13) | (result_ << 19)) + elem, elems...) {}
            constexpr __forceinline hash_const(uint32_t result_) : result(result_) {}
            operator uint32_t () { return result; }
        };

        struct hash_dynamic
        {
            uint32_t result;

            template <typename T, typename = std::enable_if_t<std::is_same_v<T, char> | std::is_same_v<T, wchar_t>>>
            hash_dynamic(const T* str)
                : result(0)
            {
                while (*str)
                {
                    result = ((result >> 13) | (result << 19)) + *str;
                    str++;
                }
            }
            template <typename T>
            hash_dynamic(const T* elems, size_t size)
                : result(0)
            {
                for (size_t i = 0; i < size; i++)
                {
                    result = ((result >> 13) | (result << 19)) + elems[i];
                }
            }
            operator uint32_t () { return result; }
        };

        namespace AnyCall
		{
			template <typename T, typename... Args>
			T cd_call(uintptr_t address, Args... args)
			{
				typedef T(__cdecl* Func)(Args...);
				auto func = (Func)address;
				return func(std::forward<Args>(args)...);
			}

			template <typename T, typename... Args>
			T std_call(uintptr_t address, Args... args)
			{
				typedef T(__stdcall* Func)(Args...);
				auto func = (Func)address;
				return func(std::forward<Args>(args)...);
			}

			template <typename T, typename C, typename... Args>
			T this_call(C* This, uintptr_t address, Args... args)
			{
				typedef T(__thiscall* Func)(PVOID, Args...);
				auto func = (Func)address;
				return func(This, std::forward<Args>(args)...);
			}
		};

        void* getProcAddress(const std::string_view dllName, const std::string_view funcName) 
        {
            auto hModule = LoadLibraryA(dllName.data());
            if (hModule)
            {
                return GetProcAddress(hModule, funcName.data());
            }
            return nullptr;
        }

        void getSystemInfo(LPSYSTEM_INFO lpSystemInfo) 
        {
            static auto func = (decltype(&GetSystemInfo))getProcAddress("kernel32.dll", "GetNativeSystemInfo");

            if (func) 
            {
                func(lpSystemInfo);
            }
            else 
            {
                GetSystemInfo(lpSystemInfo);
            }
        }

        bool disableWow64FsRedirection(PVOID& value) 
		{
			static auto func = (decltype(&Wow64DisableWow64FsRedirection))
				getProcAddress("kernel32.dll", "Wow64DisableWow64FsRedirection");
			if (func)
			{
				return func(&value);
			}
			return false;
		}

		bool revertWow64FsRedirection(PVOID& value)
		{
			static auto func = (decltype(&Wow64DisableWow64FsRedirection))
				getProcAddress("kernel32.dll", "Wow64RevertWow64FsRedirection");
			if (func)
			{
				return func(&value);
			}
			return false;
		}

        bool isWow64Process() 
        {
            BOOL result;
            IsWow64Process(GetCurrentProcess(), &result);
            return result;
        }

        std::string getSystemDirectory() 
        {
            std::string result;

            result.resize(MAX_PATH);

            auto size = GetSystemDirectoryA(result.data(), result.size());

            result.resize(size);

            return result;
        }

        std::shared_ptr<uint8_t[]> readFile(const std::string& fileName) 
        {
            HANDLE hFile = CreateFileA(
                fileName.c_str(), 
                GENERIC_READ, 
                FILE_SHARE_READ, 
                NULL, 
                OPEN_EXISTING, 
                FILE_ATTRIBUTE_NORMAL, 
                NULL);
            if (hFile == INVALID_HANDLE_VALUE) 
            {
                return {};
            }

            auto size = GetFileSize(hFile, nullptr);
            auto file = std::make_shared<uint8_t[]>(size);

            DWORD dwBytes = 0;
            auto res = ReadFile(hFile, file.get(), size, &dwBytes, nullptr);

            CloseHandle(hFile);

            if (res)
            {
                return file;
            }
            return {};
        }

        uint32_t v2f(const std::shared_ptr<uint8_t[]>& file, const uint32_t va) 
        {
            auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.get());
			auto ntHeader  = reinterpret_cast<const IMAGE_NT_HEADERS*>(dosHeader->e_lfanew + file.get());
			auto section   = IMAGE_FIRST_SECTION(ntHeader);

            for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, section++)
			{
				if (section->VirtualAddress <= va && va < (section->VirtualAddress + section->Misc.VirtualSize))
				{
					return (va - section->VirtualAddress) + section->PointerToRawData;
				}
			}

            return 0;
        }

        uint32_t getFuncIndex(const std::shared_ptr<uint8_t[]>& file, const uint32_t hash) 
        {
            uint8_t* buffer = file.get();
            uint8_t const* func = nullptr;

            if (isArch64 && isWow64)  
            {
                auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
                auto ntHeader  = reinterpret_cast<const IMAGE_NT_HEADERS64*>(dosHeader->e_lfanew + buffer);
                auto exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buffer + v2f(file, ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
                auto nameDir	 = reinterpret_cast<const uint32_t*>(buffer + v2f(file, exportDir->AddressOfNames));
				auto nameOrdinal = reinterpret_cast<const uint16_t*>(buffer + v2f(file, exportDir->AddressOfNameOrdinals));
				auto funcDir	 = reinterpret_cast<const uint32_t*>(buffer + v2f(file, exportDir->AddressOfFunctions));

                for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
                {
                    auto funcName = reinterpret_cast<const char*>(buffer + v2f(file, nameDir[i]));

                    if (hash == hash_dynamic{funcName}) 
                    {
                        func = reinterpret_cast<const uint8_t*>(buffer + v2f(file, funcDir[nameOrdinal[i]]));
                        break;
                    }
                }
            }
            else 
            {
                auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(buffer);
                auto ntHeader  = reinterpret_cast<const IMAGE_NT_HEADERS*>(dosHeader->e_lfanew + buffer);
                auto exportDir = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(buffer + v2f(file, ntHeader->OptionalHeader.DataDirectory[0].VirtualAddress));
                auto nameDir	 = reinterpret_cast<const uint32_t*>(buffer + v2f(file, exportDir->AddressOfNames));
				auto nameOrdinal = reinterpret_cast<const uint16_t*>(buffer + v2f(file, exportDir->AddressOfNameOrdinals));
				auto funcDir	 = reinterpret_cast<const uint32_t*>(buffer + v2f(file, exportDir->AddressOfFunctions));

                for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
                {
                    auto funcName = reinterpret_cast<const char*>(buffer + v2f(file, nameDir[i]));

                    if (hash == hash_dynamic{funcName}) 
                    {
                        func = reinterpret_cast<const uint8_t*>(buffer + v2f(file, funcDir[nameOrdinal[i]]));
                        break;
                    }
                }
            }

            if (func) 
            {
                for (size_t i = 0; i < 10; i++) 
                {
                    if (func[i] == 0xB8)    // mov eax, xxxx
                    {
                        return *reinterpret_cast<const uint32_t*>(func + i + 1);
                    }
                }
            }

            return -1;
        }

        void* buildFunc(const std::shared_ptr<uint8_t[]>& file, const uint32_t hash) 
        {
            auto index = detail::getFuncIndex(file, hash);

            if (index == -1) 
            {
                return nullptr;
            }

            if (isArch64) 
            {
                uint8_t syscall[] {
                    0xB8, 0x0, 0x0, 0x0, 0x0,   // mov eax,xxx
                    0x4C, 0x8B, 0xD1,           // mov r10,rcx
                    0x0F, 0x05,                 // syscall
                    0xC3                        // retn
                };

                *reinterpret_cast<uint32_t*>(&syscall[1]) = index;

                auto func = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(syscall));
                if (func) 
                {
                    memcpy(func, syscall, sizeof(syscall));
                    return func; 
                }
            }
            else 
            {
                uint8_t syscall[] {
                    0xB8, 0x0, 0x0, 0x0, 0x0,       // mov eax,xxx
                    0xE8, 0x1, 0x0, 0x0, 0x0,       // call sysentry
                    0xC3,                           // retn
                    0x8B, 0xD4,                     // mov edx, esp
                    0x0F, 0x34,                     // sysenter
                    0xC3                            // retn
                };

                *reinterpret_cast<uint32_t*>(&syscall[1]) = index;

                auto func = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, sizeof(syscall));
                if (func) 
                {
                    memcpy(func, syscall, sizeof(syscall));
                    return func;
                }
            }

            return nullptr;
        }

        void* getFuncAddress(const uint32_t hash) 
        {
            auto it = funcInfo.find(hash);

            if (it == funcInfo.end()) 
            {
                return nullptr;
            }
            
            return it->second;
        }

        #pragma warning(push)
        #pragma warning(disable : 4409)
        DWORD64 __cdecl X64Call(unsigned __int64 func, int argC, ...)
        {
        #ifndef _WIN64
            va_list args;
            va_start(args, argC);
            reg64 _rcx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
            reg64 _rdx = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
            reg64 _r8 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
            reg64 _r9 = { (argC > 0) ? argC--, va_arg(args, DWORD64) : 0 };
            reg64 _rax = { 0 };

            reg64 restArgs = { (DWORD64)&va_arg(args, DWORD64) };

            // conversion to QWORD for easier use in inline assembly
            reg64 _argC = { (DWORD64)argC };
            DWORD back_esp = 0;
            WORD back_fs = 0;

            __asm
            {
                ;// reset FS segment, to properly handle RFG
                mov    back_fs, fs
                mov    eax, 0x2B
                mov    fs, ax

                ;// keep original esp in back_esp variable
                mov    back_esp, esp

                ;// align esp to 0x10, without aligned stack some syscalls may return errors !
                ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
                ;// requires 0x10 alignment), it will be further adjusted according to the
                ;// number of arguments above 4
                and esp, 0xFFFFFFF0

                X64_Start();

                ;// below code is compiled as x86 inline asm, but it is executed as x64 code
                ;// that's why it need sometimes REX_W() macro, right column contains detailed
                ;// transcription how it will be interpreted by CPU

                ;// fill first four arguments
                REX_W mov    ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
                REX_W mov    edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
                push   _r8.v;// push    qword ptr [_r8]
                X64_Pop(_R8); ;// pop     r8
                push   _r9.v;// push    qword ptr [_r9]
                X64_Pop(_R9); ;// pop     r9
                ;//
                REX_W mov    eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
                ;// 
                ;// final stack adjustment, according to the    ;//
                ;// number of arguments above 4                 ;// 
                test   al, 1;// test    al, 1
                jnz    _no_adjust;// jnz     _no_adjust
                sub    esp, 8;// sub     rsp, 8
            _no_adjust:;//
                ;// 
                push   edi;// push    rdi
                REX_W mov    edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
                ;// 
                ;// put rest of arguments on the stack          ;// 
                REX_W test   eax, eax;// test    rax, rax
                jz     _ls_e;// je      _ls_e
                REX_W lea    edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
                ;// 
            _ls:;// 
                REX_W test   eax, eax;// test    rax, rax
                jz     _ls_e;// je      _ls_e
                push   dword ptr[edi];// push    qword ptr [rdi]
                REX_W sub    edi, 8;// sub     rdi, 8
                REX_W sub    eax, 1;// sub     rax, 1
                jmp    _ls;// jmp     _ls
            _ls_e:;// 
                ;// 
                ;// create stack space for spilling registers   ;// 
                REX_W sub    esp, 0x20;// sub     rsp, 20h
                ;// 
                call   func;// call    qword ptr [func]
                ;// 
                ;// cleanup stack                               ;// 
                REX_W mov    ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
                REX_W lea    esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
                ;// 
                pop    edi;// pop     rdi
                ;// 
        // set return value                             ;// 
                REX_W mov    _rax.dw[0], eax;// mov     qword ptr [_rax], rax

                X64_End();

                mov    ax, ds
                mov    ss, ax
                mov    esp, back_esp

                ;// restore FS segment
                mov    ax, back_fs
                mov    fs, ax
            }
            return _rax.v;
        #endif // _WIN32
            return 0;
        }
        #pragma warning(pop)

        template<typename T, typename... Args>
        T nativeCall(void* func, Args... args) 
        {
            if (detail::isArch64) 
            {
#ifdef _WIN64
				return AnyCall::std_call<T>(reinterpret_cast<uintptr_t>(func), args...);
#else
				return X64Call(reinterpret_cast<uintptr_t>(func), sizeof...(Args), (DWORD64)args...);
#endif
            }
            else 
            {
                return AnyCall::cd_call<T>(reinterpret_cast<uintptr_t>(func), args...);
            }
        }
    }

    bool initialize()
    {
        static std::once_flag flag;
        static bool result { false };

        std::call_once(flag, []()
        {
            SYSTEM_INFO si;

            detail::getSystemInfo(&si);

            detail::isArch64 = si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 
                        || si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64;

            detail::isWow64 = detail::isWow64Process();

            detail::hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
            if (!detail::hHeap) 
            {
                return;
            }

            auto ntdll = detail::getSystemDirectory() + "\\ntdll.dll";

            PVOID  fsRDR = nullptr;

            if (detail::isArch64 && detail::isWow64) 
            {
                detail::disableWow64FsRedirection(fsRDR);
            }

            std::unique_ptr<PVOID, void(*)(PVOID*)> fsRDRGuard { &fsRDR, [](PVOID* rdr) 
            {
                if (detail::isArch64 && detail::isWow64)
                {
                    detail::revertWow64FsRedirection(*rdr);
                }
            }};

            auto file = detail::readFile(ntdll);

            if (!file.get()) 
            {
                HeapDestroy(detail::hHeap);
                return;
            }

            for (auto& item : detail::funcInfo) 
            {
                item.second = detail::buildFunc(file, item.first);
            }

            result = true;
        });

        return result;
    }

    void destroy() 
    {
        if (detail::hHeap) 
        {
            HeapDestroy(detail::hHeap);
        }

        detail::funcInfo.clear();
    }
}