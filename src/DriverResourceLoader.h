#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <stdbool.h>

// Structure to hold extracted driver file paths
typedef struct {
    wchar_t driverPath[MAX_PATH];
    wchar_t catalogPath[MAX_PATH];
    wchar_t infPath[MAX_PATH];
    bool isLoaded;
} DriverResources;

// Resource extraction and driver loading functions
bool ExtractDriverResources(DriverResources* resources);
bool LoadDriverFromResources(const DriverResources* resources);
bool UnloadDriver(const DriverResources* resources);
void CleanupDriverResources(DriverResources* resources);

// Helper functions
bool EnableLoadDriverPrivilege(void);
bool CreateUniqueTempFile(const wchar_t* prefix, const wchar_t* extension, wchar_t* outputPath, size_t maxLen);
bool ExtractResourceToFile(HMODULE hModule, LPCWSTR lpType, LPCWSTR lpName, const wchar_t* outputPath);

// For BlindEdr app - simplified interface
bool InitializeDriverWithEmbeddedResources(void);
void CleanupEmbeddedDriver(void);

#ifdef __cplusplus
}
#endif