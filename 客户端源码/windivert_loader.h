/*
 * WinDivert Dynamic Loader
 * 动态加载 WinDivert.dll，避免程序启动时的 DLL 依赖检查
 */

#ifndef WINDIVERT_LOADER_H
#define WINDIVERT_LOADER_H

#include <windows.h>
#include "windivert.h"

// WinDivert 函数指针类型
typedef HANDLE (WINAPI *PFN_WinDivertOpen)(const char*, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL (WINAPI *PFN_WinDivertRecv)(HANDLE, PVOID, UINT, UINT*, PWINDIVERT_ADDRESS);
typedef BOOL (WINAPI *PFN_WinDivertSend)(HANDLE, PVOID, UINT, UINT*, PWINDIVERT_ADDRESS);
typedef BOOL (WINAPI *PFN_WinDivertClose)(HANDLE);
typedef BOOL (WINAPI *PFN_WinDivertHelperCalcChecksums)(PVOID, UINT, PWINDIVERT_ADDRESS, UINT64);

// 全局函数指针
static HMODULE g_hWinDivert = NULL;
static PFN_WinDivertOpen g_WinDivertOpen = NULL;
static PFN_WinDivertRecv g_WinDivertRecv = NULL;
static PFN_WinDivertSend g_WinDivertSend = NULL;
static PFN_WinDivertClose g_WinDivertClose = NULL;
static PFN_WinDivertHelperCalcChecksums g_WinDivertHelperCalcChecksums = NULL;

// 加载 WinDivert.dll（从指定路径）
inline bool LoadWinDivert(const char* dll_path = "WinDivert.dll") {
    if (g_hWinDivert != NULL) {
        return true;  // 已加载
    }

    // 加载 DLL
    g_hWinDivert = LoadLibraryA(dll_path);
    if (g_hWinDivert == NULL) {
        return false;
    }

    // 获取函数地址
    g_WinDivertOpen = (PFN_WinDivertOpen)GetProcAddress(g_hWinDivert, "WinDivertOpen");
    g_WinDivertRecv = (PFN_WinDivertRecv)GetProcAddress(g_hWinDivert, "WinDivertRecv");
    g_WinDivertSend = (PFN_WinDivertSend)GetProcAddress(g_hWinDivert, "WinDivertSend");
    g_WinDivertClose = (PFN_WinDivertClose)GetProcAddress(g_hWinDivert, "WinDivertClose");
    g_WinDivertHelperCalcChecksums = (PFN_WinDivertHelperCalcChecksums)GetProcAddress(g_hWinDivert, "WinDivertHelperCalcChecksums");

    if (!g_WinDivertOpen || !g_WinDivertRecv || !g_WinDivertSend ||
        !g_WinDivertClose || !g_WinDivertHelperCalcChecksums) {
        FreeLibrary(g_hWinDivert);
        g_hWinDivert = NULL;
        return false;
    }

    return true;
}

// 包装函数（直接调用函数指针）
#define WinDivertOpen g_WinDivertOpen
#define WinDivertRecv g_WinDivertRecv
#define WinDivertSend g_WinDivertSend
#define WinDivertClose g_WinDivertClose
#define WinDivertHelperCalcChecksums g_WinDivertHelperCalcChecksums

#endif // WINDIVERT_LOADER_H
