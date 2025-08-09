#include "Minhook.h"
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <fileapi.h>
#include <map>
#include <minwindef.h>
#include <psapi.h>
#include "../include/nt.hh"
#include "../include/hook.hh"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>  // 添加文件sink头文件
#include <spdlog/sinks/stdout_color_sinks.h> // 添加控制台sink头文件
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <winnt.h>
#include <direct.h>
#include <filesystem>
#include "../include/redirect.hh"

static def_CreateFileW Org_CreateFileW = NULL;
static def_ReadFile Org_ReadFile = NULL;

std::map<std::string, RedirectInfo> config;

// 初始化日志系统
void init_logger() {
    try {
        // 创建控制台和文件的双重sink
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("hook_log.txt", true);
        
        // 创建组合logger
        std::vector<spdlog::sink_ptr> sinks{console_sink, file_sink};
        auto combined_logger = std::make_shared<spdlog::logger>("multi_sink", sinks.begin(), sinks.end());
        
        // 设置日志格式
        combined_logger->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [thread %t] %v");
        
        // 设置日志级别
        combined_logger->set_level(spdlog::level::debug);
        
        // 设置为默认logger
        spdlog::set_default_logger(combined_logger);
        
        // 刷新所有日志
        spdlog::flush_every(std::chrono::seconds(3));
        
        spdlog::info("Logger initialized successfully");
    } catch (const spdlog::spdlog_ex& ex) {
        MessageBoxA(nullptr, ex.what(), "Logger initialization failed!", MB_ICONERROR | MB_OK);
        exit(1);
    }
}

HANDLE WINAPI Hk_CreateFileW(
    _In_           LPCWSTR                lpFileName,
    _In_           DWORD                 dwDesiredAccess,
    _In_           DWORD                 dwShareMode,
    _In_opt_ LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    _In_           DWORD                 dwCreationDisposition,
    _In_           DWORD                 dwFlagsAndAttributes,
    _In_opt_ HANDLE                hTemplateFile
) {
    char path[MAX_PATH];
    size_t len;
    wcstombs_s(&len, path, MAX_PATH, lpFileName, wcslen(lpFileName));
    std::string filename(path, len);
    spdlog::debug("Attempting to open file: {}", filename.c_str());
    
    std::filesystem::path p(filename);

    if (p.is_absolute()) {
        if (filename.find("\\\\?\\") == 0) {
            filename.replace(0, 4, "");
            spdlog::debug("Removed \\\\?\\ prefix: {}", filename);
        }
        if ('a' <= filename[0] && filename[0] <= 'z') {
            filename[0] = 'A' + filename[0] - 'a';
            spdlog::debug("Converted drive letter to uppercase: {}", filename);
        }
    }

    if (config.find(filename.c_str()) != config.end()) {
        auto directData = config[filename.c_str()];
        spdlog::debug("Found redirect config for: {}, cur={}, start={}, end={}", 
                     filename, directData.cur, directData.start, directData.end);
        
        if (directData.cur >= directData.start && directData.cur < directData.end) {
            spdlog::info("Redirecting {} to {}", filename, directData.target);
            
            const char* strTmpPath = directData.target.c_str();
            int cap = (strlen(strTmpPath) + 1) * sizeof(wchar_t);
            wchar_t* defaultIndex = (wchar_t*)malloc(cap);
            size_t retlen = 0;
            
            errno_t err = mbstowcs_s(&retlen, defaultIndex, cap / sizeof(wchar_t), strTmpPath, _TRUNCATE);

            directData.cur++;
            config[filename.c_str()] = directData;
            
            if (err == 0) {
                HANDLE ret = Org_CreateFileW(defaultIndex, dwDesiredAccess, dwShareMode, 
                                            lpSecurityAttributes, dwCreationDisposition, 
                                            dwFlagsAndAttributes, hTemplateFile);
                free(defaultIndex);
                return ret;
            }
            
            spdlog::error("Failed to convert path: {}, error: {}", strTmpPath, err);
            free(defaultIndex);
        } else {
            directData.cur++;
            config[filename.c_str()] = directData;
            spdlog::debug("Skipping redirect for {} (cur={})", filename, directData.cur);
        }
    } else {
        spdlog::debug("No redirect config found for: {}", filename);
    }

    return Org_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, 
                          lpSecurityAttributes, dwCreationDisposition, 
                          dwFlagsAndAttributes, hTemplateFile);
}

void start_hook() {
    init_logger();  // 初始化日志系统
    
    spdlog::info("Initializing hook system");
    
    if (MH_Initialize() != MH_OK) {
        spdlog::critical("MH_Initialize failed");
        MessageBoxA(nullptr, "MH Init Error!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
    
    spdlog::info("Creating hooks");
    if (MH_CreateHook(&CreateFileW, &Hk_CreateFileW, 
                     reinterpret_cast<LPVOID*>(&Org_CreateFileW)) != MH_OK) {
        spdlog::critical("Failed to create CreateFileW hook");
        MessageBoxA(nullptr, "MH Hook CreateFileW failed!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
    
    spdlog::info("Enabling hooks");
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        spdlog::critical("Failed to enable hooks");
        MessageBoxA(nullptr, "MH enable all hooks failed!", "ERROR", MB_ICONERROR | MB_OK);
        exit(1);
    }
    
    spdlog::info("Hook system initialized successfully");
}
