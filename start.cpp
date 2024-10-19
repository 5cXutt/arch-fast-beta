#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <psapi.h>
#include <thread>
#include <winnt.h>  
#include <string>
#include <fstream>
#include <iomanip>  
#include <tchar.h> 
#include <vector>
#include <imagehlp.h>
#include <winternl.h>
#include <cstring>

typedef NTSTATUS(WINAPI* PNTALLOCATEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
    );

typedef NTSTATUS(WINAPI* PNTWRITEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(WINAPI* PNTCREATETHREAD)(
    HANDLE* ThreadHandle,
    ULONG DesiredAccess,
    LPVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartAddress,
    LPVOID Parameter,
    BOOL CreateSuspended,
    ULONG_PTR ThreadId
    );

typedef NTSTATUS(WINAPI* PNTWRITEVIRTUALMEMORY)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG BufferSize,
    PULONG NumberOfBytesWritten
    );


void LogAction(const char* message) {
    std::cout << "[+] " << message << std::endl;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    LogAction("Getting process ID");
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                processId = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return processId;
}

DWORD WaitForProcess(const wchar_t* processName) {
    LogAction("Waiting for process to start");
    DWORD processId = 0;
    std::wcout << L"[+] Waiting for " << processName << L" to start..." << std::endl;

    while ((processId = GetProcessIdByName(processName)) == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::wcout << L"[+] Process " << processName << L" started with PID: " << processId << std::endl;
    return processId;
}

void CheckDllProtections(HMODULE hModule, DWORD processId) {
    LogAction("Checking DLL protections");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process for protection check." << std::endl;
        return;
    }

    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQueryEx(hProcess, hModule, &mbi, sizeof(mbi))) {
        std::cout << "[+] Base address of DLL: " << mbi.BaseAddress << std::endl;
        std::cout << "[+] Allocation base: " << mbi.AllocationBase << std::endl;
        std::cout << "[+] Region size: " << mbi.RegionSize << " bytes" << std::endl;

        std::cout << "[+] State: ";
        if (mbi.State & MEM_COMMIT) std::cout << "Committed ";
        if (mbi.State & MEM_FREE) std::cout << "Free ";
        if (mbi.State & MEM_RESERVE) std::cout << "Reserved ";
        std::cout << std::endl;

        std::cout << "[+] Protect: ";
        if (mbi.Protect & PAGE_EXECUTE) std::cout << "Execute ";
        if (mbi.Protect & PAGE_EXECUTE_READ) std::cout << "Execute/Read ";
        if (mbi.Protect & PAGE_EXECUTE_READWRITE) std::cout << "Execute/Read/Write ";
        if (mbi.Protect & PAGE_EXECUTE_WRITECOPY) std::cout << "Execute/WriteCopy ";
        if (mbi.Protect & PAGE_NOACCESS) std::cout << "NoAccess ";
        if (mbi.Protect & PAGE_READONLY) std::cout << "ReadOnly ";
        if (mbi.Protect & PAGE_READWRITE) std::cout << "Read/Write ";
        if (mbi.Protect & PAGE_WRITECOPY) std::cout << "WriteCopy ";
        std::cout << std::endl;
    }

    MODULEINFO modInfo;
    if (GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
        std::cout << "[+] DLL Size: " << modInfo.SizeOfImage << " bytes" << std::endl;
        // std::cout << "[+] DLL Entry point: " << modInfo.EntryPoint << std::endl;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)modInfo.lpBaseOfDll;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);
        if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) {
            std::cout << "[+] ASLR: Enabled" << std::endl;
        }
        else {
            std::cout << "[+] ASLR: Disabled" << std::endl;
        }

        if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) {
            std::cout << "[+] DEP/NX: Enabled" << std::endl;
        }
        else {
            std::cout << "[+] DEP/NX: Disabled" << std::endl;
        }

        if (ntHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) {
            std::cout << "[+] Safe SEH: Enabled" << std::endl;
        }
        else {
            std::cout << "[+] Safe SEH: Disabled" << std::endl;
        }
    }

    CloseHandle(hProcess);
}

std::wstring GetModulePath(DWORD processId, const wchar_t* moduleName, HMODULE& hModuleOut) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameEx(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    if (wcsstr(szModName, moduleName) != nullptr) {
                        hModuleOut = hMods[i];
                        CloseHandle(hProcess);
                        return szModName;
                    }
                }
            }
        }
        CloseHandle(hProcess);
    }
    return L"";
}


std::string GetMachineType(WORD machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_I386: return "x86 (32 bit)";
    case IMAGE_FILE_MACHINE_AMD64: return "x64 (64 bit)";
    default: return "Unknown Machine Type";
    }
}

std::string GetMagicType(WORD magic) {
    switch (magic) {
    case IMAGE_NT_OPTIONAL_HDR32_MAGIC: return "PE32 (32 bit)";
    case IMAGE_NT_OPTIONAL_HDR64_MAGIC: return "PE32+ (64 bit)";
    default: return "Unknown Magic Type";
    }
}

void AnalyzeImportTable(PIMAGE_NT_HEADERS ntHeaders, BYTE* baseAddress) {
    printf("[+] Analyzing import table ");
    std::ofstream outputFile("import_table_analysis.txt", std::ios::out | std::ios::trunc);
    if (!outputFile.is_open()) {
        std::cerr << "[-] Failed to open output file." << std::endl;
        return;
    }

    outputFile << "Analyzing import table" << std::endl;
    PIMAGE_DATA_DIRECTORY importDirectory = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDirectory->VirtualAddress == 0) {
        outputFile << "[-] No import table found." << std::endl;
        outputFile.close();
        return;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(baseAddress + importDirectory->VirtualAddress);

    while (importDescriptor->Name) {
        char* dllName = (char*)(baseAddress + importDescriptor->Name);
        outputFile << "[+] Importing DLL: " << dllName << std::endl;

        PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(baseAddress + importDescriptor->FirstThunk);

        while (thunk->u1.AddressOfData) {
            if (thunk->u1.AddressOfData < importDirectory->Size + (ULONG_PTR)baseAddress) {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(baseAddress + thunk->u1.AddressOfData);
                outputFile << "    Function: " << importByName->Name << std::endl;
            }
            else {
                outputFile << "[-] Invalid thunk address." << std::endl;
                break;
            }
            thunk++;
        }
        importDescriptor++;
    }

    outputFile.close();
    printf(" \n");
    printf("[+] Successfully action saved in import_table_analysis.txt \n");
}



void AnalyzeExeHeaders(DWORD processId) {
    LogAction("Analyzing executable headers");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process for EXE header analysis." << std::endl;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szExeName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szExeName, sizeof(szExeName) / sizeof(wchar_t))) {
                if (wcsstr(szExeName, L".exe") != nullptr) {
                    std::wcout << L"[+] Analyzing: " << szExeName << std::endl;

                    HANDLE hFile = CreateFile(szExeName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hFile != INVALID_HANDLE_VALUE) {
                        HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
                        if (hMapping) {
                            LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
                            if (pBase) {
                                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)pBase;
                                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)dosHeader + dosHeader->e_lfanew);

                                std::cout << "[+] Machine: " << GetMachineType(ntHeaders->FileHeader.Machine) << std::endl;
                                std::cout << "[+] Magic: " << GetMagicType(ntHeaders->OptionalHeader.Magic) << std::endl;
                                //std::cout << "[+] Size of Headers: " << ntHeaders->OptionalHeader.SizeOfHeaders << " bytes" << std::endl;

                                PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
                                for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; ++j) {
                                    //std::cout << "[+] Section Name: " << sectionHeader->Name << std::endl;
                                    //std::cout << "[+] Virtual Size: " << sectionHeader->Misc.VirtualSize << " bytes" << std::endl;
                                    //std::cout << "[+] Virtual Address: " << sectionHeader->VirtualAddress << std::endl;
                                    sectionHeader++;
                                }

                                if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
                                    PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ntHeaders + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                                    DWORD* names = (DWORD*)((BYTE*)ntHeaders + exportDir->AddressOfNames);
                                    std::cout << "[+] Exported Functions:" << std::endl;

                                    for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
                                        char* functionName = (char*)((BYTE*)ntHeaders + names[i]);
                                        std::cout << "[+] " << functionName << std::endl;
                                    }
                                }

                                AnalyzeImportTable(ntHeaders, (BYTE*)pBase);

                                UnmapViewOfFile(pBase);
                            }
                            CloseHandle(hMapping);
                        }
                        CloseHandle(hFile);
                    }
                }
            }
        }
    }

    CloseHandle(hProcess);
}

void ListLoadedDlls(DWORD processId) {
    printf("[+] Analyzing DLl Loaded ");

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        std::cerr << "[-] Failed to open process for DLL listing." << std::endl;
        return;
    }

    HMODULE hMods[1024];
    DWORD cbNeeded;

    std::ofstream outputFile("loaded_dlls.txt", std::ios::out | std::ios::trunc);
    if (!outputFile.is_open()) {
        std::cerr << "[-] Failed to open output file." << std::endl;
        CloseHandle(hProcess);
        return;
    }

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        outputFile << "[+] Loaded DLLs:" << std::endl;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szDllName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hMods[i], szDllName, sizeof(szDllName) / sizeof(wchar_t))) {
                char buffer[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, szDllName, -1, buffer, sizeof(buffer), NULL, NULL);
                outputFile << "    " << buffer << std::endl;
            }
        }
    }

    outputFile.close();
    CloseHandle(hProcess);
    printf(" \n");
    printf("[+] Successfully action saved in loaded_dlls.txt \n");

}

typedef int (WINAPI* MessageBoxA_t)(HWND, LPCSTR, LPCSTR, UINT);
MessageBoxA_t OriginalMessageBoxA = nullptr;

#define IMAGE_FIRST_IMPORT_DESCRIPTOR(Headers) ((PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)(Headers) + \
    ((PIMAGE_NT_HEADERS)((PBYTE)(Headers) + ((PIMAGE_DOS_HEADER)(Headers))->e_lfanew))->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress)))

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    MessageBoxA(NULL, "This is a hooked MessageBox!", "Hooked!", MB_OK);
    return OriginalMessageBoxA(hWnd, lpText, lpCaption, uType);
}

using PrototypeMessageBox = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
PrototypeMessageBox originalMsgBox = MessageBoxA;



unsigned char shellcode[] = {
    0x90, 0x90, // NOP instructions
    0xB8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
    0xBB, 0x00, 0x00, 0x00, 0x00, // mov ebx, 0
    0xCD, 0x2E, // int 0x2E (call ExitProcess)
    0xC3        // RET instruction
};



size_t shellcodeLength = sizeof(shellcode); 

int hookedMessageBox(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    std::cout << "[+] Injecting shellcode into .text section." << std::endl;

    LPVOID imageBase = GetModuleHandleA(NULL);
    if (!imageBase) {
        std::cerr << "[-] Failed to get module handle." << std::endl;
        return originalMsgBox(hWnd, lpText, lpCaption, uType);
    }

    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    LPVOID textSectionBase = NULL;
    SIZE_T textSectionSize = 0;

    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader->Name, ".text") == 0) {
            textSectionBase = (LPVOID)((BYTE*)imageBase + sectionHeader->VirtualAddress);
            textSectionSize = sectionHeader->SizeOfRawData;
            break;
        }
        sectionHeader++;
    }

    if (textSectionBase == NULL) {
        std::cerr << "[-] .text section not found." << std::endl;
        return originalMsgBox(hWnd, lpText, lpCaption, uType);
    }

    SIZE_T bytesWritten;
    DWORD oldProtect;
    if (VirtualProtect(textSectionBase, textSectionSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        if (WriteProcessMemory(GetCurrentProcess(), textSectionBase, shellcode, sizeof(shellcode), &bytesWritten)) {
            std::cout << "[+] Shellcode injected into .text section successfully." << std::endl;

            LPVOID execMem = (LPVOID)((BYTE*)textSectionBase); 
            HANDLE hThread = CreateRemoteThread(GetCurrentProcess(), NULL, 0, (LPTHREAD_START_ROUTINE)execMem, NULL, 0, NULL);
            if (hThread) {
                std::cout << "[+] Thread created to execute shellcode." << std::endl;
                CloseHandle(hThread); 
            }
            else {
                std::cerr << "[-] Failed to create thread for shellcode execution." << std::endl;
            }
        }
        else {
            std::cerr << "[-] Failed to write shellcode to .text section." << std::endl;
        }
        VirtualProtect(textSectionBase, textSectionSize, oldProtect, &oldProtect);
    }
    else {
        std::cerr << "[-] Failed to change memory protection for .text section." << std::endl;
    }

    return originalMsgBox(hWnd, lpText, lpCaption, uType);
}


void IATHooking() {
    LPVOID imageBase = GetModuleHandleA(NULL);
    if (!imageBase) {
        std::cerr << "[-] Failed to get module handle." << std::endl;
        return;
    }

    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDescriptor->Name != NULL) {
        LPCSTR libraryName = (LPCSTR)(importDescriptor->Name + (DWORD_PTR)imageBase);
        HMODULE library = LoadLibraryA(libraryName);

        if (library) {
            //std::cout << "[+] Loaded library: " << libraryName << std::endl;

            PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->OriginalFirstThunk);
            PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + importDescriptor->FirstThunk);

            while (originalFirstThunk->u1.AddressOfData != NULL) {
                PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + originalFirstThunk->u1.AddressOfData);

                if (strcmp(functionName->Name, "MessageBoxA") == 0) {
                    DWORD oldProtect;
                    VirtualProtect((LPVOID)&firstThunk->u1.Function, sizeof(LPVOID), PAGE_EXECUTE_READWRITE, &oldProtect);

                    firstThunk->u1.Function = (DWORD_PTR)hookedMessageBox;
                    std::cout << "[+] Hooked MessageBoxA successfully." << std::endl;

                    VirtualProtect((LPVOID)&firstThunk->u1.Function, sizeof(LPVOID), oldProtect, &oldProtect);
                }
                ++originalFirstThunk;
                ++firstThunk;
            }
        }
        else {
            std::cerr << "[-] Failed to load library: " << libraryName << std::endl;
        }

        importDescriptor++;
    }
}

void CheckInjectedShellcode(HANDLE hProcess, LPVOID textSectionBase) {
    unsigned char* injectedShellcode = new unsigned char[shellcodeLength];
    SIZE_T bytesRead;

    if (ReadProcessMemory(hProcess, textSectionBase, injectedShellcode, shellcodeLength, &bytesRead)) {
        std::cout << "[+] Injected shellcode bytes:" << std::endl;
        for (size_t i = 0; i < shellcodeLength; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)injectedShellcode[i] << " ";
        }
        std::cout << std::endl;
    }
    else {
        std::cerr << "[-] Failed to read injected shellcode. Error: " << GetLastError() << std::endl;
    }

    delete[] injectedShellcode; 
}



int main() {
    LPVOID imageBase = GetModuleHandleA(NULL);
    PIMAGE_DOS_HEADER dosHeaders = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeaders->e_lfanew);

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = nullptr;
    IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);
    LPVOID textSectionBase = nullptr;

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sectionHeader->Name, ".text") == 0) {
            textSectionBase = (LPVOID)((DWORD_PTR)imageBase + sectionHeader->VirtualAddress);
            break;
        }
        sectionHeader++;
    }

    if (textSectionBase == NULL) {
        std::cerr << "[-] .text section not found." << std::endl;
        return 1;
    }

    HANDLE hProcess = GetCurrentProcess(); 
    SIZE_T bytesWritten = 0;

    if (WriteProcessMemory(hProcess, textSectionBase, shellcode, shellcodeLength, &bytesWritten)) {
        std::cout << "[+] Shellcode injected successfully." << std::endl;
        std::cout << "[+] Bytes written: " << bytesWritten << std::endl;

        if (bytesWritten == shellcodeLength) {
            std::cout << "[+] All bytes of the shellcode have been injected." << std::endl;
        }
        else {
            std::cout << "[-] Warning: Not all bytes of the shellcode were injected." << std::endl;
        }
    }
    else {
        std::cerr << "[-] Failed to write shellcode to .text section. Error: " << GetLastError() << std::endl;
        return 1;
    }

    LogAction("Starting DLL injector");
    const wchar_t* targetProcess = L"notepad.exe";
    const wchar_t* targetDll = L"ntdll.dll";

    DWORD processId = WaitForProcess(targetProcess);

    HMODULE hModule = NULL;
    std::wstring dllPath = GetModulePath(processId, targetDll, hModule);
    if (dllPath.empty()) {
        std::wcerr << "[-] Failed to find " << targetDll << " in process." << std::endl;
        return 1;
        return 1;
    }

    std::wcout << L"[+] Utilizzando la DLL (è stata selezionata ntdll.dll, ma è possibile cambiare il nome della DLL di interesse nel codice, ad esempio win32u.dll). La scelta della DLL dipende dalla lista delle DLL esportate (loaded_dlls.txt); solitamente si utilizza ntdll.dll poiché è sempre presente: Path della dll scelta => " << dllPath << std::endl;

    CheckDllProtections(hModule, processId);
    printf("[+] Informazioni completate per la DLL nel processo caricato. \n");
    AnalyzeExeHeaders(processId);
    ListLoadedDlls(processId);

    MessageBoxA(NULL, "Hello Before Hooking", "Hello Before Hooking", 0);
    IATHooking();

    MessageBoxA(NULL, "Hello after Hooking", "Hello after Hooking", 0);
    CheckInjectedShellcode(hProcess, textSectionBase);

    return 0;
}
