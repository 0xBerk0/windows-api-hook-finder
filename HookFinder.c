#include <stdio.h>
#include <Windows.h>


int main(int argc, char *argv[]) 
{
    if (argc != 2 ) 
    {
        printf("[!] USAGE: hookfinder.exe <target module>\n");
        return -1;
    }

    PBYTE Module = (PBYTE)GetModuleHandleA(argv[1]);
    if ( !Module ) {
        printf("[-] Failed to load module\n");
        return -1;
    }

    printf("[+] Loaded Module: 0x%8llx\n\n", Module);

    PIMAGE_NT_HEADERS pImageNtHeaders = Module + ((PIMAGE_DOS_HEADER)Module)->e_lfanew;
    PIMAGE_EXPORT_DIRECTORY pImageExportDir = Module + pImageNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    PDWORD pAddrOfFunctions = Module + pImageExportDir->AddressOfFunctions;
    PDWORD pAddrOfNames = Module + pImageExportDir->AddressOfNames;
    PWORD pAddrOfOrdinals = Module + pImageExportDir->AddressOfNameOrdinals;
    
    for (DWORD i = 0; i < pImageExportDir->NumberOfNames; i++)
    {   

        FARPROC fn = Module + pAddrOfFunctions[pAddrOfOrdinals[i]];            
        PBYTE p = (PBYTE)fn;         
        if (p[0] == 0xE9)
        {
            
            
            PCHAR functionName = (PCHAR)Module + pAddrOfNames[i];   
            UINT_PTR functionAddr = Module + pAddrOfFunctions[pAddrOfOrdinals[i]];
            printf("[+] %s is hooked:\n", functionName);
            printf(" |-----> Bytes @ %p: %02X %02X %02X %02X %02X\n",p, p[0], p[1], p[2], p[3], p[4]);
            
        }
        
    }

    CloseHandle(Module);
    return 0;
}