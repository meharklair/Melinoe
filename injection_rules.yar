import "pe"

/*

Rules needed:

Shellcode injection (not using NT)
Shellcode injection (using NT)
DLL Injection


*/

/*
What is needed for shellcode injection

OpenProcess -> VirtualAllocEx -> WriteProcessMemory -> VirtualProtectEx (optional) -> CreateRemoteThreadEx

*/


rule winapi_injection
{
     meta:

        description = "Scans for a injector that utilizes win32 api to inject shellcode"

     strings:

        $open_process = "OpenProcess"
        $virtual_allocEx = "VirtualAllocEx"
        $virtual_alloc = "VirtualAlloc"
        $write_process = "WriteProcessMemory"
        $create_remote_threadEx = "CreateRemoteThreadEx"
        $create_remote_thread = "CreateRemoteThread"



    condition:

    // magic for executables
    0x5a4d and

    $open_process

    and ($virtual_allocEx or $virtual_alloc)

    and $write_process

    and ($create_remote_threadEx or $create_remote_thread)
    
}

/*
NtOpenProcess -> > NTAllocatevirtualMemory -> NtWriteVirtualMemory -> NtCreateThreadEx
*/

rule NTAPI_injection
{
    meta: 

    description = "Scans for needed imports and commands needed for NTAPI injection"

    strings:
        $write = "NtWriteVirtualMemory"
        $threadEx = "NtCreateThreadEx"

    condition:
        // magic for executables
        0x5a4d and $write and $threadEx

}


