#include <Windows.h>
#include <iostream>
#include <tlhelp32.h>

#define PATH "D:\\Programing\\Projects\\Windows\\Dll_Injection\\x64\\Release\\injected.dll"

BOOL WaitForNotepad(PDWORD pid)
{
	*pid = 0;
	do
	{
		HANDLE allprocess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (allprocess == NULL)
		{
			std::cout << "error accessing processes";
			return FALSE;
		}
		PROCESSENTRY32 pe;
		pe.dwSize = sizeof(pe);

		if (Process32First(allprocess, &pe))
		{
			if (pe.szExeFile == L"notepad.exe")
			{
				*pid = pe.th32ProcessID;
			}
			else
			{
				while (Process32Next(allprocess, &pe))
				{
					WCHAR exe[MAX_PATH] = L"notepad.exe";
					if (wcscmp(exe,pe.szExeFile) == 0)
					{
						*pid = pe.th32ProcessID;
						break;
					}
				}
			}
		}
		else
		{
			std::cout << "error accessing processes";
			return FALSE;
		}
	} while (*pid == 0);
	return *pid == 0;
}


int _stdcall WinMain(HINSTANCE hInstance,
	HINSTANCE hPrevInstance,
	LPSTR     lpCmdLine,
	int       nShowCmd)
{
	while (true)
	{
		CHAR buf[MAX_PATH];
		DWORD len = GetFullPathNameA(PATH, MAX_PATH, buf, NULL);
		LPVOID load_func = (LPVOID)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");

		if (load_func == NULL)
		{
			std::cout << "Error finding kernel proc. error code:%d\n", GetLastError();
			return 1;
		}

		DWORD pid;
		if (WaitForNotepad(&pid))
		{
			std::cout << "Error waiting for notepad. error code: " << GetLastError();
			return 1;
		}
		HANDLE note_proc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);

		PVOID proc_mem = (PVOID)VirtualAllocEx(note_proc, NULL, strlen(PATH) * sizeof(CHAR), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (proc_mem == NULL)
		{
			std::cout << "Error allocating virtual mem in the target proc. error code: " << GetLastError();
			return 1;
		}

		len = WriteProcessMemory(note_proc, proc_mem, buf, len, NULL);

		if (len == 0)
		{
			std::cout << "Error writing to virtual mem in the target proc. error code: "<< GetLastError();
			return 1;
		}

		HANDLE thread = CreateRemoteThread(note_proc, NULL, 0, (LPTHREAD_START_ROUTINE)load_func, proc_mem, 0, NULL);

		if (thread == NULL)
		{
			std::cout << "Error starting thread in the target proc. error code: "<< GetLastError();
			return 1;
		}

		WaitForSingleObject(thread, INFINITE);
		CloseHandle(thread);
		Sleep(1000);
	}
	return 0;
}