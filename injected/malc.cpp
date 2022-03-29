#include "malc.h"

BOOL show;

void ShowMessage()
{
	while (show)
	{
		MessageBoxW(NULL, L"Pay me 20M$ in cash", L":)", 0);
		Sleep(1000);
	}
}

BOOL APIENTRY DllMain(HINSTANCE hModule, DWORD call_reson, LPVOID reserved)
{
	switch (call_reson)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_PROCESS_DETACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	}
	show = TRUE;
	ShowMessage();
}

