/*
 * Deterministic capa integration fixture.
 *
 * This program is compiled but NEVER executed. It intentionally imports a
 * small set of ordinary process, network, environment, and filesystem APIs so
 * the pinned capa rules must produce at least one top-level capability.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    const char *path = getenv("PATH");
    FILE *handle = fopen("/tmp/decky-capa-fixture", "w");
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in address = {0};

    address.sin_family = AF_INET;
    address.sin_port = htons(443);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    connect(sock, (struct sockaddr *)&address, sizeof(address));

    if (handle != NULL) {
        fputs(path != NULL ? path : "", handle);
        fclose(handle);
    }
    close(sock);
    unlink("/tmp/decky-capa-fixture");
    return system("printf decky-capa-fixture >/dev/null");
}
