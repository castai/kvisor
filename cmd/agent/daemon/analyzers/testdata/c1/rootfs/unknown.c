#include <stdio.h>
#include <stdlib.h>

// Simple c program to test parser no results found.
int main() {
    const char *version = "2.14.1";
    setenv("UNKNOWN_VERSION", version, 1);

    const char *xmrVersion = getenv("UNKNOWN_VERSION");
    if (xmrVersion != NULL) {
        printf("UNKNOWN_VERSION: %s\n", xmrVersion);
    } else {
        printf("UNKNOWN_VERSION not set\n");
    }

    return 0;
}
