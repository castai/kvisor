#include <stdio.h>
#include <stdlib.h>

// Simple c program which for testing xmrig crypto miner detection.
// To compile it:
// make builder-image-enter
// cd ./cmd/agent/analyzers/testdata/c1/rootfs/
// clang unknown.c -o unknown.out
int main() {
    const char *version = "2.14.1";
    setenv("XMRIG_VERSION", version, 1);

    const char *xmrVersion = getenv("XMRIG_VERSION");
    if (xmrVersion != NULL) {
        printf("XMRIG_VERSION: %s\n", xmrVersion);
    } else {
        printf("XMRIG_VERSION not set\n");
    }

    return 0;
}
