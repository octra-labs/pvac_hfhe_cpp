#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <stdlib.h>
#elif defined(__linux__)
    #include <unistd.h>
    #include <sys/random.h>
    #include <fcntl.h>
    #include <errno.h>
#elif defined(_WIN32)
    #define NOMINMAX
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
#else
    #include <random>
#endif

namespace pvac {

inline uint64_t load_le64(const uint8_t * p) {
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) {
        x |= (uint64_t)p[i] << (8 * i);
    }
    return x;
}

inline void store_le64(uint8_t * p, uint64_t x) {
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)((x >> (8 * i)) & 0xFF);
    }
}

inline void csprng_bytes(uint8_t * out, size_t n) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(out, n);

#elif defined(__linux__)
    size_t off = 0;

    while (off < n) {
        ssize_t r = getrandom(out + off, n - off, 0);

        if (r > 0) {
            off += r;
            continue;
        }

        if (r < 0 && errno == EINTR) {
            continue;
        }

        int fd = ::open("/dev/urandom", O_RDONLY);
        if (fd < 0) {
            std::abort();
        }

        while (off < n) {
            ssize_t z = ::read(fd, out + off, n - off);

            if (z > 0) {
                off += z;
                continue;
            }

            if (z < 0 && errno == EINTR) {
                continue;
            }

            break;
        }

        ::close(fd);
        break;
    }

    if (off != n) {
        std::abort();
    }

#elif defined(_WIN32)
    NTSTATUS st = BCryptGenRandom(NULL, out, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (st != 0) {
        std::abort();
    }

#else
    std::random_device rd;
    size_t off = 0;

    while (off < n) {
        uint64_t x   = ((uint64_t)rd() << 32) ^ rd();
        size_t   take = std::min((size_t)8, n - off);
        std::memcpy(out + off, &x, take);
        off += take;
    }
#endif
}

inline uint64_t csprng_u64() {
    uint8_t b[8];
    csprng_bytes(b, 8);
    return load_le64(b);
}

}