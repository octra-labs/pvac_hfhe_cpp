#pragma once


#include <cstdlib>
#include <algorithm>

namespace pvac {

inline int g_dbg = []() {
    const char * s = std::getenv("PVAC_DBG");
    if (!s) s = std::getenv("HFHE_DBG");
    return s ? std::max(0, std::min(2, std::atoi(s))) : 1;
}();

inline void set_debug_level(int level) {
    g_dbg = std::max(0, std::min(2, level));
}

inline int get_debug_level() {
    return g_dbg;
}

}