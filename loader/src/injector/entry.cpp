#include <iostream>
#include <vector>
#include <string>
#include <set>
#include <dlfcn.h>
#include <link.h>
#include <sys/mman.h>
#include <dirent.h>
#include <mntent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include "logging.h"
#include <inttypes.h>
#include <unordered_map>

#include "daemon.h"
#include "logging.h"
#include "zygisk.hpp"
#include "module.hpp"
#include "elf_util.hpp"

using namespace std;

void *self_handle = nullptr;
void *loader_handle = nullptr;

template<typename T>
inline T *getStaticPointer(const SandHook::ElfImg &linker, std::string_view name) {
    auto *addr = reinterpret_cast<T **>(linker.getSymbAddress(name.data()));
    return addr == nullptr ? nullptr : *addr;
}

struct soinfo {
    uint32_t& rtld_flags() {
        return *reinterpret_cast<uint32_t*>((reinterpret_cast<uint8_t*>(this) + soinfo_rtld_flags_offset));
    }

    void* to_handle() {
        if (to_handle_ != nullptr) return to_handle_(this);
        return nullptr;
    }

    static bool setup(const SandHook::ElfImg &linker);

    inline static size_t soinfo_rtld_flags_offset = 328;

    // since Android 8

    inline static void* (*get_parents)(soinfo *) = nullptr;

    inline static uint32_t (*get_rtld_flags)(soinfo *) = nullptr;

    inline static void* (*to_handle_)(soinfo *) = nullptr;
};

bool soinfo::setup(const SandHook::ElfImg &linker) {
    auto somain = getStaticPointer<soinfo>(linker, "__dl__ZL6somain");
    get_parents = linker.getSymbAddress<decltype(get_parents)>("__dl__ZN6soinfo11get_parentsEv");
    get_rtld_flags = linker.getSymbAddress<decltype(get_rtld_flags)>("__dl__ZNK6soinfo14get_rtld_flagsEv");
    to_handle_ = linker.getSymbAddress<decltype(to_handle_)>("__dl__ZN6soinfo9to_handleEv");
    if (somain != nullptr && get_parents != nullptr && get_rtld_flags != nullptr && to_handle_ != nullptr) {
        auto parents = reinterpret_cast<uint8_t *>(get_parents(somain));
        auto parents_off = parents - reinterpret_cast<uint8_t *>(somain);
        auto rtld_flags = get_rtld_flags(somain);
        for (int i = 0; i < 10; i++) {
            auto possible_rtld_flags = *(reinterpret_cast<uint32_t *>(parents) + i);
            if (possible_rtld_flags == rtld_flags) { // RTLD_GLOBAL = 0x100
                soinfo_rtld_flags_offset = parents_off + i * sizeof(uint32_t); // 328
                return true;
            }
        }
        LOGW("rtld_flags offset not found");
    }
    return false;
}

extern "C" [[gnu::visibility("default")]]
void entry(void* handle, void* loader_addr) {
#ifdef NDEBUG
    logging::setfd(zygiskd::RequestLogcatFd());
#endif
    LOGD("Load injector successfully");
    SandHook::ElfImg linker("/linker");
    self_handle = handle;
    if (soinfo::setup(linker)) {
        auto find_self = linker.getSymbAddress < soinfo * (*)(
        const void*)>("__dl__Z23find_containing_libraryPKv");
        if (find_self) {
            auto loader = find_self(reinterpret_cast<const void *>(loader_addr));
            if (loader != nullptr) {
                loader_handle = loader->to_handle();
                LOGD("loader %p handle %p", loader, loader_handle);
                loader->rtld_flags() = loader->rtld_flags() & ~(RTLD_NODELETE | RTLD_GLOBAL);
            } else {
                LOGE("failed to find loader");
            }
        }
    }
    if (loader_handle == nullptr) {
        LOGW("failed to find loader, module may not be unload");
    }
    hook_functions();
}

