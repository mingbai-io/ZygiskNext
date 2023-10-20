#include "dl.h"
#include "daemon.h"

constexpr auto kInjector = "/system/" LP_SELECT("lib", "lib64") "/libzygisk_injector.so";

[[gnu::used]] [[gnu::constructor()]]
void init() {
    auto handle = DlopenExt(kInjector, RTLD_NOW);
    auto entry = reinterpret_cast<void(*)(void*, void*)>(dlsym(handle, "entry"));
    if (entry != nullptr) {
        entry(handle, (void*) &init);
    }
}
