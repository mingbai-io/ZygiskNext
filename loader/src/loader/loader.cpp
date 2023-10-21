#include "dl.h"
#include "daemon.h"
#include "logging.h"

constexpr auto kInjector = "/system/" LP_SELECT("lib", "lib64") "/libzygisk_injector.so";

[[gnu::used]] [[gnu::constructor()]]
void init() {
    if (getuid() != 0) {
        return;
    }

    std::string_view cmdline = getprogname();

    if (cmdline != "zygote" &&
        cmdline != "zygote32" &&
        cmdline != "zygote64" &&
        cmdline != "usap32" &&
        cmdline != "usap64") {
        LOGW("not zygote (cmdline=%s)", cmdline.data());
        return;
    }

    auto handle = DlopenExt(kInjector, RTLD_NOW);
    auto entry = reinterpret_cast<void(*)(void*, void*)>(dlsym(handle, "entry"));

    if (entry != nullptr) {
        entry(handle, (void*) &init);
    }
}
