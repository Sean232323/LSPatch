//
// Created by VIP on 2021/4/25.
//

#include "bypass_sig.h"

#include "../src/native_api.h"
#include "elf_util.h"
#include "logging.h"
#include "native_util.h"
#include "patch_loader.h"
#include "utils/hook_helper.hpp"
#include "utils/jni_helper.hpp"

uint64_t libxnx = 0;  // Placeholder for your 'libxnx' base address.
bool doOnc = false;
#define  LOG_TAG    "XANAX"
#define  ALOG(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)

namespace lspd {

std::string apkPath;
std::string redirectPath;
std::string redirectMapsPath;
int counter;
    bool WriteAddr(void *addr, void *buffer, size_t length) {
        unsigned long page_size = sysconf(_SC_PAGESIZE);
        unsigned long size = page_size * sizeof(uintptr_t);
        return mprotect((void *) ((uintptr_t) addr - ((uintptr_t) addr % page_size) - page_size), (size_t) size, PROT_EXEC | PROT_READ | PROT_WRITE) == 0 && memcpy(addr, buffer, length) != 0;
    }

    bool modify_maps_file(const char* maps_path) {
        FILE* maps_file = fopen(maps_path, "r");
        FILE* maps_mod_file = fopen("/data/data/com.netease.newspike/cache/llk.txt", "w");

        if (maps_file && maps_mod_file) {
            char line[1024];  // Buffer to store each line.
            while (fgets(line, sizeof(line), maps_file)) {
                if (!strstr(line, "lspatch")) {  // Check if the line contains "lspatch".
                    uint64_t start_addr = 0;
                    uint64_t end_addr = 0;

                    // Parse the start and end addresses from the line.
                    if (libxnx) {
                        if (sscanf(line, "%lx-%lx", &start_addr, &end_addr) == 2) {
                            uintptr_t ofs = start_addr - libxnx;
                            if (ofs >= 0 && ofs <= 0x120000) {
                                // Skip the line if the address falls within the range.
                                continue;
                            }
                        }
                    }

                    // Write the line to the modified file if not skipped.
                    fputs(line, maps_mod_file);
                }
            }

            fclose(maps_file);
            fclose(maps_mod_file);
            return true;
        } else {
            // Return false if files cannot be opened.
            return false;
        }
    }

inline static lsplant::Hooker<"__openat", int(int, const char*, int flag, int)> __openat_ =
    +[](int fd, const char* pathname, int flag, int mode) {
        if (pathname == apkPath) {
            ALOG("redirect openat : %s", pathname);
            return __openat_(fd, redirectPath.c_str(), flag, mode);
        }
        if (strstr(pathname, "/proc") && strstr(pathname, "/maps") && mode == 0)
        {
            ALOG("redirect openat : %s to %s", pathname, redirectMapsPath.c_str());

            if (doOnc)
            {
                ALOG("modify_maps_file skipped!");
                return __openat_(fd, redirectMapsPath.c_str(), flag, mode);
            }
            counter++;
            if (counter > 10)
            {
                doOnc = true;
            }
            if (modify_maps_file(pathname))
            {
                ALOG("modify_maps_file created succesfully.");
            }
            return __openat_(fd, redirectMapsPath.c_str(), flag, mode);
        }
        return __openat_(fd, pathname, flag, mode);
    };

bool HookOpenat(const lsplant::HookHandler& handler) { return handler.hook(__openat_, true); }

LSP_DEF_NATIVE_METHOD(void, SigBypass, enableOpenatHook, jstring origApkPath,
                      jstring cacheApkPath) {

    redirectMapsPath = "/data/data/com.netease.newspike/cache/llk.txt";

    auto r = HookOpenat(lsplant::InitInfo{
        .inline_hooker =
            [](auto t, auto r) {
                void* bk = nullptr;
                return HookFunction(t, r, &bk) == 0 ? bk : nullptr;
            },
        .art_symbol_resolver =
            [](auto symbol) { return SandHook::ElfImg("libc.so").getSymbAddress(symbol); },
    });
    if (!r) {
        ALOG("Hook __openat fail");
        return;
    }
    lsplant::JUTFString str1(env, origApkPath);
    lsplant::JUTFString str2(env, cacheApkPath);
    apkPath = str1.get();
    redirectPath = str2.get();
    ALOG("preparing hook openat:");
    ALOG("apkPath %s", apkPath.c_str());
    ALOG("redirectPath %s", redirectPath.c_str());
}

static JNINativeMethod gMethods[] = {
    LSP_NATIVE_METHOD(SigBypass, enableOpenatHook, "(Ljava/lang/String;Ljava/lang/String;)V")};

void RegisterBypass(JNIEnv* env) {
    if (libxnx == 0)
    {
        Dl_info info;
        dladdr((void*) &modify_maps_file, &info);
        libxnx = (uintptr_t)info.dli_fbase;
        uint8_t aob[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        WriteAddr((void*)libxnx, aob, sizeof(aob));
        ALOG("[>] [RegisterBypass] libpatch : 0x%llX, cleared elf!", libxnx);
    }
    REGISTER_LSP_NATIVE_METHODS(SigBypass);
}

}  // namespace lspd
