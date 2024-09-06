//
// Created by VIP on 2021/4/25.
//

#include "bypass_sig.h"
//
#include <sstream>
//

#include "../src/native_api.h"
#include "elf_util.h"
#include "logging.h"
#include "native_util.h"
#include "patch_loader.h"
#include "utils/hook_helper.hpp"
#include "utils/jni_helper.hpp"

uint64_t libxnx = 0;  // Placeholder for your 'libxnx' base address.
bool doOnc = false;
#define  LOG_TAG2    "XANAX"
#define  ALOG(...)  __android_log_print(ANDROID_LOG_INFO,LOG_TAG2,__VA_ARGS__)

namespace lspd {

std::string apkPath;
std::string redirectPath;
int counter;

    bool WriteAddr(void *addr, void *buffer, size_t length) {
        unsigned long page_size = sysconf(_SC_PAGESIZE);
        unsigned long size = page_size * sizeof(uintptr_t);
        return mprotect((void *) ((uintptr_t) addr - ((uintptr_t) addr % page_size) - page_size), (size_t) size, PROT_EXEC | PROT_READ | PROT_WRITE) == 0 && memcpy(addr, buffer, length) != 0;
    }


inline static lsplant::Hooker<"__openat", int(int, const char*, int flag, int)> __openat_ =
    +[](int fd, const char* pathname, int flag, int mode) {
        if (pathname == apkPath) {
            ALOG("redirect openat : %s", pathname);
            return __openat_(fd, redirectPath.c_str(), flag, mode);
        }
        if (strstr(pathname, "/proc") && strstr(pathname, "/maps") && mode == 0)
        {
            ALOG("redirect openat : %s", pathname);

            // Open the original /proc/self/maps
            int orig_fd = __openat_(fd, pathname, flag, mode);
            if (orig_fd < 0) {
                ALOG("failed openat : %s", pathname);
                return orig_fd;
            }

            // Read original content
            char buffer[4096];
            std::string modified_maps;
            ssize_t bytesRead;
            while ((bytesRead = read(orig_fd, buffer, sizeof(buffer) - 1)) > 0) {
                buffer[bytesRead] = '\0';
                std::string chunk(buffer);

                // Filter out lines that reference '123456.apk'
                std::istringstream stream(chunk);
                std::string line;
                while (std::getline(stream, line)) {
                    if (line.find("lspatch") == std::string::npos) {
                        modified_maps += line + "\n";
                    }
                }
            }
            close(orig_fd);

            // Create a pipe to redirect the filtered content
            int pipefd[2];
            if (pipe(pipefd) == -1) {
                ALOG("failed to pipe");
                return -1;
            }

            // Write the modified content to the pipe
            write(pipefd[1], modified_maps.c_str(), modified_maps.size());
            close(pipefd[1]);

            // Return the read end of the pipe as the file descriptor
            return pipefd[0];
        }
        return __openat_(fd, pathname, flag, mode);
    };

bool HookOpenat(const lsplant::HookHandler& handler) { return handler.hook(__openat_, true); }

LSP_DEF_NATIVE_METHOD(void, SigBypass, enableOpenatHook, jstring origApkPath,
                      jstring cacheApkPath) {

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
        dladdr((void*) &RegisterBypass, &info);
        libxnx = (uintptr_t)info.dli_fbase;
        uint8_t aob[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        WriteAddr((void*)libxnx, aob, sizeof(aob));
        ALOG("[>] [RegisterBypass] libpatch : 0x%llX, cleared elf!", libxnx);
    }
    REGISTER_LSP_NATIVE_METHODS(SigBypass);
}

}  // namespace lspd
