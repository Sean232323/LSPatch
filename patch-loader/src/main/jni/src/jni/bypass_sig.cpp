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

namespace lspd {

std::string apkPath;
std::string redirectPath;

inline static lsplant::Hooker<"__openat", int(int, const char*, int flag, int)> __openat_ =
    +[](int fd, const char* pathname, int flag, int mode) {
        if (pathname == apkPath) {
            ALOG("redirect openat : %s", pathname);
            return __openat_(fd, redirectPath.c_str(), flag, mode);
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

void RegisterBypass(JNIEnv* env) { REGISTER_LSP_NATIVE_METHODS(SigBypass); }

}  // namespace lspd
