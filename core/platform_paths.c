#include "platform_paths.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#endif

static void sanitize_path(char* path) {
    if (!path) return;
    // Basic sanitization: only allow alphanumeric, dots, slashes, underscores, hyphens, spaces
    for (char* p = path; *p; p++) {
        if (!((*p >= 'A' && *p <= 'Z') || (*p >= 'a' && *p <= 'z') || (*p >= '0' && *p <= '9') ||
            *p == '/' || *p == '\\' || *p == '.' || *p == '_' || *p == '-' || *p == ' ' || *p == ':')) {
            *p = '_';
        }
    }
}

void get_platform_data_path(char *path_buffer, size_t buffer_size) {
    if (buffer_size == 0) return;

#ifdef _WIN32
    char *localappdata = getenv("LOCALAPPDATA");
    if (localappdata && strlen(localappdata) < buffer_size - 32) {
        snprintf(path_buffer, buffer_size, "%s\\securepasswd", localappdata);
    } else {
        // Fallback if LOCALAPPDATA is not set or too long
        snprintf(path_buffer, buffer_size, ".");
    }
#elif defined(__ANDROID__)
    // Android paths are usually provided by the Java side through JNI
    // This is a fallback or for native-only tests
    snprintf(path_buffer, buffer_size, "/data/data/com.securepasswd.mgmt/files");
#else
    char *data_home = getenv("XDG_DATA_HOME");
    if (data_home && strlen(data_home) < buffer_size - 32) {
        snprintf(path_buffer, buffer_size, "%s/securepasswd", data_home);
    } else {
        char *home = getenv("HOME");
        if (home && strlen(home) < buffer_size - 32) {
            snprintf(path_buffer, buffer_size, "%s/.local/share/securepasswd", home);
        } else {
            // Fallback if HOME is not set or too long
            snprintf(path_buffer, buffer_size, ".");
        }
    }
#endif

    sanitize_path(path_buffer);
}
