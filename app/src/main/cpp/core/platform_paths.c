#include "platform_paths.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void get_config_path(char *path_buffer, size_t buffer_size) {
    if (!path_buffer || buffer_size == 0) return;

#ifdef _WIN32
    // Use AppData\Local\securepasswd on Windows
    const char *localappdata = getenv("LOCALAPPDATA"); // flawfinder: ignore
    if (localappdata) {
        snprintf(path_buffer, buffer_size, "%s\\securepasswd", localappdata); // flawfinder: ignore
    } else {
        // Fallback if LOCALAPPDATA is not set
        snprintf(path_buffer, buffer_size, "."); // flawfinder: ignore
    }
#else
    // Linux/macOS: use XDG_DATA_HOME or ~/.local/share
    const char *data_home = getenv("XDG_DATA_HOME"); // flawfinder: ignore
    if (data_home) {
        snprintf(path_buffer, buffer_size, "%s/securepasswd", data_home); // flawfinder: ignore
    } else {
        const char *home = getenv("HOME"); // flawfinder: ignore
        if (home) {
            snprintf(path_buffer, buffer_size, "%s/.local/share/securepasswd", home); // flawfinder: ignore
        } else {
            // Fallback if HOME is not set
            snprintf(path_buffer, buffer_size, "%s", "."); // flawfinder: ignore
        }
    }
#endif
    // Ensure null termination and sanitize (basic)
    path_buffer[buffer_size - 1] = '\0';
    sanitize_path(path_buffer);
}
