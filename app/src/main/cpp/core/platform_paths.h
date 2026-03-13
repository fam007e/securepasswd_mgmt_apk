#ifndef PLATFORM_PATHS_H
#define PLATFORM_PATHS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Gets the platform-specific path to the configuration directory.
 *
 * @param path_buffer The buffer to store the path in.
 * @param buffer_size The size of the path buffer.
 */
void get_config_path(char* path_buffer, size_t buffer_size);

#ifdef __cplusplus
}
#endif

#endif
