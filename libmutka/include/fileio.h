#ifndef LIBMUTKA_FILEIO_H
#define LIBMUTKA_FILEIO_H

#include <fcntl.h>
#include <sys/mman.h>

bool mutka_file_exists(const char* path);
bool mutka_dir_exists(const char* path);

// Behaves similarly to command "mkdir -p"
// If the parent directories do not exists for 'path'
// they will be created with 'perm' permissions. <-  see "man 2 open" under O_CREAT for modes.
bool mutka_mkdir_p(const char* path, mode_t perm); 

bool mutka_file_clear(const char* path);
bool mutka_file_append(const char* path, char* data, size_t size);

// 'out' must be unmapped using 'munmap' after use.
// If 'out' is NULL, only file size is written to *out_size.
// Returns 'true' if the file is empty.
bool mutka_map_file(const char* path, char** out, size_t* out_size);


#endif
