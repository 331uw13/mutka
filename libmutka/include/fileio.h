#ifndef LIBMUTKA_FILEIO_H
#define LIBMUTKA_FILEIO_H

#include <fcntl.h>


bool mutka_file_exists(const char* path);
bool mutka_dir_exists(const char* path);

// Behaves similarly to command "mkdir -p"
// If the parent directories do not exists for 'path'
// they will be created with 'perm' permissions. <-  see "man 2 open" under O_CREAT for modes.
bool mutka_mkdir_p(const char* path, mode_t perm); 

bool mutka_file_clear(const char* path);
bool mutka_file_append(const char* path, char* data, size_t size);


#endif
