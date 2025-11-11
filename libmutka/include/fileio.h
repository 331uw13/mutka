#ifndef LIBMUTKA_FILEIO_H
#define LIBMUTKA_FILEIO_H

#include <fcntl.h>
#include <sys/mman.h>

bool mutka_file_exists(const char* path);
bool mutka_dir_exists(const char* path);

// Behaves similarly to command "mkdir -p"
// If the parent directories do not exists for 'path'
// they will be created with 'perm' permissions. <-  see "open" manual pages under O_CREAT for modes.
bool mutka_mkdir_p(const char* path, mode_t perm); 

bool mutka_file_clear(const char* path);
bool mutka_file_append(const char* path, void* data, size_t size);

// Maps file into memory with 'prot' access.
// 'prot' can one or both flags: PROT_READ, PROT_WRITE
//
// Remember to synchronize the file with 'msync' if modifying the buffer
// to avoid undefined reads in the future for the file.
bool mutka_map_file(const char* path, int prot, char** out, size_t* out_size);

bool mutka_write_file(const char* path, void* data, size_t size);

// On error returns -1 otherwise the file size.
ssize_t mutka_file_size(const char* path);


#endif
