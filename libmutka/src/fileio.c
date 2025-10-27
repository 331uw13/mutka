#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

#include "../include/mutka.h"
#include "../include/fileio.h"


bool mutka_file_exists(const char* path) {
    return (access(path, F_OK) == 0);
}

bool mutka_dir_exists(const char* path) { 
    struct stat sb;
    if(lstat(path, &sb) != 0) {
        return false;
    }
    return (sb.st_mode & S_IFDIR);
}


bool mutka_mkdir_p(const char* path, mode_t perm) {
    bool result = false;
    
    if(!path) {
        goto out;
    }

    const size_t path_length = strlen(path);

    char buffer[MUTKA_PATH_MAX] = { 0 };
    size_t buffer_idx = 0;

    for(size_t i = 0; i < path_length; i++) {
        char ch = path[i];

        
        buffer[buffer_idx++] = ch;
        if(buffer_idx >= sizeof(buffer)) {
            mutka_set_errmsg("%s: The path is too long", __func__);
            goto out;
        }

        if(((i > 0) && (ch == '/')) 
        || (i+1 >= path_length)) {
            if(!mutka_dir_exists(buffer)) {
                if(mkdir(buffer, perm) != 0) {
                    mutka_set_errmsg("%s: %s", __func__, strerror(errno));
                    goto out;
                }
            }
        }
    }
    
    result = true;

out:
    return result;
}

bool mutka_file_clear(const char* path) {
    if(!path) {
        return false;
    }
    int fd = open(path, O_WRONLY | O_TRUNC);
    close(fd);
    return (fd > 0);
}

bool mutka_file_append(const char* path, char* data, size_t size) {
    bool result = false;
    if(!path) {
        goto out;
    }
    if(!data) {
        goto out;
    }
    if(!size) {
        goto out;
    }

    int fd = open(path, O_WRONLY | O_APPEND);
    if(fd > 0) {
        write(fd, data, size);
        close(fd);
        result = true;
    }
out:
    return result;
}


