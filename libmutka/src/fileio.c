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


#include <stdio.h>

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
                printf("%s: '%s'\n", __func__, buffer);
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


