#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <math.h>

#include <stdio.h> // for testing.

#include "../include/ascii_captcha.h"


#define GLYPH_NUM_ROWS 8
#define GLYPH_NUM_COLS 12
#define NUM_GLYPHS (('Z' - 'A')+1)

#define GLYPH_MAX_WIDTH 18
#define GLYPH_MAX_HEIGHT 16


struct glyph_t {
    const char rows[GLYPH_NUM_ROWS][GLYPH_NUM_COLS];
};

const struct glyph_t GLYPHS[NUM_GLYPHS]; 


size_t p_get_buffer_index(size_t buffer_width, int x, int y) {
    return (y * buffer_width + x);
}

static void p_write_glyph_of
(
    char* buffer,
    size_t buffer_size,
    size_t buffer_width,
    char ch,
    int ch_pos_x,
    int ch_pos_y
){
    if((ch < 'A') || (ch > 'Z')) {
        return;
    }

    struct glyph_t glyph = GLYPHS[ch - 'A'];

    // Characters who doent have possibility to be flipped.
    const char NON_VERTICAL_FLIP_CHARS[] = {
        'W', 'M', 'L', 'P', 'G', 'Q', 'V', 'U', 'F', 'J', 'Y'
    };

    bool can_flip_vertical = true;
    for(size_t i = 0; i < sizeof(NON_VERTICAL_FLIP_CHARS); i++) {
        if(ch == NON_VERTICAL_FLIP_CHARS[i]) {
            can_flip_vertical = false;
            break;
        }
    }

    // Have some possibility to not flip the character.
    if(can_flip_vertical) {
        if(rand() % 100 < 50) {
            can_flip_vertical = false;
        }
    }

    bool can_flip_horizontal =
        (ch != 'J') &&
        (ch != 'Q') &&
        (rand() % 100 < 50);
    
    bool can_tilt = 
        (ch != 'W') &&
        (ch != 'M') &&
        (ch != 'Q');

    int tilt_dir = rand() % 2;
    tilt_dir = tilt_dir * 2 - 1;

    for(int row = 0; row < GLYPH_NUM_ROWS; row++) {
        for(int col = 0; col < GLYPH_NUM_COLS; col++) {

            char glyph_ch = glyph.rows
                [can_flip_vertical   ? GLYPH_NUM_ROWS - row : row]
                [can_flip_horizontal ? GLYPH_NUM_COLS - col : col];
            
            if(glyph_ch != '#') {
                continue;
            }

            int X = ch_pos_x + col;
            int Y = ch_pos_y + row;

            const size_t buffer_index = p_get_buffer_index(buffer_width, X, Y);
            if(buffer_index >= buffer_size) {
                continue;
            }


            buffer[buffer_index] = rand() % ('z' - '0') + '0';
        }

        if(can_tilt && (row % 2)) {
            ch_pos_x += tilt_dir;
        }
    }

}

static void p_write_glyphs
(
    char* buffer,
    size_t buffer_size,
    size_t buffer_width,
    const char* answer,
    const size_t answer_len
){

    int x = 5;
    int y = (GLYPH_MAX_HEIGHT / 2) - (GLYPH_NUM_ROWS / 2);



    for(size_t i = 0; i < answer_len; i++) {
   
        p_write_glyph_of(buffer, buffer_size, buffer_width, answer[i], x, y);
        
        int yoff = rand() % 2;
        yoff = (yoff * 2 - 1) * 3;
        y += yoff;

        if(y < 0) {
            y = GLYPH_MAX_HEIGHT - GLYPH_NUM_ROWS;
        }
        else
        if(y+GLYPH_NUM_ROWS > GLYPH_MAX_HEIGHT) {
            y = 0;
        }

        x += GLYPH_MAX_WIDTH - 2;
    }

}


static void p_write_noise(char* buffer, size_t buffer_size, size_t buffer_width) {


    // Generate random noise around occupied glyph cells.
    for(size_t row = 0; row < GLYPH_MAX_HEIGHT; row++) {
        for(size_t col = 0; col < buffer_width; col++) {
            char ch = buffer[p_get_buffer_index(buffer_width, col, row)];

            if(ch == 0x20) {
                continue;
            }

            int noise_level = rand() % 2;
            int noise_spacing = rand() % 3 + 1;

            if(rand() % 100 < 30) {
                continue;
            }

            for(int i = 0; i < noise_level; i++) {
             
                int noise_off_x = rand() % 2;
                int noise_off_y = rand() % 2;
                noise_off_x = (noise_off_x * 2 - 1) * noise_spacing;
                noise_off_y = (noise_off_y * 2 - 1) * noise_spacing;

                int X = col + noise_off_x;
                int Y = row + noise_off_y;
                if((X < 0) || (Y < 0)) {
                    continue;
                }
                if(X >= (int64_t)buffer_width) {
                    continue;
                }
                if(Y >= GLYPH_MAX_HEIGHT) {
                    continue;
                }
                
                size_t buffer_index = p_get_buffer_index(buffer_width, X, Y);
                if(buffer_index >= buffer_size) {
                    continue;
                }

                if(buffer[buffer_index] == 0x20) {
                    buffer[buffer_index] = (rand() % 2) ? '.' : '\'';
                }
            }
        }
    }
}

char* get_random_captcha_buffer(size_t* buffer_size_out, char* answer_out, size_t answer_out_len) {

    const size_t buffer_size = answer_out_len * (GLYPH_MAX_WIDTH * GLYPH_MAX_HEIGHT);
    const size_t buffer_width = answer_out_len * GLYPH_MAX_WIDTH;

    *buffer_size_out = buffer_size;

    char* buffer = malloc(buffer_size);
    memset(buffer, 0x20, buffer_size);


    // Set newline characters to end of each row.
    for(size_t i = 0; i < GLYPH_MAX_HEIGHT; i++) {
        buffer[p_get_buffer_index(buffer_width, buffer_width-1, i)] = '\n';
    }

    // Create random answer.
    for(size_t i = 0; i < answer_out_len; i++) {
        answer_out[i] = (rand() % NUM_GLYPHS) + 'A';
    }

    p_write_glyphs(buffer, buffer_size, buffer_width, answer_out, answer_out_len);
    p_write_noise(buffer, buffer_size, buffer_width);

    return buffer;
}

bool ascii_captcha_init() {
    char rdbuf[16] = { 0 };
    int fd = open("/dev/random", O_RDONLY);
    if(fd < 0) {
        return false;
    }
    read(fd, rdbuf, sizeof(rdbuf));
    close(fd);

    int64_t seed = 0xFFFF;
    for(size_t i = 0; i < sizeof(rdbuf); i++) {
        seed += (int)rdbuf[i] * 12345;
    }

    if(seed < 0) {
        seed = seed - seed * 2;
    }

    srand(seed);
    return true;
}







const struct glyph_t GLYPHS[NUM_GLYPHS] = {
    {
        {
            "           ",
            "  #######  ",
            " ##     ## ",
            " ##     ## ",
            " ######### ",
            " ##     ## ",
            " ##     ## ",
            "           "
        }
    },
    {
        {
            "           ",
            " #######   ",
            " ##     ## ",
            " ##     ## ",
            " #######   ",
            " ##     ## ",
            " ########  ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  #######  ",
            " ##     ## ",
            " ##        ",
            " ##        ",
            " ##     ## ",
            "  #######  ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ######    ",
            " ##    ##  ",
            " ##     ## ",
            " ##     ## ",
            " ##    ##  ",
            " ######    ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  ######## ",
            " ##        ",
            " ##        ",
            " ######    ",
            " ##        ",
            "  ######## ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  ######## ",
            " ##        ",
            " ##        ",
            " #######   ",
            " ##        ",
            " ##        ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  ######## ",
            " ##        ",
            " ##        ",
            " ##  ####  ",
            " ##     ## ",
            "  ######## ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            " ######### ",
            " ##     ## ",
            " ##     ## ",
            "           ",
        }
    },
    {
        {
            "           ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "           ",
        }
    },
    {
        {
            "           ",
            "     ###   ",
            "       ##  ",
            "       ##  ",
            "       ##  ",
            " ##    ##  ",
            "  #####    ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            " ##    ##  ",
            " ##  ##    ",
            " ####      ",
            " ##  ##    ",
            " ##    ##  ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##        ",
            " ##        ",
            " ##        ",
            " ##        ",
            " ##        ",
            " ######### ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ###   ### ",
            " ## # # ## ",
            " ##  #  ## ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            " ####   ## ",
            " ## ##  ## ",
            " ##  ## ## ",
            " ##   #### ",
            " ##     ## ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  #######  ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            "  #######  ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ########  ",
            " ##     ## ",
            " ########  ",
            " ##        ",
            " ##        ",
            " ##        ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  #######  ",
            " ##     ## ",
            " ##  #  ## ",
            " ##  ## ## ",
            "  #######  ",
            "       ##  ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ########  ",
            " ##     ## ",
            " ########  ",
            " ## ##     ",
            " ##  ##    ",
            " ##   #### ",
            "           ",
        }
    },
    {
        {
            "           ",
            "  #######  ",
            " ##     ## ",
            " ##        ",
            "  #######  ",
            "        ## ",
            " ########  ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ######### ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "    ##     ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            "  #######  ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            "  ##    ## ",
            "   ##  ##  ",
            "     ##    ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            " ##     ## ",
            " ##     ## ",
            " ##  #  ## ",
            "  ## # ##  ",
            "   ## ##   ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            "  ##   ##  ",
            "   ## ##   ",
            "    ###    ",
            "  ##   ##  ",
            " ##     ## ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ##     ## ",
            "  ##   ##  ",
            "   ## ##   ",
            "    ###    ",
            "   ##      ",
            " ##        ",
            "           ",
        }
    },
    {
        {
            "           ",
            " ######### ",
            "       ##  ",
            "      ##   ",
            "    ##     ",
            "  ##       ",
            " ######### ",
            "           ",
        }
    },
};




