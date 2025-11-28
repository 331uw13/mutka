FLAGS = -ggdb -Wall -Wextra 
CC = gcc

TARGET_NAME = client

SRC  = $(shell find ./src -type f -name *.c)
OBJS = $(SRC:.c=.o)
LIBS = -L../../libmutka -Wl,-rpath,../../libmutka -lmutka -lm -lssl -lcrypto

all: $(TARGET_NAME)

%.o: %.c
	@$(CC) $(FLAGS) \
		-c $< -o $@ && (echo -e "\033[32m[Compiled]\033[0m $<") || (echo -e "\033[31m[Failed]\033[0m $<"; exit 1) 

$(TARGET_NAME): $(OBJS)
	@echo -e "\033[90mLinking...\033[0m"
	@$(CC) $(OBJS) $(LIBS) -o $@ && (echo -e "\033[36mDone.\033[0m"; ls -lh $(TARGET_NAME))

clean:
	@rm -v $(OBJS) $(TARGET_NAME)

.PHONY: all clean

