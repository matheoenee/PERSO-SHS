# Compiler and flags
CC = gcc
CFLAGS = -Wall -g

# Source files
SRC = main.c shs_crypto.c shs_functions.c

# Header files
INCLUDE = shs_crypto.h shs_functions.h

# Output binary
OUT = shs

# Object files
OBJ = $(SRC:.c=.o)

# Default target to compile the project
all: $(OUT)

# Rule to create the output binary
$(OUT): $(OBJ)
	$(CC) $(CFLAGS) -o $(OUT) $(OBJ)

# Rule to compile source files into object files
%.o: %.c $(INCLUDE)
	$(CC) $(CFLAGS) -c $< -o $@

# Rule to clean the generated files
clean:
	rm -f $(OUT) $(OBJ)

# Rule to recompile everything
rebuild: clean all
