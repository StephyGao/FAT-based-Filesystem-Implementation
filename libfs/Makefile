# Target library
lib := libfs.a

Target := fs.o disk.o

FLAGS := -Wall -Wextra -Werror -MMD

CC := gcc
CCA := ar rcs

deps := $(patsubst %.o, %.d, $(Target))
-include $(deps)



all: $(lib)


%.a: $(Target)
	$(CCA)  $@ $^

%.o: %.c
	@echo "Start $@"
	@$(CC) $(FLAGS) -c -o $@ $< 

clean:
	@echo "Clean Done"
	rm -f $(lib) $(Target) $(deps)


