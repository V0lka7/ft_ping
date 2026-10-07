SHELL = /bin/sh

#####################################################################

NAME = ft_ping

TEST_NAME = $(NAME)_test
TEST_ARCHIVE = $(NAME).a

.SUFFIXES: .c .o .a

#####################################################################
SRC_DIR = app/src
INCLUDE_DIR = app/include/	\
			  app/src/
LIB_DIR = lib
TEST_DIR = test

ifndef TEST
BUILD_DIR = .build
else
BUILD_DIR = .build_test
endif

LIBS =
LIBS_TARGET =

CC = clang
CFLAGS =
CPPFLAGS = -MMD -MP $(addprefix -I,$(INCLUDE_DIR))

LDFLAGS = $(addprefix -L,$(dir $(LIBS_TARGET)))
LDLIBS = $(addprefix -l,$(LIBS))

DIRDUP = mkdir -p $(@D)

#####################################################################

INCLUDES = ${SRC_DIR}/tmp.h \
		   ${SRC_DIR}/ft_ping.h

SRC = $(SRC_DIR)/tmp.c \
	  ${SRC_DIR}/ft_ping.c \
	  ${SRC_DIR}/initialization/arguments_parser.c
ifndef TEST
SRC += app/main.c
endif

TEST_SRC := $(shell find $(TEST_DIR) -name '*.c')
TEST_OBJS := $(TEST_SRC:%.c=$(BUILD_DIR)/%.o)

OBJS := $(SRC:%.c=$(BUILD_DIR)/%.o)
DEPS = $(OBJS:.o=.d)

#####################################################################

all: CFLAGS += -Wall -Wextra -Werror -Wunreachable-code -Wshadow -Wundef -O2
all: $(NAME)
.PHONY: all

release: all
.PHONY: release

debug: CFLAGS += -gdwarf-4 -ggdb3 -DDEBUG
debug: $(NAME)
.PHONY: debug

_test: CFLAGS += -gdwarf-4 -ggdb3 --coverage
_test: CPPFLAGS += -I $(TEST_DIR)
_test: $(TEST_NAME)
.PHONY: _test

test: fcleantest
	$(MAKE) TEST=1 _test
	./test/greatest_parallel.sh -v ./$(TEST_NAME)
.PHONY: test

#####################################################################

$(TEST_NAME): $(LIBS_TARGET) $(TEST_ARCHIVE) $(TEST_OBJS)
	$(CC) \
	$(CFLAGS) \
	$(CPPFLAGS) \
	$(LDFLAGS) \
	$(TEST_OBJS) \
	$(TEST_ARCHIVE) \
	$(LDLIBS) \
	-o $(TEST_NAME)

$(NAME): $(OBJS) $(LIBS_TARGET)
	$(CC) $(LDFLAGS) $(OBJS) $(LDLIBS) -o $(NAME)
	$(info CREATED $(NAME))

$(TEST_ARCHIVE): $(OBJS)
	ar rcsv $(TEST_ARCHIVE) $(OBJS)

$(LIBS_TARGET):
	$(MAKE) -C $(dir $@)

$(BUILD_DIR)/%.o: %.c
	@$(DIRDUP)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

-include $(DEPS)

#####################################################################

clean:
ifneq ($(strip $(LIBS_TARGET)),)
	@${MAKE} -C $(LIB_DIR)/ clean
endif
	@rm -vrf $(BUILD_DIR)
.PHONY: clean

fclean: clean
ifneq ($(strip $(LIBS_TARGET)),)
	@${MAKE} -C $(LIB_DIR)/ fclean
endif
	@rm -vrf $(NAME)
.PHONY: fclean

re: fclean all
.PHONY: re

cleantest:
	@$(MAKE) TEST=1 clean
.PHONY: cleantest

fcleantest:
	@rm -vrf $(TEST_ARCHIVE) $(TEST_NAME)
	@$(MAKE) TEST=1 clean
.PHONY: fcleantest

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all        Build in optimized release mode (-O2)"
	@echo "  release    Alias for all"
	@echo "  debug      Build with debug symbols (dwarf-5, ggdb3)"
	@echo "  test       Clean rebuild and run tests with coverage"
	@echo "  clean      Remove build objects"
	@echo "  fclean     Remove build objects and the $(NAME) binary"
	@echo "  re         fclean + all"
	@echo "  cleantest  Clean the test build"
	@echo "  fcleantest Remove the test archive and binary, then clean"
	@echo "  help       Show this message"
.PHONY: help
