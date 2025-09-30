INCLUDE_DIR		=	-Iinclude -Ilibft

CFLAGS			=	-Wall -Wextra -Werror -O3 $(INCLUDE_DIR) 

OBJ_DIR			=	obj

SRC_DIR 		=	src

MAIN_MANDATORY 	=	main.c

SRCS			=	log/log.c\
					mac_addr.c\
					ipv4_addr.c\
					network_interface.c\

MAKE_LIBFT		=	make -s -C libft -j

MAKE_LIST		=	make -s -C libft/list -j

LIBFT			= 	libft/libft.a

LIST			= 	libft/list/linked_list.a

OBJS 			= $(addprefix $(OBJ_DIR)/, $(SRCS:.c=.o))

RM			=	rm -rf


ifeq ($(findstring bonus, $(MAKECMDGOALS)), bonus)
ASCII_NAME	= "bonus"
SRCS += $(MAIN_MANDATORY)
SRCS += $(SRCS_BONUS)
CFLAGS += -DMALCOLM_BONUS
else
ASCII_NAME	= "mandatory"
SRCS += $(MAIN_MANDATORY)
endif

ifeq ($(findstring leak, $(MAKECMDGOALS)), leak)
CFLAGS = $(INCLUDE_DIR) -Wall -Wextra -Werror -g3 -fsanitize=address
else ifeq ($(findstring thread, $(MAKECMDGOALS)), thread)
CFLAGS = $(INCLUDE_DIR) -Wall -Wextra -Werror -g3 -fsanitize=thread
else ifeq ($(findstring debug, $(MAKECMDGOALS)), debug)
CFLAGS = $(INCLUDE_DIR) -Wall -Wextra -Werror -g3
else ifeq ($(findstring no_color, $(MAKECMDGOALS)), no_color)
CFLAGS = -Wall -Wextra -Werror -O3 $(INCLUDE_DIR) -DCOLOR_DISABLE
MAKE_LIBFT = make -s -C libft no_color
endif
