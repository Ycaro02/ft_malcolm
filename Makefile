include libft/rsc/mk/color.mk
include rsc/mk/source.mk

NAME            =   ft_malcolm
CC              =   clang -g3 -gdwarf-4


all:        $(NAME)

$(NAME): $(LIBFT) $(LIST) $(OBJ_DIR) $(OBJS)
	@$(MAKE_LIBFT)
	@$(MAKE_LIST)
	@./rsc/sh/ascii.sh $(ASCII_NAME)
	@printf "$(CYAN)Compiling ${NAME} ...$(RESET)\n"
	@$(CC) $(CFLAGS) -o $(NAME) $(OBJS) $(LIBFT) $(LIST)
	@printf "$(GREEN)Compiling $(NAME) done$(RESET)\n"

$(LIST):
ifeq ($(shell [ -f ${LIST} ] && echo 0 || echo 1), 1)
	@printf "$(CYAN)Compiling list...$(RESET)\n"
	@$(MAKE_LIST)
	@printf "$(GREEN)Compiling list done$(RESET)\n"
endif

$(LIBFT):
ifeq ($(shell [ -f ${LIBFT} ] && echo 0 || echo 1), 1)
	@printf "$(CYAN)Compiling libft...$(RESET)\n"
	@$(MAKE_LIBFT)
	@printf "$(GREEN)Compiling libft done$(RESET)\n"
endif

$(OBJ_DIR):
	@mkdir -p ${OBJ_DIR} 

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@printf "$(YELLOW)Compile $<$(RESET) $(BRIGHT_BLACK)-->$(RESET) $(BRIGHT_MAGENTA)$@$(RESET)\n"
	@mkdir -p $(dir $@)
	@$(CC) $(CFLAGS) -o $@ -c $<

clear_mandatory:
ifeq ($(shell [ -f ${OBJ_DIR}/main.o ] && echo 0 || echo 1), 0)
	@printf "$(RED)Clean mandatory obj $(RESET)\n"
	@rm -rf ${OBJ_DIR}
endif

clean:
ifeq ($(shell [ -d ${OBJ_DIR} ] && echo 0 || echo 1), 0)
	@$(RM) $(OBJ_DIR)
	@printf "$(RED)Clean $(OBJ_DIR) done$(RESET)\n"
	@$(RM)
endif

fclean:		clean_lib clean
	@$(RM) $(NAME)
	@printf "$(RED)Clean $(NAME)$(RESET)\n"

clean_lib:
	@$(MAKE_LIST) fclean
	@$(MAKE_LIBFT) fclean
	@printf "$(RED)Clean libft, list$(RESET)\n"

vtest: $(NAME)
	valgrind --leak-check=full --show-leak-kinds=all ./ft_malcolm 10.12.255.255 aa:bb:cc:dd:ee:ff 10.12.10.22 10:12:10:22:aa:bb


test: $(NAME)
	./ft_malcolm 10.12.255.255 aa:bb:cc:dd:ee:ff 10.12.10.22 10:12:10:22:aa:bb

btest: $(NAME)
	./ft_malcolm poisoned aa:bb:cc:dd:ee:ff target 10:12:10:22:aa:bb

complete_test: $(NAME)
	@printf "$(CYAN)Starting complete test...$(RESET)\n"
	@./rsc/tester/complete_test.sh

bonus_complete_test: bonus
	@printf "$(CYAN)Starting complete bonus test...$(RESET)\n"
	@./rsc/tester/complete_test.sh btest

bonus_mitm: bonus
	@printf "$(CYAN)Starting MITM attack test...$(RESET)\n"
	./ft_malcolm -m 10.12.12.7 10:12:12:07:07:07 10.12.10.22 10:12:10:22:aa:bb

mitm_test:
	@printf "$(CYAN)Starting MITM test...$(RESET)\n"
	@./rsc/tester/MITM_test.sh

sleep:
	@printf "$(CYAN)Starting MITM test...$(RESET)\n"
	@sleep infinity

wire:
	@printf "$(CYAN)Start wireshark container and attach the current terminal to it$(RESET)\n"
	@./rsc/docker/run.sh "$(word 2,$(MAKECMDGOALS))" ; true

no_color: clean $(NAME)
	@printf	"$(CYAN)CFLAGS: $(CFLAGS)$(RESET)\n"


bonus: clean $(NAME)
 @printf "$(CYAN)CFLAGS: $(CFLAGS)$(RESET)\n"

# @ulimit -c unlimited
leak thread debug: clean $(NAME)
	@printf	"$(CYAN)CFLAGS: $(CFLAGS)$(RESET)\n"

re: clean $(NAME)

.PHONY:		all clean fclean re bonus > Makefile
