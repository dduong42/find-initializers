.POSIX:

NAME=find-initializers
CFLAGS=-Wall -Wextra

$(NAME): $(NAME).c

fclean:
	$(RM) $(NAME)

re: fclean $(NAME)
