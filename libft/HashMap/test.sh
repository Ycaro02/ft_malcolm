#!/bin/bash

clang hashMap_test.c HashMap.c ../libft.a ../list/linked_list.a ../../obj/log/log.o -g\
	&& valgrind --leak-check=full ./a.out
rm -rf a.out
