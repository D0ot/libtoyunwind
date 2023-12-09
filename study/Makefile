unwind: unwind.c
	cc -ggdb -fsanitize=address -O0 -fno-omit-frame-pointer -funwind-tables ./unwind.c -o ./unwind -I../include/
	cc -ggdb -fsanitize=address -O0 -fno-omit-frame-pointer -funwind-tables -S ./unwind.c -o ./unwind.s -I../include/

