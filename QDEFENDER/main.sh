gcc -O3 -I. main.c -L. -lqdefender-lib -o main
export LD_LIBRARY_PATH=.
./main