NAME=bench
gcc -O3 -I. $NAME.c -L. -lqdefender-lib -o $NAME
export LD_LIBRARY_PATH=.
echo 

echo "TEST VARIANTS OF SAME FAMILY (kyber sha variants level 3)"
./$NAME Kyber768
./$NAME Kyber768-90s

echo "TEST WAR OF LATTICE KINGS (ntru-hps vs kyber level 5)"
./$NAME Kyber1024
./$NAME NTRU-HPS-4096-821
./$NAME NTRU-HRSS-1373

echo "TEST LATTICE VS NON-LATTICE (mceliece and sike vs ntru level 5)"
./$NAME NTRU-HPS-4096-821
./$NAME Classic-McEliece-6688128
./$NAME SIKE-p751
