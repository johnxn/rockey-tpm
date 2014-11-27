	CC              =gcc
all:
	$(CC) test.c ../tpm/tpm_marshalling.c printfs.c crypto.c stuff_inoutbuf.c ../crypto/sha1.c ../crypto/hmac.c -o test -I ../tpm -I ../Core -lRockeyARM -lpthread
clean:
	rm -f main *.bin
