#include "math.h"
#include "string.h"
#include "stdlib.h"
#include "absacc.h"
#include "ftrx.h"
#include "tpm_emulator.h"
#include "tpm_data.h"

#define INIT 0
#define CMD 1
#define SHUT 2

/* We can only transmit a 1020-byte buffer.
 * Buffer bigger than 1020 will cause a segment fault.
 */
#define MAX_BUF 1020 

extern unsigned char InOutBuf[0x400];
extern unsigned char ExtendBuf[0x400];
unsigned char *pInOutBuf; // for debug;
unsigned char *originInOutBuf; // for debug;

int main(void) {
    unsigned int in_size;
    unsigned char *buf;
    unsigned int out_size;
    out_size = MAX_BUF - sizeof(unsigned int);
    pInOutBuf = InOutBuf; 
    originInOutBuf = InOutBuf;
    memcpy(&in_size, InOutBuf, sizeof(unsigned int));
    if (in_size == 0xffffffff) { // use rockey for the first time;
        tpm_engine_first_time();
        return 0;
    }
    buf = InOutBuf+ sizeof(unsigned int);
    if (tpm_engine_init() != 0) {
        return -1;
    }
    if (tpm_handle_command(buf, in_size, buf, &out_size) != 0) return -1;
    if (tpm_engine_final() != 0) {
        return -1;
    }
    memcpy(InOutBuf, &out_size, sizeof(unsigned int));
    return 0;

}
