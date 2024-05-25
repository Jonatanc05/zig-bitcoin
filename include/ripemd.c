// I AM NOT THE AUTHOR OF THIS FILE
//
// author: agoebel
// github: https://github.com/agoebel/RIPEMD-160

// author's note: "unsigned int" could appear 16-bit on some older compilers
// my note: "unsigned long" actually appears as 64-bit for my tests on linux
//          so I'm going with unsigned int
typedef unsigned int uint32;

#define BLOCK_LEN 64 // length of each block for processing in bytes
#define HASH_LEN 20 // length of hash in bytes
#define WORDS_PER_BLOCK (BLOCK_LEN / sizeof(uint32))
#define WORDS_PER_HASH (HASH_LEN / sizeof(uint32))
#define N_ROUNDS 5 // it equals to WORDS_PER_HASH, but it is a mere coincidence!
#define WORD_SIZE (sizeof(uint32))

uint32 f (int rnd, uint32 B, uint32 C, uint32 D);

// #############################################################################################

int rho[WORDS_PER_BLOCK] = {7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8};
int pi[WORDS_PER_BLOCK]  = {5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12};
int lsh_amt[N_ROUNDS][WORDS_PER_BLOCK] = {
/*rnd 1*/       {11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8},
/*rnd 2*/       {12, 13, 11, 15, 6, 9, 9, 7, 12, 15, 11, 13, 7, 8, 7, 7},
/*rnd 3*/       {13, 15, 14, 11, 7, 7, 6, 8, 13, 14, 13, 12, 5, 5, 6, 9},
/*rnd 4*/       {14, 11, 12, 14, 8, 6, 5, 5, 15, 12, 15, 14, 9, 9, 8, 6},
/*rnd 5*/       {15, 12, 13, 13, 9, 5, 8, 6, 14, 11, 12, 11, 8, 6, 5, 5}
        };
uint32 K_l[WORDS_PER_HASH] = {0x0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e};
uint32 	K_r[WORDS_PER_HASH] = {0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x0};
uint32 CV[WORDS_PER_HASH] = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0};

uint32 f (int rnd, uint32 B, uint32 C, uint32 D)
{
        switch (rnd) {
                case 1: return B^C^D;
                case 2: return (B & C) | (~B & D);
                case 3: return (B | ~C) ^ D;
                case 4: return (B & D) | (C & ~D);
                case 5: return B ^ (C | ~D);
                }
}

// #############################################################################################

#define MAX_LEN 32000 // maximal allowed length of input, may be increased up to 8 megabytes

typedef unsigned char uchar;

void calc_hash(uchar* message, uchar* result);

int string_length(const char* s) {
	int i = 0;
	
	while (s[i] != 0) {
		i++;
	}
	
	return i;
}

// auxiliary arrays for precalculated amounts of bit positions to shift calculation results
int rhoL[N_ROUNDS][WORDS_PER_BLOCK], rhoR[N_ROUNDS][WORDS_PER_BLOCK]; 

// adds padding to message, returns number of blocks
int padding(uchar* message, int len) {
    int i;
    unsigned long bitLen = len * 8L; // length of message in bits
    
    message[len++] = 0x80; // padding has at least one byte
        
    // filling with zeroes upto nearest proper block border minus size of field for length (8 bytes)
    while ((len % BLOCK_LEN) != BLOCK_LEN - 8) {
        message[len++] = 0x00;
    }
    
    // filling length field
    for (i = 0; i < 8; i++) {
        message[len++] = (uchar) (bitLen & 0xFF);
        bitLen >>= 8;
    }
    
    return len / 64;
}

// cyclic rotation of the uint32 to the left, by specified number of bit positions
// e.g. rol(0x80000008, 2) = 0x00000022
uint32 rol(uint32 x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

// precalculation of values RHO used as amount of bit positions for shifting
// these values are the same for each of blocks so it is good to calculate them before evaluation
void rho_precalc(void) {
    int i, j;
    for (i = 0; i < WORDS_PER_BLOCK; i++) {
        rhoL[0][i] = i;
        rhoR[0][i] = pi[i];
        for (j = 1; j < N_ROUNDS; j++) {
            rhoL[j][i] = rho[rhoL[j - 1][i]];
            rhoR[j][i] = rho[rhoR[j - 1][i]];
        }
    }
}

// calculates hash of "message" formatted as ASCII-Z string
// 20 bytes of result are written to "result" variable
void calc_hash(uchar* message, uchar* result) {
    int len = string_length(message);
    int blocks;
    int i, j, k;
    uint32 abcdeL[WORDS_PER_HASH]; // variables Al, Bl, Cl, Dl, El are placed here
    uint32 abcdeR[WORDS_PER_HASH]; // variables Ar, Br, Cr, Dr, Er are placed here
    uint32 T;
    uint32 words[WORDS_PER_BLOCK]; // words of current block
    
    rho_precalc();
    
    blocks = padding(message, len);
    
    for (k = 0; k < blocks; k++) {
        
        // endianness-independent translation from byte*message to uint32*words
        for (i = 0; i < WORDS_PER_BLOCK; i++) {
            words[i] = 0;
            for (j = 0; j < WORD_SIZE; j++) {
                words[i] |= message[k * BLOCK_LEN + i * WORD_SIZE + j] << (j * 8);
            }
        }
        
        for (j = 0; j < WORDS_PER_HASH; j++) {
            abcdeL[j] = CV[j];
            abcdeR[j] = CV[j];
        }
        
        for (j = 0; j < N_ROUNDS; j++) {
            for (i = 0; i < WORDS_PER_BLOCK; i++) {
                T = abcdeL[0];
                T += f(j + 1, abcdeL[1], abcdeL[2], abcdeL[3]);
                T += words[rhoL[j][i]];
                T += K_l[j];
                T = rol(T, lsh_amt[j][rhoL[j][i]]);
                T += abcdeL[4];
                abcdeL[0] = abcdeL[4];
                abcdeL[4] = abcdeL[3];
                abcdeL[3] = rol(abcdeL[2], 10);
                abcdeL[2] = abcdeL[1];
                abcdeL[1] = T;
                T = abcdeR[0];
                T += f(5 - j, abcdeR[1], abcdeR[2], abcdeR[3]);
                T += words[rhoR[j][i]];
                T += K_r[j];
                T = rol(T, lsh_amt[j][rhoR[j][i]]);
                T += abcdeR[4];
                abcdeR[0] = abcdeR[4];
                abcdeR[4] = abcdeR[3];
                abcdeR[3] = rol(abcdeR[2], 10);
                abcdeR[2] = abcdeR[1];
                abcdeR[1] = T;
            }
        }
        
        T = CV[1] + abcdeL[2] + abcdeR[3];
        for (i = 1; i < WORDS_PER_HASH; i++) {
            CV[i] = CV[(i + 1) % WORDS_PER_HASH] + abcdeL[(i + 2) % WORDS_PER_HASH] + abcdeR[(i + 3) % WORDS_PER_HASH];
        }
        CV[0] = T;
    }
    
    // endianness-independent translation from uint32*hash to uchar*result
    for (i = 0; i < WORDS_PER_HASH; i++) {
        for (j = 0; j < WORD_SIZE; j++) {
            result[i * WORD_SIZE + j] = (uchar) (CV[i] & 0xFF);
            CV[i] >>= 8;
        }
    }
}
