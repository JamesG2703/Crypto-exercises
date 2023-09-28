#include "crypto.h"

/**
 * Bring normal buffer into bitsliced form
 * @param pt Input: state_bs in normal form
 * @param state_bs Output: Bitsliced state
 */
static void enslice(const uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT])
{
    // convert plaintext in normal byte form into bit-sliced form using bitwise operations
    // iterate through each input buffer bit, extracting bits from each pt array bytes and storing it
    // in the corresponding position in the bit-sliced register array
    for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++) {
        // Unrolled loop to potentially improve performance by reducing overhead
        // each line covers sets of 8 bits from the input normal form pt array
        // Convert normal buffer into bitsliced form via bitwise operations
        // Use bitwise OR between bit-sliced register array's value and the new bit
        // extracted from every byte inside the normal form input array;
        // bit pos is decided by i modulo 8, and the byte from which it is extracted is decided by i divided by 8
        state_bs[i] |= ((pt[0 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 0;
        state_bs[i] |= ((pt[1 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 1;
        state_bs[i] |= ((pt[2 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 2;
        state_bs[i] |= ((pt[3 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 3;
        state_bs[i] |= ((pt[4 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 4;
        state_bs[i] |= ((pt[5 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 5;
        state_bs[i] |= ((pt[6 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 6;
        state_bs[i] |= ((pt[7 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 7;
        
        state_bs[i] |= ((pt[8 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 8;
        state_bs[i] |= ((pt[9 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 9;
        state_bs[i] |= ((pt[10 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 10;
        state_bs[i] |= ((pt[11 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 11;
        state_bs[i] |= ((pt[12 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 12;
        state_bs[i] |= ((pt[13 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 13;
        state_bs[i] |= ((pt[14 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 14;
        state_bs[i] |= ((pt[15 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 15;
        
        state_bs[i] |= ((pt[16 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 16;
        state_bs[i] |= ((pt[17 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 17;
        state_bs[i] |= ((pt[18 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 18;
        state_bs[i] |= ((pt[19 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 19;
        state_bs[i] |= ((pt[20 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 20;
        state_bs[i] |= ((pt[21 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 21;
        state_bs[i] |= ((pt[22 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 22;
        state_bs[i] |= ((pt[23 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 23;

        state_bs[i] |= ((pt[24 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 24;
        state_bs[i] |= ((pt[25 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 25;
        state_bs[i] |= ((pt[26 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 26;
        state_bs[i] |= ((pt[27 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 27;
        state_bs[i] |= ((pt[28 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 28;
        state_bs[i] |= ((pt[29 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 29;
        state_bs[i] |= ((pt[30 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 30;
        state_bs[i] |= ((pt[31 * CRYPTO_IN_SIZE + i / 8] >> (i % 8)) & 1) << 31;
    }
}

/**
 * Bring bitsliced buffer into normal form
 * @param state_bs Input: Bitsliced state
 * @param pt Output: state_bs in normal form
 */
static void unslice(const bs_reg_t state_bs[CRYPTO_IN_SIZE_BIT], uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH])
{
    // convert the state in bit-sliced form into normal byte form
    // loop through each bit-sliced state bit, and set it in the correct byte inside the output normal form pt array
    // using bitwise operations for extraction and moving the bit to the new position, for all 256 state bits
    // e.g., first iteration gets the first bit from the initial 32 bit bitsliced state register
    // and moves it i modulo 8 bits to the left, before applying bitwise OR to move it to the correct pt byte
    for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++) {
        // Unrolled loop to potentially improve performance by reducing overhead
        pt[0 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 0) & 1) << (i % 8);
        pt[1 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 1) & 1) << (i % 8);
        pt[2 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 2) & 1) << (i % 8);
        pt[3 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 3) & 1) << (i % 8);
        pt[4 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 4) & 1) << (i % 8);
        pt[5 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 5) & 1) << (i % 8);
        pt[6 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 6) & 1) << (i % 8);
        pt[7 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 7) & 1) << (i % 8);
        
        pt[8 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 8) & 1) << (i % 8);
        pt[9 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 9) & 1) << (i % 8);
        pt[10 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 10) & 1) << (i % 8);
        pt[11 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 11) & 1) << (i % 8);
        pt[12 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 12) & 1) << (i % 8);
        pt[13 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 13) & 1) << (i % 8);
        pt[14 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 14) & 1) << (i % 8);
        pt[15 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 15) & 1) << (i % 8);
        
        pt[16 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 16) & 1) << (i % 8);
        pt[17 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 17) & 1) << (i % 8);
        pt[18 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 18) & 1) << (i % 8);
        pt[19 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 19) & 1) << (i % 8);
        pt[20 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 20) & 1) << (i % 8);
        pt[21 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 21) & 1) << (i % 8);
        pt[22 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 22) & 1) << (i % 8);
        pt[23 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 23) & 1) << (i % 8);

        pt[24 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 24) & 1) << (i % 8);
        pt[25 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 25) & 1) << (i % 8);
        pt[26 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 26) & 1) << (i % 8);
        pt[27 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 27) & 1) << (i % 8);
        pt[28 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 28) & 1) << (i % 8);
        pt[29 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 29) & 1) << (i % 8);
        pt[30 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 30) & 1) << (i % 8);
        pt[31 * CRYPTO_IN_SIZE + i / 8] |= ((state_bs[i] >> 31) & 1) << (i % 8);
    }
}

/**
 * Perform next key schedule step
 * @param key Key register to be updated
 * @param r Round counter
 * @warning For correct function, has to be called with incremented r each time
 * @note You are free to change or optimize this function
 */
static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	//
	// There is no need to edit this code - but you can do so if you want to
	// optimise further
	//

	const uint8_t sbox[16] = {
		0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 1, 0x2,
	};

	uint8_t tmp = 0;
	const uint8_t tmp2 = key[2];
	const uint8_t tmp1 = key[1];
	const uint8_t tmp0 = key[0];
	
	// rotate right by 19 bit
	key[0] = key[2] >> 3 | key[3] << 5;
	key[1] = key[3] >> 3 | key[4] << 5;
	key[2] = key[4] >> 3 | key[5] << 5;
	key[3] = key[5] >> 3 | key[6] << 5;
	key[4] = key[6] >> 3 | key[7] << 5;
	key[5] = key[7] >> 3 | key[8] << 5;
	key[6] = key[8] >> 3 | key[9] << 5;
	key[7] = key[9] >> 3 | tmp0 << 5;
	key[8] = tmp0 >> 3   | tmp1 << 5;
	key[9] = tmp1 >> 3   | tmp2 << 5;
	
	// perform sbox lookup on MSbits
	tmp = sbox[key[9] >> 4];
	key[9] &= 0x0F;
	key[9] |= tmp << 4;
	
	// XOR round counter k19 ... k15
	key[1] ^= r << 7;
	key[2] ^= r >> 1;
}


/**
 * implement the PRESENT cipher for encryption in the given normal form array
 * @param pt plaintext normal form array
 * @param key secret key
 */
void crypto_func(uint8_t pt[CRYPTO_IN_SIZE * BITSLICE_WIDTH], uint8_t key[CRYPTO_KEY_SIZE])
{
	// State buffer and additional backbuffer of same size (you can remove the backbuffer if you do not need it)
    bs_reg_t state[CRYPTO_IN_SIZE_BIT] = {0};
    bs_reg_t bb[CRYPTO_IN_SIZE_BIT];
	
	// convert the input plaintext normal form into bit-sliced form, and store it in the state buffer
	enslice(pt, state);
	
    // Perform 31 rounds of PRESENT encryption, with 3 steps: add round key, sbox layer, pbox layer
    for (uint8_t j = 1; j <= 31; j++) {
        // Add Round Key
        // Use bitwise XOR on the current state and the secret key to produce a subkey which is updated every round
        // in order to prevent the ecryption from being reversed
        for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++) {
            if (((key[i / 8 + 2] >> (i % 8)) & 1) == 1) {
                state[i] = ~state[i];
            }
        }

        // S-Box layer to apply the s-box function to each block of 4 bits of the given state
        // in order to ensure the encryption is not linear.
        // 16 sbox lookups resulting since it is applied to each nibble of the state with 64 bits
        for (uint8_t i = 0; i < 16; i++) {
            bs_reg_t a0, a1, a2, a3, b0, b1, b2, b3;

            a0 = state[i * 4];
            a1 = state[i * 4 + 1];
            a2 = state[i * 4 + 2];
            a3 = state[i * 4 + 3];

            // Minimized the S-Box expressions to improve computation speed thanks to fewer terms
            b0 = a0 ^ (~a1 & a2) ^ a3;
            b1 = (a0 & (a1 & a2))^ (~a0 & (a3 & (a1 ^ a2))) ^ (a1 ^ a3) ;
            b2 = (a0 & (a3 & (a1 ^ a2))) ^ (a0 & (a1 ^ a3)) ^ (~a1 & a3) ^ ~a2;
            b3 = (~a0 & ~(a1 & a2)) ^ (a0 & (a3 & (a1 ^ a2))) ^ (a1 ^ a3);

            // fixed 4 to 4-bit substitution (4 bit input & output)
            state[i * 4] = b0;
            state[i * 4 + 1] = b1;
            state[i * 4 + 2] = b2;
            state[i * 4 + 3] = b3;
        }

        // P-Box layer to permute the state bits to fixed pattern, using a temporary temp_state buffer
        // to avoid overwriting bits.
        bs_reg_t temp_state[CRYPTO_IN_SIZE_BIT];

        for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++) {
            temp_state[((i / 4) + (i % 4) * 16)] = state[i];
        }
        // permute the state bits after sbox layer
        memcpy(state, temp_state, 4 * CRYPTO_IN_SIZE_BIT); // copy the temp_state buffer updated bits into the state

        // Update the round key for the next loop iteration
        update_round_key(key, j);
    }

    // Add Round Key
    // First add round key is performed before the encryption rounds (whitening step).
    // Second (this) add round key is performed to make sure the plaintext is correctly encrypted
    // and prevent the risk of plaintext recovery by reversing the first add_round_key.
    for (uint8_t i = 0; i < CRYPTO_IN_SIZE_BIT; i++) {
        if (((key[i / 8 + 2] >> (i % 8)) & 1) == 1) {
            state[i] = ~state[i];
        }
    }

    // clear the plain text pt buffer before storing the cipthertext
    memset(pt, 0, CRYPTO_IN_SIZE * BITSLICE_WIDTH);

	// convert bit-sliced form ciphertext into normal form then store it inside the plaintext normal form array
	unslice(state, pt);
}