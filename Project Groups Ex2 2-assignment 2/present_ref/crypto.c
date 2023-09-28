#include "crypto.h"

// add round key function to merge text and round key via bitwise XOR operation
static void add_round_key(uint8_t pt[CRYPTO_IN_SIZE], uint8_t roundkey[CRYPTO_IN_SIZE])
{
	// for each byte in the pt and roundkey arrays
    for (uint8_t i = 0; i < CRYPTO_IN_SIZE; i++)
    {
		// perform bitwise XOR between pt and roundkey arrays bytes
		// and store the result in the pt array
		pt[i] = pt[i] ^ roundkey[i];
    }
}

// sbox lookup table
static const uint8_t sbox[16] = {
	0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
};

// s-box layer transformation to replace each state byte with corresponding bytes from the sbox table above
static void sbox_layer(uint8_t state[CRYPTO_IN_SIZE])
{
	// replace every byte in state with the sbox table corresponding value
    for (uint8_t i = 0; i < CRYPTO_IN_SIZE; i++)
    {
		// use each state byte high nibble to get corresponding sbox table value,
		// extract low nibble of state byte to get corresponding sbox table value,
		// then combine sbox values into single byte to replace the state byte
        state[i] = (sbox[state[i] >> 4] << 4) | sbox[state[i] & 0x0F];
    }
}

// implement permutation box layer on the state array of 64 bytes
static void pbox_layer(uint8_t state[CRYPTO_IN_SIZE])
{
	// create temporary array initialized with 0s to store the permutated state
    uint8_t temp_state[CRYPTO_IN_SIZE] = {0};

	// pbox transformation loop
    for (uint8_t i = 0; i < 64; i++)
    {
		// extract state bit value and store it in new var
        uint8_t source_bit = (state[i >> 3] >> (i & 7)) & 1;

		// calculate new position for bit to store in temp_state using predetermined pattern
        uint8_t target_bit_position;
        if (i == 63) 
		{
			// last bit is moved to the same position
			target_bit_position = 63;
		} else {
			// other bits are moved to their (starting position multiplied by 16) modulo 63
			target_bit_position = (16 * i) % 63;
		}

		// set bit in correct position in the temporary array via bitwise OR and left shift
        temp_state[target_bit_position >> 3] |= source_bit << (target_bit_position & 7);
    }

	// copy values of the temporary array over the original state array
	// to change the bit positions according to the predetermined pattern
    for (uint8_t i = 0; i < CRYPTO_IN_SIZE; i++)
    {
        state[i] = temp_state[i];
    }
}

static void update_round_key(uint8_t key[CRYPTO_KEY_SIZE], const uint8_t r)
{
	//
	// There is no need to edit this code
	//
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

void crypto_func(uint8_t pt[CRYPTO_IN_SIZE], uint8_t key[CRYPTO_KEY_SIZE])
{
	//
	// There is no need to edit this code
	//
	
	uint8_t i = 0;
	
	for(i = 1; i <= 31; i++)
	{
		add_round_key(pt, key + 2);
		sbox_layer(pt);
		pbox_layer(pt);
		update_round_key(key, i);
	}
	
	add_round_key(pt, key + 2);
}
