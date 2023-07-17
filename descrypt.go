package enzoic

const ascii64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func ascii_to_bin(ch byte) byte {
	lz := byte('z')
	la := byte('a')
	uz := byte('Z')
	ua := byte('A')
	ni := byte('9')
	dt := byte('.')

	if ch > lz {
		return 0
	}
	if ch >= la {
		return ch - la + 38
	}
	if ch > uz {
		return 0
	}
	if ch >= ua {
		return ch - ua + 12
	}
	if ch > ni {
		return 0
	}
	if ch >= dt {
		return ch - dt
	}
	return 0
}

var des_IP = []byte{
	58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
}

var des_key_perm = []byte{
	57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
}

var des_key_shifts = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

var des_comp_perm = []byte{
	14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
}

var des_sbox = [][]byte{
	{
		14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
		0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
		4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
		15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
	}, {
		15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
		3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
		0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
		13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
	}, {
		10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
		13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
		13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
		1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
	}, {
		7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
		13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
		10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
		3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
	}, {
		2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
		14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
		4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
		11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
	}, {
		12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
		10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
		9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
		4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
	}, {
		4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
		13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
		1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
		6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
	}, {
		13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
		1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
		7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
		2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
	},
}

var des_pbox = []byte{
	16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
	2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
}

var des_bits32 = []int{
	0x80000000, 0x40000000, 0x20000000, 0x10000000,
	0x08000000, 0x04000000, 0x02000000, 0x01000000,
	0x00800000, 0x00400000, 0x00200000, 0x00100000,
	0x00080000, 0x00040000, 0x00020000, 0x00010000,
	0x00008000, 0x00004000, 0x00002000, 0x00001000,
	0x00000800, 0x00000400, 0x00000200, 0x00000100,
	0x00000080, 0x00000040, 0x00000020, 0x00000010,
	0x00000008, 0x00000004, 0x00000002, 0x00000001,
}

var bits28 = []int{
	0x08000000, 0x04000000, 0x02000000, 0x01000000,
	0x00800000, 0x00400000, 0x00200000, 0x00100000,
	0x00080000, 0x00040000, 0x00020000, 0x00010000,
	0x00008000, 0x00004000, 0x00002000, 0x00001000,
	0x00000800, 0x00000400, 0x00000200, 0x00000100,
	0x00000080, 0x00000040, 0x00000020, 0x00000010,
	0x00000008, 0x00000004, 0x00000002, 0x00000001,
}

var bits24 = []int{
	0x00800000, 0x00400000, 0x00200000, 0x00100000,
	0x00080000, 0x00040000, 0x00020000, 0x00010000,
	0x00008000, 0x00004000, 0x00002000, 0x00001000,
	0x00000800, 0x00000400, 0x00000200, 0x00000100,
	0x00000080, 0x00000040, 0x00000020, 0x00000010,
	0x00000008, 0x00000004, 0x00000002, 0x00000001,
}

var des_bits8 = []byte{0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01}

var u_sbox = [8][64]byte{}
var m_sbox = [4][4096]byte{}
var init_perm = [64]byte{}
var final_perm = [64]byte{}
var inv_key_perm = [64]byte{}
var u_key_perm = [56]byte{}
var inv_comp_perm = [56]byte{}
var ip_maskl = [8][256]int{}
var ip_maskr = [8][256]int{}
var fp_maskl = [8][256]int{}
var fp_maskr = [8][256]int{}
var un_pbox = [32]byte{}
var psbox = [4][256]int{}
var key_perm_maskl = [8][128]int{}
var key_perm_maskr = [8][128]int{}
var comp_maskl = [8][128]int{}
var comp_maskr = [8][128]int{}

func des_init() {
	/*
	 * Invert the S-boxes, reordering the input bits.
	 */
	for i := 0; i < 8; i += 1 {
		for j := 0; j < 64; j += 1 {
			b := (j & 0x20) | ((j & 1) << 4) | ((j >> 1) & 0xf)
			u_sbox[i][j] = des_sbox[i][b]
		}
	}

	/*
	 * Convert the inverted S-boxes into 4 arrays of 8 bits.
	 * Each will handle 12 bits of the S-box input.
	 */
	for b := 0; b < 4; b += 1 {
		for i := 0; i < 64; i += 1 {
			for j := 0; j < 64; j += 1 {
				m_sbox[b][(i<<6)|j] = (u_sbox[(b << 1)][i] << 4) | u_sbox[(b<<1)+1][j]
			}
		}
	}

	/*
	 * Set up the initial & final permutations into a useful form, and
	 * initialise the inverted key permutation.
	 */
	for i := 0; i < 64; i += 1 {
		final_perm[i] = des_IP[i] - 1
		init_perm[final_perm[i]] = byte(i)
		inv_key_perm[i] = 255
	}

	/*
	 * Invert the key permutation and initialise the inverted key
	 * compression permutation.
	 */
	for i := 0; i < 56; i += 1 {
		u_key_perm[i] = des_key_perm[i] - 1
		inv_key_perm[des_key_perm[i]-1] = byte(i)
		inv_comp_perm[i] = 255
	}

	/*
	 * Invert the key compression permutation.
	 */
	for i := 0; i < 48; i += 1 {
		inv_comp_perm[des_comp_perm[i]-1] = byte(i)
	}

	/*
	 * Set up the OR-mask arrays for the initial and final permutations,
	 * and for the key initial and compression permutations.
	 */
	for k := 0; k < 8; k += 1 {
		for i := 0; i < 256; i += 1 {
			ip_maskl[k][i] = 0
			ip_maskr[k][i] = 0
			fp_maskl[k][i] = 0
			fp_maskr[k][i] = 0
			for j := 0; j < 8; j += 1 {
				inbit := 8*k + j
				if byte(i)&des_bits8[j] > 0 {
					obit := init_perm[inbit]
					if obit < 32 {
						ip_maskl[k][i] |= des_bits32[obit]
					} else {
						ip_maskr[k][i] |= des_bits32[obit-32]
					}

					obit = final_perm[inbit]
					if obit < 32 {
						fp_maskl[k][i] |= des_bits32[obit]
					} else {
						fp_maskr[k][i] |= des_bits32[obit-32]
					}
				}
			}
		}

		for i := 0; i < 128; i += 1 {
			key_perm_maskl[k][i] = 0
			key_perm_maskr[k][i] = 0
			for j := 0; j < 7; j += 1 {
				inbit := 8*k + j
				if byte(i)&des_bits8[j+1] > 0 {
					obit := inv_key_perm[inbit]
					if obit == 255 {
						continue
					}

					if obit < 28 {
						key_perm_maskl[k][i] |= bits28[obit]
					} else {
						key_perm_maskr[k][i] |= bits28[obit-28]
					}
				}
			}

			comp_maskl[k][i] = 0
			comp_maskr[k][i] = 0
			for j := 0; j < 7; j += 1 {
				inbit := 7*k + j
				if byte(i)&des_bits8[j+1] > 0 {
					obit := inv_comp_perm[inbit]
					if obit == 255 {
						continue
					}
					if obit < 24 {
						comp_maskl[k][i] |= bits24[obit]
					} else {
						comp_maskr[k][i] |= bits24[obit-24]
					}
				}
			}
		}
	}

	/*
	 * Invert the P-box permutation, and convert into OR-masks for
	 * handling the output of the S-box arrays setup above.
	 */
	for i := 0; i < 32; i += 1 {
		un_pbox[des_pbox[i]-1] = byte(i)
	}

	for b := 0; b < 4; b += 1 {
		for i := 0; i < 256; i += 1 {
			psbox[b][i] = 0
			for j := 0; j < 8; j += 1 {
				if byte(i)&des_bits8[j] > 0 {
					psbox[b][i] |= des_bits32[un_pbox[8*b+j]]
				}
			}
		}
	}
}

var en_keysl = [16]int{}
var en_keysr = [16]int{}

func des_setkey(key [8]byte) {
	rawkey0 := (uint32(key[0]) << 24) |
		(uint32(key[1]) << 16) |
		(uint32(key[2]) << 8) |
		(uint32(key[3]) << 0)

	rawkey1 := (uint32(key[4]) << 24) |
		(uint32(key[5]) << 16) |
		(uint32(key[6]) << 8) |
		(uint32(key[7]) << 0)

	/* Do key permutation and split into two 28-bit subkeys. */
	k0 := key_perm_maskl[0][rawkey0>>25] |
		key_perm_maskl[1][(rawkey0>>17)&0x7f] |
		key_perm_maskl[2][(rawkey0>>9)&0x7f] |
		key_perm_maskl[3][(rawkey0>>1)&0x7f] |
		key_perm_maskl[4][rawkey1>>25] |
		key_perm_maskl[5][(rawkey1>>17)&0x7f] |
		key_perm_maskl[6][(rawkey1>>9)&0x7f] |
		key_perm_maskl[7][(rawkey1>>1)&0x7f]
	k1 := key_perm_maskr[0][rawkey0>>25] |
		key_perm_maskr[1][(rawkey0>>17)&0x7f] |
		key_perm_maskr[2][(rawkey0>>9)&0x7f] |
		key_perm_maskr[3][(rawkey0>>1)&0x7f] |
		key_perm_maskr[4][rawkey1>>25] |
		key_perm_maskr[5][(rawkey1>>17)&0x7f] |
		key_perm_maskr[6][(rawkey1>>9)&0x7f] |
		key_perm_maskr[7][(rawkey1>>1)&0x7f]

	/* Rotate subkeys and do compression permutation. */
	shifts := 0
	for round := 0; round < 16; round++ {
		var t0, t1 int

		shifts += des_key_shifts[round]

		t0 = (k0 << shifts) | (k0 >> (28 - shifts))
		t1 = (k1 << shifts) | (k1 >> (28 - shifts))

		en_keysl[round] = comp_maskl[0][(t0>>21)&0x7f] |
			comp_maskl[1][(t0>>14)&0x7f] |
			comp_maskl[2][(t0>>7)&0x7f] |
			comp_maskl[3][t0&0x7f] |
			comp_maskl[4][(t1>>21)&0x7f] |
			comp_maskl[5][(t1>>14)&0x7f] |
			comp_maskl[6][(t1>>7)&0x7f] |
			comp_maskl[7][t1&0x7f]

		en_keysr[round] = comp_maskr[0][(t0>>21)&0x7f] |
			comp_maskr[1][(t0>>14)&0x7f] |
			comp_maskr[2][(t0>>7)&0x7f] |
			comp_maskr[3][t0&0x7f] |
			comp_maskr[4][(t1>>21)&0x7f] |
			comp_maskr[5][(t1>>14)&0x7f] |
			comp_maskr[6][(t1>>7)&0x7f] |
			comp_maskr[7][t1&0x7f]
	}
}

var saltbits = 0

func des_setup_salt(salt int) {
	saltbits = 0
	saltbit := 1
	obit := 0x800000
	for i := 0; i < 24; i += 1 {
		if salt&saltbit > 0 {
			saltbits |= obit
		}
		saltbit <<= 1
		obit >>= 1
	}
}

var des_r0 int
var des_r1 int

func des_do_des() {
	//var l, r, f, r48l, r48r;
	count := 25
	l := 0
	r := 0
	f := 0

	for count > 0 {
		count -= 1

		/* Do each round. */
		kl := 0
		kr := 0
		round := 16
		for round > 0 {
			round -= 1
			/* Expand R to 48 bits (simulate the E-box). */
			r48l := ((r & 0x00000001) << 23) | ((r & 0xf8000000) >> 9) | ((r & 0x1f800000) >> 11) | ((r & 0x01f80000) >> 13) | ((r & 0x001f8000) >> 15)
			r48r := ((r & 0x0001f800) << 7) | ((r & 0x00001f80) << 5) | ((r & 0x000001f8) << 3) | ((r & 0x0000001f) << 1) | ((r & 0x80000000) >> 31)

			/*
			 * Do salting for crypt() and friends, and
			 * XOR with the permuted key.
			 */
			f = (r48l ^ r48r) & saltbits
			r48l ^= f ^ en_keysl[kl]
			kl += 1
			r48r ^= f ^ en_keysr[kr]
			kr += 1

			/*
			 * Do sbox lookups (which shrink it back to 32 bits)
			 * and do the pbox permutation at the same time.
			 */
			f = psbox[0][m_sbox[0][r48l>>12]] | psbox[1][m_sbox[1][r48l&0xfff]] | psbox[2][m_sbox[2][r48r>>12]] | psbox[3][m_sbox[3][r48r&0xfff]]

			/*
			 * Now that we've permuted things, complete f().
			 */
			f ^= l
			l = r
			r = f
		}

		r = l
		l = f
	}

	/* Final permutation (inverse of IP). */
	des_r0 = fp_maskl[0][l>>24] |
		fp_maskl[1][(l>>16)&0xff] |
		fp_maskl[2][(l>>8)&0xff] |
		fp_maskl[3][l&0xff] |
		fp_maskl[4][r>>24] |
		fp_maskl[5][(r>>16)&0xff] |
		fp_maskl[6][(r>>8)&0xff] |
		fp_maskl[7][r&0xff]

	des_r1 = fp_maskr[0][l>>24] |
		fp_maskr[1][(l>>16)&0xff] |
		fp_maskr[2][(l>>8)&0xff] |
		fp_maskr[3][l&0xff] |
		fp_maskr[4][r>>24] |
		fp_maskr[5][(r>>16)&0xff] |
		fp_maskr[6][(r>>8)&0xff] |
		fp_maskr[7][r&0xff]
}

var initialized = false

func descrypt(key string, salt_str string) string {
	if initialized == false {
		des_init()
		initialized = true
	}

	keybuf := [8]byte{}
	output := salt_str[0:2]

	q := 0
	keypos := 0
	for q < 8 {
		if keypos >= len(key) {
			keybuf[q] = 0
		} else {
			keybuf[q] = byte(key[keypos]) << 1
		}
		q += 1
		if keypos < len(key) {
			keypos += 1
		}
	}

	des_setkey(keybuf)

	/* This is the "old style" DES crypt. */
	var salt = (uint32(ascii_to_bin(byte(salt_str[1]))) << 6) | uint32(ascii_to_bin(byte(salt_str[0])))
	des_setup_salt(int(salt))
	des_do_des()

	l := des_r0 >> 8
	output += string(ascii64[(l>>18)&0x3f])
	output += string(ascii64[((l >> 12) & 0x3f)])
	output += string(ascii64[((l >> 6) & 0x3f)])
	output += string(ascii64[((l >> 0) & 0x3f)])

	l = (des_r0 << 16) | ((des_r1 >> 16) & 0xffff)
	output += string(ascii64[((l >> 18) & 0x3f)])
	output += string(ascii64[((l >> 12) & 0x3f)])
	output += string(ascii64[((l >> 6) & 0x3f)])
	output += string(ascii64[((l >> 0) & 0x3f)])

	l = des_r1 << 2
	output += string(ascii64[((l >> 12) & 0x3f)])
	output += string(ascii64[((l >> 6) & 0x3f)])
	output += string(ascii64[((l >> 0) & 0x3f)])

	return output
}
