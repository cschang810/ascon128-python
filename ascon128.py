import secrets
from bitarray import bitarray
from bitarray.util import hex2ba, int2ba, zeros, ba2hex

ROUND_CONSTANTS = ['00000000000000f0','00000000000000e1','00000000000000d2','00000000000000c3','00000000000000b4','00000000000000a5','0000000000000096','0000000000000087','0000000000000078','0000000000000069','000000000000005a','000000000000004b']
START_IDX = {12 : 0, 8 : 4, 6 : 6}

def ascon128_encrypt(K, N, A, P):
    # ascon128 recommended parameters
    k, r, a, b = 128, 64, 12, 6
    
    # initialization
    S = initialization(K, N, k, r, a, b)
    
    # processing associated data
    S = process_ad(S, A, r, b)
    
    # processing plaintext
    S, C = process_plaintext(S, P, r, b)

    # finalization
    T = finalize(S, K, r, a, k)

    return C, T

def ascon128_decrypt(K, N, A, C, T):
    # ascon128 recommended parameters
    k, r, a, b = 128, 64, 12, 6

    # initialization
    S = initialization(K, N, k, r, a, b)

    # processing associated data
    S = process_ad(S, A, r, b)

    # processing ciphertext
    S, P = process_ciphertext(S, C, r, b)
    
    # finalization
    T_evaluated = finalize(S, K, r, a, k)

    # verifying
    if T == T_evaluated:
        return P
    else:
        return None

def initialization(K, N, k, r, a, b):
    # IV = k || r || a || b || 0*
    IV = int2ba(k, 8) + int2ba(r, 8) + int2ba(a, 8) + int2ba(b, 8) + zeros(160-k)
    # S = IV || K || N
    S = IV + K + N
    # S = pa(S) ^ (0* || K)
    S = permutation(S, a) ^ (zeros(320-k) + K)
    
    return S

def process_ad(S, A, r, b):
    # padding
    A_padded = A + ~zeros(1) + zeros(r-1-len(A)%r)
    
    # number of blocks
    s = len(A_padded) // r
    
    for idx in range(s):
        # fetch block (Ai)
        block = A_padded[idx*r:idx*r+r]
        # S = pb((Sr ^ Ai) || Sc)
        S = permutation((S[:r] ^ block) + S[r:], b)
    
    # S = S ^ (000....01)
    S = S ^ (zeros(319) + ~zeros(1))
    return S

def process_plaintext(S, P, r, b):
    # ciphertext
    C = bitarray(0)

    # padding
    P_padded = P + ~zeros(1) + zeros(r-1-len(P)%r)

    # number of blocks
    t = len(P_padded) // r
 
    for idx in range(t-1):
        # fetch block (Pi)
        block = P_padded[r*idx:r*idx+r]
        # Sr = Sr ^ Pi
        S[:r] ^= block
        # Ci = Sr
        C += S[:r]
        # S = pb(S)
        S = permutation(S, b)
    
    # Sr = Sr ^ Pt
    S[:r] ^= P_padded[-r:]
    C += S[:len(P)%r]

    return S, C

def process_ciphertext(S, C, r, b):
    # plaintext
    P = bitarray(0)

    # "complete block" numbers
    t = len(C) // r

    for idx in range(t):
        # fetch block (Ci)
        block = C[idx*r:idx*r+r]
        # Pi = Sr ^ Ci
        P += S[:r] ^ block
        # S = Ci || Sc
        S[:r] = block
        # S = pb(S)
        S = permutation(S, b)

    # (remaining) Pt = Sr ^ Ct
    Pt = S[:len(C)%r] ^ C[t*r:]
    P += Pt
    # Sr = Sr ^ (Pt || 1 || 0*)
    S[:r] ^= Pt + ~zeros(1) + zeros(r-1-len(Pt))
    
    return S, P

def finalize(S, K, r, a, k):
    # S = pa(S^(0...0 || K || 0...0))
    S = permutation(S ^ (zeros(r) + K + zeros(320-r-k)), a)
    # generate tag
    T = S[-128:] ^ K[-128:]

    return T

def permutation(S, n):
    # starting position for round constants
    start_idx = START_IDX[n]

    # split S into five 64-bit words
    x = []
    for i in range(5):
        x.append(S[64*i:64*i+64])
    
    # iterate n rounds
    for r in range(n):
        # pc: addition of constants
        x[2] ^= hex2ba(ROUND_CONSTANTS[start_idx + r])

        # ps: substitution layer
        x[0] ^= x[4]
        x[2] ^= x[1]
        x[4] ^= x[3]

        temp = []
        for i in range(5):
            temp.append((x[i] ^ ~zeros(64)) & x[(i+1)%5])
        for i in range(5):
            x[i] ^= temp[(i+1)%5]
        
        x[1] ^= x[0]
        x[3] ^= x[2]
        x[0] ^= x[4]
        x[2] ^= ~zeros(64)

        # pl: linear diffusion layer
        x[0] = x[0] ^ right_rotation(x[0], 19) ^ right_rotation(x[0], 28)
        x[1] = x[1] ^ right_rotation(x[1], 61) ^ right_rotation(x[1], 39)
        x[2] = x[2] ^ right_rotation(x[2],  1) ^ right_rotation(x[2],  6)
        x[3] = x[3] ^ right_rotation(x[3], 10) ^ right_rotation(x[3], 17)
        x[4] = x[4] ^ right_rotation(x[4],  7) ^ right_rotation(x[4], 41)
    
    return x[0] + x[1] + x[2] + x[3] + x[4]


def right_rotation(ba, n):
    return ba[len(ba)-n:] + ba[:len(ba)-n]

if __name__ == "__main__":
    generated_key = secrets.token_hex(16)
    generated_nonce = secrets.token_hex(16)

    input_ad = input("associated data: 0x")
    input_plaintext = input("plaintext: ")
    input_plaintext_bytes = str.encode(input_plaintext)
    input_plaintext_ba = bitarray(0)
    input_plaintext_ba.frombytes(input_plaintext_bytes)
    
    ciphertext, tag = ascon128_encrypt(K = hex2ba(generated_key), N = hex2ba(generated_nonce), A = hex2ba(input_ad), P = input_plaintext_ba)
    plaintext = ascon128_decrypt(K = hex2ba(generated_key), N = hex2ba(generated_nonce), A = hex2ba(input_ad), C = ciphertext, T = tag)

    print("\n============ ascon128 demo ============")
    print("plaintext:{} {} ({} bits)".format(' ' * 1, input_plaintext, len(input_plaintext_ba)))
    print("key:{} 0x{} ({} bits)".format(' ' * 7, generated_key, len(generated_key) * 4))
    print("nonce:{} 0x{} ({} bits)".format(' ' * 5, generated_nonce, len(generated_nonce) * 4))
    print("a.d.:{} 0x{} ({} bits)".format(' ' * 6, input_ad, len(input_ad) * 4))
    print("ciphertext:{} 0x{} ({} bits)".format(' ' * 0, ba2hex(ciphertext), len(ciphertext)))
    print("tag:{} 0x{} ({} bits)".format(' ' * 7, ba2hex(tag), len(tag)))
    print("decrypted:{} {} ({} bits)".format(' ' * 1, plaintext.tobytes().decode(), len(plaintext)))
    print('\n')

    