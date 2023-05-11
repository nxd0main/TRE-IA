#TRE-IA

import math
import time
import random
from Crypto.Util import number
from Crypto.Hash import SHAKE256

#Encryptor Setup - Setup the modulus a Blum Integer
def TRE_Setup(x, bits, t):
	def genPrime(bits):
		potential_prime = 1
		while potential_prime % 4 == 1:
			potential_prime = number.getPrime(bits)
		return potential_prime

	x = 0
	while x <1: 
		p = genPrime(bits)
		q = genPrime(bits)
		if p != q and q % 4 != 1:
			N = p * q
			pp = N
		x += 1
	
	phiN = (p-1) * (q-1)
	
	return pp, phiN

def TRE_Gen(pp, phiN, t):
	N = pp
	
	gcd = 0
	while gcd != 1:
		x = random.randint(2, pp//2)
		x_0 = pow(x, 2, N)
		d = pow(x_0, pow(2, t-1, phiN), N) #private decryption key, will be recovered by Solve sequentially
		gcd = math.gcd(d, phiN)
	x_t = pow(d, 2, N)
	e = pow(d, -1 , phiN) #Euclid's Extended algorithm to find multiplicative inverse of d mod phiN. In standard PKE, e is 'public' but in TRE-IA, this is also private.
	
	C = (x_0, x_t)
	
	return e, d, C, t

#TRE_Enc with Textbook RSA to test initially
def Enc(m, e, pp):
	N = pp
	c = pow(m, e, N) #textbook RSA, change to OAEP later
	return c

#TRE_Enc with full RSA-OAEP
def Enc_OAEP(m, e, pp):                                                         #Completely replaces Enc
    n = 1024                                                                    #Number of bits in the RSA modulus (double the parameter below)
    k0 = 32                                                                     #At least as big as integer type
    k1 = 8
    #m - plaintext message, n - k0 - k1 bits long
    m_prime = (m << k1).to_bytes(int((n-k0)/8), "big")                          #Zero padd message to                n - k0 = 256 bits
    r = random.randint(0, (1<<k0) - 1).to_bytes(int(k0/8), "big")               #Generate a random bit string                  k0 bits
    G = SHAKE256.new(data=r)                                                    #Pass r pass as k0/8 bytes
    Gr = G.read(length=int((n-k0)/8))                                           #Expand r to                         n - k0 = 256 bits
    X = bytes(a ^ b for a, b in zip(m_prime, Gr))                               #XOR the padded message and hash     n - k0 = 256 bits
    H = SHAKE256.new(data=X)                                                    #This reduces 256 bits to k0 bits
    HX = H.read(length=int(k0/8))                                               #Reduce X to                                   k0 bits
    Y = bytes(a ^ b for a, b in zip(r, HX))                                     #XOR r with the new hash                       k0 bits
    X = int.from_bytes(X, "big")
    Y = int.from_bytes(Y, "big")
    msg = (X << k0) | Y                                                         #Concatenate the results
    return Enc(msg, e, pp)                                                      #Encrypt using textbook RSA


#Decryptor
def TRE_Solve(pp, C, t):
	N = pp
	x_0 = C[0]
	x_t = C[1]
	
	sqrt_x_t = pow(x_0, pow(2, t - 1), N) #sequential work here
	if pow(sqrt_x_t, 2, N) == x_t: 
		d = sqrt_x_t

	return d

#TRE_Dec with Textbook RSA to test initially
def Dec(c, d, pp):
	N = pp
	m = pow(c, d, N)
	return m
	

#TRE_Dec with full RSA-OAEP
def Dec_OAEP(c, d, pp):
    msg =  Dec(c, d, pp)                                                   #Decrypt using textbook RSA
    n = 1024                                                                    #Modulus size
    k0, k1 = 32, 8                                                              #Integers fixed by protocol
    X = (msg >> k0).to_bytes(int((n-k0)/8), "big")                              #Recover X
    Y = (msg & ((1<<k0)-1)).to_bytes(int(k0/8), "big")                          #Recover Y
    H = SHAKE256.new(data=X)                                                    #Take has of X
    HX = H.read(length=int(k0/8))                                               #to get the value of HX
    r = bytes(a ^ b for a, b in zip(Y, HX))                                     #XOR with Y to recover r
    G = SHAKE256.new(data=r)                                                    #Take the hash of r
    Gr = G.read(length=int((n-k0)/8))                                           #To get the value of Gr
    m_prime = bytes(a ^ b for a, b in zip(X, Gr))                               #XOR with X to recover the padded message
    m_prime = int.from_bytes(m_prime, "big")                                    #Convert back to an integer
    m = m_prime >> k1                                                           #Remove the padding
    return m  

z = 0
t = 1000 #increase to add delay

while z < 1: 
	start_time = time.time()
	print('\nTRE_Setup running...')
	pp, phiN = TRE_Setup(1,1024,t) #Create RSA-2048 modulus
	print(f'pp: {pp} \nphiN: {phiN}')
	print('TRE_Setup time:' , round(time.time() - start_time , 4), 'seconds')

	start_time = time.time()
	print('\nTRE_Gen running...')
	e,d,C,t = TRE_Gen(pp, phiN, t)
	print(f'e: {e} \nd: {d} \nC: {C} \nt: {t}')
	print('TRE_Gen time:' , round(time.time() - start_time , 4), 'seconds')
	
	start_time = time.time()
	print('\nEnc running...')
	c = Enc(8888, e, pp) #Hardcode message to 8888 for testing
	print(f'c: {c}')
	print('Enc time:' , round(time.time() - start_time , 4), 'seconds')
	

	start_time = time.time()
	print('\nEnc_OAEP running...')
	c_OAEP = Enc_OAEP(8888, e, pp) #Hardcode message to 8888 for testing
	print(f'c_OAEP: {c_OAEP}')
	print('Enc_OAEP time:' , round(time.time() - start_time , 4), 'seconds')
	
	start_time = time.time()
	print('\nTRE_Solve running...')
	d = TRE_Solve(pp, C, t)
	print(f'd: {d}')
	print('TRE_Solve time:' , round(time.time() - start_time , 4), 'seconds')
	
	start_time = time.time()
	print('\nDec running...')
	m = Dec(c, d, pp)
	print(f'm: {m}')
	print('Dec time:' , round(time.time() - start_time , 4), 'seconds')
	
	start_time = time.time()
	print('\nDec_OAEP running...')
	m_OAEP = Dec_OAEP(c_OAEP, d, pp)
	print(f'm_OAEP: {m_OAEP}')
	print('Dec_OAEP time:' , round(time.time() - start_time , 4), 'seconds')	
	
	
	z += 1
	
	
