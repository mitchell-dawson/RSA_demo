import pdb
import sys  

reload(sys)  
sys.setdefaultencoding('utf8')

class receiver(object):
	"""person sending the message"""
	def __init__(self, p, q, try_standard_public_key):

		self.p = p
		self.q = q
		self.n = p*q

		#print "calculating phi(n)"

		self.n_totient = phi(self.p, self.q)

		#print "choosing public key"

		self.e_public_key = generate_public_key(self, try_standard_public_key)

		#print "generating private key"

		self.d_private_key = generate_private_key(self)

	def pad_text():
	
		return padded_message()	

def isPrime(n):
	"""Generic algorithm to determine if number is prime
	"""

	import sympy

	return sympy.isprime(n)


def phi(p,q):
	""" when n is a prime number, phi(n) = n-1. 
	when m and n are coprime, phi(m*n) = phi(m)*phi(n).

	If the prime factorisation of n is given by n = p_1^e_1 * ... * p_n^e_n
	then phi(n) = n *(1 - 1/p_1)* ... (1 - 1/p_n).
	
	if n = p*q, then n*(1 - 1/p)*(1 - 1/q) = n*(p-1)*(q-1)/pq = (p-1)*(q-1)
	"""
	return (p-1)*(q-1) 

def is_coprime(m,n):
	from fractions import gcd 

	if gcd(m, n) == 1:
		coprime_bool = True
	else:
		coprime_bool = False	

	return coprime_bool

def egcd(a, b):
	if a == 0:
		return (b, 0, 1)
	else:
		g, y, x = egcd(b % a, a)
		return (g, x - (b // a) * y, y)

def modinv(a, m):
	"""
	calulcate solution of a*x mod m = 1 
	http://stackoverflow.com/a/9758173
	"""
	g, x, y = egcd(a, m)
	if g != 1:
		raise Exception('modular inverse does not exist')
	else:
		return x % m


def generate_public_key(person, try_standard_public_key):
	""" generate public key 
	This number has to be stricly between 1 and n_totient, also coprime to n.
	"""
	import random


	### check if we can use the standard 65537 for public key
	if (65537 < person.n and is_coprime(65537, person.n_totient)):
		return 65537

	potential_public_keys = random.shuffle(range(person.n_totient/2,person.n_totient))

	# check all numbers between n/2 and n_totient
	# would nornmally check between 1 and n_totient
	for ii in potential_public_keys:

		# if number is coprime to totient 
		if is_coprime(ii, person.n_totient):

			# use as public keys
			e_public_key = ii
			break

	return e_public_key

def generate_private_key(person):
	import math
	""" generate private keys 
	need to calculate the modular multiplicative 
	inverse of e (mod totient(n))
	i.e. the solution of
	(e * x ) mod (totient(n)) = 1
	"""

	e_public_key = person.e_public_key
	p = person.p
	q = person.q

	d_private_key = modinv(e_public_key, ((p-1)*(q-1)))

	return d_private_key

def ba_string_to_binary(message_string):
	import bitarray

	ba = bitarray.bitarray(endian='little')
	ba.fromstring(message_string)

	blist = []

	for ii in ba:
		if ii:
			blist.append(1)
		else:
			blist.append(0)	

	return ba, tuple(blist)

def ba_binary_to_integer (ba):
	"""convert message to bit array, then to integer
	"""
	import bitarray
	
	m = 0
	for bit in ba:
		m = (m << 1) | bit

	return m	

def ba_integer_to_binary(m):
	"""convert message to bit array, then to integer
	"""
	import bitarray

	raw_ba = bitarray.bitarray(bin(m)[2:], endian='little')

	### add on zeros at beginning of message to get to correct length
	add_on =  8 - len(raw_ba)%8
	ba = bitarray.bitarray([False]*add_on, endian='little')
	ba.extend(raw_ba)

	blist = []

	for ii in ba:
		if ii:
			blist.append(1)
		else:
			blist.append(0)	

	return ba, tuple(blist)

def encrypt_message(m, person):
	"""encrypt message as (m^e) mod(n)
	"""
	encrypted_message = pow(
		m, person.e_public_key, person.n)		

	return encrypted_message

def decrypt_message(encrypted_message, person):
	"""decrypt message as ( encrypted_message ^ d) mod(n)
	"""

	decrypted_message = pow(
		encrypted_message, person.d_private_key, person.n )	

	return decrypted_message

def knowledge_table(table_data):
	from terminaltables import AsciiTable

	table = AsciiTable(table_data)

	print table.table

def choose_prime(len_string):

	import bisect



	p_potential = [263, 
	86453,
	21335779,
	5513600773,	
	597655503030737,
	4564564564564561,
	12345678910987654321,
	61654440233248340616559, 
	197352587024076973231046657,
	1119416189101109149181191199,  
	77777733222232222222222222223,
	46891012152021222527303233355051,
	1219113036371115975795111736303119121,
	23456789123456789123456789123456789123,
	958619577835947143938319314151899378973,
	13763761774552805635707475936358698644919801,
	74462898442155373703893556749928174163166777,
	357535753575357535753575357535753575357535753,
	14000000000000000000000000000000000000000000041,
	196831562512167926168594913337521971331729343125271]




	q_potential = [1949, 
	102001,
	1000075057,
	1099511628401, 
	1235711131175321,
	32462531054272512000001,
	61654440233248340616559, 
	1101111011009001101111011,
	4641588833612778892410076351,
	26252422212018161514121098641,
	8939662423123592347173339993799, 
	18133392183093337273339038129333181,
	6666666666666666666666666666666666666666641,
	11243941652563674986498110100111211214413169,
	99999999988888888777777766666655555233424443,
	123511311277095381527116483919737333174440041,
	9001000021200032001100483237793193978070200007,
	158014343936441708948923317088308354657418884731,
	1468910121415161820212224252627283032333435363839,
	1234123412341234123412341234123412341234123412341234123]

	p = p_potential[len_string-1]

	q = q_potential[len_string-1]

	return p,q


def validate_number():
	pass


def main():

	from fractions import gcd

	print ("\nConsider a situation with three people: Alice, Bob and Charlie. " +
	"Bob wishes to send a private message to Alice. " +
	"However Charlie is able to observe any information passed between Alice and Bob.\n") 

	print ("This is a demonstration of how RSA encyption can be used to allow Bob to " +
		"send a private message to Alice, without Charlie being able read it\n"
	)

	print "- - - - - - - - - - - - - - - \n"



	### user choose a message to send
	message_under_21 = False

	while not message_under_21:

		message_string = raw_input('Please choose a short message for Bob to send to Alice (under 20 characters): ')

		message_string = message_string.strip()

		if len(message_string) < 21:
			message_under_21 = True

	print "\n- - - - - - - - - - - - - - - "

	print "STAGE 1: PUBLIC KEY GENERATION"

	### make alice receiver and generate key pairs
	print "\nAlice begins by choosing two large prime numbers which she will use to generate her keys.\n"

	p, q = choose_prime(len(message_string))

	print "In this case, Alice chooses:\n\tp = %d\n\tq = %d" %(p,q)

	alice = receiver(p,q,False)

	print "\nAlice can now calculate her RSA modulus: n = p*q = %d*%d = %d ..." %(
		alice.p, alice.q, alice.n) 

	print "\nand choose her public exponent, e,\nwhich can be any integer such that 1 < e < phi(n) and gcd(e, phi(n)) = 1"

	print "\nwhere phi(n) = (p-1)*(q-1) = Euler's totient function = the number of integers less than n that are coprime to n"

	print "\nFor example, here suppose Alice chooses her public exponent to be e = %d, as gcd(%d,%d) = %d\n" %(
	alice.e_public_key, alice.e_public_key, alice.n_totient,
	gcd(alice.e_public_key, alice.n_totient)  )	

	print "- - - - - - - - - - - - - - - "
	raw = raw_input('press enter to continue ')
	print "- - - - - - - - - - - - - - - "

	print "STAGE 2: PRIVATE KEY GENERATION"

	print "\nAlice's private key, d, is then determined to be the multiplicative inverse of her public exponent modulo phi(n)" 
		
	print "Which is to say that e*d mod phi(n) = 1" 

	print "\nIn this case, d = %d, as we can verify that %d*%d mod %d = %d" %(
		alice.d_private_key, alice.d_private_key, alice.e_public_key, alice.n_totient,
		(alice.d_private_key * alice.e_public_key)%alice.n_totient)

	print "\n- - - - - - - - - - - - - - - "
	raw = raw_input('press enter to continue ')
	print "- - - - - - - - - - - - - - - "

	print "STAGE 2: PUBLIC KEY DISTRIBUTION"

	print "\nAlice can now distribute her public key, (n,e), with confidence that her private key cannot be deduced from this public information."

	print "\nThis is because calculating the private key from the public key is equivalent to factoring the RSA modulus n into the constituent primes p and q."

	print "\nFor large values of p and q, this factoring takes a very long time."

	print "\n- - - - - - - - - - - - - - - "
	raw = raw_input('press enter to continue ')
	print "- - - - - - - - - - - - - - - "

	print "Let us consider the state of knowledge at this stage." 
	print "\nAlice has generated a public key and distributed it to the others, She retains sole knowledge her private key." 
	print "\nFurthermore, neither Charlie nor Bob are able to determine what her private key is from the information they have in a practical time span\n"

	table_data = [
	['Variables','Alice knows', 'Charlie knows', 'Bob knows'],
	['Primes, (p,q) = (%d,%d)' %(p,q), 'Y', 'N', 'N'],
	['Public Key, (n,e) = (%d,%d)' %(alice.n, alice.e_public_key) , 'Y', 'Y', 'Y'],
	['Private Key, d = %d' %(alice.d_private_key), 'Y', 'N', 'N'],
	['Cipher text, m = %s' %("?"), 'N', 'N', 'N'],
	['Plain text, M = "%s"' %(message_string) , 'N' ,'N' , 'Y']]

	knowledge_table(table_data)

	print "\n- - - - - - - - - - - - - - - "
	raw = raw_input('press enter to continue ')
	print "- - - - - - - - - - - - - - - "

	print "STAGE 3: ENCODE PLAIN TEXT AS AN INTEGER\n"

	print "For RSA enryption to work, the message being sent must be an integer."

	print "\nPlain text can be encrypted by first converting each character to a corresponding binary representation"

	print "\nFor example, here each letter in the message can be represented as an 8-bit ASCII string"

	print "\nIf we concatenate these 8-bit strings we can form a binary representation of the plain text"

	print "\nWe can then convert this binary representation into a decimal representation\n"


	### convert plain text to integer
	ba, btuple = ba_string_to_binary(message_string)



	M1 = ba_binary_to_integer(ba)


	print "For example, here the message has become:\n" 
	
	print "\tPlain text: %s\n" %message_string
	print "\tBinary representation of plain text:\n\t", btuple 
	print "\n\tDecimal representation of plain text: %d" %M1

	print "\n- - - - - - - - - - - - - - - "

	raw = raw_input('press enter to continue ')

	print "- - - - - - - - - - - - - - - "

	print "STAGE 3: ENCRYPTING THE MESSAGE\n"

	### encrypt integer message using alice's keys	
	m_encrypted_message = encrypt_message(M1, alice)

	print "Bob can now generate the cipher text for his integer message using Alice's public keys.\n"	

	print "The cipher text, m, is generated from the plain text, M, by the formula: m = M^e mod n\n"

	print "In this case, m = %d^%d mod %d = %d\n" %(
		M1 , alice.e_public_key, alice.n, m_encrypted_message )  

	print "Note when calculating this value practically, we can use the formula ab mod n = (a mod n)*(b mod n) mod n"

	print "This allows us to apply the modulo step after each multiplication thereby reducing numerical errors"

	print "\n- - - - - - - - - - - - - - - "
	raw = raw_input('press enter to continue ')

	print "- - - - - - - - - - - - - - - "


	### check we have sufficiently large prime numbers to 
	### correctly transfer the message
	if m_encrypted_message > alice.n:
		print "message m, %d, exceeds alice's key size n, %d" %(
			m_encrypted_message, alice.n)

	print "STAGE 4: SENDING THE MESSAGE\n" 

	print "Bob is now able to send the cipher text to Alice publicly."
	print "\nAlthough Charlie can see the cipher text he is unable to decrypt it without access to Alice's private key\n"

	print "Here is a summary of the state of knowledge at this stage:" 

	table_data = [
	['Variables','Alice knows', 'Charlie knows', 'Bob knows'],
	['Primes, (p,q) = (%d,%d)' %(p,q), 'Y', 'N', 'N'],
	['Public Key, (n,e) = (%d,%d)' %(alice.n, alice.e_public_key) , 'Y', 'Y', 'Y'],
	['Private Key, d = %d' %(alice.d_private_key), 'Y', 'N', 'N'],
	['Cipher text, m = %s' %(m_encrypted_message), 'Y', 'Y', 'Y'],
	['Plain text, M = "%s"' %(message_string) , 'N' ,'N' , 'Y']]

	knowledge_table(table_data)

	print "\n- - - - - - - - - - - - - - - "

	raw = raw_input('press enter to continue ')

	print "- - - - - - - - - - - - - - - "

	print "STAGE 5: DECRYPTING AND DECODING THE CIPHERTEXT"

	### send the message to bob publicly
	print "\nAlice receives the cipher text, and decrypts it using the formula M = m^d mod n\n"

	### decrypt the message back to plain text integer value
	decrypted_value = decrypt_message(m_encrypted_message,alice)

	print "In this case, M = %d^%d mod %d = %d\n" %(
		m_encrypted_message , alice.d_private_key, alice.n, decrypted_value )  


	print "This decimal integer can then be decoded back into a valid binary representation, and then to a string"

	### convert plain text integer to readable text
	ba, ba_tuple = ba_integer_to_binary(decrypted_value)

	decrypted_message = ba.tostring()


	print "\nFor example, here the message received by Alice is:\n" 
	

	print "\tDecimal representation of plain text message: %d" %decrypted_value
	print "\n\tBinary representation of plain text message:\n\t", ba_tuple 
	print "\n\tDecoded message: %s\n" %decrypted_message

	print "\nwhich should be the message Bob sent her in the first place"

	print "\n- - - - - - - - - - - - - - - "
	raw = raw_input('press enter to continue ')
	print "- - - - - - - - - - - - - - - "	

	print "Let us consider the final state of knowledge:"

	table_data = [
	['Variables','Alice knows', 'Charlie knows', 'Bob knows'],
	['Primes, (p,q) = (%d,%d)' %(p,q), 'Y', 'N', 'N'],
	['Public Key, (n,e) = (%d,%d)' %(alice.n, alice.e_public_key) , 'Y', 'Y', 'Y'],
	['Private Key, d = %d' %(alice.d_private_key), 'Y', 'N', 'N'],
	['Cipher text, m = %s' %(m_encrypted_message), 'Y', 'Y', 'Y'],
	['Plain text, M = "%s"' %(message_string) , 'Y' ,'N' , 'Y']]

	knowledge_table(table_data)

	print "\nBob has been able to send Alice the plain text message without ever exchanging secret keys," 
	print "and despite the cipher text being visible to Charlie\n" 

if __name__=="__main__":
	main()
		
