---
layout: post
title: Finding alternative private keys for RSA
subtitle: Writeup of the HSCTF challenge  "regulus regulus"
#gh-repo: daattali/beautiful-jekyll
#gh-badge: [star, fork, follow]
tags: [ctf, crypto]
comments: true
published: true
---

High School CTF was amazing this year. Me and my team didn't have a lot of time at hand but the challenges I solved had clever and enjoyable solutions. The particular challenge I want to discuss is "regulus regulus". Overall the challenge was solved by 93 of around 1150 teams.  

(All the crypto challenges were named after the binomial names of bird species. In this case it was the [Goldcrest](https://en.wikipedia.org/wiki/Goldcrest))

# The Challenge

This is what the challenge looked like:

![Regulus Regulus: nc regulus-regulus.hsc.tf 1337](/assets/img/regulus-reguls-desc.jpg)

If you're wondering: the [Ahinga Ahinga](https://en.wikipedia.org/wiki/Anhinga) is another kind of bird which is unrelated to the challenge but hunts fish by spearing them with its beak.  

There was no download or source given.  

Executing the specified command will prompt the following:

```
== proof-of-work: disabled ==

1. Key generation algorithm
2. Public key
3. Private key
4. Decrypt
```

Hitting `1` will give the source code for the challenge:

```python
from Crypto.Util.number import *
import random
import sympy
flag = open('flag.txt','rb').read()
p,q = getPrime(1024),getPrime(1024)
e = 0x10001
n = p*q
m = random.randrange(0,n)
c = pow(m,e,n)
d = sympy.mod_inverse(e,(p-1)*(q-1))
def menu():
    print()
    print("1. Key generation algorithm")
    print("2. Public key")
    print("3. Private key")
    print("4. Decrypt")
    choice = input(": ").strip()
    if choice=="1":
        f = open(__file__)
        print()
        print(f.read())
        print()
        menu()
    elif choice=="2":
        print("n = "+str(n))
        print("e = 65537")
        menu()
    elif choice=="3":
        print("d = "+str(d))
        menu()
    elif choice=="4":
        d_ = int(input("What private key you like to decrypt the message with?\n : "))
        if d_%((p-1)*(q-1))==d:
            print("You are not allowed to use that private key.")
            menu()
        if (pow(c,d_,n)==m):
            print("Congrats! Here is your flag:")
            print(flag)
            exit()
        else:
            print("Sorry, that is incorrect.")
            menu()
    else:
        print("That is not a valid choice.")
        menu()
while 1:
    menu()
```

It follows that choice `2` will provide us with an RSA public key and choice `3` with the corresponding private key. This is kind of strange since RSA challenges usually require breaking the encryption of an unknown message or forging a signature but there is no encrypted message available to the user.  
The problem of this challenge is presented in choice `4`: provide a private key that successfully decrypts a message which was encrypted using the known public key. Of course this would be trivial if we could just supply the already known private key. So there is a check that prevents us from submitting the known private key or anything equivalent. 

# The Solution

Understanding how the solution to this problem works not only requires to know how RSA works but also at least a little bit *why* it works. So here is:

## A little proof of RSA
As you probably know if you're reading this writeup the steps of textbook RSA are roughly:

1. Choose to LARGE prime  numbers $p$ and $q$
2. Build $n=pq$ 
3. Choose a public exponent $e$ (usually 65537)
4. Build $\phi(n) = (q-1)(p-1)$
5. Find a $d$ such that $ed = 1 (mod \phi(n))$
6. Publish $(e, n)$ as your public key and keep $d$ private. $p$, $q$ and $\phi(n)$ can be discarded.

To encrypt a message $m$ you simply compute:

$$ c = m^e (mod n) $$

To decrypt with u use your private key:

$$ m = c^d (mod n) $$

So why does this work? Why do we recover the original message? 