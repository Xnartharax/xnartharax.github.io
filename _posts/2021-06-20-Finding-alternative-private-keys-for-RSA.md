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
{% raw %}
1. Choose to LARGE prime  numbers \\( p \\) and \\(q\\)  
2. Build \\(n=pq\\)  
3. Choose a public exponent \\( e \\) (usually 65537)  
4. Build Euler's totient: \\(\phi(n) = (q-1)(p-1)\\)  
5. Find a \\( d \\) such that \\(ed \equiv 1\ (\text{mod}\ \phi(n))\\)  
6. Publish \\( (e, n) \\) as your public key and keep \\( d \\) private. \\( p \\) , \\( q \\) and \\( \phi(n) \\) can be discarded.  

To encrypt a message \\( m \\) you simply compute:  

$$ c \equiv m^e\ (\text{mod}\ n) $$ 

To decrypt use your private key: 

$$ m \equiv c^d\ (\text{mod}\ n)  $$  

So why does this work? Why do we recover the original message?  
The answer is *Euler's theorem* which states:  

$$ a^{\phi(n)} \equiv 1\ (\text{mod}\ n) $$   

Since we earlier defined \\( e \\) and \\( d \\) such that \\( ed \equiv 1\ (\text{mod}\ n)  \\) we know that for some integer \\( k \\)  

$$ ed = 1 + k\phi(n) $$  

It follows that  

$$ c^d \equiv m^{ed} \equiv m^{1 + k\phi(n)} \equiv mm^{k\phi(n)}\ (\text{mod}\ n) $$  

And with Euler's theorem we know that \\( m^{\phi(n)} \equiv 1\ (\text{mod}\ n)  \\). So  we conclude that  

$$ mm^{k\phi(n)} \equiv m(m^{\phi(n)})^k \equiv m 1^k \equiv m\ (\text{mod}\ n)  $$

With that we understand why RSA works and can move on to the actual exploit.  
{% endraw %}

## An alternative to Euler's theorem

The solution for this problem requires us to find an alternative number \\(a\\) that satisfies 

$$ m^a \equiv 1\ (\text{mod}\ n)  $$

So that we can choose \\(ed \equiv 1 \ (\text{mod}\ a) \\) and all the equations above hold.  
Luckily there is a generalization of Euler's theorem using [Carmichael's Function](https://en.wikipedia.org/wiki/Carmichael_function):

$$ m^{\lambda(n)} \equiv 1\ (\text{mod}\ n)  $$

For a number \\(n = pq\\) that is factorized into only two primes Carmichael's Function is defined as:

$$ \lambda(n) = \text{lcm}(p-1, q-1) $$

We can then compute a new private key \\(d'\\).

$$ ed' \equiv 1\ (\text{mod}\ \text{lcm}(q-1, p-1)) $$

Carmichael's functions is often equal to Euler's totient so we may have to try a few times so that we get a \\(d' \neq d\\).

## Recovering p and q from the private key

There is still one last problem: \\(p\\) and \\(q\\) which we need to compute Carmichael's Function are not directly known. However they can be recovered if we know both the public and the private key. This is done using the following steps:

1. Compute \\(k = ed -1\\)
2. Repeat until the factorization is known:
    1. Choose a \\(1 < g < n\\) and a small \\(t\\)
    2. Compute \\(z = g^{\frac{k}{2^t}}\\)
    3. Test if either \\(\text{gcd}(z+1, n)\\) or \\(\text{gcd}(z-1, n)\\) is one of the factors
3. Once you have the first factor \\(q\\) simply compute \\(p = \frac{n}{q}\\)

## The final exploit

Putting it all together the script below first gets private and public key from the server, then recovers \\(p\\) and \\(q\\) and finally constructs a new private key using Carmichael's Function. I had to run the script three times because the new key is not necessarily distinct.

```python
import random
from math import gcd, lcm


def recover_pq(n, d, e):
    k = d*e - 1
    p = None
    while p is None:
        g = random.randint(1, n)
        #print(g)
        #print(pow(g, k//2, n))
        for t in range(200):
            tmp = pow(g, k//(2**t), n)
            #print(tmp)
            cand = gcd(tmp-1, n)
            if cand != 1 and cand != n and n % cand == 0:
                p = cand
            cand = gcd(tmp+ 1, n)
            if cand != 1 and cand != n and n % cand == 0:
                p = cand
    q = n//p
    return p, q

from pwn import *

p = remote('regulus-regulus.hsc.tf', 1337)

p.recvuntil(": ")
p.sendline("2")
p.recvuntil('n = ')
n = int(p.recvline()[:-1])
e = 0x10001 # standard exponent

p.recvuntil(': ')
p.sendline('3')
p.recvuntil('d = ')
d = int(p.recvline()[:-1])

p_, q_ =  recover_pq(n, d, e)
print('recovered primes')
carmichael = lcm(p_-1, q_-1)
d_ = pow(e, -1, carmichael)

assert d_ % ((q_-1)*(p_-1)) != d

p.recvuntil(': ')
p.sendline('4')
p.recvuntil(': ')
p.sendline(str(d_))
p.interactive()

```