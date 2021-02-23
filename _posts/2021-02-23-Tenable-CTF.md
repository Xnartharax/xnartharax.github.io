---
layout: post
title: Tenable CTF - Crypto
subtitle: Writeup of the harder Crypto-Challenges
#gh-repo: daattali/beautiful-jekyll
#gh-badge: [star, fork, follow]
#tags: [test]
comments: true
---

I recently particitpated in the Tenable CTF. My main focus was on the Crypto category. In the following I want to describe my solutions of the two harder challenges step-by-step.  
# Netrunner Encryption
The challenge provided a website that allowed a user to input a string and encrypt it using AES in ECB mode.
![very simple UI](/images/netrunner_enc1.png)
Additionally Source Code for the backend was given.  
{% highlight php linenos %}
<html>
<body>
  <h1>Netrunner Encryption Tool</h1>
  <a href="netrun.txt">Source Code</a>
  <form method=post action="crypto.php">
  <input type=text name="text_to_encrypt">
  <input type="submit" name="do_encrypt" value="Encrypt">
  </form>

<?php

function pad_data($data)
{
  $flag = "flag{wouldnt_y0u_lik3_to_know}"; 

  $pad_len = (16 - (strlen($data.$flag) % 16));
  return $data . $flag . str_repeat(chr($pad_len), $pad_len);
}

if(isset($_POST["do_encrypt"]))
{
  $cipher = "aes-128-ecb";
  $iv  = hex2bin('00000000000000000000000000000000');
  $key = hex2bin('74657374696E676B6579313233343536');
  echo "</br><br><h2>Encrypted Data:</h2>";
  $ciphertext = openssl_encrypt(pad_data($_POST['text_to_encrypt']), $cipher, $key, 0, $iv); 

  echo "<br/>";
  echo "<b>$ciphertext</b>";
}
?>
</body>
</html>
{% endhighlight %}
We can see that the server appends the immediately flag after the user-controlled string. The concatenated string is then encrypted with a constant key and shown to the user. Sadly neither the provided example key or the flag are used on the server. But that would be a little bit too easy, right?  
## Byte-at-a-time Decryption
Luckily we don't need to know them to solve the challenge. We can recover the unknown padding without knowing the key. This is done one byte at a time.  
First let's examine how ECB mode works:  
To use a block cipher we divide the plaintext into blocks of a fixed length. In the case of AES the block length is 128 bit(=16 byte).  
Each block is then independently encrypted with the key. The key for each block is the same. This means that encrypting the same 16 byte plaintext blocks at different points in the cipher will result in the same 16 byte ciphertext blocks.  
![schematic depiction of ECB mode](/images/ECB_encryption.svg)  
We can use this to decipher a single byte at the end of a block. 