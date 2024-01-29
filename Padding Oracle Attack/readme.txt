Task:
Exploiting the padding oracle in order to decrypt a message. 
It turns out that knowing whether or not a given ciphertext produces plaintext with valid padding is ALL that an attacker needs to break CBC encryption. If you can feed in ciphertexts and somehow find out whether or not they decrypt to something with valid padding or not, then you can decrypt ANY given ciphertext.

Solution:
I implemented the padding_oracle_attack_exploit function to decrypt a cipher text generated from using the encrypt function using only the calls to oracle function.
File poa.py implements padding oracle attack in python3.

How to execute:
python poa.py
Executing the file without any parameters will default the plaintext to: "This is cs528 padding oracle attack lab with hello world~~~!!" and iv to: "0000000000000000".

To provide different iv and plaintext, execute the same file as follows:
python poa.py -i "0000000000000001" -p "Hello"

Make sure iv is in string format (16-byte). 


References
[1] The Padding Oracle Attack. https://robertheaton.com/2013/07/29/padding-oracle-attack/
[2] Cryptopals: Exploiting CBC Padding Oracles https://research.nccgroup.com/2021/02/17/cryptopals- exploiting-cbc-padding-oracles/