---
title: corCTF 2023 writeup
author: tranminhprvt01
pubDatetime: 2023-08-01
featured: false
draft: false
tags:
  - Crypto
  - Linear Algebra
  - RSA Oracle
description:
  Writeup to challenge(s) I solved during the CTF
---

Cuối tuần vừa rồi (29/7 - 31/7) đã diễn ra giải corCTF 2023, mình đã đánh cho team ``m1cr0$oft 0ff1c3`` và kết thúc giải ở vị trí thứ 24.

![](https://hackmd.io/_uploads/r1aRoGri2.png)

Giải lần này diễn ra trong 2 ngày, cơ mà mình bận ngay ngày đầu nên đến hôm sau mới try hard được 😅. Vì thế chỉ solve được 3/8 câu crypto.

Dưới đây là writeup cho các câu mình đã làm được.

# TL;DR
Simple linear algebra and math

## Table of contents


## fizzbuzz100

>lsb oracles are pretty overdone... anyway here's fizzbuzz
>
>nc be.ax 31100
>
>author: wwm

Attachments:
* fizzbuzz100.py
```python
#!/usr/local/bin/python
from Crypto.Util.number import *
from os import urandom

flag = open("flag.txt", "rb").read()
flag = bytes_to_long(urandom(16) + flag + urandom(16))

p = getPrime(512)
q = getPrime(512)
n = p * q
e = 0x10001
d = pow(e, -1, (p-1)*(q-1))
assert flag < n
ct = pow(flag, e, n)

print(f"{n = }")
print(f"{e = }")
print(f"{ct = }")

while True:
    ct = int(input("> "))
    pt = pow(ct, d, n)
    out = ""
    if pt == flag:
        exit(-1)
    if pt % 3 == 0:
        out += "Fizz"
    if pt % 5 == 0:
        out += "Buzz"
    if not out:
        out = pt
    print(out)
```

Nhận xét:
- Như các kì CTF khác thì đây là challenge đầu tiên với mục đích để warm up. Thông qua việc phân tích source, ta có thể thấy ngay được rằng challenge này thuộc dạng Oracle RSA.
- Ta được yêu cầu gửi C vào server và server sẽ cho ta biết M = decrypt\(C\). Tuy nhiên, server đã chặn không cho ta gửi C = encrypt(flag).
- Vì thế, để bypass dòng điều kiện đó, ta chỉ cần đơn giản gửi vào server $2^e*C$ để khi thực hiện việc decrypt, kết quả ta thu được sẽ là $(2^e*C)^d ≡ 2*M \ (mod \ n )$. Khi này chỉ cần lấy kết quả thu được chia cho 2 ta sẽ thu được flag.
- Lưu ý rằng khi gửi tham số như trên M có thể là bội của 3, 5, 15. Nếu gặp phải trường hợp đó, ta chỉ cần tạo 1 kết nối mới vô server.

Script:
```python
from pwn import *
from Crypto.Util.number import *

host, port = "be.ax", 31100

count = 0

while True:
	print(f"Attempt {count}")
	r = remote(host, port)

	n = int(r.recvline().rstrip()[3:])
	e = int(r.recvline().rstrip()[3:])
	c = int(r.recvline().rstrip()[4:])

	r.recvuntil(b"> ")
	res = pow(2,e,n)*c%n
	r.sendline(str(res).encode())
	data = r.recvline().rstrip() 
	if data not in [b"Fizz", b"Buzz", b"FizzBuzz"]:
		print(data)
		m = long_to_bytes(int(data)//2)
		print(m)
		break
	count+=1
```

![](https://hackmd.io/_uploads/rkum9UHj3.png)

-> Flag: `corctf{h4ng_0n_th15_1s_3v3n_34s13r_th4n_4n_LSB_0r4cl3...4nyw4y_1snt_f1zzbuzz_s0_fun}`


## eyes

>can you see it?
>
>author: emh

Attachments:
* main.sage
```python
from Crypto.Util.number import bytes_to_long, getPrime

# my NEW and IMPROVED secret sharing scheme!! (now with multivariate quadratics)

with open('flag.txt', 'rb') as f:
    flag = f.read()

s = bytes_to_long(flag)
p = getPrime(len(bin(s)))
print(p)
F = GF(p)
N = 1024

conv = lambda n: matrix(F, N, 1, [int(i) for i in list(bin(n)[2:][::-1].ljust(N, '0'))])

A = random_matrix(F, N, N)

for i in range(0, N):
    for j in range(0, i):
        A[i, j] = 0
B = random_matrix(F, N, 1)
C = matrix(F, [F(s)])

fn = lambda x: (x.T * A * x + B.T * x + C)[0][0]

L = []
for i in range(7):
    L.append(fn(conv(i + 1)))

print(L)
```

* out.txt
```
1873089703968291141600166892623234932796169766648225659075834963115683566265697596115468506218441065194050127470898727249982614285036691594726454694776985338487833409983284911305295748861807972501521427415609
[676465814304447223312460173335785175339355609820794166139539526721603814168727462048669021831468838980965201045011875121145342768742089543742283566458551844396184709048082643767027680757582782665648386615861, 1472349801957960100239689272370938102886275962984822725248081998254467608384820156734807260120564701715826694945455282899948399224421878450502219353392390325275413701941852603483746312758400819570786735148132, 202899433056324646894243296394578497549806047448163960638380135868871336000334692955799247243847240605199996942959637958157086977051654225700427599193002536157848015527462060033852150223217790081847181896018, 1065982806799890615990995824412253076607488063240855100580513221962298598002468338823225586171107539104635808108356492123167315175110515086192932230998426512947581115358738651206273178867911944034690138825583, 1676559204037482856674710667663849447914859348633288513196735253002541076530170853584406282605482862202276451646974549657672382936948091649764874334064431407644457518190694888175499630744741620199798070517691, 13296702617103868305327606065418801283865859601297413732594674163308176836719888973529318346255955107009306239107173490429718438658382402463122134690438425351000654335078321056270428073071958155536800755626, 1049859675181292817835885218912868452922769382959555558223657616187915018968273717037070599055754118224873924325840103339766227919051395742409319557746066672267640510787473574362058147262440814677327567134194]
```

Nhận xét:
- Bài toán trên là 1 bài toán liên quan đến nhân ma trận trong môn đại số tuyến tính. 
- Nhìn qua source, ta thấy mọi phép tính sẽ được thực hiện trên GF\(p\), ma trận $A_{1024x1024}$ , ma trận $B_{1024x1}$ , ma trận $C_{1x1}$ , cùng với đó là 7 output của hàm fn(conv(i)) (i=1 -> 7). 
- Phân tích qua hàm conv(i), hàm này sẽ chuyển số nhập vào thành dạng nhị phân và trả về 1 ma trận 1024x1 với các phần tử là biểu diễn nhị phân của ma trận đó.
Ví dụ: 
$$
\
   conv(1) = 
  \left[ {\begin{array}{cc}
   1 \\
   0 \\
   ... \\
   0 \\
  \end{array} } \right]_{\text{1024x1}}
\
\
\
   conv(3) = 
  \left[ {\begin{array}{cc}
   1 \\
   1 \\
   ... \\
   0 \\
  \end{array} } \right]_{\text{1024x1}}
\
\
\
   conv(7) = 
  \left[ {\begin{array}{cc}
   1 \\
   1 \\
   1 \\
   ... \\
   0 \\
  \end{array} } \right]_{\text{1024x1}}
$$
- Còn về hàm fn(X), hàm này sẽ trả về giá trị duy nhất là kết quả của phép tính trên ma trận sau: $X.T * A * X + B.T * X + C$ (với X.T là ma trận chuyển vị của ma trận X).
- Ngoài ra, ta có thể thấy rằng flag sẽ nằm trong ma trận C, và ma trận A sẽ là 1 ma trận tam giác trên có dạng sau.
$$
   A = 
  \left[ {\begin{array}{cc}
   a_{0,0} & a_{0,1} & a_{0,2} & a_{0,3} & ... & a_{0,1023} \\
   0 & a_{1,1} & a_{1,2} & a_{1,3} & ... & a_{1,1023} \\
   ... & ... & ... & ... & ... & ... \\
   0 & 0 & 0 & 0 & ... & a_{1023,1023} \\
  \end{array} } \right]_{\text{1024x1024}}
$$

- Do các giá trị X được đưa vào hàm fn đều là output của hàm conv(i), vị chi ta đã biết các ma trận X này, nên ta sẽ tính tay các giá trị.
- Đối với X = conv(1), ta có:

$$
   X.T * A = 
  \left[ {\begin{array}{cc}
   a_{0,0} & a_{0,1} & a_{0,2} & a_{0,3} & ... & a_{0,1023} \\
  \end{array} } \right]_{\text{1x1024}}
$$
$$
   X.T * A * X = 
  \left[ {\begin{array}{cc}
   a_{0,0} \\
  \end{array} } \right]_{\text{1x1}}
$$
$$
   B.T * X = 
  \left[ {\begin{array}{cc}
   b_{0,0} \\
  \end{array} } \right]_{\text{1x1}}
$$

- Từ đó, ta có $L_0 = a_{0,0} + b_{0,0} + c$
- Tương tự với các X là conv(i) với (i=2->7), ta thực hiện tính tay và sẽ thu được 7 phương trình, sau đó tìm mối liên hệ giữa các phương trình để tính c -> flag.

Script:
```python
from Crypto.Util.number import *

p = 1873089703968291141600166892623234932796169766648225659075834963115683566265697596115468506218441065194050127470898727249982614285036691594726454694776985338487833409983284911305295748861807972501521427415609

L = [676465814304447223312460173335785175339355609820794166139539526721603814168727462048669021831468838980965201045011875121145342768742089543742283566458551844396184709048082643767027680757582782665648386615861, 1472349801957960100239689272370938102886275962984822725248081998254467608384820156734807260120564701715826694945455282899948399224421878450502219353392390325275413701941852603483746312758400819570786735148132, 202899433056324646894243296394578497549806047448163960638380135868871336000334692955799247243847240605199996942959637958157086977051654225700427599193002536157848015527462060033852150223217790081847181896018, 1065982806799890615990995824412253076607488063240855100580513221962298598002468338823225586171107539104635808108356492123167315175110515086192932230998426512947581115358738651206273178867911944034690138825583, 1676559204037482856674710667663849447914859348633288513196735253002541076530170853584406282605482862202276451646974549657672382936948091649764874334064431407644457518190694888175499630744741620199798070517691, 13296702617103868305327606065418801283865859601297413732594674163308176836719888973529318346255955107009306239107173490429718438658382402463122134690438425351000654335078321056270428073071958155536800755626, 1049859675181292817835885218912868452922769382959555558223657616187915018968273717037070599055754118224873924325840103339766227919051395742409319557746066672267640510787473574362058147262440814677327567134194]


m = L[0]+L[1]+L[3]+L[6] - (L[2]+L[4]+L[5])

print(m, m>p)

print(long_to_bytes(m%p))

#corctf{mind your ones and zeroes because zero squared is zero and one squared is one}
```

![](https://hackmd.io/_uploads/r1momDSih.png)

-> Flag: `corctf{mind your ones and zeroes because zero squared is zero and one squared is one}`

twist: bài này ban đầu mình nhìn sai ma trận A nên mới ra công thức như trên code, cơ mà vẫn tính ra được flag 😅

## cbc
>who on earth is putting CLASSICAL BORING CRYPTOGRAPHY in my ctf
>
>author: wwm

Attachments:
* cbc.py
```python
import random

def random_alphastring(size):
    return "".join(random.choices(alphabet, k=size))

def add_key(key, block):
    ct_idxs = [(k_a + pt_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    return "".join([alphabet[idx] for idx in ct_idxs])

def cbc(key, plaintext):
    klen = len(key)
    plaintext = pad(klen, plaintext)
    iv = random_alphastring(klen)
    blocks = [plaintext[i:i+klen] for i in range(0, len(plaintext), klen)]
    prev_block = iv
    ciphertext = ""
    for block in blocks:
        block = add_key(prev_block, block)
        prev_block = add_key(key, block)
        ciphertext += prev_block
    return iv, ciphertext
    
def pad(block_size, plaintext):
    plaintext += "X" * (-len(plaintext) % block_size)
    return plaintext

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
bs = 16

message = open("message.txt").read().upper()
message = "".join([char for char in message if char in alphabet])
flag = open("flag.txt").read()
flag = flag.lstrip("corctf{").rstrip("}")
message += flag
assert all([char in alphabet for char in message])

key = random_alphastring(bs)
iv, ct = cbc(key, pad(bs, message))
print(f"{iv = }")
print(f"{ct = }")
```
* cbc_output.txt
```
iv = 'RLNZXWHLULXRLTNP'
ct = 'ZQTJIHLVWMPBYIFRQBUBUESOOVCJHXXLXDKPBQCUXWGJDHJPQTHXFQIQMBXNVOIPJBRHJQOMBMNJSYCRAHQBPBSMMJWJKTPRAUYZVZTHKTPUAPGAIJPMZZZDZYGDTKFLWAQTSKASXNDRRQQDJVBREUXFULWGNSIINOYULFXLDNMGWWVSCEIORQESVPFNMWZKPIYMYVFHTSRDJWQBTWHCURSBPUKKPWIGXERMPXCHSZKYMFLPIAHKTXOROOJHUCSGINWYEILFIZUSNRVRBHVCJPVPSEGUSYOAMXKSUKSWSOJTYYCMEHEUNPJAYXXJWESEWNSCXBPCCIZNGOVFRTGKYHVSZYFNRDOVPNWEDDJYITHJUBVMWDNNNZCLIPOSFLNDDWYXMYVCEOHZSNDUXPIBKUJIJEYOETXWOJNFQAHQOVTRRXDCGHSYNDYMYWVGKCCYOBDTZZEQQEFGSPJJIAAWVDXFGPJKQJCZMTPMFZDVRMEGMPUEMOUVGJXXBRFCCCRVTUXYTTORMSQBLZUEHLYRNJAAIVCRFSHLLPOANFKGRWBYVSOBLCTDAUDVMMHYSYCDZTBXTDARWRTAFTCVSDRVEENLHOHWBOPYLMSDVOZRLENWEKGAWWCNLOKMKFWWAZJJPFDSVUJFCODFYIMZNZTMAFJHNLNMRMLQRTJJXJCLMQZMOFOGFPXBUTOBXUCWMORVUIIXELTVIYBLPEKKOXYUBNQONZLPMGWMGRZXNNJBUWBEFNVXUIAEGYKQSLYSDTGWODRMDBHKCJVWBNJFTNHEWGOZFEZMTRBLHCMHIFLDLORMVMOOHGXJQIIYHZFMROGUUOMXBTFMKERCTYXFIHVNFWWIUFTGLCKPJRFDRWDXIKLJJLNTWNQIOFWSIUQXMFFVIIUCDEDFEJNLKLQBALRKEYWSHESUJJXSHYWNRNPXCFUEFRJKSIGXHFTKNJXSYVITDOGYIKGJIOOHUFILWYRBTCQPRPNOKFKROTFZNOCZXZEYUNWJZDPJDGIZLWBBDGZJNRQRPFFGOTGFBACCRKLAPFLOGVYFXVIIJMBBMXWJGLPOQQHMNBCINRGZRBVSMLKOAFGYRUDOPCCULRBE'
```

Nhận xét:
- Nhìn qua bài toán trên, ta có thể thấy rằng nó khá giống CBC mode của AES khi mà message được đưa vào encrypt theo công thức sau:
```
p0+iv+key=c0
p1+c0+key=c1
p2+c1+key=c2
...
Tất cả các phép toán được thực hiện trên Zmod(26)
```
- Tuy nhiên nếu để ý kĩ, ta sẽ có thể biến đổi bài toán này về Vigenere cipher bằng cách
```
p0+key=c0-iv
p1+key=c1-c0
p2+key=c2-c1
...
Tất cả các phép toán được thực hiện trên Zmod(26)
```
- Đến đây, ta chỉ cần kiếm tool solve Vigenere cipher mà không cần biết key.

Script:
```python
import random

def random_alphastring(size):
    return "".join(random.choices(alphabet, k=size))

def add_key(key, block):
    ct_idxs = [(k_a + pt_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
    print("key", [alphabet.index(k) for k in key])
    print("pt", [alphabet.index(pt) for pt in block])
    print("res", ct_idxs)
    print("~"*40)
    return "".join([alphabet[idx] for idx in ct_idxs])

def cbc(key, plaintext):
    klen = len(key)
    plaintext = pad(klen, plaintext)
    iv = "RLNZXWHLULXRLTNP"#random_alphastring(klen)
    blocks = [plaintext[i:i+klen] for i in range(0, len(plaintext), klen)]
    print("DEBUG", blocks)
    prev_block = iv
    ciphertext = ""
    for block in blocks:
        block = add_key(prev_block, block)
        prev_block = add_key(key, block)
        ciphertext += prev_block
    return iv, ciphertext
    
def pad(block_size, plaintext):
    plaintext += "X" * (-len(plaintext) % block_size)
    return plaintext

alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
bs = 16


iv = 'RLNZXWHLULXRLTNP'
ct = 'ZQTJIHLVWMPBYIFRQBUBUESOOVCJHXXLXDKPBQCUXWGJDHJPQTHXFQIQMBXNVOIPJBRHJQOMBMNJSYCRAHQBPBSMMJWJKTPRAUYZVZTHKTPUAPGAIJPMZZZDZYGDTKFLWAQTSKASXNDRRQQDJVBREUXFULWGNSIINOYULFXLDNMGWWVSCEIORQESVPFNMWZKPIYMYVFHTSRDJWQBTWHCURSBPUKKPWIGXERMPXCHSZKYMFLPIAHKTXOROOJHUCSGINWYEILFIZUSNRVRBHVCJPVPSEGUSYOAMXKSUKSWSOJTYYCMEHEUNPJAYXXJWESEWNSCXBPCCIZNGOVFRTGKYHVSZYFNRDOVPNWEDDJYITHJUBVMWDNNNZCLIPOSFLNDDWYXMYVCEOHZSNDUXPIBKUJIJEYOETXWOJNFQAHQOVTRRXDCGHSYNDYMYWVGKCCYOBDTZZEQQEFGSPJJIAAWVDXFGPJKQJCZMTPMFZDVRMEGMPUEMOUVGJXXBRFCCCRVTUXYTTORMSQBLZUEHLYRNJAAIVCRFSHLLPOANFKGRWBYVSOBLCTDAUDVMMHYSYCDZTBXTDARWRTAFTCVSDRVEENLHOHWBOPYLMSDVOZRLENWEKGAWWCNLOKMKFWWAZJJPFDSVUJFCODFYIMZNZTMAFJHNLNMRMLQRTJJXJCLMQZMOFOGFPXBUTOBXUCWMORVUIIXELTVIYBLPEKKOXYUBNQONZLPMGWMGRZXNNJBUWBEFNVXUIAEGYKQSLYSDTGWODRMDBHKCJVWBNJFTNHEWGOZFEZMTRBLHCMHIFLDLORMVMOOHGXJQIIYHZFMROGUUOMXBTFMKERCTYXFIHVNFWWIUFTGLCKPJRFDRWDXIKLJJLNTWNQIOFWSIUQXMFFVIIUCDEDFEJNLKLQBALRKEYWSHESUJJXSHYWNRNPXCFUEFRJKSIGXHFTKNJXSYVITDOGYIKGJIOOHUFILWYRBTCQPRPNOKFKROTFZNOCZXZEYUNWJZDPJDGIZLWBBDGZJNRQRPFFGOTGFBACCRKLAPFLOGVYFXVIIJMBBMXWJGLPOQQHMNBCINRGZRBVSMLKOAFGYRUDOPCCULRBE'


iv_ls = [alphabet.index(i) for i in iv]
print(iv_ls)

ct_blocks = [ct[i:i+bs] for i in range(0, len(ct), bs)]
print(ct_blocks)

key = [0 for i in range(16)]
res = [iv_ls]
for block in ct_blocks:
	ct_ls = [alphabet.index(i) for i in block]
	res.append(ct_ls)

print(res)
pt = [[0 for _ in range(bs)] for _ in range(len(res)-1)]

for block in range(1, len(res)):
	for pos in range(bs):
		pt[block-1][pos] = res[block][pos] - res[block-1][pos]

def convert(ls):
	res = ""
	for i in ls:
		res+="".join([alphabet[_] for _ in i])
	return res
def split(s, size):
	block=[s[i:i+size] for i in range(0, len(s), size)]
	return block

print(convert(pt), bs)

#corctf{ATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS}
#vigenere auto solve
```
- Code trên của mình chỉ thực hiện việc chỉnh lại message thành dạng Vigenere cipher, và sau đó mình kiếm tool để auto solve message trên.

![](https://hackmd.io/_uploads/SkAPIwBsn.png)



![](https://hackmd.io/_uploads/HkZ58wHsh.png)

-> Flag: `corctf{ATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS}`


## Kết luận
- Ở trên là danh sách 3 bài mảng crypto mình solve được trong giải corCTF 2023. 
- Mọi thắc mắc của các bạn xin vui lòng liên hệ với mình qua discord: ``tranminhprvt01#7535``
- Cuối cùng, cảm ơn các bạn đã đọc. Have a good day! 🥰