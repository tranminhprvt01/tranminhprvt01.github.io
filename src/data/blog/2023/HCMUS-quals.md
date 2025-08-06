---
title: HCMUSCTF Qualifications 2023 writeup
author: tranminhprvt01
pubDatetime: 2023-05-08
featured: false
draft: false
tags:
  - Crypto
  - Coppersmith
  - Linear Algebra
description:
  Writeup to challenge(s) I solved during the CTF
---

# TL;DR
Writeup of most challenges of HCMUS2023 (5/6 crypto solved). Yes I learned LaTex now.

## Table of contents


## Bootleg AES
Đề cho ta 3 file, 1 file bash script, 1 file log và ciphertext.

Đọc qua bash script và file log

Attachments:
* enc.sh
```bash
#!/bin/bash

echo "$(cat pad.bin)$FLAG" > flag.bin
ls -alF ./pad.bin
x=$(openssl rand -hex 32)
echo $x
openssl enc -aes-256-cbc -K $x -iv $(openssl rand -hex 16) -in flag.bin -out ciphertext.bin
```
* log.txt
```
-rw-r--r-- 1 hoang hoang 256 Apr  2 13:03 ./pad.bin
c9a391c6f65bbb38582044fd78143fe72310e96bf67401039b3b6478455a1622
```

Ta có thể thấy rằng, FLAG của chúng ta được nối vào sau file pad.bin. Cùng với đó ta biết được key được sử dụng cho việc encrypt aes-256-cbc.

Mặc dù, ta không biết thông số về iv được xài cho việc encrypt nhưng tham số này là không quan trọng. Vì FLAG đã được pad ở cuối file pad.bin còn iv trong aes-256-cbc chỉ ảnh hưởng đến block đầu.
Chính vì vậy bài này ta chỉ cần chạy câu lệnh
```bash
openssl enc -aes-256-cbc -d -K c9a391c6f65bbb38582044fd78143fe72310e96bf67401039b3b6478455a1622 -iv $(openssl rand -hex 16) -in ciphertext.bin -out flag.txt; cat flag.txt
```
- Ta sẽ thu được flag
```
�x�F�<ܸk;L��VB4�����)َ�:��C��2@[Z��0��(�b�wJ<H�^��]T�a}U^&�&

 �\|�S9��HCMUS-CTF{it5_c4ll3d_pr1v4t3_k3y_crypt09raphy_f0r_4_r3450n}
```

=> Flag: ``HCMUS-CTF{it5_c4ll3d_pr1v4t3_k3y_crypt09raphy_f0r_4_r3450n}``

## False Hood

Attachments:

* prob.py

```python
import os
import numpy as np
from sage.all import ComplexField, PolynomialRing
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
from binascii import hexlify

FLAG = os.getenv('FLAG', "FLAG{this is a real flag}")
bits = 1111
C = ComplexField(bits)
P = PolynomialRing(C, names='x')
(x,) = P.gens()

key_array = np.random.choice(256, size=(16,))
key = b''.join([int(i).to_bytes(1, 'big') for i in key_array])

f = sum([coeff * x**i for i, coeff in enumerate(key_array)])
hint = []
for _ in range(16):
    X = random.randint(10**8, 10**10)
    Y = int(abs(f(X)))
    while [X, Y] in hint:
        X = random.randint(10**8, 10**10)
        Y = int(abs(f(X)))
    hint.append([X, Y])


cip = AES.new(key, AES.MODE_CBC)
ct = cip.encrypt(pad(FLAG.encode(),16))
iv = cip.iv
with open('output.txt', 'w') as file:
    file.write(str(hint)+'\n')
    print(f"ct = {hexlify(ct).decode()}, iv = {hexlify(iv).decode()}", file=file)
```

Phân tích qua file challenge, ta sẽ thấy rằng flag được encrypt AES với key và iv. Ở đây ta đã biết thông số iv, còn key thì ta biết được rằng đã được tạo ra thông qua key_array

```python
key_array = np.random.choice(256, size=(16,))
key = b''.join([int(i).to_bytes(1, 'big') for i in key_array])
```

Vậy tức là nếu ta đoán được các thành phần trong list key_array, ta hoàn toàn có thể tính được key và decrypt ciphertext.

Ở đây, file challenge còn cho ta biết thêm 1 thông tin là list hint gồm 16 cặp (x, y) khác nhau có dạng: ``hint = [x, abs(f(x))]``

Hàm f(x) lại được định nghĩa ở trên file challenge có dạng sau:
$f(x) = a_0 + a_1*x + a_2*x^2 + a_3*x^3 + ... + a_{15}*x^{15}$
với list các $a_i$ tương ứng với $\text{key\_array}_i$.

Ở bài này, với việc ta đã biết 16 cặp (x, f(x)) khác nhau dẫn đến việc ta có thể chuyển bài toán trên thành ma trận.

Gọi ma trận A là ma trận chứa các hệ số của các $x_i^{j}$ với j chạy từ 0 -> 15, i chạy từ 0 -> 15 , ma trận X là ma trận chứa các $\text{key\_array}_i$ , ma trận C là ma trận chứa các $f(x_i)$
$$
A =
\left[
  \begin{array}{ccccc}
    1 & x_0 & x_0^{2} & \dots & x_0^{15} \\
    1 & x_1 & x_1^{2} & \dots & x_1^{15} \\
    \vdots & \vdots & \vdots & \ddots & \vdots \\
    1 & x_{15} & x_{15}^{2} & \dots & x_{15}^{15}
  \end{array}
\right]_{\text{16x16}},
\quad
X =
\left[
  \begin{array}{c}
    a_0 \\ a_1 \\ a_2 \\ \vdots \\ a_{15}
  \end{array}
\right]_{\text{16x1}},
\quad
C =
\left[
  \begin{array}{c}
    f(x_0) \\ f(x_1) \\ f(x_2) \\ \vdots \\ f(x_{15})
  \end{array}
\right]_{\text{16x1}}
$$

Từ đó, ta sẽ cần giải quyết bài toán nhân ma trận $A X = B$

Mình sẽ sử dụng sage để tính ma trận X

```python
hint = [[8833677163, 7159466859734884050485160017085648949938620549936739498951806707835448713685207536552299918328868591349533273061478374089984223260577742322460362334647], [1762352339, 226021067407224282748442153993506422184559341973942542463611713009302649608941949660293486972516731321467369225717344439888178648461773300463], [6814325828, 145915445591160853098610646953738314537732696913127480076359637783667652244881400087606152610739138506056218199806589240306741950875956525839170443027], [7865890147, 1255960511416167089973436987379886082394930531153251392262351559661203914293720867397614316726175343133363293139291718249474745356688772183204229822751], [3446680058, 5293859406843167459297872689128502546567761548640003856519557803475599388573073027426285178678302790672452768542207529392596772806973985884693237], [5877771652, 15883583178415793156782570756223737797760371065858523945056072346852806064052610100332389954372845836435762293469821829936427366159434784004504398291], [5589586633, 7472281200056449019563455444999813482028446397663996508394508567670602924631065370355170602075256758870709465268255309886778027432655593535614166637], [1175276268, 518629639886914674796931012497083502361229856009622285824810204881645367508380387007577326543311405957619591605841895258801496781885398507], [3312651249, 2920072124198357353277671402963439479294095254775553378538026906919501392975483266953780010186413153114694525677661955925502702904273824951901573], [1690420045, 120969905638890571692249167310237577968012605711450331530578304692989016303379573026678222839813088165787719888874515256743894818676147474521], [8298141391, 2802013920829536770649820952830225273137583982204944734413323800249577243089166668778583649665043009034143120874987986020037964205143133245123290632883], [733386150, 439287044309927586596972381366960178061704411347096135895831191742005839221734048948610767236121358802659929070752762370822244956535801], [7897145685, 1332938401210287323326359805632057169759318295533885927320250339098837407040892547133970478663396358868892779722453565866390506758764909670000617998161], [9797888335, 33864534898740204255025855638155912349784294672865719351405048784504660475905319925895086755774471151890089727930776090169445401259844048317273142069811], [4557234547, 349364318043137479854576449493426376983315472777226775365310579193760250715517761090058069937282741206013319707277840448237966901906357292702335951], [7667001731, 855344863189641492213600127143839128290386097202448105626863527763958015786114563445357087338205788545215994676722500375202243293047596358065835329663]]

l=len(hint)
print(l)
coeff=[i[0] for i in hint]
val=[i[1] for i in hint]

ls=[]
for i in range(16):
	for j in range(16):
		ls.append(coeff[i]^j)
print(ls, len(ls))
A=Matrix(16, 16, ls)
B=vector(val)
print(A.rank(), "bruh",  A.parent())
K=A.solve_right(B)

print(K, K.parent())
k_=[]
for i in range(16):
	k_.append(int(abs(K[i])))
print(k_)
#[151, 31, 144, 9, 171, 106, 24, 3, 175, 203, 78, 154, 44, 113, 201, 46]
```
Sau khi recover lại được key_array, ta chỉ cần tính key và decrypt ciphertext.
```python
from Crypto.Cipher import AES

k_array=[151, 31, 144, 9, 171, 106, 24, 3, 175, 203, 78, 154, 44, 113, 201, 46]


ct="be205fd34ebe59af55ea11fec9aea50197fbf35d5b52c650a6c9563186625e8b6021ba31db538fa4b60c69a42c96ee3bebaba53ac9afa9c3c185d4d0b145bc8251d892c243f1aa4037aeea003714e24c"

iv="370abc6fce33f812de7b88daaa82e4c4"

key = b''.join([int(i).to_bytes(1, 'big') for i in k_array])

print(key)


cip = AES.new(key, AES.MODE_CBC, bytes.fromhex(iv))


print(cip.decrypt(bytes.fromhex(ct)))

#b"HCMUS-CTF{just_because_you're_correct_doesn't_mean_you're_right}\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
```

=> Flag: ``HCMUS-CTF{just_because_you're_correct_doesn't_mean_you're_right}``

## Mside

Attachments:

* prob.py

```python
from Crypto.Util.number import getStrongPrime, bytes_to_long as b2l, isPrime
import os


FLAG = os.getenv('FLAG', 'FLAG{hue_hue_hue}').encode()
p = getStrongPrime(512)
q = getStrongPrime(512)
while not isPrime(4 * p * p + q * q):
    p = getStrongPrime(512)
    q = getStrongPrime(512)

hint = 4 * p * p + q * q
e = 65537
print(f"hint: {hint}")
# n for wat?
print(f"ct: {pow(b2l(FLAG), e, p * q)}")

"""
hint: 461200758828450131454210143800752390120604788702850446626677508860195202567872951525840356360652411410325507978408159551511745286515952077623277648013847300682326320491554673107482337297490624180111664616997179295920679292302740410414234460216609334491960689077587284658443529175658488037725444342064697588997
ct: 8300471686897645926578017317669008715657023063758326776858584536715934138214945634323122846623068419230274473129224549308720801900902282047728570866212721492776095667521172972075671434379851908665193507551179353494082306227364627107561955072596424518466905164461036060360232934285662592773679335020824318918
"""
```

Phân tích file source, ta thấy rằng đây là bài toán RSA. Tuy nhiên ở đây ta không được cho biết thông số n mà chỉ biết thông số $hint = 4p^2 + q^2$

Nhận thấy rằng hint là một số nguyên tố, mình đã tìm được 1 [tài liệu khá liên quan](https://en.wikipedia.org/wiki/Fermat%27s_theorem_on_sums_of_two_squares#:~:text=If%20a%20number%20which%20is,a%20sum%20of%20two%20squares.)
Dựa vào tài liệu trên, ta chỉ cần tìm 1 số non-quadratic residues của hint và sử dụng extended euclid, 2 số chia lấy dư đầu tiên nhỏ hơn $\sqrt{hint}$ chính là 2p và q.

Từ đó ta đã có đủ mọi dữ kiện cần để giải quyết bài toán RSA trên.

Source

```python
import gmpy2 
from gmpy2 import mpz
from Crypto.Util.number import inverse, long_to_bytes
import math
def square_root(a, p):
    #Tonelli–Shanks algorithm
    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return 0
    elif p % 4 == 3:
        return pow(a, (p + 1) / 4, p)

    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1

    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1

    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e

    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x

        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def legendre_symbol(a, p):

    ls = pow(a, (p - 1) // 2, p)
    return -1 if ls == p - 1 else ls

def egcd(a, b, MOD):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        if r < math.isqrt(MOD)+1: print("fuck",r)
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        
    gcd = b
    return gcd, x, y
	
hint = 461200758828450131454210143800752390120604788702850446626677508860195202567872951525840356360652411410325507978408159551511745286515952077623277648013847300682326320491554673107482337297490624180111664616997179295920679292302740410414234460216609334491960689077587284658443529175658488037725444342064697588997
c = 8300471686897645926578017317669008715657023063758326776858584536715934138214945634323122846623068419230274473129224549308720801900902282047728570866212721492776095667521172972075671434379851908665193507551179353494082306227364627107561955072596424518466905164461036060360232934285662592773679335020824318918

p = hint
for i in range(hint):
	if legendre_symbol(i, hint) == -1:
		tmp=i
		break
print(tmp)

x = pow(tmp, (p-1) // 4, p)
print(x)
egcd(x, p, p)

p = 19253294223314315727716037086964210594461001022934798241434958729430216563195726834194376256655558434205505701941181260137383350002506166062809813588037666
q = 9513749018075983034085918764185242949986187938391728694055305209717744257503225678393636438369553095045978207938932347555839964566376496993702806422385729

p//=2
phi=(p-1)*(q-1)
e=65537
d=inverse(e,phi)
print(long_to_bytes(pow(c,d,p*q)))

#HCMUS-CTF{either_thu3_0r_3uclid_wh1ch3v3r_it_t4k35}
```

=> Flag: ``HCMUS-CTF{either_thu3_0r_3uclid_wh1ch3v3r_it_t4k35}``

## Sneak Peek

Attachment:
* prob.py
```python
from Crypto.Util.number import getPrime, bytes_to_long as b2l

FLAG = b2l(b'HMCSU-CFT{SO YOU THINK THIS FLAG IS REAL\xff}')

p = getPrime(512)
q = getPrime(512)


n = p * q
peek = p >> 240

print(n)
print(peek)
print(pow(FLAG, 65537, n))
"""
137695652953436635868173236797773337408441001182675256086214756367750388214098882698624844625677992374523583895607386174643756159168603070583418054134776836804709359451133350283742854338177917816199855370966725059377660312824879861277400624102267119229693994595857701696025366109135127015217981691938713787569
6745414226866166172286907691060333580739794735754141517928503510445368134531623057
60939585660386801273264345336943282595466297131309357817378708003135300231065734017829038358019271553508356563122851120615655640023951268162873980957560729424913748657116293860815453225453706274388027182906741605930908510329721874004000783548599414462355143868922204060850666210978837231187722295496753756990
"""
```

Đây là 1 dạng bài phổ biến trong RSA. Khi mà ta đã được cho biết 512 - 240 = 282 > ($\frac{1024}{4}=256$) MSB của p. Lúc này, ta có thể áp dụng định lí Coppersmith.

Nhắc lại về định lí Coppersmith:
- Cho N = pq, N là 1 số n-bits. Khi đó nếu ta biết được tối thiểu $\frac{n}{4}$ least significant bits (LSB) của p hoặc $\frac{n}{4}$ most significant bits (MSB) của p. Ta sẽ phân tích N thành thừa số nguyên tố được.

Áp dụng vào bài toán trên, gọi 240-bits đã bị mất là x, ta sẽ dựng được hàm $f = peek * 2^{240} + x$. Mọi công đoạn sau đó, ta sẽ nhờ sagemath tìm kiếm x thỏa mãn với hàm **small_roots()**

Source:
```python

bits=240
R=2^bits
N=137695652953436635868173236797773337408441001182675256086214756367750388214098882698624844625677992374523583895607386174643756159168603070583418054134776836804709359451133350283742854338177917816199855370966725059377660312824879861277400624102267119229693994595857701696025366109135127015217981691938713787569
a=6745414226866166172286907691060333580739794735754141517928503510445368134531623057#p>>240
c=60939585660386801273264345336943282595466297131309357817378708003135300231065734017829038358019271553508356563122851120615655640023951268162873980957560729424913748657116293860815453225453706274388027182906741605930908510329721874004000783548599414462355143868922204060850666210978837231187722295496753756990
e=65537

print(a)

P.<x> = PolynomialRing(Zmod(N))

f = R*a + x
f=f.monic()

r = f.small_roots(X = R, beta = 0.5, epsilon = 0.02)
print("Found root : ",r)
```

Khi ta đã tìm được số x thành công, ta sẽ thay số x vào lại phương trình $p = peek*2^{240} + x$ ban đầu để tính được p. Và từ đó, ta đã có đủ thông số để giải mã RSA.

```python
from math import gcd
from Crypto.Util.number import *

n=137695652953436635868173236797773337408441001182675256086214756367750388214098882698624844625677992374523583895607386174643756159168603070583418054134776836804709359451133350283742854338177917816199855370966725059377660312824879861277400624102267119229693994595857701696025366109135127015217981691938713787569
peek=6745414226866166172286907691060333580739794735754141517928503510445368134531623057
c=60939585660386801273264345336943282595466297131309357817378708003135300231065734017829038358019271553508356563122851120615655640023951268162873980957560729424913748657116293860815453225453706274388027182906741605930908510329721874004000783548599414462355143868922204060850666210978837231187722295496753756990
e=65537

bits=240
R=2^bits

x=1068145393984575104564040557511108681247660129429767665495025468528378439

p =(2**bits)*peek+x
print(p)
q=n//p
phi=(p-1)*(q-1)
d=inverse(e,phi)

print(long_to_bytes(pow(c,d,n)))

#HCMUS-CTF{d0nt_b3_4n_3XhiB1ti0ni5t_0r_y0uLL_g3t_eXp0s3d}
```

=> Flag: ``HCMUS-CTF{d0nt_b3_4n_3XhiB1ti0ni5t_0r_y0uLL_g3t_eXp0s3d}``

## Cry1

Attachment:
* server.py

```python
import time
import random
import threading
import socketserver
import os

FLAG_FILE = os.getenv("FLAG")
PORT = int(os.getenv("APP_PORT"))
HOST = "0.0.0.0"

assert FLAG_FILE is not None, "Environment variable FLAG not set"
assert PORT is not None, "Environment variable APP_PORT not set"


class Service(socketserver.BaseRequestHandler):
    def handle(self):
        self.flag = self.get_flag()
        self.user_id = int(time.time())
        self.send(f"Welcome\n")
        assert len(self.flag) == 26
        self.send(
            f"Here is your encoded flag: {self.encode(self.flag, self.gen_key(self.user_id, len(self.flag)))}\n"
        )

    def get_flag(self):
        with open(FLAG_FILE, "r") as f:
            return f.readline()

    def encode(self, data, key):
        return sum([a * ord(b) for a, b in zip(key, data)])

    def gen_key(self, user_id, n):
        random.seed(user_id)
        return [random.randrange(1024) for i in range(n)]

    def send(self, string: str):
        self.request.sendall(string.encode("utf-8"))

    def receive(self):
        return self.request.recv(1024).strip().decode("utf-8")


class ThreadedService(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer,
    socketserver.DatagramRequestHandler,
):
    pass


def main():
    service = Service
    server = ThreadedService((HOST, PORT), service)
    server.allow_reuse_address = True
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()

    print("Server started on " + str(server.server_address) + "!")
    # Now let the main thread just wait...
    while True:
        time.sleep(10)


if __name__ == "__main__":
    main()
```
Ở bài này, ta được cho source của server. Phân tích qua file source, ta sẽ biết rằng sau khi connect vào server, ta sẽ nhận dòng chữ "Welcome" và "Here is your encoded flag: xxx" với xxx là số được tính qua hàm ``self.encode(self.flag, self.gen_key(self.user_id, len(self.flag)))``

Hàm **gen_key(user_id, n)** sẽ set random.seed(user_id) và trả về một mảng chứa n số random từ 0 -> 1024.

Hàm **encode(data, key)** sẽ được tính bằng $\Sigma_{i=0}^{25} (key_i * ord(data_i))$.

Ở bài này ta đã biết độ dài flag = 26, user_id = int(time.time()).

Nói sơ qua một chút về hàm int(time.time()) này thì nó sẽ trả về giá trị int của thời gian ngay thời điểm chúng ta chạy đoạn code. Tức là ngay khi ta thực hiện connection vào server ta sẽ thu được time.time() có thể bị lệch vài miliseconds, tuy nhiên mình nghĩ sẽ không ảnh hưởng nhiều do đã được lấy ép kiểu về int.

Nếu vậy, ở bài toán này với việc ta nắm được **seed** trong tay, ta hoàn toàn biết được chính xác $key_i$ và từ đó lại dẫn chúng ta về bài toán nhân ma trận.

Đầu tiên, mình sẽ viết 1 đoạn code để gửi tương tác với server 26 lần và thu về các dữ liệu cần thiết
```python
from pwn import *
import time
import random
#from sage.all import *

def gen_key(user_id, n):
        random.seed(user_id)
        return [random.randrange(1024) for i in range(n)]

host, port = "cry1.chall.ctf.blackpinker.com", 443


coeff=[]
val=[]

for i in range(26):
	r=remote(host, port, ssl = True)
	l = 26
	ls = gen_key(int(time.time()), l)
	print(int(time.time()))
	print(ls)
	r.recvline()
	r.recvuntil(b"Here is your encoded flag: ")
	data=int(r.recvline().rstrip().decode())
	ls.append(data)
	coeff.append(ls)
	val.append(data)
	time.sleep(1)
	r.close()


print(coeff, len(coeff))
print(val)
```
Lưu ý, nên có khoảng nghỉ time.sleep(1) ở giữa mỗi lần connect để tránh việc trùng seed, trùng key.

Ở lần connect thứ i, gọi ma trận A là ma trận chứa các $key_{i, j}$ với j chạy từ 0 -> 25, i chạy từ 0 -> 25 , ma trận X là ma trận chứa các $\text{flag}_i$ , ma trận C là ma trận chứa các giá trị tính toán qua hàm ``self.encode(self.flag, self.gen_key(self.user_id, len(self.flag)))`` ở lần connect thứ i
$$
A =
\left[
  \begin{array}{ccccc}
    \text{key}_{0,0} & \text{key}_{0,1} & \text{key}_{0,2} & \dots & \text{key}_{0,25} \\
    \text{key}_{1,0} & \text{key}_{1,1} & \text{key}_{1,2} & \dots & \text{key}_{1,25} \\
    \vdots & \vdots & \vdots & \ddots & \vdots \\
    \text{key}_{25,0} & \text{key}_{25,1} & \text{key}_{25,2} & \dots & \text{key}_{25,25}
  \end{array}
\right]_{\text{26x26}},
\quad
X =
\left[
  \begin{array}{c}
    \text{flag}_0 \\ \text{flag}_1 \\ \text{flag}_2 \\ \vdots \\ \text{flag}_{25} 
  \end{array}
\right]_{\text{26x1}},
\quad
C =
\left[
  \begin{array}{c}
    y_0 \\ y_1 \\ y_2 \\ \vdots \\ y_{25}
  \end{array}
\right]_{\text{26x1}}
$$

Tương tự bài toán trên, ta hoàn toàn có thể giải quyết bằng hàm sẵn có trong sagemath là **X = A.solve_right(B)**. Tuy nhiên, khi thực hiện cách này mình lại không thu được giá trị X là số nguyên.

Nhưng phát biểu lại bài toán nhân ma trận, ta đang thực sự giải quyết với bài toán giải 1 hệ phương trình gồm 26 phương trình, 26 ẩn. Vì thế mình sẽ lập 1 ma trận mở rộng 


$$
A =
\left[
  \begin{array}{ccccc|c}
    \text{key}_{0,0} & \text{key}_{0,1} & \text{key}_{0,2} & \dots & \text{key}_{0,25} & y_0 \\
    \text{key}_{1,0} & \text{key}_{1,1} & \text{key}_{1,2} & \dots & \text{key}_{1,25} & y_1 \\
    \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\
    \text{key}_{25,0} & \text{key}_{25,1} & \text{key}_{25,2} & \dots & \text{key}_{25,25} & y_{25}
  \end{array}
\right]_{\text{26x27}}
$$

Và ta sẽ rút gọn ma trận trên bằng hàm có sẵn trong Sagemath **A.echelon_form()**

Khi đó, ta thu được 1 ma trận có dạng

$$
\left[
  \begin{array}{ccccc|c}
    1 & 0 & 0 & \dots & 0 & \text{flag}_0 \\
    0 & 1 & 0 & \dots & 0 & \text{flag}_1 \\
    \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\
    0 & 0 & 0 & \dots & 1 & \text{flag}_{25}
  \end{array}
\right]_{\text{26x27}}
$$

- Và từ đó chỉ cần chuyển về dạng bytes, ta sẽ thu được flag
```python

A = matrix(QQ,[[334, 910, 918, 127, 581, 1004, 824, 1, 483, 647, 926, 29, 517, 678, 706, 397, 864, 379, 373, 205, 460, 635, 38, 835, 797, 777, 1242555], [1019, 623, 487, 472, 929, 787, 480, 633, 928, 669, 575, 711, 348, 511, 850, 303, 287, 603, 197, 518, 726, 816, 759, 957, 575, 569, 1374344], [461, 63, 26, 854, 263, 935, 193, 441, 424, 296, 924, 470, 996, 616, 588, 50, 291, 334, 345, 488, 770, 953, 756, 609, 270, 951, 1168456], [474, 906, 401, 72, 710, 76, 988, 718, 264, 876, 382, 162, 662, 578, 115, 601, 610, 327, 863, 62, 835, 194, 998, 995, 473, 810, 1210986], [838, 515, 845, 773, 718, 675, 364, 873, 297, 337, 121, 994, 226, 763, 679, 197, 990, 959, 681, 767, 78, 1004, 415, 425, 888, 932, 1385537], [291, 368, 482, 86, 622, 924, 81, 339, 614, 508, 113, 489, 451, 730, 962, 607, 529, 768, 174, 74, 1016, 576, 695, 882, 171, 38, 1017887], [86, 999, 435, 496, 104, 99, 735, 149, 336, 970, 963, 441, 344, 1022, 944, 307, 784, 415, 358, 181, 378, 472, 993, 808, 766, 956, 1286049], [834, 839, 645, 268, 210, 152, 558, 42, 896, 239, 600, 119, 1018, 883, 869, 407, 127, 832, 107, 9, 212, 631, 329, 967, 239, 620, 1082063], [887, 622, 579, 745, 742, 518, 559, 649, 722, 55, 641, 595, 746, 367, 623, 639, 391, 133, 700, 528, 468, 342, 779, 479, 792, 162, 1174997], [158, 908, 520, 474, 439, 954, 92, 401, 523, 574, 366, 336, 255, 507, 738, 514, 148, 480, 774, 935, 614, 577, 926, 437, 323, 436, 1078988], [116, 412, 916, 922, 295, 208, 61, 90, 49, 838, 22, 704, 1009, 976, 945, 496, 293, 594, 183, 424, 40, 195, 588, 433, 218, 842, 1045203], [2, 142, 743, 219, 965, 817, 195, 653, 139, 175, 585, 642, 948, 888, 225, 221, 422, 77, 763, 532, 14, 982, 160, 182, 549, 352, 1005207], [925, 570, 798, 61, 608, 124, 585, 134, 770, 230, 445, 974, 98, 893, 63, 186, 747, 348, 704, 168, 244, 88, 127, 55, 719, 912, 1001738], [569, 16, 961, 574, 1016, 80, 695, 596, 422, 293, 1013, 130, 230, 933, 213, 164, 923, 866, 196, 5, 681, 653, 721, 671, 124, 88, 1088160], [777, 1016, 725, 580, 203, 219, 117, 58, 844, 280, 981, 74, 874, 553, 872, 751, 891, 224, 418, 354, 650, 203, 52, 415, 553, 665, 1142898], [393, 409, 614, 784, 276, 516, 90, 144, 666, 367, 47, 915, 562, 864, 868, 189, 20, 985, 66, 849, 49, 267, 239, 542, 593, 586, 1019565], [236, 786, 6, 659, 713, 472, 591, 275, 435, 711, 18, 254, 766, 25, 670, 335, 130, 45, 531, 150, 564, 842, 192, 762, 284, 258, 907900], [908, 881, 434, 448, 432, 307, 272, 78, 528, 749, 34, 963, 906, 63, 438, 586, 575, 901, 991, 323, 3, 349, 298, 1008, 280, 1023, 1192766], [491, 805, 701, 105, 529, 396, 879, 827, 824, 289, 981, 145, 442, 1008, 580, 189, 880, 909, 143, 945, 160, 722, 253, 466, 11, 509, 1194956], [416, 568, 726, 627, 119, 121, 712, 920, 600, 65, 881, 527, 141, 906, 781, 169, 135, 389, 945, 13, 803, 382, 278, 274, 312, 856, 1081319], [735, 313, 125, 758, 975, 646, 877, 632, 917, 590, 321, 121, 6, 511, 757, 97, 258, 822, 542, 887, 525, 347, 419, 303, 411, 185, 1051639], [682, 123, 197, 794, 596, 345, 397, 813, 884, 526, 152, 485, 851, 571, 616, 825, 977, 699, 208, 335, 1007, 10, 810, 871, 998, 1014, 1352914], [685, 737, 90, 756, 28, 181, 965, 244, 374, 136, 87, 744, 110, 365, 406, 1020, 627, 899, 298, 72, 649, 653, 803, 601, 54, 185, 929974], [667, 422, 111, 246, 913, 815, 998, 880, 577, 243, 983, 227, 614, 649, 200, 375, 174, 16, 513, 872, 960, 944, 467, 909, 451, 823, 1293289], [2, 546, 107, 153, 821, 487, 876, 91, 884, 944, 520, 948, 793, 911, 573, 926, 618, 243, 110, 839, 501, 891, 87, 260, 633, 924, 1302831], [531, 468, 138, 1013, 293, 351, 699, 107, 215, 676, 876, 613, 904, 640, 494, 902, 269, 880, 449, 431, 866, 417, 651, 688, 751, 224, 1247099]])


A=A.echelon_form()
print(A)

ms=[]
for i in range(26):
	ms.append(A[i][-1])
print(bytes(ms))

#HCMUS-CTF{the_EASIEST_0ne}
```

=> Flag: ``HCMUS-CTF{the_EASIEST_0ne}``


## Kết luận
- Ở trên là danh sách 5 bài mảng crypto mình solve được trong giải HCMUSCTF Qualifications 2023. 
- Mọi thắc mắc của các bạn xin vui lòng liên hệ với mình qua discord: ``tranminhprvt01#7535``
- Cuối cùng, cảm ơn các bạn đã đọc. Have a good day! 🥰
