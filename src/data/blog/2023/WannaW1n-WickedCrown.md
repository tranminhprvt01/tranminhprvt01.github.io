---
title: WannaW1n WickedCrown 2023 writeup
author: tranminhprvt01
pubDatetime: 2023-09-17
featured: false
draft: false
tags:
  - Crypto
  - LCG
  - Coppersmith
  - Pollard p-1
  - Binary Search
  - RSA
description:
  Writeup to challenge(s) I solved during the CTF
---

Xin chào mọi người, mình là **Trần Minh** là sinh viên lớp **ATTN2022**. Vừa rồi đã diễn ra cuộc thi tuyển CLB **Wanna.W1n** và mình đã kết thúc giải ở top 6 (sau 1 ngày thi hơi choked 😥) với 2 câu crypto solve được.

![](https://hackmd.io/_uploads/rJ0qTH7JT.png)


# TL;DR
Some "quite" common crypto challenges. Both from my shifu, shoutout to `d4rkn19ht`


## Table of contents


## DHLCG
>Diffie hellman on finite field was too easy for you? I will change it to LCG then
>
>P/S: Here is my gift even though you still can't solve it :D -https://www.youtube.com/watch?v=qWNQUvIk954
>
>author d4rkn19ht


```python file=DHLCG.py
from Crypto.Util.number import long_to_bytes as ltb , getPrime, isPrime, getRandomRange
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad 
import random
from secret import FLAG, hint
from hashlib import sha256 

def f(a, b, x, mod):
    return (a*x + b) % mod 

def Xn(a, b, x, n, mod):
    X = x 
    for i in range(n):
        X = f(a, b, X, mod)
    return X 
    #you may think:"How da heo can this compute such a large number?"
    #because I have a supercomputer, idiot :P

p = 253124343713187900774555463876030540737349270963561331390907876266826416285173608781046103998025571922987541328220629719904523466259089107010586433496746979699703152921471010925715339786724191668080154086619451623075539654108918173538947700048917690068763753304706837347078871045230506141231379595014672208368105497383
#print(p)
a = getRandomRange(1, p)
b = getRandomRange(1, p)

print(f"p : {p}")
print(f"a : {a}")
print(f"b : {b}")

random.seed(random.randint(1, 0x1337)) #to spice things up, I will random the x0, so you have to find it yourself

x = random.randint(1, p - 1)


AliceKey = getRandomRange(1, p)
BobKey = getRandomRange(1, p)
AlicePubkey = Xn(a, b,x, AliceKey, p)
BobPubkey = Xn(a, b, x, BobKey, p)

print(f"Alice Public Key : {AlicePubkey}")
print(f"Bob Public Key : {BobPubkey}")

assert(Xn(a, b, AlicePubkey, BobKey, p) == Xn(a, b, BobPubkey, AliceKey, p))

sharekey = Xn(a, b, AlicePubkey, BobKey, p)
#LCG is hard, so I will probaly give you some hint about flag
print(f"hint : {hint}")

#it's time for final part: encrypting
iv = get_random_bytes(16)
key = sha256(str(sharekey).encode()).digest()[:16]
cipher = AES.new(key, AES.MODE_CBC, iv) 
encrypted = cipher.encrypt(pad(FLAG, 16))
print(f"iv : {iv.hex()}")
print(f"enc : {encrypted.hex()}")
print(f"complete!")
#another thing, you will probaly gonna receive a gift from me when you "decrypt the FLAG"
```


```txt file=out.txt
p : 253124343713187900774555463876030540737349270963561331390907876266826416285173608781046103998025571922987541328220629719904523466259089107010586433496746979699703152921471010925715339786724191668080154086619451623075539654108918173538947700048917690068763753304706837347078871045230506141231379595014672208368105497383
a : 236980503663131916745383319367628912529719661721974885682452997888851388115592431643616595886551596456880343910407279239525313460409807672928638025004150328675607355678823548974715744447967351357073652016109888603689966540425586260204629631252461654520080681232418379585694433628242967067483620058262935046157068200840
b : 229846911309744969375833535945955054778909265778779820734660700510889584916845040310314881529676984252884590464101858093600297004896945862624825385465776467489059245213881166145288509791113634746363781489600709970005103442554390814078987754476542071226133328737685853281826183073930051968522687627724104762415136378285
Alice Public Key : 13035987322048310166857021868949995471117799262130633171010623103933986247984123484036238302128208556136112482147989102531984085451905404721959217184444611071906285152581751915829299698168746640673958224289631677012988017746406865509305807928965475916312071440779131570632275186707665507510534324837131999826554929322
Bob Public Key : 184755395016347238616689459531551377481032936286107931359668197731574906307472711191190322098928615457225804695255925500593675247896328181996406536086387553579659753976339744292155936320495186544230247157581869969082077115504165150597454726083437674912737321066107102667017555180873644283375605169989962570314656434687
hint : ZmxhZyBoaW50IC0+IDogaHR0cHM6Ly93d3cueW91dHViZS5jb20vd2F0Y2g/dj1kUXc0dzlXZ1hjUQ==
iv : 6fbdbe144bb0556860b02179457fa917
enc : 62d777585f5dbe9d727daf8682b2dd0cb5a2455340cdd64c34ce5a90bc754e77bc79fa78c52565f3a6c25c26b1c46bca9927017ae10be30886d0ea4318eed07b
complete!
```

Nhận xét:
Đây là 1 scheme trao đổi khóa Diffie-Hellman dựa trên LCG. Bạn có thể kiếm thấy bài tương tự đã từng xuất hiện [ở đây](https://jsur.in/posts/2022-08-08-corctf-2022-crypto-writeups#exchanged).
Ý tưởng cơ bản chính là ta có:
+ Gọi **AlicePubKey** là **A**, **AliceKey** là **n1**;  **BobPubKey** là **B**, **BobKey** là **n2**
+ Gọi hàm LCG có dạng $f(x) ≡ a*x + b \ (mod \ p)$ và nếu LCG được gọi **k** lần ta kí hiệu là $f^{k}(x)$
+ Ta có thể thấy rằng mỗi khi gọi lại đệ quy hàm `x = f(x)`. Đây là thứ chúng ta thu được:
$$
\begin{aligned}
f(x) &\equiv a \cdot x + b \pmod{p} \\[1em]
f^{2}(x) &\equiv a \cdot (a \cdot x + b) + b \equiv a^{2} \cdot x + a \cdot b + b \pmod{p} \\[1em]
f^{3}(x) &\equiv a \cdot (a^{2} \cdot x + a \cdot b + b) + b \equiv a^{3} \cdot x + a^{2} \cdot b + a \cdot b + b \pmod{p} \\[1em]
&\vdots \\[1em]
f^{k}(x) &\equiv a^{k} \cdot x + \sum_{i=1}^{k} a^{k-i} \cdot b \equiv a^{k} \cdot x + b \cdot \frac{a^{k} - 1}{a-1} \pmod{p}
\end{aligned}
$$
>   Don't ask me if you dont know this, ask CSN instead 👀
+ Áp dụng các tính chất trên, ta có các công thức sau:
$$
\begin{aligned}
A &\equiv a^{n1} \cdot x + b \cdot \frac{a^{n1} - 1}{a-1} \pmod{p} \\[1.5em]
B &\equiv a^{n2} \cdot x + b \cdot \frac{a^{n2} - 1}{a-1} \pmod{p}
\end{aligned}
$$
với x là 1 số random nào đó theo seed và quan trọng nhất là
$$
\text{share} \equiv a^{n2} \cdot A + b \cdot \frac{a^{n2} - 1}{a-1} \equiv a^{n1} \cdot B + b \cdot \frac{a^{n1} - 1}{a-1} \pmod{p}
$$
+ Ở đây ta để ý rằng **share** và **B** đều có chung đuôi $b*\frac{a^{n2} - 1}{a-1}$, nên ta lấy 
$$
\text{share} - B \equiv a^{n2}(A-x) \pmod{p} \tag{1}
$$
Lại có:
$$
\begin{aligned}
B &\equiv a^{n2} \cdot x + b \cdot \frac{a^{n2} - 1}{a-1} \pmod{p} \\[1.5em]
\implies B &\equiv a^{n2} \cdot x + \frac{b \cdot a^{n2}}{a-1} - \frac{b}{a-1} \pmod{p} \\[1.5em]
\implies a^{n2} &\equiv \frac{B+\frac{b}{a-1}}{x + \frac{b}{a-1}} \pmod{p} \tag{2}
\end{aligned}
$$

+ Thế (2) vào (1) ta thu được:
$$
\begin{aligned}
\text{share} - B &\equiv \frac{B+\frac{b}{a-1}}{x + \frac{b}{a-1}} \cdot (A-x) \pmod{p}\\[1.5em]
\implies \text{share} &\equiv \frac{B+\frac{b}{a-1}}{x + \frac{b}{a-1}} \cdot (A-x) + B \pmod{p}
\end{aligned}
$$
Mặc dù trông hơi cồng kềnh nhưng ta đã có thể tính được **share** chỉ dựa vào các tham số **a**, **b**, **A**, **B**, **x**.
Và ta biết được rằng **x** là số được random theo seed. Nên ta sẽ brute seed và thử từng seed một để tính share và decrypt ciphertext.




Script:
```python
import random
from Crypto.Util.number import *
from Crypto.Cipher import AES 
from Crypto.Util.Padding import pad, unpad 
import random
from hashlib import sha256 
from tqdm import tqdm           #pip install tqdm

p = 253124343713187900774555463876030540737349270963561331390907876266826416285173608781046103998025571922987541328220629719904523466259089107010586433496746979699703152921471010925715339786724191668080154086619451623075539654108918173538947700048917690068763753304706837347078871045230506141231379595014672208368105497383
a = 236980503663131916745383319367628912529719661721974885682452997888851388115592431643616595886551596456880343910407279239525313460409807672928638025004150328675607355678823548974715744447967351357073652016109888603689966540425586260204629631252461654520080681232418379585694433628242967067483620058262935046157068200840
b = 229846911309744969375833535945955054778909265778779820734660700510889584916845040310314881529676984252884590464101858093600297004896945862624825385465776467489059245213881166145288509791113634746363781489600709970005103442554390814078987754476542071226133328737685853281826183073930051968522687627724104762415136378285
A = 13035987322048310166857021868949995471117799262130633171010623103933986247984123484036238302128208556136112482147989102531984085451905404721959217184444611071906285152581751915829299698168746640673958224289631677012988017746406865509305807928965475916312071440779131570632275186707665507510534324837131999826554929322
B = 184755395016347238616689459531551377481032936286107931359668197731574906307472711191190322098928615457225804695255925500593675247896328181996406536086387553579659753976339744292155936320495186544230247157581869969082077115504165150597454726083437674912737321066107102667017555180873644283375605169989962570314656434687

iv = bytes.fromhex("6fbdbe144bb0556860b02179457fa917")
enc = bytes.fromhex("62d777585f5dbe9d727daf8682b2dd0cb5a2455340cdd64c34ce5a90bc754e77bc79fa78c52565f3a6c25c26b1c46bca9927017ae10be30886d0ea4318eed07b")




for seed in tqdm(range(1, 0x1337+1)):
    random.seed(seed)
    x = random.randint(1, p-1)
    share = (B + b*inverse(a-1, p)) * inverse(x + b*inverse(a-1, p), p) * (A - x) + B
    share%=p
    key = sha256(str(share).encode()).digest()[:16]
    res = AES.new(key, AES.MODE_CBC, iv).decrypt(enc)
    if b"W1{" in res:
        print(f"Found on seed {seed}")
        print(res)
```


![](https://hackmd.io/_uploads/Hkvsh8mJT.png)

-> Flag: `W1{m4yb3_LCG_w45_n0t_th4t_hard_4s_1t_s41d_t0_b3}`

Bonus: thực tế thì vẫn còn hint chưa xài nên bạn nào muốn có thể thử nhé 😁.



## Warm Up
>A warm up challenge, like every other CTFs ...
>
>author d4rkn19ht


```python file=chall.py
from Crypto.Util.number import getPrime, isPrime 
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
from random import randint 
from secret import FLAG


def genprimes1():
    while True:
        p = getPrime(512)
        q = p + int(str(p), 12) + 1
        if isPrime(q):
            return p, q
        
def genprimes2():
    ok =  btl(b'd4rkn19ht_w4s_h3r3')
    while True:
        p = getPrime(512)
        q = ok *p +  randint(pow(2,255), pow(2, 256) - 1)
        if isPrime(q):
            return p, q 

def gensmoothprime(bitlen, smoothness ):
    p = 2
    while (bitlen - p.bit_length()) > 2*smoothness:
        p = p * getPrime(smoothness)
    while True:
        bit = bitlen - p.bit_length()
        q = p * getPrime(bit//2) * getPrime(bit//2)
        if isPrime(q+1):
            return q + 1

def genprimes3():
    p = gensmoothprime(1024, 18)
    q = getPrime(1024)
    return p, q 
p1, q1 = genprimes1()

p2, q2 = genprimes2()

p3, q3 = genprimes3()


n1 = p1 * q1 
n2 = p2 * q2 
n3 = p3 * q3

e1 = e2 = e3 = 65537
L = len(FLAG)
part1 = btl(FLAG[ : L // 3])
part2 = btl(FLAG[L // 3 : (2*L)//3])
part3 = btl(FLAG[(2 * L) // 3 : ])

c1 = pow(part1, e1, n1)
c2 = pow(part2, e2, n2)
c3 = pow(part3, e3, n3)

print(f"{n1 = }")
print(f"{e1 = }")
print(f"{c1 = }")

print(f"{n2 = }")
print(f'{e2 = }')
print(f"{c2 = }")

print(f"{n3 = }")
print(f"{e3 = }")
print(f"{c3 = }")
```


```txt file=output.txt
n1 = 211455521422020258783290017786833203694890601609542266572436689343387975873851663714826878488933573192758684466992443467575547666866148922830759132550414787179476403839100558419435557761636689850531979449862710134176010990573930089590543054663710498337567392413667902039363909716461423780921274784964048201261615244456563
e1 = 65537
c1 = 155418209978735408945517158166215780665415976629503903289584371825469697474469343720429315161504813773884932054871475346668022365253354309172510206853178681311268276851307960534785621244053849034169181072159335358550066055001840012695163671358539407821466685911438264884558726042393234252026079141088412007925402309181305
n2 = 1556419694977074420750239158897899631469826483957603939360368802327653630130981740036704150568796140290764000336428428488285423441865456015063486859824968187861539255264172310760537054139580128911600222858752984388304888111133106642922872407380377205772921378334031465881260979584977844288646384759864854775319523643613669692525031061599635491191498349

e2 = 65537
c2 = 814853698863591711616294956238631732573315851128484059387714793653181142383960479109157116069042282680832432053035109228714088507195567442154173032565469226942472090529328452132107943811408737294966578597692504678621473678055677609726740706850101983317960048448310998482312534333138456629762423325180613370693789240335308211213919600203990152520269025
n3 = 3993193907009943655630571031029488807651266438317568663483791746675374480884841475846941780549436733527157152622547743749865993415756807272582234085567951844648680787553253234423625845487826860988553995685527888492246204541421972864421335071765915451441830451498783420498130746986190652474314925189790891632266843591316211442273150964679169025504263980998481563244440787983555826067831717381311713782245979706619729054780078140296347468352791645492038792748920064037539868854753851135845319699845278305219332816250661827780267748573080430881938636610669022125346981839219169743131435780102335356123362116245634666019
e3 = 65537
c3 = 3038260918139845903074652597748841639455687273919226184257585711899516866664647973911092701304989844742443789090639605869993114311780464276426644555372038897779711647654834593931443264191893734612861453608801393950275435588799921767292542465787248532376276920658237311699672046201586224320506731637656286323866642053860452092904286129575302841341060886728622409806032791873719801623552252933762835350644368024272122563384527013406586202093124271242114121604135749274213770981572917875049020014649835636798619380796309394877135974984198332443434780773175200892355325975094655738946378919412649188846687302492873166182
```

Nhận xét
- Đây là bài đầu tiên mình làm khi vào giải và sau khi thông báo author bài này bug đến 2 lần thì cuối cùng cũng có bản hoàn chỉnh 😅
- Nhìn vào bài toán trên ta ta có thể thấy flag được chia làm 3 phần và mỗi phần ứng với 1 bài toán RSA nhỏ khác nhau. Mình sẽ gọi là a, b, c

- Xét bài toán a, nhìn vào quá trình gen prime, ta thấy rằng
```python
def genprimes1():
    while True:
        p = getPrime(512)
        q = p + int(str(p), 12) + 1
        if isPrime(q):
            return p, q
```
- Dựa vào [kinh nghiệm](https://scrapbox.io/crypto-writeup-public/HITCON_CTF_2022_%7C_superprime) của mình thì ta có thể thấy rằng q là hàm tuyến tính tức là khi **p** tăng dần, **q** cũng tăng dần dẫn đến **n** cũng tăng dần.
- Vì thế cách làm là ta sẽ binary search kết quả trên đoạn từ 0 đến n. Vì n chỉ tầm 1k bits hơn nên binasearch kết quả sẽ khá nhanh.

script:
```python
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
from Crypto.Util.number import *
import gmpy2
import math

l = 0
r = n1
p1 = 0
while l < r:
    mid = (l+r)//2
    #print(mid, l, r)
    tmp = mid*(mid + int(str(mid), 12) + 1)
    if tmp == n1:
        print("FOUnd")
        p1 = mid
        print(p1)
        break
    elif tmp > n1:
        r = mid-1
    elif tmp < n1:
        l = mid+1

q1 = n1//p1
assert p1*q1 == n1 and isPrime(p1) and isPrime(q1) and q1 == p1 + int(str(p1), 12) + 1
phi1 = math.lcm(p1-1, q1-1)
d1 = inverse(e1, phi1)
m1 = pow(c1, d1, n1)
assert pow(m1, e1, n1) == c1
m1 = ltb(m1)
print(m1)

#m1 = W1{Th3_s3cr3t_
```

- Xét bài toán b, nhìn vào quá trình gen prime, ta thấy rằng
```python
def genprimes2():
    ok =  btl(b'd4rkn19ht_w4s_h3r3')
    while True:
        p = getPrime(512)
        q = ok *p +  randint(pow(2,255), pow(2, 256) - 1)
        if isPrime(q):
            return p, q 
```

- Ở bài này ta thấy rằng $q = k*p + r$ với k là 1 số đã biết và r là 1 số random nhỏ.
- Và bằng 1 cách thần kì nào đó, thứ đập vào đầu mình đầu tiên là phương pháp xấp xỉ 😅.
- Ta có $n = p*q = p*(k*p+r) = k*p^2 + r$
- Vì r là số random nhỏ vậy nên có thể nói rằng $n \approx k*p^2$ => $p \approx \sqrt{\frac{n}{k}}$
- Đương nhiên p sẽ có sai số so với $\sqrt{\frac{n}{k}}$, nhưng sai số này là khá nhỏ, mà nhắc đến **nhỏ** ta lại nhớ đến [Coppersmith](https://en.wikipedia.org/wiki/Coppersmith_method)
- Bài này mình sẽ xài phương pháp tương tự với [bài này](http://tranminhprvt01.github.io/posts/2023/hcmus-quals#sneak-peek)

Script (sagemath)
```python
from Crypto.Util.number import *
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
import math
from random import randint 

n = 1556419694977074420750239158897899631469826483957603939360368802327653630130981740036704150568796140290764000336428428488285423441865456015063486859824968187861539255264172310760537054139580128911600222858752984388304888111133106642922872407380377205772921378334031465881260979584977844288646384759864854775319523643613669692525031061599635491191498349
e = 65537
c = 814853698863591711616294956238631732573315851128484059387714793653181142383960479109157116069042282680832432053035109228714088507195567442154173032565469226942472090529328452132107943811408737294966578597692504678621473678055677609726740706850101983317960048448310998482312534333138456629762423325180613370693789240335308211213919600203990152520269025



k = btl(b'd4rkn19ht_w4s_h3r3')
tmp = math.isqrt(n//k) >> 120



P.<x> = PolynomialRing(Zmod(n))

f = 2^120 * tmp + x

r = f.small_roots(X = 2^120, beta = 0.3, epsilon = 0.2)
p = 2^120 * tmp + r[0]
p = int(p)

q = n // p
assert p*q == n

d = inverse(e, (p-1)*(q-1))

m2 = ltb(int(pow(c, int(d), n)))
print(m2)

#m2 = 0f_succ355_1s_g
```

- Xét bài toán c, nhìn vào quá trình gen prime, ta thấy rằng
```python
def gensmoothprime(bitlen, smoothness ):
    p = 2
    while (bitlen - p.bit_length()) > 2*smoothness:
        p = p * getPrime(smoothness)
    while True:
        bit = bitlen - p.bit_length()
        q = p * getPrime(bit//2) * getPrime(bit//2)
        if isPrime(q+1):
            return q + 1

def genprimes3():
    p = gensmoothprime(1024, 18)
    q = getPrime(1024)
    return p, q 
```

- Điểm yếu chính của bài này đó là p là 1 smooth number (nghĩa là p-1 có thể factor thành tích các prime nhỏ)
- Vì thế ở bài này, ta đơn giản sẽ xài thuật toán [Pollard's p − 1 algorithm](https://en.wikipedia.org/wiki/Pollard%27s_p_%E2%88%92_1_algorithm)

Script:
```python
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
from gmpy2 import mpz, powmod, next_prime, gcd

def polard(n: int, cap):
    g = mpz(3)
    cur = mpz(2)
    # pbar = tqdm(total=int(cap))
    # pbar.update(int(cur))
    while cur < cap:
        g = powmod(g, cur**10, n)
        if g == 1:
            break
        check = gcd(g - 1, n)
        if check != 1:
            return int(check)
        nx = next_prime(cur)
        # delta = nx - cur
        # pbar.update(int(delta))
        cur = nx
        # pbar.close()
    return None

p3 = polard(n3, 2**18)
q3 = n3//p3
assert p3*q3 == n3

d3 = inverse(e3, (p3-1)*(q3-1))

m3 = ltb(pow(c3, d3, n3))

print(m3)

#m3 = 3ttin9_st4rt3d}
```


Full Script:
```python
n1 = 211455521422020258783290017786833203694890601609542266572436689343387975873851663714826878488933573192758684466992443467575547666866148922830759132550414787179476403839100558419435557761636689850531979449862710134176010990573930089590543054663710498337567392413667902039363909716461423780921274784964048201261615244456563
e1 = 65537
c1 = 155418209978735408945517158166215780665415976629503903289584371825469697474469343720429315161504813773884932054871475346668022365253354309172510206853178681311268276851307960534785621244053849034169181072159335358550066055001840012695163671358539407821466685911438264884558726042393234252026079141088412007925402309181305

n2 = 1556419694977074420750239158897899631469826483957603939360368802327653630130981740036704150568796140290764000336428428488285423441865456015063486859824968187861539255264172310760537054139580128911600222858752984388304888111133106642922872407380377205772921378334031465881260979584977844288646384759864854775319523643613669692525031061599635491191498349
e2 = 65537
c2 = 814853698863591711616294956238631732573315851128484059387714793653181142383960479109157116069042282680832432053035109228714088507195567442154173032565469226942472090529328452132107943811408737294966578597692504678621473678055677609726740706850101983317960048448310998482312534333138456629762423325180613370693789240335308211213919600203990152520269025

n3 = 3993193907009943655630571031029488807651266438317568663483791746675374480884841475846941780549436733527157152622547743749865993415756807272582234085567951844648680787553253234423625845487826860988553995685527888492246204541421972864421335071765915451441830451498783420498130746986190652474314925189790891632266843591316211442273150964679169025504263980998481563244440787983555826067831717381311713782245979706619729054780078140296347468352791645492038792748920064037539868854753851135845319699845278305219332816250661827780267748573080430881938636610669022125346981839219169743131435780102335356123362116245634666019
e3 = 65537
c3 = 3038260918139845903074652597748841639455687273919226184257585711899516866664647973911092701304989844742443789090639605869993114311780464276426644555372038897779711647654834593931443264191893734612861453608801393950275435588799921767292542465787248532376276920658237311699672046201586224320506731637656286323866642053860452092904286129575302841341060886728622409806032791873719801623552252933762835350644368024272122563384527013406586202093124271242114121604135749274213770981572917875049020014649835636798619380796309394877135974984198332443434780773175200892355325975094655738946378919412649188846687302492873166182

from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl 
from Crypto.Util.number import *
import gmpy2
import math


#~~~~~~~~~~~HERE LIES PART 1~~~~~~~~~~~~~#
l = 0
r = n1
p1 = 0
while l < r:
    mid = (l+r)//2
    #print(mid, l, r)
    tmp = mid*(mid + int(str(mid), 12) + 1)
    if tmp == n1:
        print("FOUnd")
        p1 = mid
        print(p1)
        break
    elif tmp > n1:
        r = mid-1
    elif tmp < n1:
        l = mid+1

q1 = n1//p1
assert p1*q1 == n1 and isPrime(p1) and isPrime(q1) and q1 == p1 + int(str(p1), 12) + 1
phi1 = math.lcm(p1-1, q1-1)
d1 = inverse(e1, phi1)
m1 = pow(c1, d1, n1)
assert pow(m1, e1, n1) == c1
m1 = ltb(m1)
print(m1)


#~~~~~~~~~~~HERE LIES PART 2~~~~~~~~~~~~~#
m2 = ltb(251306617397372846213753891689029479)
print(m2)


#~~~~~~~~~~~HERE LIES PART 3~~~~~~~~~~~~~#
from gmpy2 import mpz, powmod, next_prime, gcd
def polard(n: int, cap):
    g = mpz(3)
    cur = mpz(2)
    # pbar = tqdm(total=int(cap))
    # pbar.update(int(cur))
    while cur < cap:
        g = powmod(g, cur**10, n)
        if g == 1:
            break
        check = gcd(g - 1, n)
        if check != 1:
            return int(check)
        nx = next_prime(cur)
        # delta = nx - cur
        # pbar.update(int(delta))
        cur = nx
        # pbar.close()
    return None

p3 = polard(n3, 2**18)
q3 = n3//p3
assert p3*q3 == n3

d3 = inverse(e3, (p3-1)*(q3-1))

m3 = ltb(pow(c3, d3, n3))

print(m3)


print(m1+m2+m3)
```


![](https://hackmd.io/_uploads/S1oyNwQ1T.png)


-> Flag : `W1{Th3_s3cr3t_0f_succ355_1s_g3ttin9_st4rt3d`



## Kết luận
- Ở trên là danh sách các bài mảng crypto mình làm được trong kì thi tuyển CLB WannaW1n vừa rồi.
- Mặc dù ngày hôm nay mình thi hơi choked :))), tuy nhiên đề các anh ra cũng rất vui và bổ ích.
- Những bài còn lại thì mình sẽ ráng solve vào "một ngày nào đó?" 😶
- Mọi thắc mắc của các bạn xin vui lòng liên hệ với mình qua discord: ``tranminhprvt01#7535``
- Cuối cùng, cảm ơn các bạn đã đọc. Have a good day! 🥰
