---
title: ACSC 2023 writeup
author: tranminhprvt01
pubDatetime: 2023-03-06
featured: false
draft: false
tags:
  - Crypto
  - RSA
  - CRT
description:
  Writeup to challenge(s) I solved during the CTF
---

# TL;DR
Solving RSA given a bunch of (e, k), and I havent learned LaTex here Dx.


## Table of contents


## Check_number_63
> I know the "common modulus attack" on RSA. But as far as I know, the attacker can NOT factor n, right? I generated 63 keys with different public exponents. I also generated the check numbers to confirm the keys were valid. Sadly, public exponents and check numbers were leaked. Am I still safe?

Attachments:

* flag.py
```python
from Crypto.Util.number import *
from hashlib import sha512

p = getStrongPrime(1024)
q = getStrongPrime(1024)
n = p*q
e = 65537
d = inverse(e,(p-1)*(q-1))

if p > q:p,q = q,p
flag = "ACSC{" + sha512( f"{p}{q}".encode() ).hexdigest() + "}" 
open("flag","w").write(flag)
open("key","w").write(str(p) + "\n" + str(q))
```

* problem.sage
```python
from Crypto.Util.number import *
import gmpy2
from flag import *

f = open("output.txt","w")

f.write(f"n = {n}\n")

while e < 66173:
  d = inverse(e,(p-1)*(q-1))
  check_number = (e*d - 1) // ( (p-1)*(q-1) )
  f.write(f"{e}:{check_number}\n")
  assert (e*d - 1) % ( (p-1)*(q-1) ) == 0
  e = gmpy2.next_prime(e)
  
f.close()
```

* output.txt
```=0
n = 24575303335152579483219397187273958691356380033536698304119157688003502052393867359624475789987237581184979869428436419625817866822376950791646781307952833871208386360334267547053595730896752931770589720203939060500637555186552912818531990295111060561661560818752278790449531513480358200255943011170338510477311001482737373145408969276262009856332084706260368649633253942184185551079729283490321670915209284267457445004967752486031694845276754057130676437920418693027165980362069983978396995830448343187134852971000315053125678630516116662920249232640518175555970306086459229479906220214332209106520050557209988693711
65537:36212
65539:5418
65543:27200
65551:37275
65557:19020
65563:18986
65579:30121
65581:55506
65587:34241
65599:35120
65609:49479
65617:38310
65629:65504
65633:15629
65647:27879
65651:6535
65657:24690
65677:57656
65687:58616
65699:19857
65701:9326
65707:8739
65713:60630
65717:35109
65719:47240
65729:12246
65731:35776
65761:23462
65777:48929
65789:13100
65809:10941
65827:55227
65831:21264
65837:36029
65839:1057
65843:11772
65851:30488
65867:45637
65881:40155
65899:42192
65921:64114
65927:8091
65929:5184
65951:8153
65957:33274
65963:17143
65981:7585
65983:62304
65993:58644
66029:15067
66037:47377
66041:35110
66047:30712
66067:4519
66071:53528
66083:1925
66089:29064
66103:32308
66107:52310
66109:13040
66137:27981
66161:36954
66169:9902
```


Nhận xét:
- Nhìn vào file flag.py, ta có thể thấy flag sẽ có format: ``ACSC{sha512("pq".encode()).hexdigest()}``
- Vậy thì ở bài này ta cần tìm được p, q để thu được flag
- Phân tích file problem.py
```python
from Crypto.Util.number import *
import gmpy2
from flag import *

f = open("output.txt","w")

f.write(f"n = {n}\n")

while e < 66173:
  d = inverse(e,(p-1)*(q-1))
  check_number = (e*d - 1) // ( (p-1)*(q-1) )
  f.write(f"{e}:{check_number}\n")
  assert (e*d - 1) % ( (p-1)*(q-1) ) == 0
  e = gmpy2.next_prime(e)
  
f.close()
```
- Nhắc lại công thức của RSA, ta có : 
```
ed ≡ 1 (mod phi)
=> ed = 1 + k*phi
=> (ed-1)/phi = k
```
- Vậy check_number chính là các k
- Để ý 1 xíu ta sẽ thấy:
```
ed - 1 = k*phi   (1)
Vì ta có ẩn e và ẩn k đã biết 
nên ta có thể chuyển pt (1) thành pt đồng dư theo e hoặc k

Ở đây mình sẽ chọn lấy đồng dư theo e
vì các e đã đồng nguyên tố với nhau 
vì thế ta có thể xài định lý đồng dư Trung Hoa(CRT)

(1) => -1 ≡ k*phi (mod e)

Ở đây nếu các bạn chỉ lấy 63 pt e và k đã cho để tìm phi
Bạn sẽ fail vì e có độ dài 16 bit
tích các e = 63*16 = 1008 bit
còn phi=(p-1)*(q-1) = 2048 bit
Do bit phi > bit tích các e nên khi crt số ta tính được chỉ là phi%e
không phải phi ban đầu
Nên ta sẽ cần nghĩ ra 1 cách khác để biến đối sao cho bit phi < bit e
Ta thấy phi=(p-1)*(q-1) = pq-p-q+1 = n+1-r (Gọi r=p+q)
Lúc này n đã biết nên ta k cần quan tâm bit của nó
còn bit của r thì tầm lỡn hơn 1024 bit 1 xíu và nó vẫn lớn hơn bit e
Nên ta sẽ cần brute thêm 1 cặp (e, k) để ghép vô crt 
sao cho bit e lớn hơn bit r
Nếu chọn e là 1 số 16 bit 
vì 64*16 = 1024 là đủ nhưng chưa chắc nó sẽ lớn hơn bit r 
Nên mình sẽ chọn e là 1 số 17 bit để chắc chắn lơn hơn bit r

(1) => -1 ≡ k*phi (mod e)
=> -1 ≡ k(n+1-r)=> r ≡ k(n+1) *pow(k,-1,e) (mod e)
```
- Sau khi crt ra được r = p+q
- Ta chỉ cần giải hệ pt p+q = r, p*q = n
- Và từ đó sẽ tính được p, q

Full code in python:
```python
from Crypto.Util.number import *
import gmpy2
from math import gcd, prod, isqrt
from hashlib import sha512


cnt=0
public=[]
with open("output.txt",'rb') as f:
	for lines in f:
		if cnt==0: pubn=int(lines[4:-1])
		else:public.append((int(lines[:5]),int(lines[6:-1])))
		cnt+=1
print(public)
e=[]
a=[]
for i in public:
	e.append(i[0])
	k=i[1]
	a.append((k*(pubn+1)+1) *inverse(k,i[0])%i[0])
	#-1=k*(n+1) -k*r mod e
print(e)
#print(a)

print(e)
def crt(a,n):
	Ntot=prod(n)
	N=[prod(n[:t]+n[t+1:]) for t in range(len(n))]
	y=[pow(N[i],n[i]-2,n[i]) for i in range(len(n))]
	mys_a=0
	for i in range(len(n)):
		mys_a+=a[i]*N[i]*y[i]
	mys_a %= Ntot
	return mys_a

print(pubn)
e.append(getPrime(18))
a.append(0)
trys=0
while True:
	print(trys)
	a[-1]=trys
	print(e)
	print(a)
	r=crt(a,e)
	print(r)
	denta=r*r-4*pubn
	if denta > 0:
		denta=isqrt(denta)
		x1=(r+denta)//2
		x2=(r-denta)//2
		print(x1)
		print(x2)

		p1=pubn//x1
		p2=pubn//x2
		
		if p1+x1 == r or p2+x2 == r:
			print("lmao")
			print(p1+x1)
			print(p2+x2)
			p=p2
			q=x2
			break
	trys+=1
if p > q:p,q = q,p
flag = "ACSC{" + sha512( f"{p}{q}".encode() ).hexdigest() + "}" 
print(flag)
```

- Cảm ơn các bạn đã đọc. Peace! 🥰




Mọi thắc mắc xin hãy liên hệ với mình qua discord: ``tranminhprvt01#7535``