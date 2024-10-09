---
title: "WannaGame Freshman 2022 writeup"
layout: post
tag:
- crypto
- ctf
- beginner
star: true
category: blog
author: tranminhprvt01
description: Writeup for challenges I solved in WannaGame Freshman 2022
---

# WannaGame Freshman 2022 writeup


## writeup available for:
### Crypto:
1.  [Ước mơ của Naruto](#Ước-mơ-của-Naruto)
2.  [Xor Starter](#Xor-Starter)
3.  [Diffie-Hellman Starter](#Diffie-Hellman-Starter)
4.  [substitution](#substitution)
5.  [W1 in the middle](#W1-in-the-middle)
### RE
1. [rev01](#rev01) 
2. [rev02](#rev02)


## Ước mơ của Naruto

> Naruto vừa trải qua kì thi kỳ thi Chunin và trở thành thủ khoa UIT. Do quá chán ghét thế giới nhẫn giả anh ấy rút về ở ẩn, chuyển sang dev web kiếm cơm. Naruto dự định code một trang web bán mì Ramen nhưng ôi không chương trình có bug! Sử dụng nhẫn thuật của mình, Na dễ dàng fix bằng cách search google. Nhưng ôi không lần này anh ấy gặp phải "The Gold-Bug", các nhẫn giả có thể giúp Na fix con bug vàng này không ? Khi tìm ra được secret các bạn cần nộp đúng format: W1{secret} (các chữ cái trong secret đều viết hoa)
> 
> Author: @GiongfNef
> 
Attachments:
* naruto_scroll.png
![](https://i.imgur.com/AdMa1fe.png)
Nhận xét:
- Có vẻ như là 1 loại cipher nào đó. Cùng xài tool mạng nào :D

![](https://i.imgur.com/uayPGuH.png)

- Gold bug dường như đã được đề cập đến ở trong description vậy nên chỉ có thể là loại cipher này. Cùng giải mã bằng tool mạng thôi :D

![](https://i.imgur.com/UbAAUBA.png)

###### flag: `W1{WELCOMETOUNIVERSITYOFDEADLINE}` 😅


## Xor Starter

> Xorrrrrrrrrrrrr!!!!!!!!!! https://en.wikipedia.org/wiki/XOR_cipher

Attachments:
* Chall.py
``` python=0
from flag import flag #this is secret
import os 


def xor(s1,s2): # xor 2 string
	if len(s2)>len(s1):
		return xor(s2,s1)
	s2=s2*(1+len(s1)//len(s2))
	return bytes(x^y for x,y in zip(s1,s2))

key=os.urandom(1)
ciphertext=xor(flag,key)

print(f"ciphertext: {ciphertext}")
print(f"key: {key}")

"""
ciphertext: b'\xd1\xb7\xfd\xfe\xe9\xf4\xd9\xf5\xf2\xe7\xf4\xf2\xe3\xf4\xd9\xe7\xd8\xe4\xbb\xe5\xab\xb8\xe4\xbb\xe7\xd8\xe5\xa7\xa7\xa7\xfb'
key: b'\x86'
"""
```
Nhận xét:
- Well đây hẳn là 1 bài xor cơ bản. Dựa vào tính chất của hàm xor, ta có: cipher=xor(flag,key) => flag=xor(cipher,key)

python script:
```python=0
ciphertext=b'\xd1\xb7\xfd\xfe\xe9\xf4\xd9\xf5\xf2\xe7\xf4\xf2\xe3\xf4\xd9\xe7\xd8\xe4\xbb\xe5\xab\xb8\xe4\xbb\xe7\xd8\xe5\xa7\xa7\xa7\xfb'
key=b'\x86'
def xor(s1,s2): # xor 2 string
	if len(s2)>len(s1):
		return xor(s2,s1)
	s2=s2*(1+len(s1)//len(s2))
	return bytes(x^y for x,y in zip(s1,s2))
flag=xor(ciphertext,key)
print(f"flag: {flag}")
```

```
flag: b'W1{xor_starter_a^b=c->b=a^c!!!}'
```


## Diffie-Hellman Starter
> Do you know diffie-hellman key exchange and find the share a secret See this: https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange Note: Wrap the share secret wih W1{}

Attachments:
* CHAL.py
```python=0
from Crypto.Util.number import getPrime
from random import randint

p=getPrime(256) #public parameter
g=randint(1,p) #public parameter

a=randint(1,p)#Alice secret key
b=randint(1,p)#Bob secret key


A=pow(g,a,p)#Alice public key
B=pow(g,b,p)#Bob public key


print(f"p = {p}")
print(f"g = {g}")

print(f"a = {a}")
print(f"b = {b}")

print(f"A = {A}")
print(f"B = {B}")

"""
p = 105289530576910586993080686413065233666909808406167258320240665999037512412167
g = 24838294643411202270303295608356773369339119328370385652821250303621388842929
a = 31021392049888292856704119145874300423538107186086931448155721488074527967901
b = 39412701781635497500413670988426568302931123084939036709295930496132785235003
A = 59738048815521064986833410993326825917641950113703945492494937836746747952020
B = 57640893954620640011123005499912176173169275880144658833184771392490079334626
"""
```
Nhận xét:
- Sau khi nghiên cứu về Diffie-Hellman key exchange trong wiki. Ta sẽ có kết luận share secret cần tìm chính là: pow(A,b,p) hoặc là pow(B,a,p). Hai thằng này sẽ bằng nhau nên chọn cái nào cũng được 😅
``` python=0
p = 105289530576910586993080686413065233666909808406167258320240665999037512412167
g = 24838294643411202270303295608356773369339119328370385652821250303621388842929
a = 31021392049888292856704119145874300423538107186086931448155721488074527967901
b = 39412701781635497500413670988426568302931123084939036709295930496132785235003
A = 59738048815521064986833410993326825917641950113703945492494937836746747952020
B = 57640893954620640011123005499912176173169275880144658833184771392490079334626

s=pow(B,a,p)
s1=pow(A,b,p)
print(s)
print(s1)

```

```
52028760248329888261692191826340542224456084720285189553961610936341838926487
52028760248329888261692191826340542224456084720285189553961610936341838926487
```

###### flag: `W1{52028760248329888261692191826340542224456084720285189553961610936341838926487}`


## substitution
> Can you decrypt this classic cipher? Remember to wrap the flag with format W1{}

Attachments:
* Chal.py
```python=0
from random import shuffle
import string
original = string.ascii_letters[:26]
encrypted = list(original)
shuffle(encrypted)
encrypted = ''.join(encrypted)
dec = open('plaintext.txt','r').read()
open('encrypted.txt','w').write(dec.translate(dec.maketrans(original, encrypted)))
```

* encrypted.txt
```
h jskke zkx y vhgnsu kx sok sk dkccuds vijucz, zkx h oyj eyrue ohsa sau akxxkx kz sau sahgt. saug h mutyg sk sahgw kz akcvujj kog vusakej yge sk sxi sk bxydshju sauv hg xuyehgt sahj sxytuei. hs oyj, ycyj, kgci skk uyji sk ek. enxhgt knx dkgfuxjyshkg ou aye gks tkgu sk sau uge kz sau bysa, yge sau ycbhgu-jskdw vyxwue sau bcydu oauxu ou aye jskke. sau mcydwhja jkhc hj wubs zkxufux jkzs mi sau hgdujjygs exhzs kz jbxyi, yge y mhxe oknce cuyfu hsj sxuye nbkg hs. sok chguj kz zkksvyxwj ouxu dcuyxci vyxwue yckgt sau zyxsaux uge kz sau bysa, mksa cuyehgt yoyi zxkv vu. sauxu ouxu gkgu xusnxghgt. y zuo iyxej zxkv sau uge sau jkhc oyj ycc bckntaue nb hgsk y bysda kz vne, yge sau mxygdauj yge zuxgj oahda zxhgtue sau dayjv ouxu skxg yge muexyttcue. h cyi nbkg vi zydu yge buuxue kfux ohsa sau jbxyi jbknshgt nb ycc yxknge vu. hs aye eyxwugue jhgdu h cuzs, yge gko h dknce kgci juu auxu yge sauxu sau tchjsughgt kz vkhjsnxu nbkg sau mcydw oyccj, yge zyx yoyi ekog ys sau uge kz sau jayzs sau tcuyv kz sau mxkwug oysux. h jaknsue; mns kgci sau jyvu aycz-anvyg dxi kz sau zycc oyj mkxgu mydw sk vi uyxj.

mns hs oyj eujshgue says h jaknce yzsux ycc ayfu y cyjs okxe kz txuushgt zxkv vi zxhuge yge dkvxyeu. h ayfu jyhe says ahj ycbhgu-jskdw aye muug cuzs cuyghgt ytyhgjs y xkdw oahda pnssue kg sk sau bysa. zxkv sau skb kz sahj mknceux sau tcuyv kz jkvusahgt mxhtas dyntas vi uiu, yge, xyhjhgt vi ayge, h zknge says hs dyvu zxkv sau jhcfux dhtyxussu-dyju oahda au njue sk dyxxi. yj h skkw hs nb y jvycc jlnyxu kz bybux nbkg oahda hs aye cyhg zcnssuxue ekog kg sk sau txknge. ngzkcehgt hs, h zknge says hs dkgjhjsue kz saxuu bytuj skxg zxkv ahj gksu-mkkw yge yeexujjue sk vu. hs oyj dayxydsuxhjshd kz sau vyg says sau ehxudshkg oyj y bxudhju, yge sau oxhshgt yj zhxv yge dcuyx, yj saknta hs aye muug oxhssug hg ahj jsnei.

vi euyx oysjkg, au jyhe, h oxhsu sauju zuo chguj saxknta sau dknxsuji kz vx. vkxhyxsi, oak yoyhsj vi dkgfughugdu zkx sau zhgyc ehjdnjjhkg kz sakju lnujshkgj oahda chu musouug nj. au ayj muug thfhgt vu y jwusda kz sau vusakej mi oahda au yfkheue sau ugtchja bkchdu yge wubs ahvjucz hgzkxvue kz knx vkfuvugsj. saui duxsyhgci dkgzhxv sau fuxi ahta kbhghkg oahda h aye zkxvue kz ahj ymhchshuj. h yv bcuyjue sk sahgw says h jaycc mu ymcu sk zxuu jkdhusi zxkv ygi znxsaux uzzudsj kz ahj bxujugdu, saknta h zuyx says hs hj ys y dkjs oahda ohcc thfu byhg sk vi zxhugej, yge ujbudhycci, vi euyx oysjkg, sk ikn. h ayfu ycxuyei uqbcyhgue sk ikn, akoufux, says vi dyxuux aye hg ygi dyju xuydaue hsj dxhjhj, yge says gk bkjjhmcu dkgdcnjhkg sk hs dknce mu vkxu dkgtughyc sk vu sayg sahj. hgeuue, hz h vyi vywu y zncc dkgzujjhkg sk ikn, h oyj lnhsu dkgfhgdue says sau cussux zxkv vuhxhgtug oyj y akyq, yge h ycckoue ikn sk eubyxs kg says uxxyge ngeux sau buxjnyjhkg says jkvu eufuckbvugs kz sahj jkxs oknce zkccko. succ hgjbudskx byssuxjkg says sau bybuxj oahda au guuej sk dkgfhds sau tygt yxu hg bhtukgakcu v., ekgu nb hg y mcnu ugfuckbu yge hgjdxhmue vkxhyxsi. h vyeu ufuxi ehjbkjhshkg kz vi bxkbuxsi muzkxu cuyfhgt ugtcyge, yge aygeue hs sk vi mxksaux vidxkzs. bxyi thfu vi txuushgtj sk vxj. oysjkg, yge muchufu vu sk mu, vi euyx zuccko,

fuxi jhgduxuci iknxj,
jauxckdw akcvuj.

y zuo okxej vyi jnzzhdu sk succ sau chsscu says xuvyhgj. yg uqyvhgyshkg mi uqbuxsj cuyfuj chsscu eknms says y buxjkgyc dkgsujs musouug sau sok vug ugeue, yj hs dknce ayxeci zyhc sk uge hg jnda y jhsnyshkg, hg sauhx xuuchgt kfux, ckdwue hg uyda ksauxj yxvj. ygi yssuvbs ys xudkfuxhgt sau mkehuj oyj ymjkcnsuci akbucujj, yge sauxu, euub ekog hg says exuyeznc dycexkg kz johxchgt oysux yge juusahgt zkyv, ohcc chu zkx ycc shvu sau vkjs eygtuxknj dxhvhgyc yge sau zkxuvkjs dayvbhkg kz sau cyo kz sauhx tuguxyshkg. sau johjj iknsa oyj gufux zknge ytyhg, yge sauxu dyg mu gk eknms says au oyj kgu kz sau gnvuxknj ytugsj oakv vkxhyxsi wubs hg ahj uvbcki. yj sk sau tygt, hs ohcc mu ohsahg sau vuvkxi kz sau bnmchd ako dkvbcusuci sau ufheugdu oahda akcvuj aye yddnvncysue uqbkjue sauhx kxtyghryshkg, yge ako auyfhci sau ayge kz sau euye vyg ouhtaue nbkg sauv. kz sauhx suxxhmcu dahuz zuo eusyhcj dyvu kns enxhgt sau bxkduuehgtj, yge hz h ayfu gko muug dkvbuccue sk vywu y dcuyx jsysuvugs kz ahj dyxuux hs hj enu sk sakju hgpnehdhknj dayvbhkgj oak ayfu ugeuyfknxue sk dcuyx ahj vuvkxi mi yssydwj nbkg ahv oakv h jaycc ufux xutyxe yj sau mujs yge sau ohjujs vyg oakv h ayfu ufux wgkog. zcyt : oucdkvuskdxibsktxybaih jskke zkx y vhgnsu kx sok sk dkccuds vijucz, zkx h oyj eyrue ohsa sau akxxkx kz sau sahgt. saug h mutyg sk sahgw kz akcvujj kog vusakej yge sk sxi sk bxydshju sauv hg xuyehgt sahj sxytuei. hs oyj, ycyj, kgci skk uyji sk ek. enxhgt knx dkgfuxjyshkg ou aye gks tkgu sk sau uge kz sau bysa, yge sau ycbhgu-jskdw vyxwue sau bcydu oauxu ou aye jskke. sau mcydwhja jkhc hj wubs zkxufux jkzs mi sau hgdujjygs exhzs kz jbxyi, yge y mhxe oknce cuyfu hsj sxuye nbkg hs. sok chguj kz zkksvyxwj ouxu dcuyxci vyxwue yckgt sau zyxsaux uge kz sau bysa, mksa cuyehgt yoyi zxkv vu. sauxu ouxu gkgu xusnxghgt. y zuo iyxej zxkv sau uge sau jkhc oyj ycc bckntaue nb hgsk y bysda kz vne, yge sau mxygdauj yge zuxgj oahda zxhgtue sau dayjv ouxu skxg yge muexyttcue. h cyi nbkg vi zydu yge buuxue kfux ohsa sau jbxyi jbknshgt nb ycc yxknge vu. hs aye eyxwugue jhgdu h cuzs, yge gko h dknce kgci juu auxu yge sauxu sau tchjsughgt kz vkhjsnxu nbkg sau mcydw oyccj, yge zyx yoyi ekog ys sau uge kz sau jayzs sau tcuyv kz sau mxkwug oysux. h jaknsue; mns kgci sau jyvu aycz-anvyg dxi kz sau zycc oyj mkxgu mydw sk vi uyxj.

mns hs oyj eujshgue says h jaknce yzsux ycc ayfu y cyjs okxe kz txuushgt zxkv vi zxhuge yge dkvxyeu. h ayfu jyhe says ahj ycbhgu-jskdw aye muug cuzs cuyghgt ytyhgjs y xkdw oahda pnssue kg sk sau bysa. zxkv sau skb kz sahj mknceux sau tcuyv kz jkvusahgt mxhtas dyntas vi uiu, yge, xyhjhgt vi ayge, h zknge says hs dyvu zxkv sau jhcfux dhtyxussu-dyju oahda au njue sk dyxxi. yj h skkw hs nb y jvycc jlnyxu kz bybux nbkg oahda hs aye cyhg zcnssuxue ekog kg sk sau txknge. ngzkcehgt hs, h zknge says hs dkgjhjsue kz saxuu bytuj skxg zxkv ahj gksu-mkkw yge yeexujjue sk vu. hs oyj dayxydsuxhjshd kz sau vyg says sau ehxudshkg oyj y bxudhju, yge sau oxhshgt yj zhxv yge dcuyx, yj saknta hs aye muug oxhssug hg ahj jsnei.

vi euyx oysjkg, au jyhe, h oxhsu sauju zuo chguj saxknta sau dknxsuji kz vx. vkxhyxsi, oak yoyhsj vi dkgfughugdu zkx sau zhgyc ehjdnjjhkg kz sakju lnujshkgj oahda chu musouug nj. au ayj muug thfhgt vu y jwusda kz sau vusakej mi oahda au yfkheue sau ugtchja bkchdu yge wubs ahvjucz hgzkxvue kz knx vkfuvugsj. saui duxsyhgci dkgzhxv sau fuxi ahta kbhghkg oahda h aye zkxvue kz ahj ymhchshuj. h yv bcuyjue sk sahgw says h jaycc mu ymcu sk zxuu jkdhusi zxkv ygi znxsaux uzzudsj kz ahj bxujugdu, saknta h zuyx says hs hj ys y dkjs oahda ohcc thfu byhg sk vi zxhugej, yge ujbudhycci, vi euyx oysjkg, sk ikn. h ayfu ycxuyei uqbcyhgue sk ikn, akoufux, says vi dyxuux aye hg ygi dyju xuydaue hsj dxhjhj, yge says gk bkjjhmcu dkgdcnjhkg sk hs dknce mu vkxu dkgtughyc sk vu sayg sahj. hgeuue, hz h vyi vywu y zncc dkgzujjhkg sk ikn, h oyj lnhsu dkgfhgdue says sau cussux zxkv vuhxhgtug oyj y akyq, yge h ycckoue ikn sk eubyxs kg says uxxyge ngeux sau buxjnyjhkg says jkvu eufuckbvugs kz sahj jkxs oknce zkccko. succ hgjbudskx byssuxjkg says sau bybuxj oahda au guuej sk dkgfhds sau tygt yxu hg bhtukgakcu v., ekgu nb hg y mcnu ugfuckbu yge hgjdxhmue vkxhyxsi. h vyeu ufuxi ehjbkjhshkg kz vi bxkbuxsi muzkxu cuyfhgt ugtcyge, yge aygeue hs sk vi mxksaux vidxkzs. bxyi thfu vi txuushgtj sk vxj. oysjkg, yge muchufu vu sk mu, vi euyx zuccko,

fuxi jhgduxuci iknxj,
jauxckdw akcvuj.

y zuo okxej vyi jnzzhdu sk succ sau chsscu says xuvyhgj. yg uqyvhgyshkg mi uqbuxsj cuyfuj chsscu eknms says y buxjkgyc dkgsujs musouug sau sok vug ugeue, yj hs dknce ayxeci zyhc sk uge hg jnda y jhsnyshkg, hg sauhx xuuchgt kfux, ckdwue hg uyda ksauxj yxvj. ygi yssuvbs ys xudkfuxhgt sau mkehuj oyj ymjkcnsuci akbucujj, yge sauxu, euub ekog hg says exuyeznc dycexkg kz johxchgt oysux yge juusahgt zkyv, ohcc chu zkx ycc shvu sau vkjs eygtuxknj dxhvhgyc yge sau zkxuvkjs dayvbhkg kz sau cyo kz sauhx tuguxyshkg. sau johjj iknsa oyj gufux zknge ytyhg, yge sauxu dyg mu gk eknms says au oyj kgu kz sau gnvuxknj ytugsj oakv vkxhyxsi wubs hg ahj uvbcki. yj sk sau tygt, hs ohcc mu ohsahg sau vuvkxi kz sau bnmchd ako dkvbcusuci sau ufheugdu oahda akcvuj aye yddnvncysue uqbkjue sauhx kxtyghryshkg, yge ako auyfhci sau ayge kz sau euye vyg ouhtaue nbkg sauv. kz sauhx suxxhmcu dahuz zuo eusyhcj dyvu kns enxhgt sau bxkduuehgtj, yge hz h ayfu gko muug dkvbuccue sk vywu y dcuyx jsysuvugs kz ahj dyxuux hs hj enu sk sakju hgpnehdhknj dayvbhkgj oak ayfu ugeuyfknxue sk dcuyx ahj vuvkxi mi yssydwj nbkg ahv oakv h jaycc ufux xutyxe yj sau mujs yge sau ohjujs vyg oakv h ayfu ufux wgkog. zcyt : oucdkvuskdxibsktxybai
```
 Nhận xét:
 - Bài này các bạn có thể xài tool online để làm https://planetcalc.com/8047/
- Hoặc các bạn có thể tham khảo code bẩn của mình 😶

```python=0
import string
encrypted_message="y zuo okxej vyi jnzzhdu sk succ sau chsscu says xuvyhgj. yg uqyvhgyshkg mi uqbuxsj cuyfuj chsscu eknms says y buxjkgyc dkgsujs musouug sau sok vug ugeue, yj hs dknce ayxeci zyhc sk uge hg jnda y jhsnyshkg, hg sauhx xuuchgt kfux, ckdwue hg uyda ksauxj yxvj. ygi yssuvbs ys xudkfuxhgt sau mkehuj oyj ymjkcnsuci akbucujj, yge sauxu, euub ekog hg says exuyeznc dycexkg kz johxchgt oysux yge juusahgt zkyv, ohcc chu zkx ycc shvu sau vkjs eygtuxknj dxhvhgyc yge sau zkxuvkjs dayvbhkg kz sau cyo kz sauhx tuguxyshkg. sau johjj iknsa oyj gufux zknge ytyhg, yge sauxu dyg mu gk eknms says au oyj kgu kz sau gnvuxknj ytugsj oakv vkxhyxsi wubs hg ahj uvbcki. yj sk sau tygt, hs ohcc mu ohsahg sau vuvkxi kz sau bnmchd ako dkvbcusuci sau ufheugdu oahda akcvuj aye yddnvncysue uqbkjue sauhx kxtyghryshkg, yge ako auyfhci sau ayge kz sau euye vyg ouhtaue nbkg sauv. kz sauhx suxxhmcu dahuz zuo eusyhcj dyvu kns enxhgt sau bxkduuehgtj, yge hz h ayfu gko muug dkvbuccue sk vywu y dcuyx jsysuvugs kz ahj dyxuux hs hj enu sk sakju hgpnehdhknj dayvbhkgj oak ayfu ugeuyfknxue sk dcuyx ahj vuvkxi mi yssydwj nbkg ahv oakv h jaycc ufux xutyxe yj sau mujs yge sau ohjujs vyg oakv h ayfu ufux wgkog. zcyt : oucdkvuskdxibsktxybai"
stored_letters={}
for char in encrypted_message:
	if char not in stored_letters: stored_letters[char] = 1
	else: stored_letters[char] += 1
#print(stored_letters)
stored_letters=dict(sorted(stored_letters.items(), key = lambda item: item[1]))
#print(stored_letters)
mal=[]
for i in stored_letters: 
	if i.isalpha():
		mal.append(i) # mal = most appeared letters
mal=mal[::-1]
#print(mal)

alphabet=string.ascii_uppercase
#print(alphabet)
custom_alphabet="HPLCDVNIYSOxBUWJxZTGEMKRAF"
#                ABCDEFGHIJKLMNOPQRSTUVWXYZ

ms=[]
#print(encrypted_message)

for i in encrypted_message:
	if i.isalpha():
		if i.islower():
			for m, n in enumerate(alphabet):
				if i.upper() == n:
					ms.append(custom_alphabet[m].lower())
		else:
			for m, n in enumerate(alphabet):
				if i == n:
					ms.append(custom_alphabet[m])
	else: ms.append(i)
	
	
print(''.join(ms))

```
- Code này thì mình chỉ check mỗi đoạn nghi chứa flag của file encrypted.txt đồng thời nhập tay custom_alphabet đến khi nào ra đoạn tiếng Anh có nghĩa🤔. Vì thế tiếng Anh rất quan trọng.🙄

``
a few words may suffice to tell the little that remains. an examination by experts leaves little doubt that a personal contest between the two men ended, as it could hardly fail to end in such a situation, in their reeling over, locked in each others arms. any attempt at recovering the bodies was absolutely hopeless, and there, deep down in that dreadful caldron of swirling water and seething foam, will lie for all time the most dangerous criminal and the foremost champion of the law of their generation. the swiss youth was never found again, and there can be no doubt that he was one of the numerous agents whom moriarty kept in his employ. as to the gang, it will be within the memory of the public how completely the evidence which holmes had accumulated exposed their organization, and how heavily the hand of the dead man weighed upon them. of their terrible chief few details came out during the proceedings, and if i have now been compelled to make a clear statement of his career it is due to those injudicious champions who have endeavoured to clear his memory by attacks upon him whom i shall ever regard as the best and the wisest man whom i have ever known. flag : welcometocryptography
``

###### flag:`W1{welcometocryptography}`


## W1 in the middle
> Do you know how dangerous in the middle?
> nc 45.122.249.68 10019
> 
> author: @f4tu

Attachments:
* server.py
```python=0
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from flag import FLAG
import hashlib
import os

bit = 512
p = 9361670555169673278885701122852986238110075825623048853480143702977287835591027782340194497190532246273820028870655358636697024716730745803059296862336171
g = getRandomRange(2,p)
a = getRandomRange(2,p)
b = getRandomRange(2,p)
iv = os.urandom(16)


def encrypt_flag(shared_secret: int, iv: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Encrypt flag
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    # Prepare data to send
    return ciphertext.hex()

def is_pkcs7_padded(message):
    padding = message[-message[-1]:]
    return all(padding[i] == len(padding) for i in range(0, len(padding)))

def decrypt_flag(shared_secret: int, iv: str, ciphertext: str):
    # Derive AES key from shared secret
    sha1 = hashlib.sha1()
    sha1.update(str(shared_secret).encode('ascii'))
    key = sha1.digest()[:16]
    # Decrypt flag
    ciphertext = bytes.fromhex(ciphertext)
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)

    if is_pkcs7_padded(plaintext):
        return unpad(plaintext, 16).decode('ascii')
    else:
        return plaintext.decode('ascii')


print('''
Welcome to Diffie hellman key exchange, we have two friend Alice and Bob
You need to help them seding messenge to each other.
''')
print('Received from Alice:')
print('p: ', p)
print('g: ', g)
print('A: ', pow(g,a,p))
print('Send to Bob:')
print("p: ", end = '')
fake_p = int(input())
print("g: ", end = '')
fake_g = int(input())
print("A: ", end = '')
fake_A = int(input())

assert fake_p == p
assert fake_g == g
assert fake_A != 0 and fake_A != 1
share_A = pow(fake_A,b,p)

print('Received from Bob:')
print('B: ', pow(g,b,p))
print('Send to Alice:')
print("B: ", end = '')
fake_B = int(input())

assert fake_B != 0 and fake_B != 1
share_B = pow(fake_B,a,p)
assert share_B == share_A
print()
ciphertext = encrypt_flag(share_A,iv)
print("Well done!! Here is the final part, let send us a shared key to decrypt the ciphertext:")
print("Shared key:", end = '')
key = int(input())
print("Here we go!!! Here's your flag: ", end = '')
print(decrypt_flag(key,iv.hex(),ciphertext))
```

Nhận xét:
- Đây là 1 bài mình đánh giá là rất hay ở trong mảng crypto này 😁
- Phân tích file server.py ta có thể thấy rằng khi chạy nc 45.122.249.68 10019
-- Đầu tiên, ta sẽ được cho 3 thông số p(cố định), g, A.
-- Sau đó, chúng ta được yêu cầu nhập vào fake_p, fake_g, fake_A. Tuy nhiên, vì trong server.py có các dòng này.
```python 
assert fake_p == p
assert fake_g == g
assert fake_A != 0 and fake_A != 1
```
-- Nên fake_p được gửi đi cũng phải bằng p, fake_g được gửi đi cũng phải bằng g và fake_A được gửi đi chỉ cần khác 0 và khác 1.
-- Sau đó share_A sẽ được tính bằng share_A=pow(fake_A,b,p), đồng thời ta sẽ nhận được thông số B và được yêu cầu gửi lại fake_B và tương tự fake_B cũng phải khác 0 và 1.
-- share_B sau đó cũng được tính bằng share_B=pow(fake_B,a,p).
-- Tiếp tục phân tích file server.py đến bước này thằng
ciphertext = encrypt_flag(share_A,iv) nhưng chúng ta sẽ chưa quan tâm vội.
-- Ngay sau đó, chúng ta được yêu cầu nhập shared_key để có thể có flag.
-- Ta có thể thấy rằng shared_key cần nhập này phải bằng với share_A = share_B
-- Hmmm 🤔, có vẻ như chúng ta cần biết thông tin về a, b để có thể đoán được share_A và share_B qua đó để đoán shared_key nhưng điều đó dường như là không khả thi khi server không tiết lộ thông tin cho ta về 2 thằng a, b.
-- Hold up 👀, cùng liếc lại cách share_A và share_B được tạo nào:
```python
share_A = pow(fake_A,b,p)
share_B = pow(fake_B,a,p)
```

-- chúng ta có quyền nhập fake_A, fake_B theo ý của mình miễn sao là share_A == share_B thì đó là shared_key.

-- Ở đây, mình sẽ chọn fake_A cũng như là fake_B bằng số p
thì khi đó share_A, share_B luôn = 0 🤣.




```
Welcome to Diffie hellman key exchange, we have two friend Alice and Bob
You need to help them seding messenge to each other.

Received from Alice:
p:  9361670555169673278885701122852986238110075825623048853480143702977287835591027782340194497190532246273820028870655358636697024716730745803059296862336171
g:  4390591264041583959954245817925441879795740390823574772675416625164770670483563915572323472137688252061450947504469475266665833899157514866536755609208047
A:  8152540647510911107467931404807663800959070305220553556242560287696382569357737731520951958833708015031471678960183503118819852265980554076242130694582489
Send to Bob:
p: 9361670555169673278885701122852986238110075825623048853480143702977287835591027782340194497190532246273820028870655358636697024716730745803059296862336171
g: 4390591264041583959954245817925441879795740390823574772675416625164770670483563915572323472137688252061450947504469475266665833899157514866536755609208047
A: 9361670555169673278885701122852986238110075825623048853480143702977287835591027782340194497190532246273820028870655358636697024716730745803059296862336171
Received from Bob:
B:  2973750505056950067254377964580649451137516084952813040827331726542840075184232591750223557903162206297738151453793392480361196965786806004831571005574834
Send to Alice:
B: 9361670555169673278885701122852986238110075825623048853480143702977287835591027782340194497190532246273820028870655358636697024716730745803059296862336171

Well done!! Here is the final part, let send us a shared key to decrypt the ciphertext:
Shared key:0
Here we go!!! Here's your flag: W1{Mid_or_Middle_or_NotMiddle_or_Not???}

```

###### flag: `W1{Mid_or_Middle_or_NotMiddle_or_Not???}`

## RE
### Vì mình không phải 1 main RE nên 2 bài rev01, rev02 ở dưới mình chỉ đoán mò được flag và vô tình đúng. 😅

## rev01

Attachments:
* **chall.cs**
```csharp=0
public static void Main(string args){
    Console.WriteLine("Will you get the flag?");
    Console.WriteLine("> Please enter your flag: ");
    string flag = Console.ReadLine();

    if check(flag){
        Console.WriteLine("> The flag is W1{" + flag + "}");
    }
    else{
        Console.WriteLine("Try again");
    }

    public static bool check(string flag){
        byte x0=Convert.ToByte(flag.Substring(0,1));
        byte x1=Convert.ToByte(flag.Substring(1,1));
        byte x2=Convert.ToByte(flag.Substring(2,1));
        byte x3=Convert.ToByte(flag.Substring(3,1));
        byte x4=Convert.ToByte(flag.Substring(4,1));
        byte x5=Convert.ToByte(flag.Substring(5,1));
        byte x6=Convert.ToByte(flag.Substring(6,1));
        byte x7=Convert.ToByte(flag.Substring(7,1));
        byte x8=Convert.ToByte(flag.Substring(8,1));
        byte x9=Convert.ToByte(flag.Substring(9,1));
        byte x10=Convert.ToByte(flag.Substring(10,1));
        byte x11=Convert.ToByte(flag.Substring(11,1));
        byte x12=Convert.ToByte(flag.Substring(12,1));
        byte x13=Convert.ToByte(flag.Substring(13,1));
        byte x14=Convert.ToByte(flag.Substring(14,1));
        byte x15=Convert.ToByte(flag.Substring(15,1));
        byte x16=Convert.ToByte(flag.Substring(16,1));

        if(x0==102 && x1^(x0*3)==320 && x2-x5^x10==-71 && x4+5*9==140 && x3*5+10==555 && x4^x6^x8==11 && x5*2 + x4*3==483 && x11-x2^13==53 && x6+x7+x8==249 && (x7-x2)^(x5^3)+5==74 && x8|x9+x10+x16==255 && x9+(x13^56)+9==174 && x10+x13-x16-x12==46 && x11-x16-x14==5 && (x12^12)|x14==115 && x13+x16-x8==8 && x14*5 ^(x11-2)==150 && x15-5+x3==222 && x16==51) {
            return true;
        }
        else{
            return false;
        }
    }
}
}
```

Nhận xét:
- Phân tích file **chall.cs** ta thu được đoạn code C# như trên.
- Đọc sơ sơ qua thì có vẻ như flag của chúng ta sẽ có dạng W1{...}.
-  Theo đó là 17 thằng x, và mỗi thằng x sẽ tương đương với 1 kí tự trong flag.
-  Chúng ta cùng phân tích đoạn:
```csharp
if(x0==102 && x1^(x0*3)==320 && x2-x5^x10==-71 && x4+5*9==140 && x3*5+10==555 && x4^x6^x8==11 && x5*2 + x4*3==483 && x11-x2^13==53 && x6+x7+x8==249 && (x7-x2)^(x5^3)+5==74 && x8|x9+x10+x16==255 && x9+(x13^56)+9==174 && x10+x13-x16-x12==46 && x11-x16-x14==5 && (x12^12)|x14==115 && x13+x16-x8==8 && x14*5 ^(x11-2)==150 && x15-5+x3==222 && x16==51)
```
- Quao có vẻ chúng ta cần tách các dữ kiện ra cho dễ nhìn.
- Ở đây mình sẽ tổng hợp lại các x có thể tính trực tiếp từ điều kiện trên bằng python:
```python=0
lst=[0]*17
lst[0]=102
lst[1]=320^(lst[0]*3)
lst[3]=545//5
lst[4]=140-5*9
lst[5]=(483-lst[4]*3)//2
lst[15]=222-lst[3]+5               
lst[16]=51
```
- Sau đó, ta có thể thấy dữ kiện:
```csharp
x11-x16-x14==5 
x14*5 ^(x11-2)==150
```
- Vì thế, mình sẽ bruteforce các cặp x11,x14 thỏa mãn dữ kiện trên:
```python=0
#bf 11,14
print("x11","x14")
for i in range(33,128):
	for j in range(33,128):
		if i-j == 5+lst[16] and j*5^(i-2) == 150 :
			print(i,j,chr(i),chr(j))
```
```
x11 x14
96 40 ` (
104 48 h 0
107 51 k 3
```
- Vì x11, x14 chỉ có thể là chữ nên mình sẽ loại case ``x11 = 96, x14 = 40``.
- Cùng thử với case ``x11 = 104, x12 = 48`` nào.
- Sau đó ta sẽ tính được 1 loạt các kí tự tiếp theo như sau:
```python=0
lst[2]=lst[11]-(53^13)
#Đoạn này thì mình lười đảo ngược phép toán của x7 nên chạy for cho nhanh 😥
print("x7")
for i in range(33,128):
	if (i-lst[2])^(lst[5]^3) + 5 == 74:
		print(i,chr(i))
lst[7]=95
lst[10]=lst[2]-lst[5]^-71
lst[13]=46+lst[12]+lst[16]-lst[10]
lst[8]=lst[13]+lst[16]-8
lst[6]=249-lst[7]-lst[8]
lst[9]=174-9-(lst[13]^56)
```
- Riêng x12 vì k biết đảo ngược hàm | nên mình chạy for và đoán case của x12. 😅
```python
print("x12")
for i in range(33,128):
	if (i^12)|lst[14] == 115:
		print(i,chr(i))
lst[12]=95 
```
- Cuối cùng, cùng tổng hợp lại các chữ số tính được nào:
    
```python=0
ms=[""]*17
cnt=0
for i in lst:
	ms[cnt]=chr(i)
	cnt+=1
print("".join(ms))
```

Full code in python:
```python=0
lst=[0]*17
lst[0]=102
lst[1]=320^(lst[0]*3)
lst[3]=545//5
lst[4]=140-5*9
lst[5]=(483-lst[4]*3)//2
lst[15]=222-lst[3]+5               
lst[16]=51


#bf 11,14
print("x11","x14")
for i in range(33,128):
	for j in range(33,128):
		if i-j == 5+lst[16] and j*5^(i-2) == 150 :
			print(i,j,chr(i),chr(j))
#co 2 t/h
#x11=107 or x11=104
#x14=51  or x14=48
lst[11]=104
lst[14]=48
#bf 12 dua vao 14
print("x12")
for i in range(33,128):
	if (i^12)|lst[14] == 115:
		print(i,chr(i))
lst[12]=95 

lst[2]=lst[11]-(53^13)
print("x7")
for i in range(33,128):
	if (i-lst[2])^(lst[5]^3) + 5 == 74:
		print(i,chr(i))
lst[7]=95
lst[10]=lst[2]-lst[5]^-71
lst[13]=46+lst[12]+lst[16]-lst[10]
lst[8]=lst[13]+lst[16]-8
lst[6]=249-lst[7]-lst[8]
lst[9]=174-9-(lst[13]^56)
ms=[""]*17
cnt=0
for i in lst:
	ms[cnt]=chr(i)
	cnt+=1
print("".join(ms))
```
```
x11 x14
96 40 ` (
104 48 h 0
107 51 k 3
x12
79 O
95 _
111 o
127 
x7
95 _
fr0m_c#_w1th_L0v3
```

###### flag: `W1{fr0m_c#_w1th_L0v3}`


## rev02

Attachments:
* chall.py
``` python=0
import base64 as b64

def KSA(key):
    key_len=len(key)
    S=list(range(256))
    j=0
    for i in range(256):
        j=(j+S[i]+key[i%key_len])%256
        S[i], S[j]=S[j], S[i]
    return S

def PRGA(S,n):
    i,j=0,0
    key=[]
    while n>0:
        n-=1
        i=(i+1)%256
        j=(j+S[i])%256
        S[i], S[j]=S[j], S[i]
        K=S[(S[i]+S[j])%256]
        key.append(K)
    return key



def encrypt(pt,key):
    S=KSA(list(key.encode()))
    keystream=PRGA(S, len(pt))
    pt=list(pt.encode())

    res=[]
    for i in range(len(pt)):
        res.append(pt[i]^keystream[i])
    return res



ck1=[493, 573, 566, 499, 515, 516, 458, 518, 531, 494, 510, 486, 505]
ck=[47, 73, 69, 57, 53, 48, 99, 50, 76, 54, 88, 55, 104, 68, 120, 103, 107, 120, 100, 82, 110, 67, 86, 65, 120, 83, 72, 106, 69, 98, 106, 108, 77, 76, 117, 81, 73, 101, 111, 87, 113, 76, 54, 52, 55, 98, 111, 107, 118, 69, 85, 51, 103, 52, 105, 80, 80, 65, 61, 61]


key=input("Enter your key: ")

tmp=[]
for i in range(len(key)):
    tmp.append(((ord(key[i]) - i) * 5) ^ (i + 7))

if tmp!=ck1:
    print("Wrong key")
else:
    pt=input("Enter your flag: ")
    enc=bytes(encrypt(pt,key))
    res=list(b64.b64encode(enc))
    if res!=ck:
        print("Sorry, no flag for you")
    else:
        print("Correct flag")
```


Nhận xét:
- Phân tích đoạn code trên, ta sẽ cần nhập 1 key mà sau đó tmp sẽ được biến đổi dựa vào key để thành ck1. Vì thế ta có thể đảo ngược đoạn này để kiếm key.
```python=0
tmp=[]
cnt=0
for i in ck1:
	tmp.append(chr((i^(cnt+7)) //5 + cnt))
	cnt+=1
key=''.join(tmp)
print(f"key: {key}")
```
```
key: bruhlmaotomon
```
- Sau đó, ta thấy cần biến res = ck để có flag. Check lại thấy 2 dòng này:
```python=0
enc=bytes(encrypt(pt,key))
res=list(b64.b64encode(enc))
```
- Ta thấy enc sẽ được tính qua hàm encrypt. Cùng liếc qua hàm đó nào:
```python=0
def encrypt(pt,key):
    S=KSA(list(key.encode()))
    keystream=PRGA(S, len(pt))
    pt=list(pt.encode())

    res=[]
    for i in range(len(pt)):
        res.append(pt[i]^keystream[i])
    return res
```
- Hàm encrypt này đại khái có vẻ sẽ là 1 hàm xor và trả giá trị về 1 list các số nguyên. Theo sau đó enc sẽ lấy dạng bytes của list các số nguyên này và cuối cùng
``res = list(b64encode(enc))``
- Vì là hàm xor nên ta có thể lấy flag bằng cách
``pt[i] = res[i]^keysteam[i]``

- Vì thế để đảo ngược quá trình này ta cần lấy a=list(b64decode()) để có được độ dài của flag

```python=0
from base64 import *
ct=[]
for i in ck:
	ct.append(chr(i))
ct=''.join(ct)
a=list(b64decode(ct))
print(a,len(a))
```
- Do đã biết key nên ta có thể tính S hàm KSA mà không cần phân tích hàm đó cũng như đã biết độ dài của ciphertext nên không cần xét hàm PRGA.
- Cuối cùng ta có hàm decrypt như sau:
```python=0
def decrypt(ct,key):
	S=KSA(list(key.encode()))
	keystream=PRGA(S, len(ct))

	pt=[]
	for i in range(len(ct)):
	    	pt.append(chr(a[i]^keystream[i]))
	return ''.join(pt)
```

Full code in python:
```python=0
def KSA(key):
    key_len=len(key)
    S=list(range(256))
    j=0
    for i in range(256):
        j=(j+S[i]+key[i%key_len])%256
        S[i], S[j]=S[j], S[i]
    return S
    
def PRGA(S,n):
    i,j=0,0
    key=[]
    while n>0:
        n-=1
        i=(i+1)%256
        j=(j+S[i])%256
        S[i], S[j]=S[j], S[i]
        K=S[(S[i]+S[j])%256]
        key.append(K)
    return key


ck1=[493, 573, 566, 499, 515, 516, 458, 518, 531, 494, 510, 486, 505]
ck=[47, 73, 69, 57, 53, 48, 99, 50, 76, 54, 88, 55, 104, 68, 120, 103, 107, 120, 100, 82, 110, 67, 86, 65, 120, 83, 72, 106, 69, 98, 106, 108, 77, 76, 117, 81, 73, 101, 111, 87, 113, 76, 54, 52, 55, 98, 111, 107, 118, 69, 85, 51, 103, 52, 105, 80, 80, 65, 61, 61]

tmp=[]
cnt=0
for i in ck1:
	tmp.append(chr((i^(cnt+7)) //5 + cnt))
	cnt+=1
key=''.join(tmp)
print(f"key: {key}")

from base64 import *
ct=[]
for i in ck:
	ct.append(chr(i))
ct=''.join(ct)
a=list(b64decode(ct))
print(a,len(a))

def decrypt(ct,key):
	S=KSA(list(key.encode()))
	keystream=PRGA(S, len(ct))

	pt=[]
	for i in range(len(ct)):
	    	pt.append(chr(a[i]^keystream[i]))
	return ''.join(pt)
	
print(decrypt(a,key))	
```

```
key: bruhlmaotomon
[252, 129, 61, 231, 71, 54, 47, 165, 251, 132, 60, 96, 147, 23, 81, 156, 37, 64, 197, 33, 227, 17, 184, 229, 48, 187, 144, 33, 234, 22, 168, 190, 184, 237, 186, 36, 188, 69, 55, 131, 136, 143, 60] 43
W1{s0m3_b45iC_3ncRypt0n_4lgO_yoU_wi11_m3Et}
```

###### flag: `W1{s0m3_b45iC_3ncRypt0n_4lgO_yoU_wi11_m3Et}`


## Kết luận
- Ở trên là danh sách 7 bài first blood của mình trong WannaGame Freshman 2022. 
- Vì mình không giỏi trong việc truyền đạt lại nên nếu như các bạn gặp khó khăn, không hiểu ở một chỗ nào đó, hoặc cần giải thích lại thì đừng ngần ngại liên hệ với mình qua discord: ``tranminhprvt01#7535``
- Cuối cùng, cảm ơn các bạn đã đọc. Have a good day! 🥰
