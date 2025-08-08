---
title: SEKAICTF 2023 writeup
author: tranminhprvt01
pubDatetime: 2023-08-29
featured: false
draft: false
tags:
  - Crypto
  - GES
description:
  Writeup to challenge(s) I solved during the CTF
---


Cuối tuần vừa rồi (25/8 - 27/8) đã diễn ra giải **SEKAICTF 2023**, mình đã đánh cho team ``m1cr0$oft 0ff1c3`` và kết thúc giải ở vị trí thứ 27.

![](https://hackmd.io/_uploads/rJwQOBqah.png)

Giải này là một trong các giải yêu thích của mình, cơ mà lần này mình thi hơi choked nên chỉ solve được vài câu ppc và 1 câu crypto.


# TL;DR
Graph and PPC everywhere

## Table of contents


## cryptoGRAPHy1

>Graphs have gained an increasing amount of attention in the world of Cryptography. They are used to model many real-world problems ranging from social media to traffic routing networks. Designing a secure Graph Encryption Scheme (GES) is important as querying plaintext graph database can leak sensitive information about the users.
> 
> In this challenge I have implemented a novel GES. Please help me verify if the cryptosystem works.
> 
> Author: sahuang
> 
> ❖ Note
> lib.zip remains unchanged in this series. The flag for this challenge will be used to access the next one when unlocked.
> 
> nc chals.sekai.team 3001

Attachments:
* lib (update later)
* server.py (update later)
```python
from . import GES
from . import utils
import networkx as nx
import random

from SECRET import flag, decrypt

NODE_COUNT = 130
EDGE_COUNT = 260
SECURITY_PARAMETER = 16

def gen_random_graph(node_count: int, edge_count: int) -> nx.Graph:
    nodes = [i for i in range(1, node_count + 1)]
    edges = []
    while len(edges) <  edge_count:
        u, v = random.choices(nodes, k=2)
        if u != v and (u, v) not in edges and (v, u) not in edges:
            edges.append([u, v])
    return utils.generate_graph(edges)

if __name__ == '__main__':
    try:
        print("[+] Generating random graph...")
        G = gen_random_graph(NODE_COUNT, EDGE_COUNT)
        myGES = GES.GESClass(cores=4, encrypted_db={})
        key = myGES.keyGen(SECURITY_PARAMETER)
        print(f"[*] Key: {key.hex()}")

        print("[+] Encrypting graph...")
        enc_db = myGES.encryptGraph(key, G)

        print("[!] Answer 50 queries to get the flag. In each query, input the shortest path \
              decrypted from response. It will be a string of space-separated nodes from \
              source to destination, e.g. '1 2 3 4'.")
        for q in range(50):
            while True:
                u, v = random.choices(list(G.nodes), k=2)
                if nx.has_path(G, u, v):
                    break
            print(f"[+] Query {q+1}/50: {u} {v}")
            token = myGES.tokenGen(key, (u, v))
            _, resp = myGES.search(token, enc_db)
            print(f"[*] Response: {resp.hex()}")

            ans = input("> Original query: ").strip()
            if ans != decrypt(u, v, resp, key):
                print("[!] Wrong answer!")
                exit()
        print(f"[+] Flag: {flag}")
    except:
        exit()
```

Nhận xét:
- Đây là bài dễ nhất trong mảng crypto và là bài duy nhất mình solve được trong thời gian giải diễn ra. 😥
- Đề bài này mô phỏng lại [Graph Encryption Scheme (GES)](https://dl.acm.org/doi/pdf/10.1145/3433210.3453099). 
- Đại loại thông qua việc phân tích thư viện thì mình hiểu GES là cấu trúc mã hóa dữ liệu trên đồ thị và hỗ trợ việc truy vấn quan hệ của một cặp đỉnh (u, v) đến dữ liệu đó thông qua token và kết quả được trả về là đường đi ngắn nhất từ u đến v được mã hóa.
- Quay lại với challenge trên, ta được cho biết giá trị **key** (thứ mà vốn đáng ra nên được giữ bí mật).
- Vì thế, công việc của chúng ta chỉ là căng mắt ra đọc cách mã hóa trong các file thư viện để có thể tìm ra được cách giải mã khi được cho biết response của query một cặp (u, v) cũng như giá trị u, v đó.
- Sau một hồi căng mắt ra đọc, thì mình cũng nắm được giá trị **resp** thể hiện cho đường đi ngắn nhất từ u->v của chúng ta đó là mã hóa AES_CBC, và mỗi block 32 bytes thu được từ **resp** chính là mã hóa của (i, v) (với các i nằm trên đường đi từ u->v, không kể u). Và do đã được cung cấp **key** nên việc decrypt dễ như trở bàn tay.

Script:
```python
from pwn import *
from tqdm import tqdm
import utils


host, port = "chals.sekai.team", 3001
r = remote(host, port)#process(["python", "test.py"])


r.recvuntil(b"Key: ")
key = bytes.fromhex(r.recvline().rstrip().decode())
print(f"Given key: {key.hex()}")

key_SKE, key_DES = key[:16], key[16:]

for i in tqdm(range(50)):
    r.recvuntil(f"Query {i+1}/50: ".encode())
    u, v = r.recvline().rstrip().decode().split(" ")
    u = int(u)
    v = int(v)
    print(f"Given nodes: {u}, {v}")
    path = [u]
    r.recvuntil(b"Response: ")
    resp = bytes.fromhex(r.recvline().rstrip().decode())
    block = [resp[i:i+32] for i in range(0, len(resp), 32)]
    for i in block:
        next_vertex, root = eval(utils.SymmetricDecrypt(key_SKE, i).decode())
        path.append(next_vertex)
    #print(path)
    data = " ".join([str(i) for i in path])
    print(f"Recovering path successfully:\n{data}")

    r.sendlineafter(b"> Original query: ", data.encode())

r.interactive()
#SEKAI{GES_15_34sy_2_br34k_kn@w1ng_th3_k3y}
```

-> Flag: `SEKAI{GES_15_34sy_2_br34k_kn@w1ng_th3_k3y}`

## cryptoGRAPHy2

> I am wondering what can be leaked in my GES. Let me know if you can recover the graph structure in an Honest-But-Curious setting.
> 
> Author: sahuang
> 
> ❖ Note
> lib.zip remains unchanged in this series. The flag for this challenge will be used to access the next one when unlocked.
> 
> nc chals.sekai.team 3062

Attachments:

* lib.zip
* server.py
```python
import GES, utils
import networkx as nx
import random

from SECRET import flag, get_SDSP_node_degrees

'''
get_SDSP_node_degrees(G, dest) returns the node degrees in the single-destination shortest path (SDSP) tree, sorted in ascending order.
For example, if G has 5 nodes with edges (1,2),(1,3),(2,3),(2,5),(4,5) and dest=1, returns "1 1 2 2 2".
[+] Original:       [+] SDSP:
1--2--5--4          1--2--5--4
| /                 |
3                   3
'''
# Another example for sanity check
TestGraph = utils.generate_graph([[1, 2], [1, 4], [1, 6], [6, 5], [6, 7], [4, 7], [2, 5]])
assert get_SDSP_node_degrees(TestGraph, 1) == '1 1 1 2 2 3'

NODE_COUNT = 130
EDGE_PROB = 0.031
SECURITY_PARAMETER = 32

def gen_random_graph() -> nx.Graph:
    return nx.fast_gnp_random_graph(n=NODE_COUNT, p=EDGE_PROB)

if __name__ == '__main__':
    try:
        print("[!] Pass 10 challenges to get the flag:")
        for q in range(10):
            print(f"[+] Challenge {q+1}/10. Generating random graph...")
            while True:
                G = gen_random_graph()
                if nx.is_connected(G):
                    break
            myGES = GES.GESClass(cores=4, encrypted_db={})
            key = myGES.keyGen(SECURITY_PARAMETER)

            print("[+] Encrypting graph...")
            enc_db = myGES.encryptGraph(key, G)

            dest = random.choice(list(G.nodes()))
            print(f"[*] Destination: {dest}")

            attempts = NODE_COUNT
            while attempts > 0:
                attempts -= 1
                query = input("> Query u,v: ").strip()
                try:
                    u, v = map(int, query.split(','))
                    assert u in G.nodes() and v in G.nodes() and u != v
                except:
                    print("[!] Invalid query!")
                    break
                token = myGES.tokenGen(key, (u, v)) 
                print(f"[*] Token: {token.hex()}")
                print(f"[*] Query Response: {tok.hex() + resp.hex()}")

            ans = input("> Answer: ").strip()
            if ans != get_SDSP_node_degrees(G, dest):
                print("[!] Wrong answer!")
                exit()
        print(f"[+] Flag: {flag}")
    except:
        exit()
```

Nhận xét:
- Đây là bài thứ 2 trong series cryptoGRAPHy và đồng thời cũng là bài crypto dễ thứ hai cho đến lúc end giải.
- Tóm tắt đề:
    + Ta được cho một đồ thị G mà sau đó đồ thị này sẽ được giản lược thành cây single-destination shortest path (SDSP) (đại loại sẽ là cây có 1 nút là gốc, và các nút còn lại sẽ được giữ quan hệ hệt trong đồ thị gốc đã cho, nhưng phải thỏa điều kiện đường đi từ các nút còn lại đến nút gốc là ngắn nhất).
    + Tiếp theo, ta được cho biết nút gốc của cây SDSP trên và được phép thực hiện 130 query (u, v) tới server và thu lại các token cùng với response.
    + Mục tiêu của chúng ta là cần in ra bậc của mỗi đỉnh trong cây SDSP trên theo thứ tự tăng dần.
- Tương tự cách mã hóa hệt bài đầu, nhờ vào việc phân tích file thư viện, giả sử rằng đường đi ngắn nhất từ u đến dest là u->a->b->c->dest, ta có thể biết được rằng khi thực hiện việc search vào database, ta sẽ cần cung cấp token của cặp (u, dest) và ta sẽ thu được response là mã hóa của cặp (a, dest) đồng thời tok sẽ lưu giá trị token của cặp (a, dest) này để tiếp tục thực hiện việc search token đến cặp (b, dest), v.v, cho đến cặp cuối cùng là (dest, dest).
- Chính vì thế, nếu ta gọi query của cặp (x, dest) với x là toàn bộ các nút trong đồ thị ngoại trừ nút dest, dựa vào các token ta thu được, ta hoàn toàn có thể phục hồi lại cây SDSP ban đầu và thực hiện việc tính bậc của mỗi đỉnh sẽ rất dễ dàng.
- Để cho dễ hiểu hơn, ta có thể hiểu rằng tồn tại 1 cách mapping sao cho các token của các giá trị (u, dest) trở thành chính các nút (x, dest) với x là các nút trên đường đi ngắn nhất từ u đến dest.
- Vì thế ở bài này, đơn thuần là sau khi ta thu được toàn bộ các token, ta sẽ thực hiện việc so sánh chuỗi để có thể tìm ra luôn bậc của các đỉnh.

Script:
```python
from pwn import *
from tqdm import tqdm

host, port = "chals.sekai.team", 3062

r = remote(host, port)




flag = b"SEKAI{GES_15_34sy_2_br34k_kn@w1ng_th3_k3y}"
r.sendlineafter(b"Flag for cryptoGRAPHy 1: ", flag)

for i in range(10):
    print(f"Attempts {i+1}/10")
    r.recvuntil(b"Destination: ")
    dest = int(r.recvline().rstrip())
    print("Given dest:", dest)
    res = []
    print("Querying phase")
    for i in tqdm(range(130)):
        #print(f"Querrying on node {i}, {dest}")
        if i == dest: continue
        r.sendlineafter(b"> Query u,v: ", f"{i},{dest}".encode())
        r.recvuntil(b"[*] Token: ")
        token = r.recvline().rstrip().decode()
        r.recvuntil(b"Query Response: ")
        data = r.recvline().rstrip().decode()
        tok, resp = data[:len(data)//2], data[len(data)//2:]
        res.append(token+tok)

    r.sendlineafter(b"> Query u,v: ", f"{i},{dest}".encode()) #for the last

    
    
    res.sort(key = len)
    data = []

    root = res[0][-64:]
    deg_root = 0
    for i in range(len(res)):
        if root == res[i][64:64+64]:
            deg_root+=1
    res = [i[:-64] for i in res]
    data.append(deg_root)


    cnt = 0
    while True:
        if len(res) == 0: break
        cur = res[0][-64:]
        deg = 0
        for i in range(1, len(res)):
            if cur == res[i][64:64+64]:
                deg+=1
                res[i] = res[i][:-64]

        res = res[1:]
        for i in range(len(res)):
            if res[i][-64:] == cur:
                res[i] = res[i][:-64]
        data.append(deg+1)
        cnt+=1

    
    
    data = " ".join(str(i) for i in sorted(data))
    print(f"Recover path successfully :\n{data}")
        
    
    r.sendlineafter(b"> Answer: ", data.encode())

    print("~"*40)

r.interactive()
#SEKAI{3ff1c13nt_GES_4_Shortest-Path-Queries-_-}
```

Giải thích:
- Sau khi thực hiện việc lưu các token vào mảng res, mình sort lại mảng này theo thứ tự độ dài của chuỗi.
- Tiếp theo mình sẽ tính bậc của nút gốc, do nút gốc chắc chắn luôn xuất hiện ở 64 hex cuối cùng của mọi phần tử trong mảng res (dễ hiểu là do mọi nút đều luôn đi về root nên 64 hex cuối luôn là token ứng với (root, root)), nên sau khi loại bỏ 64 hex cuối của mọi phần tử trong res, phần tử nào chỉ còn độ dài = 64, chắc chắn phần tử đó sẽ là một nút được nối trực tiếp đến root, khi này ta tăng bậc của root.
- Áp dụng mindset tương tự với phần tử chỉ còn độ dài 64 hiện tại gọi là cur, ta cũng sẽ tìm kiếm các phần tử trong res sao cho phần tử đó có 64 hex đứng ở vị trí 64:128 == cur để tăng bậc của cur (ta sẽ cần cộng 1 vô sau khi tính được toàn bộ bậc để thể hiện việc cur được nối với nút trước đó là root, bonus: những phần tử thỏa mãn chắc chắn lúc này chỉ có độ dài là 128). Tiếp theo, ta sẽ loại bỏ mọi phần tử có chứa cur ở cuối và loại bỏ cur khỏi mảng để xét phần tử tiếp theo cho đến khi nào mảng rỗng.

-> Flag: `SEKAI{3ff1c13nt_GES_4_Shortest-Path-Queries-_-}`


