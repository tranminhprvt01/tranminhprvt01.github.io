---
title: PlaidCTF 2024 writeup
author: tranminhprvt01
pubDatetime: 2024-04-20
featured: false
draft: false
tags:
  - Crypto
  - Chacha20
  - Poly1305
  - nonce reuse
  - forge tag

description:
  Writeup to challenge(s) I solved during the CTF
---


Giải PlaidCTF2024 diễn cuối tuần vừa rồi (13/4 - 15/4), mình đã không thực sự làm tốt lắm khi không solve được câu crypto nào 😥. Tuy nhiên, end giải thì mình đã gắng làm lại challenge **DHCPPP** vì mình thấy đây là 1 câu khá hay và cũng không quá khó. Sau đây là writeup cho challenge **DHCPPP**

# TL;DR
Forge tag chacha20-poly1305

## Table of contents



## Source Code Analysis



```python file=dhcppp.py
import time, zlib
import secrets
import hashlib
import requests
from Crypto.Cipher import ChaCha20_Poly1305
import dns.resolver

CHACHA_KEY = secrets.token_bytes(32)
TIMEOUT = 1e-1

def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    nonce = sha256(msg[:32] + nonce[:32])[:12]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce

def decrypt_msg(msg):
    ct = msg[:-28]
    tag = msg[-28:-12]
    nonce = msg[-12:]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    return pt

def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

def sha256(msg):
    return hashlib.sha256(msg).digest()

RNG_INIT = secrets.token_bytes(512)

class DHCPServer:
    def __init__(self):
        self.leases = []
        self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
        self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
        self.gateway_ip = "192.168.1.1"

        self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))

    def get_lease(self, dev_name):
        if len(self.ips) != 0:
            ip = self.ips.pop(0)
            self.leases.append((ip, dev_name, time.time(), []))
        else:
            # relinquish the oldest lease
            old_lease = self.leases.pop(0)
            ip = old_lease[0]
            self.leases.append((ip, dev_name, time.time(), []))

        pkt = bytearray(
            bytes([int(x) for x in ip.split(".")]) +
            bytes([int(x) for x in self.gateway_ip.split(".")]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name +
            b"\x00"
        )

        pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)

        return pkt

    def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x01"):
            # lease request
            dev_name = msg[1:]
            lease_resp = self.get_lease(dev_name)
            return (
                self.mac +
                src_mac + # dest mac
                lease_resp
            )
        else:
            return None

class FlagServer:
    def __init__(self, dhcp):
        self.mac = bytes.fromhex("53 79 82 b5 97 eb")
        self.dns = dns.resolver.Resolver()
        self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))

    def send_flag(self):
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        curl("example.com", f"/{flag}", self.dns)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x02"):
            # lease response
            pkt = msg[1:-4]
            pkt = decrypt_msg(pkt)
            crc = msg[-4:]
            assert crc == calc_crc(pkt)

            self.ip = ".".join(str(x) for x in pkt[0:4])
            self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
            self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
            self.dns1 = ".".join(str(x) for x in pkt[12:16])
            self.dns2 = ".".join(str(x) for x in pkt[16:20])
            self.dns.nameservers = [self.dns1, self.dns2]
            assert pkt.endswith(b"\x00")

            print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)

            return None

        elif len(msg) and msg.startswith(b"\x03"):
            # FREE FLAGES!!!!!!!
            self.send_flag()
            return None

        else:
            return None

def curl(url, path, dns):
    ip = str(dns.resolve(url).response.resolve_chaining().answer).strip().split(" ")[-1]
    url = "http://" + ip
    print(f"Sending flage to {url}")
    requests.get(url + path)

if __name__ == "__main__":
    dhcp = DHCPServer()
    flagserver = FlagServer(dhcp)

    while True:
        pkt = bytes.fromhex(input("> ").replace(" ", "").strip())

        out = dhcp.process_pkt(pkt)
        if out is not None:
            print(out.hex())

        out = flagserver.process_pkt(pkt)
        if out is not None:
            print(out.hex())
```


Với cái source khá oằn tà là vằn ở trên, ta nên chia nhỏ ra thành từng phần một để phân tích cho dễ. Mình sẽ tóm tắt một vài phần chính để các bạn rõ hơn về flow của bài. Bài này dựng 2 class **DHCP Server** và **Flag server**, và challenge này đơn giản là cho chúng ta thực hiện "giao tiếp" với 2 thằng trên, đi kèm với đó là 3 options để phân biệt thằng nào đang được giao tiếp.

Bắt đầu với class **DHCP Server**:

```python
class DHCPServer:
    def __init__(self):
        self.leases = []
        self.ips = [f"192.168.1.{i}" for i in range(3, 64)]
        self.mac = bytes.fromhex("1b 7d 6f 49 37 c9")
        self.gateway_ip = "192.168.1.1"

        self.leases.append(("192.168.1.2", b"rngserver_0", time.time(), []))

    def get_lease(self, dev_name):
        if len(self.ips) != 0:
            ip = self.ips.pop(0)
            self.leases.append((ip, dev_name, time.time(), []))
        else:
            # relinquish the oldest lease
            old_lease = self.leases.pop(0)
            ip = old_lease[0]
            self.leases.append((ip, dev_name, time.time(), []))

        pkt = bytearray(
            bytes([int(x) for x in ip.split(".")]) +
            bytes([int(x) for x in self.gateway_ip.split(".")]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name +
            b"\x00"
        )

        pkt = b"\x02" + encrypt_msg(pkt, self.get_entropy_from_lavalamps()) + calc_crc(pkt)

        return pkt

    def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x01"):
            # lease request
            dev_name = msg[1:]
            lease_resp = self.get_lease(dev_name)
            return (
                self.mac +
                src_mac + # dest mac
                lease_resp
            )
        else:
            return None
```

Nhìn vào hàm **\_\_init\_\_**, đây là hàm khởi tạo khi gọi class, hàm này khởi tạo sẵn 1 list IP từ 192.168.1.3 đến 192.168.1.63, cùng với đó là định nghĩa dhcp_mac, gateway_ip, và thêm vào mảng leases bộ số ``("192.168.1.2", b"rngserver_0", time.time(), [])``, có thể hiểu đơn giản là thêm vào mảng leases (ip, dev_name, ...)

Nhìn vào hàm **process_pkt(message)**, ta thấy hàm này sẽ check phần mac gửi vào ở đầu message sao cho destination_mac là dhcp_mac vả source_mac không phải là dchp_mac. Sau khi check xong phần mac, server sẽ check message đang gửi hiện tại có phải là option 1 hay không (option 1 bắt đầu với byte b'\x01'), và bắt đầu vào hàm **get_lease()** với input cho hàm này là phần message đã bỏ qua mac và bỏ qua option 1. Và cuối cùng hàm trả về `dhcp_mac + source_mac + lease_response`

Đến với hàm **get_lease(dev_name)**, hàm này lấy giá trị IP = giá trị IP hiện tại ở đầu mảng IPs, khởi tạo pkt là 1 chuỗi byte = `ip hiện tại + gateway_ip + subnet + dns1 + dns2 + dev_name + b'\x00'`, và cuối cùng gán pkt = `b'\x02' + encrypt(pkt, get_entropy_from_lavalamps()) + calc_crc(pkt)` vả hàm trả về giá trị pkt này.

Cuối cùng, ta đến với hàm **get_entropy_from_lavalamps()**, hàm này các bạn có thể hiểu đơn giản là trả về giá trị nonce bằng việc gửi request tới các IPs đang có trong mảng leases.

-> Tóm lại, khi ta "giao tiếp" với **DHCP Server**, ta đơn giản là đang gán các IPs có sẵn của nó vào các device_name mà ta gửi vào hay nói một cách tường minh hơn là ta đang thu về ciphertext dựa trên các dev_name ta gửi vào cho **DHCP Server** đối với một IP nào đó đang xét hiện tại. Và ciphertext ở đây chính là encrypt(pkt, nonce), loại mã hóa được xài là [**ChaCha20-Poly1305**](https://en.wikipedia.org/wiki/ChaCha20-Poly1305).
> Sơ lược 1 chút về ChaCha20-Poly1305, ChaCha20 là stream cipher, còn Poly1305 là 1 phần riêng chỉ phục vụ mục đích tạo ra tính xác thực cho văn bản (authentication).

Tiếp theo, ta cùng đến với class **Flag Server**

```python
class FlagServer:
    def __init__(self, dhcp):
        self.mac = bytes.fromhex("53 79 82 b5 97 eb")
        self.dns = dns.resolver.Resolver()
        self.process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))

    def send_flag(self):
        with open("flag.txt", "r") as f:
            flag = f.read().strip()
        curl("example.com", f"/{flag}", self.dns)

    def process_pkt(self, pkt):
        assert pkt is not None

        src_mac = pkt[:6]
        dst_mac = pkt[6:12]
        msg = pkt[12:]

        if dst_mac != self.mac:
            return None

        if src_mac == self.mac:
            return None

        if len(msg) and msg.startswith(b"\x02"):
            # lease response
            pkt = msg[1:-4]
            pkt = decrypt_msg(pkt)
            crc = msg[-4:]
            assert crc == calc_crc(pkt)

            self.ip = ".".join(str(x) for x in pkt[0:4])
            self.gateway_ip = ".".join(str(x) for x in pkt[4:8])
            self.subnet_mask = ".".join(str(x) for x in pkt[8:12])
            self.dns1 = ".".join(str(x) for x in pkt[12:16])
            self.dns2 = ".".join(str(x) for x in pkt[16:20])
            self.dns.nameservers = [self.dns1, self.dns2]
            assert pkt.endswith(b"\x00")

            print("[FLAG SERVER] [DEBUG] Got DHCP lease", self.ip, self.gateway_ip, self.subnet_mask, self.dns1, self.dns2)

            return None

        elif len(msg) and msg.startswith(b"\x03"):
            # FREE FLAGES!!!!!!!
            self.send_flag()
            return None

        else:
            return None
```

Bắt đầu với hàm khởi tạo, hàm này cũng gần tương tự với **DHCP Server** khi khởi tạo flag_mac, định nghĩa 1 object dns và gọi `process_pkt(dhcp.process_pkt(self.mac+dhcp.mac+b"\x01"+b"flag_server"))`. Ta có thể hiểu đơn giản là khi vừa vào khởi tạo, server đã thực hiện trước việc giao tiếp giữa **Flag Server** với **DHCP Server** với dev_name là `flag_server`.

Tiếp theo là hàm **process_pkt**, hàm này sẽ nhận message được gửi vào, và xét message của chúng ta đang thuộc option 2 (b'\x02') hay option 3 (b'\x03'). Nếu message của chúng ta thuộc option 2, server sẽ thực hiện việc **decrypt(ciphertext)** và **xác thực** tag gửi kèm có chính xác hay không, sau đó, server sẽ chỉnh sửa lại các giá trị (ip, gateway_ip, subnet, dns1, dns2) đang được gán cho flag_server hiện tại thành các giá trị vừa decrypt được. Còn nếu message của chúng ta là option 3 thì, server sẽ thực hiện việc **send_flag()** bằng cách curl vào url `example.com` với path là flag với tham số dns hiện tại đang được gán cho flag_server.

-> Tóm lại, khi thực hiện giao tiếp với **Flag Server**, ta đơn giản là đang được server decrypt ciphertext mà ta gửi vào, và bằng cách nào đó, ta sẽ cần chỉnh sửa ciphertext sao cho khi server decrypt giá trị này, nó sẽ được chỉnh sửa thành các giá trị ta cần để có thể curl flag. Cụ thể, trong bài này, với ~~một chút~~ kiến thức network, các bạn sẽ thấy ngay ta cần chỉnh sửa 2 giá trị dns1 và dns2 thành IP VPS của các bạn.


## Fantastic Bugs and Where to Hack Them

Sau khi đã hình dung sơ sơ được về cách bài này hoạt động, ta cùng tìm hiểu vì sao challenge này lại không an toàn.

Cùng nhìn lại cách mã hóa/giải mã hoạt động:
```python
CHACHA_KEY = secrets.token_bytes(32)
TIMEOUT = 1e-1

def encrypt_msg(msg, nonce):
    # In case our RNG nonce is repeated, we also hash
    # the message in. This means the worst-case scenario
    # is that our nonce reflects a hash of the message
    # but saves the chance of a nonce being reused across
    # different messages
    nonce = sha256(msg[:32] + nonce[:32])[:12]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(msg)

    return ct+tag+nonce

def decrypt_msg(msg):
    ct = msg[:-28]
    tag = msg[-28:-12]
    nonce = msg[-12:]

    cipher = ChaCha20_Poly1305.new(key=CHACHA_KEY, nonce=nonce)
    pt = cipher.decrypt_and_verify(ct, tag)

    return pt


...
def get_entropy_from_lavalamps(self):
        # Get entropy from all available lava-lamp RNG servers
        # Falling back to local RNG if necessary
        entropy_pool = RNG_INIT

        for ip, name, ts, tags in self.leases:
            if b"rngserver" in name:
                try:
                    # get entropy from the server
                    output = requests.get(f"http://{ip}/get_rng", timeout=TIMEOUT).text
                    entropy_pool += sha256(output.encode())
                except:
                    # if the server is broken, get randomness from local RNG instead
                    entropy_pool += sha256(secrets.token_bytes(512))

        return sha256(entropy_pool)
...
```

- Trước đó, ta biết hàm encrypt chỉ được gọi đối với option 1 với input là pkt và output của hàm **get_entropy_from_lavalamps()**, well hàm tạo nonce đó nhìn khá random nhưng lại không hề random một miếng nào, các bạn có thể tự mình kiểm chứng đối với remote hoặc local, kết quả trả ra luôn là như nhau. Vì thế, trong hàm encrypt, giá trị `nonce = sha256(msg[:32] + nonce[:32])[:12]` khi này chỉ còn phụ thuộc vào pkt và nếu pkt[:32] là như nhau, thì ta sẽ có nonce bằng nhau -> Điều này dẫn đến bug duy nhất của bài đó là **nonce reuse**.

- Vậy nonce reuse thì ảnh hưởng bài này như thế nào. Ta thấy bài này sử d       ụng **ChaCha20-Poly1305**, biết rằng, **ChaCha20** là stream cipher. Ta có thể hiểu đơn giản **ChaCha20** thực hiện mã hóa như sau: $\text{plaintext} \oplus \text{chacha\_keystream(key, nonce)} = \text{ciphertext}$

- Đến đây, các bạn có thể sẽ nghĩ rằng vì ta đã biết plaintext với ciphertext, ta có thể kiếm lại keystream và từ đó có thể tự encrypt lại plaintext đã chỉnh sửa là xong. Quá ư là dễ nhỉ 😅. Tuy nhiên, đoạn khó nằm ở chỗ **xác thực** giá trị tag được gửi kèm để server check liệu tag đó có đúng hay không. Bài toán này được biết đến với keyword **forge tag**.

- Toàn bộ việc tính tag đều nằm trong [**Poly1305**](https://en.wikipedia.org/wiki/Poly1305), các bạn có thể tham khảo thêm [paper này](https://link.springer.com/content/pdf/10.1007%2F11502760_3.pdf), hoặc để đơn giản hơn thì chỉ cần tham khảo đường [link sau](https://link.springer.com/content/pdf/10.1007%2F11502760_3.pdf).

- Mình sẽ tóm tắt nhanh công thức tính tag như sau:
$tag = (((c_1 * r^{k} + c_2 *r^{k-1} + ... + c_k * r^{1}) \ mod \ 2^{130} - 5) + s) \ mod \ 2^{128}$ 
với $c_i$ là giá trị được lấy từ ciphertext, $k = \lceil \frac{len(ciphertext)}{16} \rceil$, còn $r$ với $s$ thì được lấy từ `ChaCha20(key, nonce).encrypt(b'\x00'*32)`. Có thể nói rằng đối với 1 cặp (key, nonce), ta cũng sẽ chỉ có duy nhất 1 cặp (r, s)
- Để cho tiện trong các giai đoạn sau, mình sẽ gọi tắt phương trình tính tag thành $tag = (poly(r) \ mod \ 2^{130} - 5) + s) \ mod \ 2^{128}$ 

![image](https://hackmd.io/_uploads/SkGaMfx-A.png)


- Để hiểu thêm về cách hoạt động của ChaCha20-Poly1305, các bạn có thể mò source lib python và đọc hoặc làm tà đạo hơn là mò source implement lại chacha20-poly1305 bằng python trên Github như mình =))

- Quay trở về với bài toán của chúng ta, xét trong bối cảnh ta đang có giá trị nonce bị lặp lại đối với 2 message khác nhau. Vậy ta có thể nói rằng giá trị r và s được sinh ra là y như nhau.

- Vậy hãy thử lấy 2 giá trị tag được trả ra từ 2 message xài chung nonce tính toán với nhau xem chuyện gì sẽ xảy ra
$$
\begin{align*}
tag1 &= ((poly(r)\ mod \ 2^{130} - 5) + s) \ mod \ 2^{128} \\
tag2 &= ((poly'(r) \ mod \ 2^{130} - 5) + s) \ mod \ 2^{128} \\
tag1 - tag2 + (i-j)*2^{128}&=(poly(r) \ mod \ 2^{130} - 5) - (poly'(r) \ mod \ 2^{130} - 5) \\ &=((poly-poly')(r) \ mod \ 2^{130} - 5)
\end{align*}
$$
- Có thể thấy rằng, ta đã bỏ được giá trị $s$ ra khỏi phương trình trên. Ngoài ra, ta thấy rằng giá trị tag được tính từ $poly(r) \ mod \ 2^{130} - 5$, là 1 giá trị ~130 bits sau đó lại được $mod \ 2^{128}$ , nghĩa là giá trị tag đã bị mất đi 2 bits, vì thế ta có thể tính được ngay $i, j \in  [0, 3] \rightarrow (i-j) \in [-3, 3]$.

- Vậy thì, đối với mỗi giá trị trong khoảng [-3, 3], ta sẽ dựng được 1 phương trình trên $GF(2^{130}-5)$, và đến đây, ta sẽ tìm nghiệm của phương trình đã xét và nghiệm trả về của phương trình sẽ là giá trị $r$, khi này chỉ cần thay thế $r$ vào lại 1 trong 2 phương trình tính tag là ta sẽ thu được $s$.

- Một lưu ý nhỏ, dễ dàng ta thấy phương trình dựng được tối ưu nhất sẽ là một phương trình bậc 2 -> 2 nghiệm r, và với mỗi giá trị (i-j) ta sẽ có tương ứng số nghiệm tương tự, vì thế làm sao để có thể loại nghiệm hiệu quả. Đáp án là, mò source github =))), ta thấy ngay giá trị r được mod với 1 con số khác dẫn đến r chỉ còn ~ 124 bits, đây sẽ là điều kiện để ta loại bớt nghiệm.

![image](https://hackmd.io/_uploads/S1IR0Gx-0.png)

- Vậy thì sau khi có được cặp (r, s) đối với cặp (key, nonce) hiện tại, ta hoàn toàn có thể forge ra 1 cái tag cho ciphertext mới của chúng ta. Khi này, các bạn gửi option 2 với mọi dữ kiện tính toán ở trên, 1000% là server sẽ decrypt thành công và chỉnh sửa lại các thông số của flag_server thành pkt mà ta đã custom.

- Nếu đã đến được bước đi thì các bạn đã hoàn thành xong phần crypto của challenge này, phần còn lại là **DNS spoofing**. Tuy nhiên vì mình ~~không biết làm~~ là 1 main crypto 😎, nên mình đã nhờ bạn mình config giùm server và gửi option 3 để send flag đến server. 


solve.sage
```python
from pwn import *
import zlib

io = remote("dhcppp.chal.pwni.ng", 1337)#process(["python", "dhcppp.py"])

print("~"*20 + "PREPARING PHASE" + "~"*20)

flag_mac = bytes.fromhex("53 79 82 b5 97 eb")
dhcp_mac = bytes.fromhex("1b 7d 6f 49 37 c9")




def calc_crc(msg):
    return zlib.crc32(msg).to_bytes(4, "little")

def sha256(msg):
    return hashlib.sha256(msg).digest()


def calc(s):
    ls = s.split('.')
    ls = [int(i) for i in ls]
    return sum(ls)

def parse_ip(s:bytes):
    ls = s.split()
    return ls[6]


def check(s:bytes, target_ip):
    ls = s.split()
    if ls[-1] == target_ip: return True
    return False


def reset_ip(cur_ip, dev_name):
    print("Flushing all the IPs")
    while True:
        io.sendlineafter(b'> ', (flag_mac+dhcp_mac+option+dev_name).hex().encode())
        #io.recvuntil(b'option1: ')
        res = bytes.fromhex(io.recvline().rstrip().decode())
        results.append(res)
        io.sendlineafter(b'> ', (res).hex().encode())
        data.append(io.recvline().rstrip().decode())
        if calc(parse_ip(data[-1])) == calc(cur_ip)-1:
            break


def parse_value(s:bytes):
    ct = s[6+6+1:-4] #flag_mac + dhcp_mac + option
    ct, tag, nonce = ct[:-28], ct[-28:-12], ct[-12:]
    crc = s[-4:]
    return ct, tag, nonce, crc


data = []
results = []

option = b'\x01'

reset_ip('192.168.1.3', b':D')


print("Requesting ciphertext1")
dev_name1 = b'a_my_laptop_1'
io.sendlineafter(b'> ', (flag_mac+dhcp_mac+option+dev_name1).hex().encode())
#io.recvuntil(b'option1: ')
res = bytes.fromhex(io.recvline().rstrip().decode())
results.append(res)
io.sendlineafter(b'> ', (res).hex().encode())
data.append(io.recvline().rstrip().decode())

ct1, tag1, nonce1, crc1 = parse_value(results[-1])


reset_ip('192.168.1.3', b':D')


print("Requesting ciphertext2")
dev_name2 = b'a_my_laptop_2'
io.sendlineafter(b'> ', (flag_mac+dhcp_mac+option+dev_name2).hex().encode())
#io.recvuntil(b'option1: ')
res = bytes.fromhex(io.recvline().rstrip().decode())
results.append(res)
io.sendlineafter(b'> ', (res).hex().encode())
data.append(io.recvline().rstrip().decode())

ct2, tag2, nonce2, crc2 = parse_value(results[-1])


assert nonce1 == nonce2


print(f"Ciphertext1: {ct1.hex()}")
print(f"Ciphertext2: {ct2.hex()}")
print(f"Tag1: {tag1.hex()}")
print(f"Tag2: {tag2.hex()}")




print("~"*20 + "ATTACK PHASE" + "~"*20)

msg1 = bytearray(
            bytes([192, 168, 1, 3]) +
            bytes([192, 168, 1, 1]) +
            bytes([255, 255, 255, 0]) +
            bytes([8, 8, 8, 8]) +
            bytes([8, 8, 4, 4]) +
            dev_name1 +
            b"\x00"
)

assert len(msg1) == len(ct1)

keystream = xor(msg1, ct1)



dev_name = b'Duy_laptop'
mod_msg = bytearray(
            bytes([192, 168, 1, 3]) +
            bytes([192, 168, 1, 1]) +
            bytes([255, 255, 255, 0]) +
            bytes([194, 233, 68, 172]) +
            bytes([194, 233, 68, 172]) +
            dev_name +
            b"\x00"
)


mod_ct = xor(keystream[:len(mod_msg)], mod_msg)


def pad16(data):
    """Return padding for the Associated Authenticated Data"""
    #print(data, type(data))
    if len(data) % 16 == 0:
        return bytearray(0)
    else:
        return bytearray(16-(len(data)%16))


def divceil(divident, divisor):
    """Integer division with rounding up"""
    quot, r = divmod(divident, divisor)
    return quot + int(bool(r))


chachanonce = nonce1

tag1_int = int.from_bytes(tag1, 'little')
tag2_int = int.from_bytes(tag2, 'little')

Pr.<x> = PolynomialRing(GF(2^130-5))
x = Pr.gen()



def make_poly(ct):
    data = b""
    mac_data = data + pad16(data)
    mac_data += ct + pad16(ct)
    mac_data += struct.pack('<Q', len(data))
    mac_data += struct.pack('<Q', len(ct))
    f = 0
    for i in range(0, divceil(len(mac_data), 16)):
        n = mac_data[i*16:(i+1)*16] + b'\x01'
        n += (17-len(n)) * b'\x00'
        f = (f + int.from_bytes(n, 'little')) * x
    return f



f1 = make_poly(ct1)
f2 = make_poly(ct2)


print(f"Pol1: {f1}")
print(f"Pol2: {f2}")


res = []

for k in range(-4, 5):
    rhs = tag1_int - tag2_int + 2^128 * k
    #print(rhs, k)
    f = rhs - (f1 - f2)
    for r, _ in f.roots():
        if int(r).bit_length() <= 124:
            s = (tag1_int - int(f1(r))) % 2^128
            res.append((r, s))

    
print(f"Possible result: {res}")

assert len(res) == 1

for r, s in res:
    print(f"using param ({r}, {s})")
    f = make_poly(mod_ct)
    tag = (int(f(r)) + s) % 2^128
    print("computed tag", tag)
    tag = int(tag).to_bytes(16, 'little')
    data = mod_ct + tag + chachanonce
    print(f"Sending: {data.hex()}")
    io.sendlineafter(b'> ', (dhcp_mac+flag_mac+b'\x02'+data+calc_crc(mod_msg)).hex().encode())
    recv = io.recvline().rstrip().decode()
    if check(recv, '194.233.68.172'):
        print("SUCCESS MODIFYING AND AUTHENTICATE MESSAGE")
        print(recv)


#io.sendlineafter(b'> ', (dhcp_mac+flag_mac+b'\x03').hex())

io.interactive()
```



![image](https://hackmd.io/_uploads/rJHB7mgbR.png)

![image](https://hackmd.io/_uploads/ByasQXlZ0.png)


-> Flag: `PCTF{d0nt_r3u5e_th3_n0nc3_d4839ed727736624}`



## Conclusion

- Ở trên là writeup của mình đối với challenge **DHCPPP** của giải PlaidCTF2024. Đây là lần đầu tiên mình đụng dạng toán **forge tag** này, cũng như là lần đầu mình tương tác với **ChaCha20-Poly1305** nhiều như thế.
- Hi vọng đọc writeup này xong các bạn đều sẽ không quá xoắn não vì độ ảo ma của nó. 
- Mình vô cùng cảm kích anh `vnc` vì đã sấy mình khi mình đọc sai source :v, cũng như `tr4c3datr4il` đã giúp mình làm phần network trong challenge.
- Mọi thắc mắc về bài viết, các bạn có thể nhắn tin trực tiếp với mình qua discord `tranminhprvt01`. Peace! 🥰

