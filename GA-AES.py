# crypto_benchmark_gui.py
# Dependencies:
#   pip install pycryptodome cryptography

import os
import time
import random
import threading
import queue
import tkinter as tk
from tkinter import scrolledtext, ttk

from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# cryptography for ECC/ECIES (optional)
try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    ECC_AVAILABLE = True
except ImportError:
    ECC_AVAILABLE = False

# —— 参数配置 ——
DATA_SIZE        = 1024 * 1024    # 对称算法测试时明文长度 (bytes)
GA_AES_KEY_SIZE  = 16             # 改进 GA-AES 密钥长度 (bytes)
AES_KEY_SIZE     = 16             # AES-128 密钥长度 (bytes)
DES_KEY_SIZE     = 8              # DES 密钥长度 (bytes)
RSA_KEY_SIZE     = 2048           # RSA 密钥位数
RSA_DATA_SIZE    = 190            # RSA 单次加密最大长度 (bytes)
ACC_ROUNDS       = 20             # 功能正确性测试轮次
LINEAR_ROUNDS    = 2000           # 线性偏差测试轮次（单块 16B）
AVALANCHE_ROUNDS = 1000           # 雪崩效应测试轮次（单块 16B）
BLOCK_SIZE       = 16             # 分组大小 (bytes)，用于单块测试

# —— GA 演化参数 ——
GA_POP           = 20             # 种群大小
GA_GENS          = 10             # 迭代代数

# —— 原始 AES S-Box ——
AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

# —— 多目标适应度：雪崩 + 线性偏差 ——
def fitness_sbox(sbox, rounds=50):
    total_ham = 0
    for _ in range(rounds):
        x   = random.randrange(256)
        x2  = x ^ 1
        total_ham += bin(sbox[x] ^ sbox[x2]).count("1")
    avalanche = total_ham / rounds

    match = 0
    for _ in range(rounds):
        x = random.randrange(256)
        if (x & 1) == (sbox[x] & 1):
            match += 1
    bias = abs(2 * match / rounds - 1)

    # 我们希望雪崩分数高，偏差低
    return avalanche - 2.0 * bias

# —— 演化动态 S-Box ——
def evolve_sbox(pop=GA_POP, gens=GA_GENS):
    pool = [AES_SBOX[:] for _ in range(pop)]
    global key0
    key0 = get_random_bytes(GA_AES_KEY_SIZE)
    for gen in range(gens):
        scored    = [(fitness_sbox(s), s) for s in pool]
        scored.sort(key=lambda x: x[0], reverse=True)
        survivors = [s for _, s in scored[:pop//2]]
        newpool   = survivors[:]
        while len(newpool) < pop:
            p1, p2 = random.sample(survivors, 2)
            # 基因级随机交叉
            child = [ random.choice((p1[i], p2[i])) for i in range(256) ]
            # 自适应变异
            mut_rate = 0.2 * (1 - gen/gens) + 0.05
            if random.random() < mut_rate:
                i, j = random.sample(range(256), 2)
                child[i], child[j] = child[j], child[i]
            newpool.append(child)
        pool = newpool
    # 选最优
    best = max(pool, key=fitness_sbox)
    inv  = [0]*256
    for i, v in enumerate(best):
        inv[v] = i
    return best, inv

# —— 模块加载时生成动态 S-Box & 翻译表 ——
DYN_SBOX, DYN_INV_SBOX     = evolve_sbox()
DYN_SBOX_TABLE             = bytes(DYN_SBOX)
DYN_INV_SBOX_TABLE         = bytes(DYN_INV_SBOX)

# —— PKCS7 填充 / 去填 ——
def pad_pkcs7(data: bytes, bs: int = 16) -> bytes:
    p = bs - (len(data) % bs)
    return data + bytes([p]) * p

def unpad_pkcs7(data: bytes) -> bytes:
    return data[:-data[-1]]

# —— 改进 GA-AES 加密 ——
def improved_ga_aes_encrypt(plaintext: bytes, key: bytes) -> bytes:
    # 1. PKCS7 填充
    padded = pad_pkcs7(plaintext, BLOCK_SIZE)
    # 2. C-level 预置换
    pre    = padded.translate(DYN_SBOX_TABLE)
    # 3. 一次性多块 AES-ECB 加密
    ct     = AES.new(key, AES.MODE_ECB).encrypt(pre)
    # 4. C-level 后置换
    return ct.translate(DYN_INV_SBOX_TABLE)

# —— 改进 GA-AES 解密 ——
def improved_ga_aes_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    # 1. C-level 预置换（还原 AES 输出）
    pre = ciphertext.translate(DYN_SBOX_TABLE)
    # 2. 一次性多块 AES-ECB 解密
    pt  = AES.new(key, AES.MODE_ECB).decrypt(pre)
    # 3. C-level 后置换 + 去填充
    return unpad_pkcs7(pt.translate(DYN_INV_SBOX_TABLE))

# —— 通用计时与吞吐 ——
def timed(fn, *args, **kwargs):
    t0 = time.perf_counter()
    res = fn(*args, **kwargs)
    return res, time.perf_counter() - t0

def calc_throughput(nbytes, secs):
    return (nbytes * 8) / (secs * 1e6) if secs > 0 else float("inf")

# —— 单块线性偏差测试 ——
def test_linear(log, enc_fn, key_params):
    log("    ○ 线性偏差测试...")
    match = 0
    for _ in range(LINEAR_ROUNDS):
        pt = get_random_bytes(BLOCK_SIZE)
        ct = enc_fn(pt, **key_params)
        if (pt[0] & 1) == (ct[0] & 1):
            match += 1
    corr = 2 * match / LINEAR_ROUNDS - 1
    bias = abs(corr)
    log(f"      ✓ corr: {corr:.4f}, bias: {bias:.4f}")
    return bias

# —— 单块雪崩效应测试 ——
def test_avalanche(log, enc_fn, key_params):
    log("    ○ 雪崩效应测试...")
    total_diff = 0
    bits       = BLOCK_SIZE * 8
    for _ in range(AVALANCHE_ROUNDS):
        pt0 = get_random_bytes(BLOCK_SIZE)
        b   = random.randrange(bits)
        pt1 = bytearray(pt0)
        pt1[b//8] ^= 1 << (b % 8)
        ct0 = enc_fn(pt0, **key_params)
        ct1 = enc_fn(bytes(pt1), **key_params)
        total_diff += sum(bin(a^b).count('1') for a, b in zip(ct0, ct1))
    avg_diff  = total_diff / AVALANCHE_ROUNDS
    ratio_pct = avg_diff / bits * 100
    log(f"      ✓ avg diff bits: {avg_diff:.2f}, ratio: {ratio_pct:.2f}%")
    return ratio_pct

# —— 各算法测试 ——
def test_ga_aes(log):
    log("=== 测试 改进 GA-AES ===")
    key   = get_random_bytes(GA_AES_KEY_SIZE)
    e_sum = d_sum = 0.0
    ok    = 0
    for _ in range(ACC_ROUNDS):
        pt = get_random_bytes(DATA_SIZE)
        ct, te  = timed(improved_ga_aes_encrypt, pt, key)
        pt2, td = timed(improved_ga_aes_decrypt, ct, key)
        e_sum  += te
        d_sum  += td
        if pt2 == pt:
            ok += 1
    avg_e = e_sum / ACC_ROUNDS
    avg_d = d_sum / ACC_ROUNDS
    thr   = calc_throughput(DATA_SIZE, avg_e)
    acc   = ok / ACC_ROUNDS * 100
    log(f"  ✓ Enc: {avg_e:.4f}s  Dec: {avg_d:.4f}s  Acc: {acc:.2f}%  Thr: {thr:.2f}Mb/s")
    # 用闭包捕获 key，保证 test_linear/test_avalanche 正确调用
    lb = test_linear(log, lambda d: improved_ga_aes_encrypt(d, key), {})
    av = test_avalanche(log, lambda d: improved_ga_aes_encrypt(d, key), {})
    return {"enc": avg_e, "dec": avg_d, "throughput": thr,
            "accuracy": acc, "linear_bias": lb, "avalanche": av}

def test_aes(log):
    log("=== 测试 AES-128-ECB ===")
    key   = get_random_bytes(AES_KEY_SIZE)
    e_sum = d_sum = 0.0
    ok    = 0
    for _ in range(ACC_ROUNDS):
        pt = get_random_bytes(DATA_SIZE)
        ct, te  = timed(AES.new(key, AES.MODE_ECB).encrypt, pt)
        pt2, td = timed(AES.new(key, AES.MODE_ECB).decrypt, ct)
        e_sum  += te
        d_sum  += td
        if pt2 == pt:
            ok += 1
    avg_e = e_sum / ACC_ROUNDS
    avg_d = d_sum / ACC_ROUNDS
    thr   = calc_throughput(DATA_SIZE, avg_e)
    acc   = ok / ACC_ROUNDS * 100
    log(f"  ✓ Enc: {avg_e:.4f}s  Dec: {avg_d:.4f}s  Acc: {acc:.2f}%  Thr: {thr:.2f}Mb/s")
    lb = test_linear(log,
                     lambda d, **kw: AES.new(kw['key'], AES.MODE_ECB).encrypt(d),
                     {"key": key})
    av = test_avalanche(log,
                        lambda d, **kw: AES.new(kw['key'], AES.MODE_ECB).encrypt(d),
                        {"key": key})
    return {"enc": avg_e, "dec": avg_d, "throughput": thr,
            "accuracy": acc, "linear_bias": lb, "avalanche": av}

def test_des(log):
    log("=== 测试 DES-CBC ===")
    key = get_random_bytes(DES_KEY_SIZE)
    iv  = get_random_bytes(DES_KEY_SIZE)
    e_sum = d_sum = 0.0
    ok    = 0
    for _ in range(ACC_ROUNDS):
        pt = get_random_bytes(DATA_SIZE)
        ct, te  = timed(DES.new(key, DES.MODE_CBC, iv).encrypt, pt)
        pt2, td = timed(DES.new(key, DES.MODE_CBC, iv).decrypt, ct)
        e_sum  += te
        d_sum  += td
        if pt2 == pt:
            ok += 1
    avg_e = e_sum / ACC_ROUNDS
    avg_d = d_sum / ACC_ROUNDS
    thr   = calc_throughput(DATA_SIZE, avg_e)
    acc   = ok / ACC_ROUNDS * 100
    log(f"  ✓ Enc: {avg_e:.4f}s  Dec: {avg_d:.4f}s  Acc: {acc:.2f}%  Thr: {thr:.2f}Mb/s")
    lb = test_linear(log,
                     lambda d, **kw: DES.new(kw['key'], DES.MODE_CBC, kw['iv']).encrypt(d),
                     {"key": key, "iv": iv})
    av = test_avalanche(log,
                        lambda d, **kw: DES.new(kw['key'], DES.MODE_CBC, kw['iv']).encrypt(d),
                        {"key": key, "iv": iv})
    return {"enc": avg_e, "dec": avg_d, "throughput": thr,
            "accuracy": acc, "linear_bias": lb, "avalanche": av}

def test_rsa(log):
    log("=== 测试 RSA-2048-OAEP ===")
    log("  • 生成密钥对…")
    kp, tg = timed(RSA.generate, RSA_KEY_SIZE)
    pub    = kp.publickey()
    cipher = PKCS1_OAEP.new(pub)
    dec    = PKCS1_OAEP.new(kp)
    e_sum = d_sum = 0.0
    ok    = 0
    for _ in range(ACC_ROUNDS):
        pt = get_random_bytes(RSA_DATA_SIZE)
        ct, te  = timed(cipher.encrypt, pt)
        pt2, td = timed(dec.decrypt, ct)
        e_sum  += te
        d_sum  += td
        if pt2 == pt:
            ok += 1
    avg_e = e_sum / ACC_ROUNDS
    avg_d = d_sum / ACC_ROUNDS
    thr   = calc_throughput(RSA_DATA_SIZE, avg_e)
    acc   = ok / ACC_ROUNDS * 100
    log(f"  ✓ Enc: {avg_e:.4f}s  Dec: {avg_d:.4f}s  Acc: {acc:.2f}%  Thr: {thr:.2f}Mb/s")
    lb = test_linear(log, lambda d, **kw: cipher.encrypt(d), {})
    av = test_avalanche(log, lambda d, **kw: cipher.encrypt(d), {})
    return {"keygen": tg, "enc": avg_e, "dec": avg_d,
            "throughput": thr, "accuracy": acc,
            "linear_bias": lb, "avalanche": av}

def test_ecc(log):
    if not ECC_AVAILABLE:
        log("=== 跳过 ECC 测试 (未安装 cryptography) ===")
        return {"keygen":0,"enc":0,"dec":0,
                "throughput":0,"accuracy":0,
                "linear_bias":0,"avalanche":0}
    log("=== 测试 ECC-256 (ECIES) ===")
    t0    = time.perf_counter()
    priv  = ec.generate_private_key(ec.SECP256R1(), default_backend())
    pub   = priv.public_key()
    tg    = time.perf_counter() - t0
    e_sum = d_sum = 0.0
    ok    = 0
    info  = b"ecies-test"
    for _ in range(ACC_ROUNDS):
        plain = get_random_bytes(DATA_SIZE)
        # Encrypt
        t1    = time.perf_counter()
        eph   = ec.generate_private_key(ec.SECP256R1(), default_backend())
        shared= eph.exchange(ec.ECDH(), pub)
        sym   = HKDF(hashes.SHA256(), length=16, salt=None,
                     info=info, backend=default_backend()).derive(shared)
        aesg  = AESGCM(sym)
        nonce = os.urandom(12)
        ct    = aesg.encrypt(nonce, plain, None)
        te    = time.perf_counter() - t1
        # Decrypt
        t2     = time.perf_counter()
        shared2= priv.exchange(ec.ECDH(), eph.public_key())
        sym2   = HKDF(hashes.SHA256(), length=16, salt=None,
                      info=info, backend=default_backend()).derive(shared2)
        aesg2  = AESGCM(sym2)
        pt2    = aesg2.decrypt(nonce, ct, None)
        td     = time.perf_counter() - t2
        e_sum += te
        d_sum += td
        if pt2 == plain:
            ok += 1
    avg_e = e_sum / ACC_ROUNDS
    avg_d = d_sum / ACC_ROUNDS
    thr   = calc_throughput(DATA_SIZE, avg_e)
    acc   = ok / ACC_ROUNDS * 100
    log(f"  ✓ Enc: {avg_e:.4f}s  Dec: {avg_d:.4f}s  Acc: {acc:.2f}%  Thr: {thr:.2f}Mb/s")
    # 固定一次对称通道做线性/雪崩
    eph_t  = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_ = eph_t.exchange(ec.ECDH(), pub)
    sym_   = HKDF(hashes.SHA256(), length=16, salt=None,
                  info=info, backend=default_backend()).derive(shared_)
    aesg_  = AESGCM(sym_)
    nonce_ = os.urandom(12)
    lb = test_linear(log, lambda d, **kw: aesg_.encrypt(nonce_, d, None), {})
    av = test_avalanche(log, lambda d, **kw: aesg_.encrypt(nonce_, d, None), {})
    return {"keygen": tg, "enc": avg_e, "dec": avg_d,
            "throughput": thr, "accuracy": acc,
            "linear_bias": lb, "avalanche": av}

# —— GUI 主体 ——
class CryptoBenchmarkGUI:
    def __init__(self, root):
        self.root = root
        root.title("加密算法性能对比")
        root.geometry("900x580")
        self.btn = ttk.Button(root, text="开始测试", command=self.start)
        self.btn.pack(fill=tk.X, padx=5, pady=5)
        self.logbox = scrolledtext.ScrolledText(root, state="disabled")
        self.logbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.q = queue.Queue()
        root.after(100, self.flush)

    def log(self, msg):
        self.q.put(f"[{time.strftime('%H:%M:%S')}] {msg}\n")

    def flush(self):
        try:
            while True:
                line = self.q.get_nowait()
                self.logbox.configure(state="normal")
                self.logbox.insert(tk.END, line)
                self.logbox.configure(state="disabled")
                self.logbox.yview(tk.END)
        except queue.Empty:
            pass
        finally:
            self.root.after(100, self.flush)

    def start(self):
        self.btn.config(state="disabled")
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        try:
            metrics = {
                "GA-AES": test_ga_aes(self.log),
                "AES":    test_aes(self.log),
                "DES":    test_des(self.log),
                "RSA":    test_rsa(self.log),
                "ECC":    test_ecc(self.log),
            }
            self.log("\n=== 汇总 ===")
            hdr = (
                f"{'算法':<8} {'KeyGen':>7} {'Enc':>7} {'Dec':>7} "
                f"{'Thr(Mb/s)':>10} {'Acc(%)':>8} {'LinBias':>9} {'Aval(%)':>9}"
            )
            self.log(hdr)
            for name, m in metrics.items():
                kg = m.get("keygen", 0.0)
                e, d = m["enc"], m["dec"]
                tps  = m["throughput"]
                ac   = m["accuracy"]
                lb   = m["linear_bias"]
                av   = m["avalanche"]
                self.log(
                    f"{name:<8} {kg:7.4f} {e:7.4f} {d:7.4f} "
                    f"{tps:10.2f} {ac:8.2f} {lb:9.4f} {av:9.2f}"
                )
            self.log("测试完成。")
        except Exception as ex:
            self.log(f"出错: {ex}")
        finally:
            self.btn.config(state="normal")

if __name__ == "__main__":
    root= tk.Tk()
    CryptoBenchmarkGUI(root)
    root.mainloop()
