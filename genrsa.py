import random
import base64
import time
import textwrap
import os


rand = random.SystemRandom().getrandbits
hexToBytes = base64.binascii.a2b_hex
bytesToBase64 = base64.binascii.b2a_base64

def isProbablePrime(n):
    return pow(rand(64), n - 1, n) == 1

def nextProbablePrime(n):
    if n & 1 == 0:
        n += 1
    while not isProbablePrime(n):
        n += 2
    return n

def getPrivateExponent(p, q, e):
    k = 1
    while (k * (p - 1) * (q - 1) + 1) % e != 0:
        k += 1
    return (k * (p - 1) * (q - 1) + 1) // e

def getSizePrefix(n):
    size = len(n) // 2
    if size <= 0x7F:
        n = format(size, "x") + n
        n = ("0" if len(n) % 2 == 1 else "") + n
    elif size <= 0xFF:
        n = "81" + format(size, "x") + n
    elif size <= 0xFFFF:
        n = format(size, "x") + n
        n = "82" + ("0" if len(n) % 2 == 1 else "") + n
    elif size <= 0xFFFFFF:
        n = format(size, "x") + n
        n = "83" + ("0" if len(n) % 2 == 1 else "") + n
    else:
        n = format(size, "x") + n
        n = "84" + ("0" if len(n) % 2 == 1 else "") + n
    return n

def longToASN1Int(n):
    n = format(n, "x")
    if len(n) % 2 == 1:
        n = "0" + n
    if n[0] not in (str(i) for i in range(8)):
        n = "00" + n
    return "02" + getSizePrefix(n)

def getPublicSequence(n, e):
    n = longToASN1Int(n)
    e = longToASN1Int(e)
    r = n + e
    return "30" + getSizePrefix(r)

def getPrivateSequence(n, e, d, p, q, dP, dQ, qInv):
    v = longToASN1Int(0)
    n = longToASN1Int(n)
    e = longToASN1Int(e)
    d = longToASN1Int(d)
    p = longToASN1Int(p)
    q = longToASN1Int(q)
    dP = longToASN1Int(dP)
    dQ = longToASN1Int(dQ)
    qInv = longToASN1Int(qInv)
    r = v + n + e + d + p + q + dP + dQ + qInv
    return "30" + getSizePrefix(r)

def createKey(size, publicKeyName, privateKeyName):
    start = time.time()
    p = rand(size // 2)
    q = (rand(size) | 1 << size - 1) // p
    p = nextProbablePrime(p)
    q = nextProbablePrime(q)
    e = 65537
    d = getPrivateExponent(p, q, e)
    n = p * q
    m = random.getrandbits(size // 2)
    if pow(pow(m, e, n), d, n) == m:
        seq = getPublicSequence(n, e)
        seq = str(bytesToBase64(hexToBytes(seq)))[2:-3]
        with open(publicKeyName, "w") as f:
            f.write("-----BEGIN RSA PUBLIC KEY-----\n")
            f.write(textwrap.fill(seq, 64))
            f.write("\n-----END RSA PUBLIC KEY-----\n")
        if p < q:
            p, q = q, p
        dP = d % (p - 1)
        dQ = d % (q - 1)
        qInv = pow(q, p - 2, p)
        seq = getPrivateSequence(n, e, d, p, q, dP, dQ, qInv)
        seq = str(bytesToBase64(hexToBytes(seq)))[2:-3]
        with open(privateKeyName, "w") as f:
            f.write("-----BEGIN RSA PRIVATE KEY-----\n")
            f.write(textwrap.fill(seq, 64))
            f.write("\n-----END RSA PRIVATE KEY-----\n")
        finish = time.time()
        print("Time Taken: " + str(round(finish - start, 3)) + " Seconds")
    else:
        print("KEY NOT VALID - Regenerating Key")
        createKey(size, privateKeyName)


if __name__ == "__main__":
    size = int(input("Enter RSA Key Size: "))
    amount = int(input("Enter Number of Key Pairs to Create: "))
    for i in range(amount):
        print("\n" + str(i + 1) + ".")
        publicKey = "RSA PUBLIC KEY " + str(i + 1) + ".key"
        privateKey = "RSA PRIVATE KEY " + str(i + 1) + ".key"
        createKey(size, publicKey, privateKey)
    os.system("pause")
