def fib(n):
    a = 0
    b = 1
     
    # Check is n is less
    # than 0
    if n < 0:
        print("Incorrect input")
         
    # Check is n is equal
    # to 0
    elif n == 0:
        return 0
       
    # Check if n is equal to 1
    elif n == 1:
        return b
    else:
        for i in range(1, n):
            c = a + b
            a = b
            b = c
        return b

def xor_of_digits(n):
    num = n
    sum = 0
    while (num != 0):
        sum ^= num % 10;
        num //= 10
    
    return sum

flag = b"flag : zh3r0{967a23927d374a7e58e7a12ef62f5}"

def decrypt_byte(flag, pos):
    return (flag[pos] ^ fib(pos) ^ xor_of_digits(fib(pos))) & 0xff

enc = []

for i in range(len(flag)):
    enc.append(decrypt_byte(flag, i))

b = ""

for i in enc:
    b += "0x%.2X, " % i

print(b)
#zh3r0{967a23927d374a7e58e7a12ef62f5fb6982a3e:8f03ni5b5k7c6ae90
#zh3r0{967a23927d374a7e58e7a12ef62f5fb6982b9b13d50ef0a9d1d2ba3114fcb998}