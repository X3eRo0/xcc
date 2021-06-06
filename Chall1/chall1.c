#include "xlib.h"

u32 fib(u32 n){
    
    u32 sum = 0;
    for (u32 i = 0; i < n; i++){
        for (u32 j = 0; j < n; j++){
            for (u32 k = 0; k < i * j; k++){
                for (u32 l = 0; l < i * j * k; l++){
                    sum += i*j+k-l;
                }
            }
        }
    }

    if (n <= 1){
        return n;
    } else {
        return fib(n-1) + fib(n-2);
    }
}

// u32 fib(u32 n)
// {
//   u32 a = 0, b = 1, c, i;
//   if( n == 0)
//     return a;
//   for (i = 2; i <= n; i++)
//   {
//      c = a + b;
//      a = b;
//      b = c;
//   }
//   return b;
// }


u32 xor_of_digits(u32 n){
    u32 num = n;
    u32 sum = 0;
    while (num != 0){
        sum ^= num % 10;
        num /= 10;
    }
    return sum;
}

u32  decrypt_byte(char * enc_flag, char * dec, u32 pos){
    u32 f = fib(pos);
    dec[pos] = (enc_flag[pos] ^ f ^ xor_of_digits(fib(pos))) & 0xff;
    return 0;
}

int main() {
    u8 enc[] = {
        0x66, 0x6C, 0x61, 0x67, 0x20, 0x3A, 0x20, 0x75, 0x7E, 0x16, 0x45, 0x68, 0xEA, 0xD2, 0x4C, 0x52, 0xBC, 0x05, 0x20, 0x60, 0x5D, 0xFF, 0x4A, 0xCC, 0x18, 0x20, 0x5B, 0x76, 0x1B, 0x89, 0x1D, 0xB5, 0x34, 0x89, 0xD1, 0xF2, 0xDE, 0x14, 0x1B, 0x91, 0xAB, 0x53, 0x47
    };
    char  buff[0x100];
    for (u32 i = 0; i < sizeof(enc); i++){
        decrypt_byte(enc, buff, i);
        write(1, buff+i, 1);
    }
    print("\n");
    return 0;
}
