main_asm = '''_start:
    call main
    hlt

decrypt_xor:
    ; $r1 -- byte_ptr
    ; $r2 -- key_ptr
    ; $r3 -- counter
    ; $r6 -- byte[counter]
    ; $r7 -- key[counter mod 32]
    xor   $r3, $r3
decrypt_xor_loop:
    mov   $r6, $r1
    add   $r6, $r3

    mov   $r7, $r3
    div   $r7, #32
    mov   $r7, $r5
    add   $r7, $r2

    xorb  [$r6], [$r7]
    inc   $r3
    cmp   $r3, #0x1000
    jz    decrypt_xor_ret
    jmp   decrypt_xor_loop

decrypt_xor_ret:
    ret


main:
    push  $bp
    mov   $bp, $sp
    sub   $sp, #0x8
    mov   [$bp - #4], #0 ; counter
    mov   [$bp - #8], #0 ; result

    mov   $r1, ASK_PASSWORD
    call  print

    mov   $r1, input
    mov   $r2, #0xff
    call  gets

main_inner_loop:
    cmp   [$bp - #4], #360
    jae   main_exit_inner_loop

    mov   $r0, [$bp - #4]
    and   $r0, #31
    cmp   $r0, #0
    jnz   main_call_functions

    mov   $r0, [$bp - #4]
    rsu   $r0, #5
    lsu   $r0, #12
    mov   $r4, $r0
    mov   $r5, #0x31337000
    add   $r5, $r4
    mov   $r0, [$bp - #4]
    rsu   $r0, #5
    mov   $r4, $r0
    mov   $r2, keys
    mul   $r4, #4
    add   $r2, $r4
    mov   $r2, [$r2]
    mov   $r1, $r5
    call  decrypt_xor


main_call_functions:
    mov   $r1, input
    mov   $r0, [$bp - #4]
    mov   $r4, .L__const.main.fcn_ptrs
    mul   $r0, #4
    add   $r4, $r0
    call  [$r4]
    dec   $r0
    or    $r0, [$bp - #8]
    mov   [$bp - #8], $r0
    inc   [$bp - #4]
    jmp   main_inner_loop


main_exit_inner_loop:
    cmp   [$bp - #8], #0
    jnz   main_fail_msg

    mov   $r1, MSG_SUCCESS
    call  puts
    jmp   main_ret

main_fail_msg:
    mov   $r1, MSG_FAILURE
    call  puts

main_ret:
    xor   $r0, $r0
    mov   $sp, $bp
    pop   $bp
    ret

.section .data
.xcc_ident:
    .asciz    "xcc version 1.0.0\\nAuthor : X3eRo0\\nDate : 7th March, 2021\\n"

input:
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00, #0x00,
    .db       #0x00, #0x00, #0x00, #0x00, #0x00, #0x00

MSG_SUCCESS:
    .asciz    "Correct Password"

MSG_FAILURE:
    .asciz    "Wrong Password"

ASK_PASSWORD:
    .asciz    "Enter Password: "

key_0:
    .asciz    "%s"

.L__const.main.fcn_ptrs:
'''