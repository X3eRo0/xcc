_start:
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
    .asciz    "xcc version 1.0.0\nAuthor : X3eRo0\nDate : 7th March, 2021\n"

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
    .asciz    "bfn1drrdpfqb9p1ztpbhzfzzssmtx4kw"

.L__const.main.fcn_ptrs:
	.dd #0x31337000
	.dd #0x31337073
	.dd #0x313370e6
	.dd #0x31337159
	.dd #0x313371cc
	.dd #0x3133723f
	.dd #0x313372ab
	.dd #0x3133731e
	.dd #0x31337391
	.dd #0x31337404
	.dd #0x31337477
	.dd #0x313374ea
	.dd #0x3133755d
	.dd #0x313375c5
	.dd #0x31337638
	.dd #0x313376ab
	.dd #0x3133771e
	.dd #0x31337791
	.dd #0x31337804
	.dd #0x31337877
	.dd #0x313378ea
	.dd #0x3133795d
	.dd #0x313379d0
	.dd #0x31337a43
	.dd #0x31337aaf
	.dd #0x31337b22
	.dd #0x31337b95
	.dd #0x31337c08
	.dd #0x31337c7b
	.dd #0x31337ce7
	.dd #0x31337d5a
	.dd #0x31337dcd
	.dd #0x31338000
	.dd #0x31338073
	.dd #0x313380e6
	.dd #0x31338159
	.dd #0x313381cc
	.dd #0x31338234
	.dd #0x313382a7
	.dd #0x3133831a
	.dd #0x3133838d
	.dd #0x31338400
	.dd #0x31338473
	.dd #0x313384e6
	.dd #0x31338559
	.dd #0x313385cc
	.dd #0x3133863f
	.dd #0x313386b2
	.dd #0x31338725
	.dd #0x31338798
	.dd #0x3133880b
	.dd #0x3133887e
	.dd #0x313388f1
	.dd #0x31338964
	.dd #0x313389d7
	.dd #0x31338a4a
	.dd #0x31338ab6
	.dd #0x31338b25
	.dd #0x31338b98
	.dd #0x31338c0b
	.dd #0x31338c7e
	.dd #0x31338cf1
	.dd #0x31338d5d
	.dd #0x31338dd0
	.dd #0x31339000
	.dd #0x31339073
	.dd #0x313390df
	.dd #0x3133914b
	.dd #0x313391be
	.dd #0x31339231
	.dd #0x3133929d
	.dd #0x31339309
	.dd #0x3133937c
	.dd #0x313393ef
	.dd #0x31339462
	.dd #0x313394ce
	.dd #0x3133953a
	.dd #0x313395ad
	.dd #0x31339620
	.dd #0x3133968c
	.dd #0x313396ff
	.dd #0x3133976b
	.dd #0x313397de
	.dd #0x31339851
	.dd #0x313398c4
	.dd #0x31339937
	.dd #0x313399a3
	.dd #0x31339a16
	.dd #0x31339a89
	.dd #0x31339afc
	.dd #0x31339b6f
	.dd #0x31339be2
	.dd #0x31339c55
	.dd #0x31339cc8
	.dd #0x31339d3b
	.dd #0x31339dae
	.dd #0x3133a000
	.dd #0x3133a073
	.dd #0x3133a0df
	.dd #0x3133a14b
	.dd #0x3133a1be
	.dd #0x3133a231
	.dd #0x3133a2a4
	.dd #0x3133a317
	.dd #0x3133a383
	.dd #0x3133a3f6
	.dd #0x3133a469
	.dd #0x3133a4dc
	.dd #0x3133a54f
	.dd #0x3133a5c2
	.dd #0x3133a635
	.dd #0x3133a6a8
	.dd #0x3133a714
	.dd #0x3133a787
	.dd #0x3133a7f3
	.dd #0x3133a866
	.dd #0x3133a8d9
	.dd #0x3133a945
	.dd #0x3133a9b8
	.dd #0x3133aa2b
	.dd #0x3133aa97
	.dd #0x3133ab0a
	.dd #0x3133ab76
	.dd #0x3133abe9
	.dd #0x3133ac5c
	.dd #0x3133accf
	.dd #0x3133ad42
	.dd #0x3133adb5
	.dd #0x3133b000
	.dd #0x3133b073
	.dd #0x3133b0e6
	.dd #0x3133b152
	.dd #0x3133b1c5
	.dd #0x3133b238
	.dd #0x3133b2ab
	.dd #0x3133b31e
	.dd #0x3133b391
	.dd #0x3133b404
	.dd #0x3133b470
	.dd #0x3133b4e3
	.dd #0x3133b556
	.dd #0x3133b5c9
	.dd #0x3133b63c
	.dd #0x3133b6af
	.dd #0x3133b722
	.dd #0x3133b78e
	.dd #0x3133b801
	.dd #0x3133b86d
	.dd #0x3133b8e0
	.dd #0x3133b953
	.dd #0x3133b9c6
	.dd #0x3133ba39
	.dd #0x3133baac
	.dd #0x3133bb1f
	.dd #0x3133bb92
	.dd #0x3133bc05
	.dd #0x3133bc71
	.dd #0x3133bce4
	.dd #0x3133bd57
	.dd #0x3133bdca
	.dd #0x3133c000
	.dd #0x3133c073
	.dd #0x3133c0df
	.dd #0x3133c152
	.dd #0x3133c1c5
	.dd #0x3133c238
	.dd #0x3133c2ab
	.dd #0x3133c31e
	.dd #0x3133c391
	.dd #0x3133c404
	.dd #0x3133c470
	.dd #0x3133c4e3
	.dd #0x3133c556
	.dd #0x3133c5c9
	.dd #0x3133c63c
	.dd #0x3133c6af
	.dd #0x3133c722
	.dd #0x3133c795
	.dd #0x3133c808
	.dd #0x3133c87b
	.dd #0x3133c8e7
	.dd #0x3133c95a
	.dd #0x3133c9cd
	.dd #0x3133ca40
	.dd #0x3133caac
	.dd #0x3133cb1f
	.dd #0x3133cb92
	.dd #0x3133cc05
	.dd #0x3133cc78
	.dd #0x3133cceb
	.dd #0x3133cd5e
	.dd #0x3133cdd1
	.dd #0x3133d000
	.dd #0x3133d06c
	.dd #0x3133d0df
	.dd #0x3133d14b
	.dd #0x3133d1be
	.dd #0x3133d231
	.dd #0x3133d29d
	.dd #0x3133d310
	.dd #0x3133d383
	.dd #0x3133d3f6
	.dd #0x3133d469
	.dd #0x3133d4dc
	.dd #0x3133d548
	.dd #0x3133d5bb
	.dd #0x3133d62e
	.dd #0x3133d6a1
	.dd #0x3133d714
	.dd #0x3133d787
	.dd #0x3133d7fa
	.dd #0x3133d86d
	.dd #0x3133d8e0
	.dd #0x3133d953
	.dd #0x3133d9c6
	.dd #0x3133da39
	.dd #0x3133daa5
	.dd #0x3133db18
	.dd #0x3133db84
	.dd #0x3133dbf7
	.dd #0x3133dc6a
	.dd #0x3133dcdd
	.dd #0x3133dd50
	.dd #0x3133ddbc
	.dd #0x3133e000
	.dd #0x3133e073
	.dd #0x3133e0e6
	.dd #0x3133e152
	.dd #0x3133e1c5
	.dd #0x3133e238
	.dd #0x3133e2ab
	.dd #0x3133e317
	.dd #0x3133e38a
	.dd #0x3133e3fd
	.dd #0x3133e470
	.dd #0x3133e4e3
	.dd #0x3133e556
	.dd #0x3133e5c9
	.dd #0x3133e63c
	.dd #0x3133e6af
	.dd #0x3133e722
	.dd #0x3133e795
	.dd #0x3133e801
	.dd #0x3133e874
	.dd #0x3133e8e0
	.dd #0x3133e94f
	.dd #0x3133e9c2
	.dd #0x3133ea35
	.dd #0x3133eaa8
	.dd #0x3133eb14
	.dd #0x3133eb87
	.dd #0x3133ebf3
	.dd #0x3133ec5f
	.dd #0x3133ecd2
	.dd #0x3133ed45
	.dd #0x3133edb8
	.dd #0x3133f000
	.dd #0x3133f073
	.dd #0x3133f0e6
	.dd #0x3133f152
	.dd #0x3133f1c5
	.dd #0x3133f238
	.dd #0x3133f2ab
	.dd #0x3133f317
	.dd #0x3133f38a
	.dd #0x3133f3fd
	.dd #0x3133f470
	.dd #0x3133f4e3
	.dd #0x3133f556
	.dd #0x3133f5c9
	.dd #0x3133f63c
	.dd #0x3133f6af
	.dd #0x3133f722
	.dd #0x3133f795
	.dd #0x3133f808
	.dd #0x3133f87b
	.dd #0x3133f8ea
	.dd #0x3133f95d
	.dd #0x3133f9d0
	.dd #0x3133fa3c
	.dd #0x3133faa8
	.dd #0x3133fb1b
	.dd #0x3133fb8e
	.dd #0x3133fc01
	.dd #0x3133fc74
	.dd #0x3133fce7
	.dd #0x3133fd5a
	.dd #0x3133fdcd
	.dd #0x31340000
	.dd #0x3134006c
	.dd #0x313400df
	.dd #0x31340152
	.dd #0x313401be
	.dd #0x31340231
	.dd #0x313402a4
	.dd #0x31340317
	.dd #0x3134038a
	.dd #0x313403fd
	.dd #0x31340470
	.dd #0x313404e3
	.dd #0x31340556
	.dd #0x313405c9
	.dd #0x31340635
	.dd #0x313406a8
	.dd #0x3134071b
	.dd #0x3134078e
	.dd #0x31340801
	.dd #0x31340874
	.dd #0x313408e7
	.dd #0x3134095a
	.dd #0x313409cd
	.dd #0x31340a40
	.dd #0x31340ab3
	.dd #0x31340b26
	.dd #0x31340b99
	.dd #0x31340c0c
	.dd #0x31340c7f
	.dd #0x31340cf2
	.dd #0x31340d65
	.dd #0x31340dd8
	.dd #0x31341000
	.dd #0x31341073
	.dd #0x313410e6
	.dd #0x31341159
	.dd #0x313411cc
	.dd #0x3134123f
	.dd #0x313412ae
	.dd #0x31341321
	.dd #0x31341394
	.dd #0x31341407
	.dd #0x3134147a
	.dd #0x313414ed
	.dd #0x31341560
	.dd #0x313415d3
	.dd #0x31341646
	.dd #0x313416b9
	.dd #0x3134172c
	.dd #0x3134179f
	.dd #0x31341812
	.dd #0x31341885
	.dd #0x313418f8
	.dd #0x3134196b
	.dd #0x313419de
	.dd #0x31341a51
	.dd #0x31341ac4
	.dd #0x31341b37
	.dd #0x31341ba3
	.dd #0x31341c16
	.dd #0x31341c89
	.dd #0x31341cfc
	.dd #0x31341d6f
	.dd #0x31341de2
	.dd #0x31342000
	.dd #0x31342073
	.dd #0x313420e2
	.dd #0x31342155
	.dd #0x313421c8
	.dd #0x31342234
	.dd #0x313422a7
	.dd #0x3134231a

keys:
	.dd #0x1337f16b
	.dd #0x31337e39
	.dd #0x31338e43
	.dd #0x31339e1a
	.dd #0x3133ae21
	.dd #0x3133be3d
	.dd #0x3133ce40
	.dd #0x3133de2f
	.dd #0x3133ee2b
	.dd #0x3133fe40
	.dd #0x31340e4b
	.dd #0x31341e4e

