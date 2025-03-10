+++
title = "Baby crypt - HTB Challenge"
date = "2021-04-19"
weight = 0

[taxonomies]
tags=["HTB", "challenge", "reversing"]
difficulty=["easy"]
+++

# Information and behavior

First we extract the file

```bash
smavl:/baby-crypt $ file baby_crypt
baby_crypt: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=24af7e68eab982022ea63c1828813c3bfa671b51, for GNU/Linux 3.2.0, not stripped
```


***Not stripped***

After `chmod +x baby_crypt`, we execute the file and are presented with the problem:

```bash
smavl:/baby-crypt $ ./baby_crypt
Give me the key and I'll give you the flag: nono
Q
 [b')k
smavl:/baby-crypt $ ./baby_crypt
Give me the key and I'll give you the flag: fuck off
YVj=$c%babvpN'mN- iuf08

```

We notice that the depending on the input (`nono` and `fuck off`), the 'baby'-output varies.

We continue to investigate in ghidra.

## Ghidra

The main function looks like this

```c
undefined8 main(void)

{
  char *__s;
  long in_FS_OFFSET;
  int local_44;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined2 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Give me the key and I\'ll give you the flag: ");
  __s = (char *)malloc(4);
  fgets(__s,4,stdin);
  local_38 = 7999878687861597247;
  local_30 = 0x28130304026f0446;
  local_28 = 0x5000f4358280e52;
  local_20 = 0x4d56;
  local_44 = 0;
  while (local_44 < 0x1a) {
    *(byte *)((long)&local_38 + (long)local_44) =
         *(byte *)((long)&local_38 + (long)local_44) ^ __s[local_44 % 3];
    local_44 = local_44 + 1;
  }
  printf("%.26s\n",&local_38);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Due to my poor knowledge in C, i wasn't able to point the aparent logic to solve the problem.

***However*** the `local_xx = xxx` didnt seem to exist without importance

#### The Great Oracle
After consulting a great oracle [Hmm...](https://www.youtube.com/watch?v=ITD8CgzCkNw) i was enlightened

The `fgets(_s,4,stdin)`
`stdin` means user imput
`4` means the first 4 bytes of the line.

### Loop

`while (local_44 < 0x1a) {`

loops `0x1a` times

### Array

In the loop the first 4 byte and such are getting done with the help of an array.

### Xor

##### [Hackernoon - Why XOR is imp....](hackernoon.com%2Freasons-why-xor-is-important-in-cryptography-6tcn32yx)

The flag is XOR'ed through an array* 

This is the reason why the the flag is becomming 'Baby-language' 

However, due to the nature of XOR, we can work out the the key if we know some of the plaintext.

And we do. The first 4 bytes of the plaintext: HTB{ 

In that manner we can get the key, if we present the first `4 bytes` of the plaintext as the key.

```bash
$ ./baby_crypt
Give me the key and I'll give you the flag: HTB{
w0wDM;L;@LWQ`L`
```

Effectively, we've manipulated the baby into giving out the key, which is `w0wD`:

Hence: 
```bash 
$ ./baby_crypt
Give me the key and I'll give you the flag: w0wDM
HTB{x0r_1s_us3d_by_h4x0r!}
```

Really cool box. Quite easy if you could grasp the C code and knew about the nature of XOR

