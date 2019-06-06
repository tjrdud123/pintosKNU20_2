#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/user/syscall.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
static void syscall_handler (struct intr_frame *);

void halt (void);
void exit (int status);
pid_t exec (const char *cmd_lime);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{

    uint32_t syscall_number= *(uint32_t *)(f->esp);
    uint32_t args[4];
    if(!is_user_vaddr(f->esp+4) || !is_user_vaddr(f->esp+8) || !is_user_vaddr(f->esp+12))
        exit(-1);


    args[0]=*(uint32_t*) (f->esp+4);
    args[1]=*(uint32_t*) (f->esp+8);
    args[2]=*(uint32_t*) (f->esp+12);


    switch (syscall_number) {
    case SYS_EXIT:
            exit(args[0]);
            break;

    case SYS_HALT:
            halt();
            break;
    case SYS_EXEC:
            if(!is_user_vaddr((uint32_t*)args[0]))
                exit(-1);

            f->eax=exec((char*)args[0]);
            break;
    case SYS_WAIT:
            f->eax =wait(args[0]);
            break;
    case SYS_CREATE:
            if(!is_user_vaddr((uint32_t*)args[0]))
                exit(-1);
            f->eax = create((const char *)args[0], (unsigned)args[1]);
            break;
    case SYS_REMOVE:
            if(!is_user_vaddr((uint32_t*)args[0]))
                exit(-1);
            f->eax = remove((const char*)args[0]);
            break;
    case SYS_OPEN:
            if(!is_user_vaddr((uint32_t*)args[0]))
               exit(-1);
            f->eax = open((const char*)args[0]);
            break;
    case SYS_FILESIZE:
            f->eax = filesize((int)args[0]);
            break;
    case SYS_READ:
            if(!is_user_vaddr((uint32_t*)args[1]))
                exit(-1);
            f->eax=read(args[0],(char*)args[1],args[2]);
            break;
    case SYS_WRITE:
         if(!is_user_vaddr((uint32_t*)args[1]))
                 exit(-1);
         f->eax=write(args[0],(char*)args[1],args[2]);
         break;
    case SYS_SEEK:
         seek((int)args[0], (unsigned)args[1]);
         break;
    case SYS_TELL:
         f->eax = tell((int)*(uint32_t *)(f->esp + 4));
         break;
    case SYS_CLOSE:
         close((int)args[0]);
         break;
                      
    }
}

int wait (pid_t pid) {
      return process_wait(pid);
}

pid_t exec (const char *cmd_line) {
    pid_t ret=-1;
    if(cmd_line==NULL)
        exit(-1);

    lock_acquire(&filesys_lock);
    ret=process_execute(cmd_line);
    lock_release(&filesys_lock);
    
    return ret;
   
}

void halt (void) {
      shutdown_power_off();
      
}

void exit (int status) {
     printf("%s: exit(%d)\n", thread_name(), status);
     thread_current()->exit_status=status;
     thread_exit ();
}

int write (int fd, const void *buffer, unsigned size) {
    int ret=-1;

    if(buffer==NULL)
        exit(-1);
    
    lock_acquire(&filesys_lock);
    if (fd == 1) {
        putbuf(buffer, size);
        ret=size;
    } else if (fd > 2) {
        if (thread_current()->fd[fd] == NULL) {
            lock_release(&filesys_lock);
            exit(-1);
        }

        if (((struct file*)(thread_current()->fd[fd]))->deny_write) {
            file_deny_write(thread_current()->fd[fd]);
        }

        ret=file_write(thread_current()->fd[fd], buffer, size);
    }
    

    lock_release(&filesys_lock);
    return ret; 
}

bool create (const char *file, unsigned initial_size)
{
    bool ret=0;
    if(file==NULL)
        exit(-1);

    lock_acquire(&filesys_lock);
    ret=filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return ret;
}

bool remove (const char *file)
{
    bool ret=0;

    if(file==NULL)
        exit(-1);

    lock_acquire(&filesys_lock);
    ret=filesys_remove(file);
    lock_release(&filesys_lock);
    return ret;
}
int open (const char *file)
{
    int i;
    int ret=-1;

    if(file==NULL)
        exit(-1);
    
    lock_acquire(&filesys_lock);
    struct file* fp = filesys_open(file);
    if (fp == NULL) {               
        ret=-1; 
    } else {
        for (i = 3; i < 256; i++) {
            if (thread_current()->fd[i] == NULL) {
                if (strcmp(thread_current()->name, file) == 0) {
                    file_deny_write(fp);
                }   


                thread_current()->fd[i] = fp;
                ret = i;
                break;
            }   
        }   
    }
    lock_release(&filesys_lock);
    return ret; 
}

int filesize (int fd)
{
    int ret=0;
    lock_acquire(&filesys_lock);
    ret=file_length(thread_current()->fd[fd]);
    lock_release(&filesys_lock);
    return ret;
    
}

int read (int fd, void *buffer, unsigned size)
{
    unsigned i;
    int ret=-1;

    if(buffer==NULL)
        exit(-1);

    lock_acquire(&filesys_lock);
    if (fd == 0) {
        for (i = 0; i < size; i ++) {
            if (((char *)buffer)[i] == '\0') {
                break;
            } 
        }   
        ret = i;
    } else if (fd > 2) {
        if(thread_current()->fd[fd]==NULL)
        {
            lock_release(&filesys_lock);
            exit(-1);
        }

        ret=file_read(thread_current()->fd[fd], buffer, size);
    }
    lock_release(&filesys_lock);
    return ret;
}
void seek (int fd, unsigned position)
{
    lock_acquire(&filesys_lock);
    file_seek(thread_current()->fd[fd], position);
    lock_release(&filesys_lock);
}

unsigned tell (int fd)
{
    unsigned ret=0;
    lock_acquire(&filesys_lock);
    ret=file_tell(thread_current()->fd[fd]);
    lock_release(&filesys_lock);
    return ret;
}

void close (int fd)
{

    lock_acquire(&filesys_lock);
    if(thread_current()->fd[fd]==NULL)
    {
        lock_release(&filesys_lock);
        exit(-1);
    }
    
    struct file *fp=thread_current()->fd[fd];
    thread_current()->fd[fd]=NULL;
    
    file_close(fp);
    lock_release(&filesys_lock);
}
