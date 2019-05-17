#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/filesys.h"
#include "filesys/off_t.h"

#include "threads/synch.h"
struct file{
  struct inode *inode;
  off_t pos;
  bool deny_write;
};

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

void check_user_vaddr(const void *vaddr)
{
  if(!is_user_vaddr(vaddr))
    exit(-1);
}

void
syscall_init (void) 
{
 lock_init(&filesys_lock);
 intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
//  printf ("system call!\n");
  int *p = f->esp;
  int syscall_number = *p;
  
  // verify address

//  printf("\n\n\n%d\n\n\n", syscall_number);
//  hex_dump(f->esp, f->esp, 100, 1);
  switch(syscall_number)
  {
    case SYS_HALT: // 0
      halt();
      break;
    case SYS_EXIT: // 1
      check_user_vaddr(f->esp + 4); 
      exit(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_EXEC: // 2
      check_user_vaddr(f->esp + 4);
      f->eax = exec((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_WAIT: // 3
      check_user_vaddr(f->esp + 4); 
      f->eax = wait(*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CREATE: // 4
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE: // 5
      check_user_vaddr(f->esp + 4);
      f->eax = remove((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN: // 6
      check_user_vaddr(f->esp + 4);
      f->eax = open((const char *)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE: // 7
      check_user_vaddr(f->esp + 4);
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_READ: // 8
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      check_user_vaddr(f->esp + 12);
      f->eax = read((int)*(uint32_t *)(f->esp + 4), (void*)*(uint32_t *)(f->esp + 8), (unsigned)*((uint32_t *)(f->esp + 12)));
      break;
    case SYS_WRITE: // 9
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      check_user_vaddr(f->esp + 12);
      f->eax = write((int)*(uint32_t *)(f->esp + 4), (void *)*(uint32_t *)(f->esp + 8), (unsigned)*(uint32_t *)(f->esp + 12));
      break;
    case SYS_SEEK: // 10
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL: // 11
      check_user_vaddr(f->esp + 4);
      f->eax = tell((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE: // 12
      check_user_vaddr(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
      break;
    default:
      //exit
      break;
  }
  //thread_exit ();
}

void exit(int status)
{
  int i;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  for(i=3; i<128; i++)
  {
    if(thread_current()->fd[i] != NULL)
    {
      close(i);
    }
  }

  thread_exit();
}

int write(int fd, const void *buffer, unsigned size)
{
  int ret = -1;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if(fd == 1)
  {
    putbuf(buffer, size);
    ret = size;
  }
  else if(fd > 2)
  {
    if(thread_current()->fd[fd] == NULL)
    {
      lock_release(&filesys_lock);
      exit(-1);
    }
    if(thread_current()->fd[fd]->deny_write)
      file_deny_write(thread_current()->fd[fd]);
    ret = file_write(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return ret;
}

void halt(void)
{
  shutdown_power_off();
}

pid_t exec(const char *cmd_line)
{
  return process_execute(cmd_line);
}

int wait(pid_t pid)
{
  return process_wait(pid);
}

int read(int fd, void *buffer, unsigned size)
{
  int i;
  int ret;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if(fd == 0)
  {
    for(i=0; i<size; i++)
    {
      if(((char *)buffer)[i] == '\0')
        break;
    }
    ret = i;
  }
  else if(fd > 2)
  {
    if(thread_current()->fd[fd] == NULL)
      exit(-1);
    ret = file_read(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return ret;
}

bool create(const char *file, unsigned initial_size)
{
  if(file == NULL)
    exit(-1);
  return filesys_create(file, initial_size); 
}

int open(const char *file)
{
  int i;
  int ret = -1;
  struct file * fp;
  if(file == NULL)
    exit(-1);

  check_user_vaddr(file);
  lock_acquire(&filesys_lock);
  fp = filesys_open(file);
  if(fp == NULL)
    ret = -1;
  else
  {
    for(i=3; i<128; i++)
    {
      if(thread_current()->fd[i] == NULL)
      {
        if(strcmp(thread_current()->name, file) == 0)
	{
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

bool remove(const char *file)
{
  return filesys_remove(file);
}

int filesize(int fd)
{
  return file_length(thread_current()->fd[fd]);
}

void seek(int fd, unsigned position)
{
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell(int fd)
{
  return file_tell(thread_current()->fd[fd]);
}

void close(int fd)
{
  struct file *fp;
  if(thread_current()->fd[fd] == NULL)
    exit(-1);
  fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
}
