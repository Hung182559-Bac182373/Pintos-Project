#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/off_t.h"
#include "threads/synch.h"


static void syscall_handler (struct intr_frame *);
{

  switch (*(uint32_t *)(f->esp)) {
  
    case SYS_CREATE:
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_REMOVE:
      check_user_vaddr(f->esp + 4);
      f->eax = remove((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      check_user_vaddr(f->esp + 4);
      f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      check_user_vaddr(f->esp + 4);
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
       break;
  
    case SYS_SEEK:
      check_user_vaddr(f->esp + 4);
      check_user_vaddr(f->esp + 8);
      seek((int)*(uint32_t *)(f->esp + 4), (unsigned)*(uint32_t *)(f->esp + 8));
      break;
    case SYS_TELL:
      check_user_vaddr(f->esp + 4);
      f->eax = tell((int)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_CLOSE:
      check_user_vaddr(f->esp + 4);
      close((int)*(uint32_t *)(f->esp + 4));
      break;
  }
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

bool create (const char *file, unsigned initial_size) {
  return filesys_create(file, initial_size);
}

bool remove (const char *file) {
  return filesys_remove(file);
}

int open (const char *file) {
  int i;
  struct file* fp = filesys_open(file);
  if (fp == NULL) {
      return -1; 
  } else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        thread_current()->fd[i] = fp; 
        return i;
      } 
    }   
  }
  return -1; 
}

int filesize (int fd) {
  return file_length(thread_current()->fd[fd]);
}

int read (int fd, void* buffer, unsigned size) {
  int i;
  if (fd == 0) {
    for (i = 0; i < size; i ++) {  
      if (((char *)buffer)[i] == '\0') {
        break;
      }   
    }   
  } else if (fd > 2) {
    return file_read(thread_current()->fd[fd], buffer, size);
  }
  return i;
}

int write (int fd, const void *buffer, unsigned size) {


  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  } else if (fd > 2) {
    return file_write(thread_current()->fd[fd], buffer, size);
  }
  return -1; 
}     

void seek (int fd, unsigned position) {
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd) {
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd) {
  return file_close(thread_current()->fd[fd]);
}

void exit (int status) {
  int i;
  printf("%s: exit(%d)\n", thread_name(), status);
  thread_current()->exit_status = status;
  for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] != NULL) {
          close(i);
      }   
  }   
  thread_exit (); 
}

bool create (const char *file, unsigned initial_size) {
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  return filesys_create(file, initial_size);

}

bool remove (const char *file) {
  if (file == NULL) {
      exit(-1);
  }   
  check_user_vaddr(file);
  return filesys_remove(file);
}

int open (const char *file) {
  int i;
  struct file* fp; 
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  fp = filesys_open(file);
  if (fp == NULL) {
      return -1;
  } else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        thread_current()->fd[i] = fp;
        return i;
      }
    }
  }
  return -1;
}

int filesize (int fd) {
  if (thread_current()->fd[fd] == NULL) {
      exit(-1);
  }
  return file_length(thread_current()->fd[fd]);
}

int read (int fd, void* buffer, unsigned size) {
  int i;
  check_user_vaddr(buffer);
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      exit(-1);
    }
    return file_read(thread_current()->fd[fd], buffer, size);
  }
  return i;
}

int write (int fd, const void *buffer, unsigned size) {

  check_user_vaddr(buffer);
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      exit(-1);
    }
    return file_write(thread_current()->fd[fd], buffer, size);
  }
  return -1;
}

void seek (int fd, unsigned position) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  file_seek(thread_current()->fd[fd], position);
}

unsigned tell (int fd) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  return file_tell(thread_current()->fd[fd]);
}

void close (int fd) {
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  return file_close(thread_current()->fd[fd]);
}

static void
syscall_handler (struct intr_frame *f) 
{

  switch (*(uint32_t *)(f->esp)) {
  
    case SYS_CREATE:
      check_user_vaddr(f->esp + 16);
      check_user_vaddr(f->esp + 20);
      f->eax = create((const char *)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp + 20));
      break;
    case SYS_REMOVE:
      check_user_vaddr(f->esp + 4);
      f->eax = remove((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_OPEN:
      check_user_vaddr(f->esp + 4);
      f->eax = open((const char*)*(uint32_t *)(f->esp + 4));
      break;
    case SYS_FILESIZE:
      check_user_vaddr(f->esp + 4);
      f->eax = filesize((int)*(uint32_t *)(f->esp + 4));
      break;
  
    case SYS_SEEK:
      check_user_vaddr(f->esp + 16);
      check_user_vaddr(f->esp + 20);
      seek((int)*(uint32_t *)(f->esp + 16), (unsigned)*(uint32_t *)(f->esp + 20));
      break;
  }
}

void close (int fd) {
  struct file* fp;
  if (thread_current()->fd[fd] == NULL) {
    exit(-1);
  }
  fp = thread_current()->fd[fd];
  thread_current()->fd[fd] = NULL;
  return file_close(fp);
} 

int open (const char *file) {
  int i;
  struct file* fp; 
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  fp = filesys_open(file);
  if (fp == NULL) {
      return -1; 
  } else {
    for (i = 3; i < 128; i++) {
      if (thread_current()->fd[i] == NULL) {
        if (strcmp(thread_current()->name, file) == 0) {
            file_deny_write(fp);
        }   
        thread_current()->fd[i] = fp; 
        return i;
        }   
    }   
  }
  return -1; 
}

int write (int fd, const void *buffer, unsigned size) {
  check_user_vaddr(buffer);
  if (fd == 1) {
    putbuf(buffer, size);
    return size;
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      exit(-1);
    }
    if (thread_current()->fd[fd]->deny_write) {
        file_deny_write(thread_current()->fd[fd]);
    }
    return file_write(thread_current()->fd[fd], buffer, size);
  }
  return -1;
}

struct file
  {
    struct inode *inode;        /* File's inode. */
    off_t pos;                  /* Current position. */
    bool deny_write;            /* Has file_deny_write() been called? */
  };

  struct lock filesys_lock;
void
syscall_init (void) 
{
  lock_init(&filesys_lock); /* new */
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

int open (const char *file) {
  int i;
  int ret = -1;
  struct file* fp;
  if (file == NULL) {
      exit(-1);
  }
  check_user_vaddr(file);
  lock_acquire(&filesys_lock);
  fp = filesys_open(file);
  if (fp == NULL) {
      ret = -1;
  } else {
    for (i = 3; i < 128; i++) {
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


int read (int fd, void* buffer, unsigned size) {
  int i;
  int ret;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 0) {
    for (i = 0; i < size; i ++) {
      if (((char *)buffer)[i] == '\0') {
        break;
      }
    }
    ret = i;
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      exit(-1);
      }
    ret = file_read(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return ret;
}

int write (int fd, const void *buffer, unsigned size) {

  int ret = -1;
  check_user_vaddr(buffer);
  lock_acquire(&filesys_lock);
  if (fd == 1) {
    putbuf(buffer, size);
    ret = size;
  } else if (fd > 2) {
    if (thread_current()->fd[fd] == NULL) {
      lock_release(&filesys_lock);
      exit(-1);
    }
    if (thread_current()->fd[fd]->deny_write) {
        file_deny_write(thread_current()->fd[fd]);
    }
    ret = file_write(thread_current()->fd[fd], buffer, size);
  }
  lock_release(&filesys_lock);
  return ret;
}