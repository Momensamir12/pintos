#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "process.h"
#include "pagedir.h"
#include <string.h>
#include <stdlib.h>
#include "filesys/filesys.h"
#include "filesys/file.h"

static struct lock lock;

/* Function declarations */
static void syscall_handler(struct intr_frame *);
static bool get_user_bytes(void *dst, const void *usrc, size_t bytes);
static bool validate_string(const char *str);
static bool validate_user_buffer(const void *buffer, size_t size);
static int allocate_fd(void);
void halt(void);
static void sys_exit(int status);
tid_t sys_exec(const char *cmd_line);
int sys_wait(int pid);
bool sys_create(const char *file, unsigned intial_size);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_read(int fd, void *buffer, unsigned size);
int file_size(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_write(int fd, void *buffer, unsigned size);


void syscall_init(void)
{
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&lock);
}

/* Safely copy bytes from user space to kernel space */
static bool get_user_bytes(void *dst, const void *usrc, size_t bytes)
{
  uint8_t *dst_byte = (uint8_t *)dst;
  const uint8_t *src_byte = (const uint8_t *)usrc;
  
  for (size_t i = 0; i < bytes; i++) {
    /* Validate each byte before reading */
    if (!is_user_vaddr(src_byte + i) || 
        pagedir_get_page(thread_current()->pagedir, src_byte + i) == NULL) {
      return false;
    }
    dst_byte[i] = src_byte[i];
  }
  return true;
}

/* Validate a string in user space */
static bool validate_string(const char *str)
{
  if (str == NULL)
    return false;
    
  /* Check each character until we find null terminator */
  while (true) {
    /* Validate current byte */
    if (!is_user_vaddr(str) || 
        pagedir_get_page(thread_current()->pagedir, str) == NULL)
      return false;
      
    /* Check if it's the null terminator */
    if (*str == '\0')
      break;
      
    str++;
  }
  return true;
}

/* Validate a buffer in user space */
static bool validate_user_buffer(const void *buffer, size_t size)
{
  if (buffer == NULL)
    return false;
    
  const uint8_t *buf = (const uint8_t *)buffer;
  const uint8_t *end = buf + size;
  
  /* Check first byte */
  if (!is_user_vaddr(buf) || 
      pagedir_get_page(thread_current()->pagedir, buf) == NULL)
    return false;
    
  /* Check last byte if size > 0 */
  if (size > 0) {
    if (!is_user_vaddr(end - 1) || 
        pagedir_get_page(thread_current()->pagedir, end - 1) == NULL)
      return false;
  }
  
  /* For larger buffers, check each page boundary */
  uintptr_t page_start = pg_round_down((uintptr_t)buf);
  uintptr_t page_end = pg_round_down((uintptr_t)(end - 1));
  
  for (uintptr_t page = page_start; page <= page_end; page += PGSIZE) {
    if (pagedir_get_page(thread_current()->pagedir, (void *)page) == NULL)
      return false;
  }
  
  return true;
}

static void
syscall_handler(struct intr_frame *f)
{
  void *esp = f->esp;
  
  /* Validate esp first */
  if (!is_user_vaddr(esp) || 
      pagedir_get_page(thread_current()->pagedir, esp) == NULL) {
    sys_exit(-1);
    return;
  }
  
  /* Safely read syscall number */
  int syscall_num;
  if (!get_user_bytes(&syscall_num, esp, sizeof(int))) {
    sys_exit(-1);
    return;
  }
  
  switch (syscall_num)
  {
  case SYS_HALT:
    halt();
    break;

  case SYS_EXIT:
  {
    int status;
    if (!get_user_bytes(&status, (uint8_t *)esp + 4, sizeof(int))) {
      sys_exit(-1);
      return;
    }
    sys_exit(status);
  }
  break;

  case SYS_EXEC:
  {
    char *cmd;
    if (!get_user_bytes(&cmd, (uint8_t *)esp + 4, sizeof(char *))) {
      sys_exit(-1);
      return;
    }
    if (!validate_string(cmd)) {
      sys_exit(-1);
      return;
    }
    //lock_acquire(&lock);
    f->eax = sys_exec(cmd);
    //lock_release(&lock);
  }
  break;

  case SYS_WAIT:
  {
    int pid;
    if (!get_user_bytes(&pid, (uint8_t *)esp + 4, sizeof(int))) {
      sys_exit(-1);
      return;
    }
    f->eax = sys_wait(pid);
  }
  break;

  case SYS_CREATE:
  {
    char *file;
    unsigned size;
    
    if (!get_user_bytes(&file, (uint8_t *)esp + 4, sizeof(char *)) ||
        !get_user_bytes(&size, (uint8_t *)esp + 8, sizeof(unsigned))) {
      sys_exit(-1);
      return;
    }
    
    if (!validate_string(file)) {
      sys_exit(-1);
      return;
    }
    
    f->eax = sys_create(file, size);
  }
  break;

  case SYS_REMOVE:
  {
    char *file;
    if (!get_user_bytes(&file, (uint8_t *)esp + 4, sizeof(char *))) {
      sys_exit(-1);
      return;
    }
    if (!validate_string(file)) {
      sys_exit(-1);
      return;
    }
    f->eax = sys_remove(file);
  }
  break;

  case SYS_OPEN:
  {
    char *file;
    if (!get_user_bytes(&file, (uint8_t *)esp + 4, sizeof(char *))) {
      sys_exit(-1);
      return;
    }
    if (!validate_string(file)) {
      sys_exit(-1);
      return;
    }
    f->eax = sys_open(file);
  }
  break;

  case SYS_FILESIZE:
  {
    int fd;
    if (!get_user_bytes(&fd, (uint8_t *)esp + 4, sizeof(int))) {
      sys_exit(-1);
      return;
    }
    f->eax = file_size(fd);
  }
  break;

  case SYS_READ:
  {
    int fd;
    void *buffer;
    unsigned size;
    
    if (!get_user_bytes(&fd, (uint8_t *)esp + 4, sizeof(int)) ||
        !get_user_bytes(&buffer, (uint8_t *)esp + 8, sizeof(void *)) ||
        !get_user_bytes(&size, (uint8_t *)esp + 12, sizeof(unsigned))) {
      sys_exit(-1);
      return;
    }
    
    if (buffer == NULL || !validate_user_buffer(buffer, size)) {
      sys_exit(-1);
      return;
    }
    
    f->eax = sys_read(fd, buffer, size);
  }
  break;

  case SYS_WRITE:
  {
    int fd;
    void *buffer;
    unsigned size;
    
    if (!get_user_bytes(&fd, (uint8_t *)esp + 4, sizeof(int)) ||
        !get_user_bytes(&buffer, (uint8_t *)esp + 8, sizeof(void *)) ||
        !get_user_bytes(&size, (uint8_t *)esp + 12, sizeof(unsigned))) {
      sys_exit(-1);
      return;
    }
    
    /* Handle zero size before buffer validation */
    if (size == 0) {
      f->eax = 0;
      return;
    }
    
    if (buffer == NULL || !validate_user_buffer(buffer, size)) {
      sys_exit(-1);
      return;
    }
    
    f->eax = sys_write(fd, buffer, size);
  }
  break;

  case SYS_SEEK:
  {
    int fd;
    unsigned position;
    
    if (!get_user_bytes(&fd, (uint8_t *)esp + 4, sizeof(int)) ||
        !get_user_bytes(&position, (uint8_t *)esp + 8, sizeof(unsigned))) {
      sys_exit(-1);
      return;
    }
    
    sys_seek(fd, position);
  }
  break;

  case SYS_TELL:
  {
    int fd;
    if (!get_user_bytes(&fd, (uint8_t *)esp + 4, sizeof(int))) {
      sys_exit(-1);
      return;
    }
    f->eax = sys_tell(fd);
  }
  break;

  case SYS_CLOSE:
  {
    int fd;
    if (!get_user_bytes(&fd, (uint8_t *)esp + 4, sizeof(int))) {
      sys_exit(-1);
      return;
    }
    sys_close(fd);
  }
  break;

  default:
    sys_exit(-1);
  }
}

static void sys_exit(int status)
{
  struct thread *cur = thread_current();
  int i;
  for(i = 2; i < MAX_FD; i++){
    struct file *f = cur->fd[i];
    if(f != NULL)
    {
      lock_acquire(&lock);
      file_close(f);
      lock_release(&lock);
      cur->fd[i] = NULL;
    }
  }
  cur->exit_status = status;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  thread_exit();
}

tid_t sys_exec(const char *cmd_line)
{
  
  tid_t tid = process_execute(cmd_line);
  tid_t result = (tid == TID_ERROR) ? -1 : tid;
  return result;
}

void halt(void) { shutdown_power_off(); }

int sys_wait(int pid)
{
  return process_wait(pid);
}

bool sys_create(const char *file, unsigned intial_size)
{
  lock_acquire(&lock);
  bool created = filesys_create(file, intial_size);
  lock_release(&lock);
  return created;
}

bool sys_remove(const char *file)
{
  lock_acquire(&lock);
  bool removed = filesys_remove(file);
  lock_release(&lock);
  return removed;
}

int sys_open(const char *file)
{
  if (file == NULL)
    return -1;

  lock_acquire(&lock);
  struct file *f = filesys_open(file);
  lock_release(&lock);

  if (f == NULL)
    return -1;

  int fd = allocate_fd();
  if (fd == -1) {
    file_close(f);
    return -1;  
  }

  thread_current()->fd[fd] = f;
  return fd;
}

static int allocate_fd(void)
{
  struct thread *cur = thread_current();
  for (int fd = 2; fd < MAX_FD; fd++)
  {
    if (cur->fd[fd] == NULL)
      return fd;
  }
  return -1;
}

int sys_read(int fd, void *buffer, unsigned size)
{
  if (fd < 0 || fd >= MAX_FD)
    return -1;
    
  if (buffer == NULL)
    return -1;
    
  unsigned bytes_read = 0;
  
  if (fd == 0)
  {
    lock_acquire(&lock);
    uint8_t *buf = (uint8_t *)buffer;
    for (bytes_read = 0; bytes_read < size; bytes_read++)
    {
      buf[bytes_read] = input_getc();
    }
    lock_release(&lock);
    return bytes_read;
  }

  if (fd == 1)
    return -1;

  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    return -1;

  lock_acquire(&lock);
  bytes_read = file_read(f, buffer, size);
  lock_release(&lock);
  
  return bytes_read;
}

int file_size(int fd)
{
  if (fd < 0 || fd >= MAX_FD)
    return -1;

  struct file *f = thread_current()->fd[fd];
  if (f != NULL)
    return file_length(f);
  else
    return -1;
}

int sys_write(int fd, void *buffer, unsigned size)
{
  if (fd < 0 || fd >= MAX_FD)
    return -1;

  /* Handle zero size */
  if (size == 0)
    return 0;

  unsigned bytes_written = 0;

  if (fd == 0)
    return -1;

  if (fd == 1)
  {
    lock_acquire(&lock);
    putbuf(buffer, size);
    bytes_written = size;
    lock_release(&lock);
  }
  else
  {
    struct file *f = thread_current()->fd[fd];
    if (f == NULL)
      return -1;

    lock_acquire(&lock);
    bytes_written = (int)file_write(f, buffer, size);
    lock_release(&lock);
  }
  return bytes_written;
}

void sys_seek(int fd, unsigned position)
{
  struct file *f = thread_current()->fd[fd];
  if(f == NULL)
    return;
  lock_acquire(&lock);
  file_seek(f, position);
  lock_release(&lock);
}

unsigned sys_tell(int fd)
{
  if (fd < 2 || fd >= MAX_FD)
    return -1;
    
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    return -1;
    
  lock_acquire(&lock);
  unsigned pos = file_tell(f);
  lock_release(&lock);
  
  return pos;
}

void sys_close(int fd)
{
  if (fd < 2 || fd >= MAX_FD)
    return;
    
  struct file *f = thread_current()->fd[fd];
  if (f == NULL)
    return;
    
  lock_acquire(&lock);
  file_close(f);
  thread_current()->fd[fd] = NULL;
  lock_release(&lock);
}