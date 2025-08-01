#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

#define USER_STACK_LIMIT 0x1000

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
  
  // Use a separate copy for thread name extraction
  char *name_copy = palloc_get_page(0);
  if (name_copy == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;
  }
  strlcpy(name_copy, file_name, PGSIZE);
  
  char *name; 
  char *savepointer;
  name = strtok_r(name_copy, " ", &savepointer);
  
  tid = thread_create (name, PRI_DEFAULT, start_process, fn_copy);
  
  palloc_free_page(name_copy);
  
  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
    return TID_ERROR;  // Return immediately, don't wait on semaphore!
  }
  
  // Only wait on semaphore if thread was created successfully
  sema_down(&thread_current()->load_sema);
  if(!thread_current()->load_success)
    tid = TID_ERROR;

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  
  // Initialize all the register fields
  if_.edi = 0;
  if_.esi = 0; 
  if_.ebp = 0;
  if_.esp_dummy = 0;
  if_.ebx = 0;
  if_.edx = 0;
  if_.ecx = 0;
  if_.eax = 0;
  
  // Set segment registers
  if_.gs = SEL_UDSEG;
  if_.fs = SEL_UDSEG;
  if_.es = SEL_UDSEG;
  if_.ds = SEL_UDSEG;
  
  // Set interrupt/exception fields
  if_.vec_no = 0;
  if_.error_code = 0;
  if_.frame_pointer = NULL;
  
  // CPU-pushed fields
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  if_.ss = SEL_UDSEG;
    
  success = load (file_name, &if_.eip, &if_.esp);


  /* Signal parent whether load succeeded */
  struct thread *parent = thread_current()->parent;
         
if (parent != NULL) {
  /* Add to children list with interrupts disabled */
  if (success) {
    enum intr_level old_level = intr_disable();
    list_push_back(&parent->children, &thread_current()->child_elem);
    intr_set_level(old_level);
  }
  parent->load_success = success;
 
  sema_up(&parent->load_sema);  // Move inside the if block
}


  /* Free resources */
  palloc_free_page (file_name);
  
  if (!success) {
    thread_exit ();
  }

  /* Start user process */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid) 
{
  struct thread *cur = thread_current();
  struct thread *child = NULL;
  struct list_elem *e;
  
  /* Find the child with interrupts disabled to prevent races */
  
  for(e = list_begin(&cur->children); e != list_end(&cur->children); e = list_next(e))
  {
    struct thread *t = list_entry(e, struct thread, child_elem);
    if(t->tid == child_tid){
      child = t;
      break;
    }
  }
  
  if(child == NULL) {
    return -1;
  }
  
  if(child->waited) {
    return -1;
  }
  
  child->waited = true;
  /* Wait for child to exit */
  sema_down(&child->wait_sema);
  
  /* Get exit status */
  int exit_status = child->exit_status;
  
  /* Remove from children list with interrupts disabled */
  list_remove(&child->child_elem);
  
  /* Allow child to be freed */
  sema_up(&child->exit_sema);
  
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  for (int fd = 0; fd < 128; fd++) {
    if (cur->fd[fd] != NULL) {
      file_close(cur->fd[fd]);
      cur->fd[fd] = NULL;
    }
  }
  
  /* Close executable file */
  if (cur->file != NULL) {
    file_allow_write(cur->file);
    file_close(cur->file);
    cur->file = NULL;
  }
  /* Close executable file */
  if (cur->file != NULL) {
    file_allow_write(cur->file);
    file_close(cur->file);
    cur->file = NULL;
  }

  /* Notify parent we're done */
  if(cur->parent != NULL) {
    sema_up(&cur->wait_sema);
    /* Wait for parent to collect our exit status */
    sema_down(&cur->exit_sema);
  } else {
    /* If we're an orphan, we can exit immediately */
    // Don't wait for parent that doesn't exist
  }
  
  /* Remove all children with interrupts disabled */
  enum intr_level old_level = intr_disable();
  while (!list_empty(&cur->children)) {
    struct list_elem *e = list_pop_front(&cur->children);
    struct thread *child = list_entry(e, struct thread, child_elem);
    child->parent = NULL;
    /* Wake up any orphaned children waiting on exit_sema */
    if (child->status == THREAD_DYING) {
      sema_up(&child->exit_sema);
    }
  }
  intr_set_level(old_level);
    
  /* Destroy page directory */
  pd = cur->pagedir;
  if (pd != NULL) 
  {
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp, const char *file_name);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  
  // Extract just the executable name from the command line
  char *exe_name = palloc_get_page(0);  // Use palloc instead of malloc
  if (exe_name == NULL)
    return false;
    
  strlcpy(exe_name, file_name, PGSIZE);
  char *save_ptr;
  char *token = strtok_r(exe_name, " ", &save_ptr);
  
  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file - ONLY ONCE! */
  file = filesys_open (token);
  if (file == NULL) 
    {
      goto done; 
    }
  
  /* Store file handle and deny writes */
  thread_current()->file = file;  
  file_deny_write(file);    
  
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (uint8_t *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp, file_name))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not.
     We do NOT close the file here - it stays open while the process runs
     and is closed in process_exit(). */
  palloc_free_page(exe_name);
  return success;
}
/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;
  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Check if page already exists */
      uint8_t *existing_kpage = pagedir_get_page(thread_current()->pagedir, upage);
      uint8_t *kpage;
      
      if (existing_kpage != NULL) {
        kpage = existing_kpage;
        
        /* Read into the existing page - this handles overlapping segments */
        if (file_read (file, kpage + pg_ofs(upage), page_read_bytes) != (int) page_read_bytes) {
          return false; 
        }
        
        /* Zero the rest if needed */
        if (page_zero_bytes > 0) {
          memset (kpage + pg_ofs(upage) + page_read_bytes, 0, page_zero_bytes);
        }
      } else {
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL) {
          return false;
        }

        /* Load this page. */
        if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
          palloc_free_page (kpage);
          return false; 
        }
        
        memset (kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) {
          palloc_free_page (kpage);
          return false; 
        }
      }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp, const char *cmd_line_args) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
  {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
    {
      *esp = PHYS_BASE;
      
      /* Use palloc instead of malloc in kernel */
      char *cmd_copy = palloc_get_page(0);
    if (cmd_copy == NULL) {
    // Page is already installed, just clear the mapping
    pagedir_clear_page(thread_current()->pagedir, 
                ((uint8_t *) PHYS_BASE) - PGSIZE);
    return false;
         }
      
      strlcpy(cmd_copy, cmd_line_args, PGSIZE);
      char *argv[128];
      int argc = 0;
      
      char *save_pointer;
      char *token;
      
      /* Parse arguments with bounds checking */
      for(token = strtok_r(cmd_copy, " ", &save_pointer);
          token != NULL && argc < 127;
          token = strtok_r(NULL, " ", &save_pointer)) {
        argv[argc] = token;
        argc++;
      }
      
      if (argc == 0) {
        palloc_free_page(cmd_copy);
        palloc_free_page(kpage);
        return false;
      }
      
      /* Push argument strings onto stack */
      for(int i = argc - 1; i >= 0; i--) {
        size_t len = strlen(argv[i]) + 1;
        *esp -= len;
        
        /* Check for stack overflow */
        if (*esp < (void *)((uint8_t *)PHYS_BASE - PGSIZE)) {
          palloc_free_page(cmd_copy);
          return false;
        }
        
        memcpy(*esp, argv[i], len);
        argv[i] = *esp;  /* Update to stack address */
      }
      
      /* Word align to 4-byte boundary */
      while ((uintptr_t)*esp % 4 != 0) {
        *esp = (uint8_t *)*esp - 1;
        *(uint8_t *)*esp = 0;
      }
      
      /* Push null pointer sentinel */
      *esp = (uint8_t *)*esp - sizeof(char *);
      *(char **)*esp = NULL;
      
      /* Push argv pointers in reverse order */
      for (int i = argc - 1; i >= 0; i--) {
        *esp = (uint8_t *)*esp - sizeof(char *);
        *(char **)*esp = argv[i];
      }
      
      /* Save argv address */
      char **argv_ptr = (char **)*esp;
      
      /* Push argv (pointer to argv[0]) */
      *esp = (uint8_t *)*esp - sizeof(char **);
      *(char ***)*esp = argv_ptr;
      
      /* Push argc */
      *esp = (uint8_t *)*esp - sizeof(int);
      *(int *)*esp = argc;
      
      /* Push fake return address */
      *esp = (uint8_t *)*esp - sizeof(void *);
      *(void **)*esp = NULL;
      
      palloc_free_page(cmd_copy);
    }
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}    