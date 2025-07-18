# Pintos OS Project

This repository contains my implementation of Project 1 (**Threads**) and Project 2 (**User Programs**) from the [Pintos Operating System](https://web.stanford.edu/class/cs140/projects/pintos/pintos_1.html), a teaching operating system used in many university-level OS courses.

###  Project 1: Threads

**Focus:** Kernel-level thread management and scheduling

**Key Implementations:**

- **Priority Scheduling**  
  Implemented a priority-based thread scheduler to replace the default round-robin scheduling.

- **Priority Donation**  
  Solved the *priority inversion* problem by implementing nested priority donation when threads acquire locks.

- **Advanced Scheduler**  
  Added support for the multi-level feedback queue scheduler (MLFQS), using fixed-point arithmetic to calculate recent CPU usage and load average.

- **Synchronization Primitives**  
  Enhanced semaphores, locks, and condition variables with priority-aware mechanisms.

---

### Project 2: User Programs

**Focus:** User process execution and syscall interface

**Key Implementations:**

- **System Calls**  
  Implemented system calls such as:
  - `exit`, `exec`, `wait`
  - File operations: `open`, `read`, `write`, `close`
  - File descriptors per process

- **Process Isolation & Validation**  
  Ensured safe access to user memory using pointer validation and address checks.

- **Process Management**  
  Designed mechanisms for process creation, loading ELF executables, argument passing via stack setup, and process waiting with proper synchronization.

- **File System Access Control**  
  Prevented concurrent access issues to the file system using locks.
  
---
## Repository Structure

pintos/
├── src/
│ ├── threads/ # Project 1: Thread management
│ ├── userprog/ # Project 2: User program support



