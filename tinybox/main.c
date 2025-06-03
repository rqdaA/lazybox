#define STDIN_FD 0
#define STDOUT_FD 1

// syscall
static long syscall(long register cmd, long register arg1, long register arg2,
                    long register arg3, long register arg4, long register arg5,
                    long register arg6) {
  long register ret;
  __asm__ volatile("mov rax, %1;"
                   "mov rdi, %2;"
                   "mov rsi, %3;"
                   "mov rdx, %4;"
                   "mov r10, %5;"
                   "mov r8, %6;"
                   "mov r9, %7;"
                   "syscall;"
                   "mov %0, rax;"
                   : "=r"(ret)
                   : "r"(cmd), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4),
                     "r"(arg5), "r"(arg6)
                   : "rax", "rdi", "rsi", "rdx", "r10", "r8", "r9", "rcx",
                     "r11");
  return ret;
}

static int inline read(int fd, void *buf, long count) {
  return syscall(0, fd, (long)buf, count, 0, 0, 0);
}
static int inline write(int fd, void *buf, long count) {
  return syscall(1, fd, (long)buf, count, 0, 0, 0);
}
static int inline close(int fd) { return syscall(3, fd, 0, 0, 0, 0, 0); }

struct stat {
  unsigned int st_dev;
  unsigned long st_ino;
  unsigned int st_mode;
  unsigned long st_nlink;
  unsigned int st_uid;
  unsigned int st_gid;
  unsigned int st_rdev;
  long st_size;
  long st_blksize;
  long st_blocks;
  long st_atime;
  long st_mtime;
  long st_ctime;
};
static int inline stat(char *pathname, struct stat *statbuf) {
  return syscall(4, (long)pathname, (long)statbuf, 0, 0, 0, 0);
}

static int inline fstat(int fd, struct stat *statbuf) {
  return syscall(5, fd, (long)statbuf, 0, 0, 0, 0);
}

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02
#define MAP_SHARED_VALIDATE 0x03
#define MAP_DROPPABLE 0x08
#define MAP_FIXED 0x10
#define MAP_ANONYMOUS 0x20
#define MAP_POPULATE 0x008000

static void inline *mmap(void *addr, long length, int prot, int flags, long fd,
                         long offset) {
  return (void *)syscall(9, (long)addr, length, prot, flags, fd, offset);
}
static int inline munmap(void *addr, long length) {
  return syscall(11, (long)addr, length, 0, 0, 0, 0);
}

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_DIRECTORY 0200000

static int inline open(char *pathname, int flags, int mode) {
  return syscall(2, (long)pathname, flags, mode, 0, 0, 0);
}

static int inline chdir(char *path) {
  return syscall(80, (long)path, 0, 0, 0, 0, 0);
}

static int inline exit(int status) {
  return syscall(60, status, 0, 0, 0, 0, 0);
}

struct linux_dirent {
  unsigned long d_ino;
  unsigned long d_off;
  unsigned short d_reclen;
  char d_name[];
};

static int inline getdents(int fd, void *dirp, int count) {
  return syscall(78, fd, (long)dirp, count, 0, 0, 0);
}
static int inline getuid() { return syscall(102, 0, 0, 0, 0, 0, 0); }

// lib

char *strchr(char *s, char c) {
  for (int i = 0;; i++) {
    if (s[i] == '\0')
      break;
    if (s[i] == c)
      return &s[i];
  }
  return 0;
}

long strlen(char *s) {
  long i = 0;
  for (;;) {
    if (!s[i])
      return i;
    i++;
  }
}

int memcmp(char *s1, char *s2, long n) {
  for (long i = 0; i < n; i++) {
    if (s1[i] != s2[i])
      return 1;
  }
  return 0;
}

void ltostr(long n, char *buf, long size) {
  int is_negative = n < 0;
  long num = !is_negative ? n : -n;
  long i = 0;
  if (num == 0) {
    buf[0] = '0';
    buf[1] = '\0';
    return;
  }

  while (num > 0 && i < size - 1) {
    buf[i++] = (num % 10) + '0';
    num /= 10;
  }
  if (is_negative) {
    buf[i++] = '-';
  }
  int len = i;
  for (int j = 0; j < len / 2; j++) {
    char temp = buf[j];
    buf[j] = buf[len - 1 - j];
    buf[len - 1 - j] = temp;
  }
}

void puts(char *s) {
  if (!*s)
    return;
  write(STDOUT_FD, s, strlen(s));
  write(STDOUT_FD, "\n", 1);
}

// commands
void cat(char *buf) {
  int fd, ret;
  long sz;
  char *filename = strchr(buf, ' ');
  char *filebuf;
  struct stat *statbuf;
  if (!filename) {
    puts("cat: No filename passed");
    return;
  }
  filename++;
  fd = open(filename, O_RDONLY, 0);
  if (!fd) {
    puts("cat: No such file");
    return;
  }
  statbuf = mmap(0, sizeof(struct stat), PROT_READ | PROT_WRITE,
                 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if ((long)statbuf < 0) {
    puts("cat: Failed to allocate a buffer for stat");
    goto cleanup_fd;
  }
  ret = fstat(fd, statbuf);
  if (ret < 0) {
    puts("cat: Failed to fstat");
    goto cleanup_stat;
  }
  sz = statbuf->st_size;
  if (sz < 0) {
    puts("cat: Invalid file");
    goto cleanup_stat;
  }
  filebuf = mmap(0, sz, PROT_READ, MAP_PRIVATE, fd, 0);
  if ((long)filebuf == -1) {
    puts("cat: Failed to mmap");
    goto cleanup_stat;
  }
  write(STDOUT_FD, filebuf, sz);
  puts("");

  munmap(filebuf, sz);
cleanup_stat:
  munmap(statbuf, sizeof(struct stat));
cleanup_fd:
  close(fd);
}

void ls(char *buf) {
  int fd, ret, pos;
  struct linux_dirent *d;
  char dirp[0x100];
  char *filename = strchr(buf, ' ');
  if (!filename) {
    filename = ".";
  } else {
    filename++;
  }
  fd = open(filename, O_RDONLY | O_DIRECTORY, 0);
  for (;;) {
    ret = getdents(fd, dirp, sizeof(dirp));
    if (ret == 0) {
      break;
    }
    if (ret < 0) {
      puts("ls: getdents failed");
      break;
    }
    for (pos = 0; pos < ret;) {
      d = (struct linux_dirent *)(dirp + pos);
      puts(d->d_name);
      pos += d->d_reclen;
    }
  }

  close(fd);
}

void cd(char *buf) {
  int ret;
  char *filename = strchr(buf, ' ');
  if (!filename) {
    puts("cd: No destination passed");
    return;
  }
  filename++;
  ret = chdir(filename);
  if (ret < 0) {
    puts("cd: chdir failed");
  }
}

void ps1() {
  char buf[0x100 + 1] = {0};
  int ret;
  write(1, getuid() == 0 ? "#" : "$", 1);
  write(1, " ", 1);
}

void _start() {
  int ret;
  char *ptr;
  char buf[0x100];

  for (;;) {
    ps1();
    ret = read(STDIN_FD, buf, 0xff);
    if (ret == 0) {
      write(1, "\n", 1);
      continue;
    }
    buf[ret] = '\0';
    ptr = strchr(buf, '\n');
    if (ptr)
      *ptr = '\0';

    if (!memcmp(buf, "cat ", 4)) {
      cat(buf);
    } else if (!memcmp(buf, "ls ", 3)) {
      ls(buf);
    } else if (!memcmp(buf, "ls\0", 3)) {
      ls(buf);
    } else if (!memcmp(buf, "cd ", 3)) {
      cd(buf);
    } else if (!memcmp(buf, "exit", 4)) {
      exit(0);
    } else {
      write(1, buf, ret);
      puts(": command not found");
    }
  }
}
