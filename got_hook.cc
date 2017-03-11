// Copyright (c) 2017 Lonny Wang <lonnywang@qq.com>
//
// URL: https://github.com/lonnywang/glibcmock
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//
// Author: Lonny Wang <lonnywang@qq.com>
//
// Mock glibc function by changing GOT value to custom static function address.
//
// As we know, glibc function address is store in GOT (Global Offset Table).
// Change the GOT value to a custom static function address, then the glibc call
// will call the custom static function actually. In the custom static function,
// we make it to call a Google Mock method, then we have mocked the glibc function.

#include "got_hook.h"

#include <elf.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <mutex>
#include <stack>
#include <memory>

#include "gtest/gtest.h"

#ifdef SYS_gettid
// get current thread id
#define gettid() syscall(SYS_gettid)
#endif

namespace testing {

// ELF information
struct Elf_Info {
    // initialized or not
    bool inited{false};
    // section header table
    std::unique_ptr<Elf64_Shdr[]> sh_tbl;
    // section header table count
    size_t sh_cnt{0};
    // section header string table
    std::unique_ptr<char[]> shstr_tbl;
    // section header string table size
    size_t shstr_tab_size{0};
    // dynamic linker symbol table
    const Elf64_Sym *dynsym_tbl{nullptr};
    // dynamic linker symbol count
    size_t dynsym_cnt{0};
    // dynamic string table
    const char *dynstr_tbl{nullptr};
    // dynamic string count
    size_t dynstr_size{0};
    // dynamic relocation entries table
    const Elf64_Rela *dyn_tbl{nullptr};
    // dynamic relocation entries count
    size_t dyn_cnt{0};
    // procedure linkage table
    const Elf64_Rela *plt_tbl{nullptr};
    // procedure linkage count
    size_t plt_cnt{0};
#ifdef PT_GNU_RELRO
    // begin of segment virtual address
    const char *relro_start{nullptr};
    // end of segment virtual address
    const char *relro_end{nullptr};
#endif
};

// Initialize ELF information.
static void InitElfInfo() noexcept;
// Initialize ELF information.
static void DoInitElfInfo(const int fd, const Elf64_Ehdr *ehdr) noexcept;
// Get ELF section table.
static void GetSectionTable(const char *name, const Elf64_Shdr **shdr) noexcept;
// Get GOT entry address of the function.
static void GetGotEntryAddr(const char *name, void ***addr) noexcept;
// Get GOT entry address of the function.
static void DoGetGotAddr(const char* name, size_t len, const Elf64_Rela* rel, void*** addr, bool *found) noexcept;
// Set GOT value to a static function address.
static void SetGotValue(void **addr, void *value) noexcept;

// ELF information
static Elf_Info g_elf_info;
// the thread which holds the lock
static pid_t g_locked_thread_id;
// key is the GOT entry address, value is the original function address
std::map<void**, void*> g_original_addr;
// avoid multiple threads changing GOT value at the same time
static std::recursive_mutex g_hook_mutex;
// LIFO of GotHook object id to support recursive call
static std::stack<unsigned int> g_object_stack;

#ifdef PT_GNU_RELRO
// memory page size
static size_t g_page_size = sysconf(_SC_PAGESIZE);
#endif

// auto add error number and error description string to the end
#define E(S) S << " error [" << errno << "] [" << strerror(errno) << "]"

// Initialize ELF information.
static void InitElfInfo() noexcept {
    // get ELF base address
    FILE *fp = fopen("/proc/self/maps", "r");
    E(ASSERT_NE(nullptr, fp) << "fopen [/proc/self/maps]");
    char buf[128];
    auto p = fgets(buf, sizeof(buf), fp);
    fclose(fp);
    E(ASSERT_NE(nullptr, p) << "fgets [/proc/self/maps]");
    unsigned long base;
    ASSERT_EQ(1, sscanf(buf, "%lx-%*x r-xp %*x %*x:%*x %*u ", &base)) << "invalid [/proc/self/maps] [" << buf << "]";

    // open executable file to read ELF information
    int fd = open("/proc/self/exe", O_RDONLY);
    E(ASSERT_NE(-1, fd) << "open [/proc/self/exe]");
    DoInitElfInfo(fd, (const Elf64_Ehdr*) base);
    close(fd);

    // initialize successfully or not
    if (!testing::Test::HasFailure()) {
        g_elf_info.inited = true;
    }
}

// Initialize ELF information.
static void DoInitElfInfo(const int fd, const Elf64_Ehdr *ehdr) noexcept {
    ASSERT_NE(nullptr, ehdr) << "elf ehdr is nullptr";
    ASSERT_EQ(ET_EXEC, ehdr->e_type) << "object file type should be [ET_EXEC]";

    // read section header table
    ASSERT_EQ(sizeof(Elf64_Shdr), ehdr->e_shentsize) << "section header table entry size invalid";
    off_t offset = ehdr->e_shoff;
    E(ASSERT_EQ(offset, lseek(fd, offset, SEEK_SET)) << "seek section header table");
    g_elf_info.sh_tbl = std::unique_ptr<Elf64_Shdr[]>(new Elf64_Shdr[ehdr->e_shnum]);
    ssize_t size = ehdr->e_shnum * ehdr->e_shentsize;
    E(ASSERT_EQ(size, read(fd, g_elf_info.sh_tbl.get(), size)) << "read section header table");
    g_elf_info.sh_cnt = ehdr->e_shnum;

    // read section header string table
    auto str_tbl = g_elf_info.sh_tbl[ehdr->e_shstrndx];
    offset = str_tbl.sh_offset;
    size = g_elf_info.shstr_tab_size = str_tbl.sh_size;
    g_elf_info.shstr_tbl = std::unique_ptr<char[]>(new char[g_elf_info.shstr_tab_size]);
    E(ASSERT_EQ(offset, lseek(fd, offset, SEEK_SET)) << "seek section header string table");
    E(ASSERT_EQ(size, read(fd, g_elf_info.shstr_tbl.get(), size)) << "read section header string table");

#ifdef PT_GNU_RELRO
    // read program header table
    offset = ehdr->e_phoff;
    Elf64_Phdr phdr;
    size = sizeof(phdr);
    ASSERT_EQ(offset, lseek(fd, offset, SEEK_SET)) << "lseek program header table error";
    for (size_t idx = 0; idx < ehdr->e_phnum; idx++) {
        E(ASSERT_EQ(size, read(fd, &phdr, size)) << "read program header table");
        if (phdr.p_type == PT_GNU_RELRO) {
            g_elf_info.relro_start = (const char*) phdr.p_vaddr;
            g_elf_info.relro_end = g_elf_info.relro_start + phdr.p_memsz;
            break;
        }
    }
#endif

    const Elf64_Shdr *shdr;
    // get dynamic linker symbol table
    ASSERT_NO_FATAL_FAILURE(GetSectionTable(".dynsym", &shdr));
    ASSERT_EQ((uint32_t)SHT_DYNSYM, shdr->sh_type) << ".dynsym section type invalid";
    ASSERT_EQ(sizeof(Elf64_Sym), shdr->sh_entsize) << ".dynsym section entry size invalid";
    g_elf_info.dynsym_tbl = (const Elf64_Sym*) shdr->sh_addr;
    g_elf_info.dynsym_cnt = shdr->sh_size / shdr->sh_entsize;

    // get dynamic string table
    ASSERT_NO_FATAL_FAILURE(GetSectionTable(".dynstr", &shdr));
    ASSERT_EQ((uint32_t)SHT_STRTAB, shdr->sh_type) << ".dynstr section type invalid";
    g_elf_info.dynstr_tbl = (const char*) shdr->sh_addr;
    g_elf_info.dynstr_size = shdr->sh_size;

    // get dynamic relocation entries
    ASSERT_NO_FATAL_FAILURE(GetSectionTable(".rela.dyn", &shdr));
    ASSERT_EQ((uint32_t)SHT_RELA, shdr->sh_type) << ".rela.dyn section type invalid";
    ASSERT_EQ(sizeof(Elf64_Rela), shdr->sh_entsize) << ".rela.dyn section entry size invalid";
    g_elf_info.dyn_tbl = (Elf64_Rela *) shdr->sh_addr;
    g_elf_info.dyn_cnt = shdr->sh_size / sizeof(Elf64_Rela);

    // get procedure linkage table
    ASSERT_NO_FATAL_FAILURE(GetSectionTable(".rela.plt", &shdr));
    ASSERT_EQ((uint32_t)SHT_RELA, shdr->sh_type) << ".rela.plt section type invalid";
    ASSERT_EQ(sizeof(Elf64_Rela), shdr->sh_entsize) << ".rela.plt section entry size invalid";
    g_elf_info.plt_tbl = (Elf64_Rela *) shdr->sh_addr;
    g_elf_info.plt_cnt = shdr->sh_size / sizeof(Elf64_Rela);
}

// Get ELF section table.
static void GetSectionTable(const char *name, const Elf64_Shdr **shdr) noexcept {
    size_t len = strlen(name);
    for (size_t i = 0; i < g_elf_info.sh_cnt; i++) {
        auto sh = &g_elf_info.sh_tbl[i];
        ASSERT_LT(sh->sh_name + len, g_elf_info.shstr_tab_size) << "header string table overflow";
        if (strcmp(&g_elf_info.shstr_tbl[sh->sh_name], name) == 0) {
            // found the section
            *shdr = sh;
            return;
        }
    }
    FAIL() << "failed to find the section [" << name << "]";
}

// Get GOT entry address of the function.
static void GetGotEntryAddr(const char *name, void ***addr) noexcept {
    // initialize first
    if (!g_elf_info.inited) {
        ASSERT_NO_FATAL_FAILURE(InitElfInfo());
    }
    size_t len = strlen(name);
    bool found = false;
    // find on dynamic relocation entries
    for (size_t i = 0; i < g_elf_info.dyn_cnt; i++) {
        ASSERT_NO_FATAL_FAILURE(DoGetGotAddr(name, len, &g_elf_info.dyn_tbl[i], addr, &found));
        if (found) return;
    }
    // find on procedure linkage table
    for (size_t i = 0; i < g_elf_info.plt_cnt; i++) {
        ASSERT_NO_FATAL_FAILURE(DoGetGotAddr(name, len, &g_elf_info.plt_tbl[i], addr, &found));
        if (found) return;
    }
    if (!found) {
        FAIL() << "couldn't find the function name [" << name << "]";
    }
}

// Get GOT entry address of the function.
static void DoGetGotAddr(const char* name, size_t len, const Elf64_Rela* rel, void*** addr, bool *found) noexcept {
    auto type = ELF64_R_TYPE(rel->r_info);
    if (type == R_X86_64_JUMP_SLOT || type == R_X86_64_GLOB_DAT) {
        // dynamic linker symbol index
        size_t dynsym_idx = ELF64_R_SYM(rel->r_info);
        ASSERT_LT(dynsym_idx, g_elf_info.dynsym_cnt) << ".dynsym index overflow";
        // dynamic string table index
        auto dynstr_idx = g_elf_info.dynsym_tbl[dynsym_idx].st_name;
        ASSERT_LT(dynstr_idx, g_elf_info.dynstr_size) << "string table index overflow";
        // dynamic string name
        auto dynstr = g_elf_info.dynstr_tbl + dynstr_idx;
        if (strncmp(dynstr, name, len) == 0 && (dynstr[len] == '\0' || dynstr[len] == '@')) {
            *addr = (void**) (rel->r_offset);
            *found = true;
            return;
        }
    }
}

// Set GOT value to a static function address.
static void SetGotValue(void **addr, void *value) noexcept {
#ifdef PT_GNU_RELRO
    // set the global offset table writable
    void *maddr = nullptr;
    if (g_elf_info.relro_start <= (char*)addr && (char*)addr < g_elf_info.relro_end) {
        maddr = (void*)((size_t)addr & ~(g_page_size - 1));
        E(ASSERT_EQ(0, mprotect(maddr, g_page_size, PROT_READ | PROT_WRITE)) << "mprotect");
    }
#endif

    // change the GOT value
    *addr = value;

#ifdef PT_GNU_RELRO
    // set the global offset table read only
    if (maddr != nullptr) {
        mprotect(maddr, g_page_size, PROT_READ);
    }
#endif
}

// Get lock first to avoid multiple threads changing GOT value at the same time.
// While an other thread is holding the lock, `wait` is true then the current
// thread will be blocked, otherwise will has fatal failure.
static void AssertGetLockSuccessful(bool wait) {
    if (wait) {
        // waiting for the lock.
        g_hook_mutex.lock();
    } else {
        // return immediately when try lock failed.
        ASSERT_TRUE(g_hook_mutex.try_lock()) << "should not use GotHook concurrently";
    }
    // set the current thread holding the lock.
    g_locked_thread_id = gettid();
}

// Mock glibc function by changing GOT value to custom static function address.
// While an other thread is holding the lock, `wait` is true then the current
// thread will be blocked, otherwise will has fatal failure.
GotHook::GotHook(bool wait) {
    // because of GOT is global, change it in multiple threads is dangerous.
    AssertGetLockSuccessful(wait);
    if (testing::Test::HasFailure()) {
        // get lock failed, then can't mock glibc function later.
        object_id_ = 0;
        return;
    }
    // set a unique increased id for the object.
    static unsigned int unique_id_generator = 0;
    object_id_ = ++unique_id_generator;
    g_object_stack.push(object_id_);
}

// Restore all GOT value to original.
GotHook::~GotHook() {
    // the object didn't get the lock, do nothing.
    if (object_id_ == 0) {
        return;
    }
    // last object should be delete first, to make sure that GOT value can be restore to the right one.
    EXPECT_TRUE(!g_object_stack.empty()
            && object_id_ == g_object_stack.top()) << "last new GotHook object should be deleted first";
    // if the deleting object is on the top or in the middle of the stack, then restore GOT value to original.
    // otherwise, an object before this has been deleted, may not be able to restore GOT value to original correctly.
    if (!g_object_stack.empty() && object_id_ <= g_object_stack.top()) {
        for (auto it = original_addr_.begin(); it != original_addr_.end(); original_addr_.erase(it++)) {
            SetGotValue(it->first, it->second);
        }
    }
    // pop the deleting object and the objects after it.
    while (!g_object_stack.empty() && object_id_ <= g_object_stack.top()) {
        g_object_stack.pop();
    }
    // if the first object is being deleted, restore all GOT to original glibc function address.
    if (g_object_stack.empty()) {
        for (auto it = g_original_addr.begin(); it != g_original_addr.end(); g_original_addr.erase(it++)) {
            SetGotValue(it->first, it->second);
        }
    }
    // release the look.
    EXPECT_EQ(g_locked_thread_id, gettid()) << "the GotHook object should not be deleted by the other thread";
    g_hook_mutex.unlock();
}

// Mock a glibc function by changing GOT value to a static function address.
// If success and `original` is not NULL, then the GOT old value will assign to it.
void GotHook::MockFunction(const char *name, void *func, void **original) {
    ASSERT_NE(0u, object_id_) << "should not hook function before getting the lock";
    ASSERT_EQ(g_locked_thread_id, gettid()) << "should not share GotHook object between multiple threads";
    // get GOT entry address of the function
    void **addr;
    ASSERT_NO_FATAL_FAILURE(GetGotEntryAddr(name, &addr));
    // store original function address.
    // may be not the glibc function address when there are more then one GotHook object.
    if (original_addr_.find(addr) == original_addr_.end()) {
        original_addr_.insert(std::make_pair(addr, *addr));
    }
    // store the glibc original function address to a static map
    if (g_original_addr.find(addr) == g_original_addr.end()) {
        g_original_addr.insert(std::make_pair(addr, *addr));
    }
    // return the original function address
    if (original != nullptr) {
        *original = *addr;
    }
    // change the GOT value to a new function address
    ASSERT_NO_FATAL_FAILURE(SetGotValue(addr, func));
}

}
