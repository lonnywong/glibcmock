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
// A sample that use GotHook to mock glibc function.

#include "got_hook.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include <fcntl.h>
#include <stdarg.h>

#include <mutex>

using testing::_;
using testing::Invoke;
using testing::Return;

constexpr const char *prod_file = "/usr/local/xxx";
constexpr const char *test_file = "/tmp/xxx";

struct Panda {
    void OpenFile() {
        auto fd = open(prod_file, O_RDONLY);
        // ...
        ASSERT_NE(-1, fd) << "open error [" << errno << "] [" << strerror(errno) << "]";
        // check the file name which has been opened
        char fd_path[128], file_path[128];
        snprintf(fd_path, sizeof(fd_path), "/proc/self/fd/%d", fd);
        memset(file_path, 0, sizeof(file_path));
        ASSERT_NE(-1, readlink(fd_path, file_path, sizeof(file_path)))
                    << "readlink error [" << errno << "] [" << strerror(errno) << "]";
        EXPECT_STREQ(test_file, file_path);
        if (fd != -1) {
            close(fd);
        }
    }
};

struct MockPanda : Panda {
    MOCK_METHOD2(Open, int(const char*, int));
};

static std::mutex g_test_mutex;

static MockPanda *g_panda{nullptr};

static int (*libc_open)(const char*, int, ...);

struct PandaTest : testing::Test {
    testing::GotHook *got_hook{nullptr};

    virtual void SetUp() {
        g_test_mutex.lock(); // not thread safe
        g_panda = new MockPanda();
        ASSERT_NO_FATAL_FAILURE({
            got_hook = new testing::GotHook();
            got_hook->MockFunction("open", (void*)&Open, (void**)&libc_open);
        });
        ON_CALL(*g_panda, Open(_, _)).WillByDefault(Invoke(libc_open));
        // ...
        // create the test file
        int fd = open(test_file, O_CREAT, 0600);
        EXPECT_NE(-1, fd) << "open [" << test_file << "] error [" << errno << "] [" << strerror(errno) << "]";
        if (fd != -1) {
            close(fd);
        }
    }

    virtual void TearDown() {
        delete got_hook;
        delete g_panda;
        g_test_mutex.unlock();
    }

    static int Open(const char *pathname, int flags, ...) {
        if (strcmp(prod_file, pathname) == 0) {
            return g_panda->Open(test_file, flags);
        } else {
            if (flags & O_CREAT) {
                va_list arg;
                va_start(arg, flags);
                mode_t mode = va_arg(arg, mode_t);
                va_end(arg);
                return libc_open(pathname, flags, mode);
            } else {
                return libc_open(pathname, flags);
            }
        }
    }
};

TEST_F(PandaTest, OpenTestFile) {
    // ...
    EXPECT_CALL(*g_panda, Open(test_file, O_RDONLY));
    // ...
    g_panda->OpenFile();
    // ...
}
