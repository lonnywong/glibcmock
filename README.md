# glibc mock

[![Build Status](https://travis-ci.org/lonnywang/glibcmock.svg?branch=master)](https://travis-ci.org/lonnywang/glibcmock)
[![Coverage Status](https://coveralls.io/repos/github/lonnywang/glibcmock/badge.svg?branch=master)](https://coveralls.io/github/lonnywang/glibcmock?branch=master)
[![Coverage Status](https://img.shields.io/codecov/c/github/lonnywang/glibcmock/master.svg)](https://codecov.io/gh/lonnywang/glibcmock)
[![Code Health](https://landscape.io/github/lonnywang/glibcmock/master/landscape.svg?style=flat)](https://landscape.io/github/lonnywang/glibcmock/master)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](../master/LICENSE)
  
Welcome to **glibc mock**, a solution of mocking glibc function (open, read, write … etc.) with [Google Test](https://github.com/google/googletest) and [Google Mock](https://github.com/google/googletest/blob/master/googlemock/README.md)!  
  
*Mock glibc function by changing GOT value to custom static function address.*  
  
As we know, glibc function address is store in GOT (Global Offset Table).  
Change the GOT value to a custom static function address, then the glibc call will call the custom static function actually.  
In the custom static function, we make it to call a Google Mock method, then we have mocked the glibc function.

## Usage
1. Copy `got_hook.h` and `got_hook.cc` to your C++ test project.
2. Add `#include "got_hook.h"` to your test source code.

## Sample 0
```c++  
struct MockMalloc {
    MOCK_METHOD1(Malloc, void *(size_t));
};

static MockMalloc *g_mock{nullptr};

static void *Malloc(size_t size) {
    return g_mock->Malloc(size);
}

static std::mutex g_test_mutex;

TEST(MallocTest, ReturnNull) {
    std::lock_guard<std::mutex> lock(g_test_mutex); // not thread safe
    std::unique_ptr<MockMalloc> mock(g_mock = new MockMalloc());
    testing::GotHook got_hook;
    ASSERT_NO_FATAL_FAILURE(got_hook.MockFunction("malloc", (void*)&Malloc););
    // ... do your test here, for example:
    EXPECT_CALL(*g_mock, Malloc(testing::_)).WillOnce(testing::Return(nullptr));
    EXPECT_EQ(nullptr, malloc(1));
}
```

## Sample 1

```c++  
constexpr key_t shm_key = 0x123;

struct Turtle {
    void UseSharedMemory() {
        auto shm_id = shmget(shm_key, 0, 0);
        auto buffer = shmat(shm_id, nullptr, 0);
        EXPECT_STREQ("a fake shm buffer", (char*)buffer);
        // ...
        shmdt(buffer);
    }
};

struct MockTurtle : Turtle {
    MOCK_METHOD3(shmget, int(key_t, size_t, int));
    MOCK_METHOD3(shmat, void*(int, const void*, int));
    MOCK_METHOD1(shmdt, int(const void*));
};

static MockTurtle *g_turtle{nullptr};

static int my_shmget(key_t key, size_t size, int shmflg) {
    return g_turtle->shmget(key, size, shmflg);
}

static void *my_shmat(int shmid, const void *shmaddr, int shmflg) {
    return g_turtle->shmat(shmid, shmaddr, shmflg);
}

static int my_shmdt(const void *shmaddr) {
    return g_turtle->shmdt(shmaddr);
}

static std::mutex g_test_mutex;

TEST(TurtleTest, FakeSharedMemory) {
    std::lock_guard<std::mutex> lock(g_test_mutex); // not thread safe
    std::unique_ptr<MockTurtle> turtle(g_turtle = new MockTurtle());
    testing::GotHook got_hook;
    ASSERT_NO_FATAL_FAILURE({
        got_hook.MockFunction("shmget", (void*)&my_shmget);
        got_hook.MockFunction("shmat", (void*)&my_shmat);
        got_hook.MockFunction("shmdt", (void*)&my_shmdt);
    });
    constexpr int shm_id = 100;
    char fake_shm_buffer[2000]{"a fake shm buffer"};
    // ...
    EXPECT_CALL(*g_turtle, shmget(shm_key, _, _)).WillOnce(Return(shm_id));
    EXPECT_CALL(*g_turtle, shmat(shm_id, _, _)).WillOnce(Return(fake_shm_buffer));
    EXPECT_CALL(*g_turtle, shmdt(fake_shm_buffer)).WillOnce(Return(0));
    // ...
    g_turtle->UseSharedMemory();
    // ...
}
```  

## Sample 2
```c++  
constexpr const char *prod_file = "/usr/local/xxx";
constexpr const char *test_file = "/tmp/xxx";

struct Panda {
    void OpenFile() {
        auto fd = open(prod_file, O_RDONLY);
        // ...
        close(fd);
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
```  

# Requirements
For now support Linux **64-bit** only. If you need a **32-bit** version, contact me [lonnywang@qq.com](mailto:lonnywang@qq.com).
  * C++11 or newer
  * Google Test
  * Google Mock
