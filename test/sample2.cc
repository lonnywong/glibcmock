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

#include <sys/ipc.h>
#include <sys/shm.h>

#include <mutex>
#include <memory>

using testing::_;
using testing::Return;

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
    // should not be placed into ASSERT_NO_FATAL_FAILURE, or it will be destructed before test
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
