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
// Test the GotHook class.

#include "got_hook.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include <sys/time.h>
#include <sys/socket.h>

#include <mutex>
#include <thread>
#include <condition_variable>

using testing::_;
using testing::Invoke;
using testing::Return;

struct MockFunction {

    MOCK_METHOD3(Socket, int(int domain, int type, int protocol));

    MOCK_METHOD1(Close, int(int fd));

    MOCK_METHOD1(Time, time_t(time_t *tloc));

};

static MockFunction *g_mock{nullptr};

static std::mutex g_test_mutex;

struct GotHookTest : testing::Test {

    virtual void SetUp() {
        g_test_mutex.lock();
        g_mock = new MockFunction();
    }

    virtual void TearDown() {
        delete g_mock;
        g_test_mutex.unlock();
    }

    void CreateAndCloseSocket() {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd != -1) {
            close(fd);
        }
    }

    static int Socket(int domain, int type, int protocol) {
        return g_mock->Socket(domain, type, protocol);
    }

    static int Close(int fd) {
        return g_mock->Close(fd);
    }

    static time_t Time(time_t *tloc) {
        return g_mock->Time(tloc);
    }

};

struct Barrier {

    explicit Barrier(std::size_t count) {
        count_ = count;
        threshold_ = count;
        generation_ = count;
    }

    void Wait() {
        auto gen = generation_;
        std::unique_lock<std::mutex> lock{mutex_};
        if (!--count_) {
            generation_++;
            count_ = threshold_;
            cond_.notify_all();
        } else {
            cond_.wait(lock, [this, gen] { return gen != generation_; });
        }
    }

private:

    std::mutex  mutex_;

    std::condition_variable cond_;

    std::size_t threshold_;

    std::size_t count_;

    std::size_t generation_;

};

TEST_F(GotHookTest, MockSocket) {
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook());

    // mock socket and close
    ASSERT_NO_FATAL_FAILURE({
        got_hook->MockFunction("socket", (void*)&Socket);
        got_hook->MockFunction("close", (void*)&Close);
    });

    // should has been mocked
    constexpr int socket_fd = 1000;
    EXPECT_CALL(*g_mock, Socket(_, _, _)).WillOnce(Return(socket_fd));
    EXPECT_CALL(*g_mock, Close(socket_fd)).WillOnce(Return(0));
    CreateAndCloseSocket();

    // restore to original
    got_hook.reset();

    // should not has been mocked anymore
    EXPECT_CALL(*g_mock, Socket(_, _, _)).Times(0);
    EXPECT_CALL(*g_mock, Close(_)).Times(0);
    CreateAndCloseSocket();
}

TEST_F(GotHookTest, MockTime) {
    constexpr time_t fake_time = 200;
    time_t true_time = time(nullptr);
    ASSERT_NE(true_time, fake_time);

    time_t (*sys_time)(time_t *tloc);

    // mock socket and close
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook());
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("time", (void*)&Time, (void**)&sys_time));

    // should has been mocked
    EXPECT_CALL(*g_mock, Time(nullptr)).WillOnce(Return(fake_time));
    EXPECT_EQ(fake_time, time(nullptr));
    EXPECT_NEAR(true_time, sys_time(nullptr), 1);

    // restore to original
    got_hook.reset();

    // should not has been mocked anymore
    EXPECT_CALL(*g_mock, Time(_)).Times(0);
    EXPECT_NE(fake_time, time(nullptr));
    EXPECT_NEAR(true_time, time(nullptr), 1);
}

void MockNotExistsFunction() {
    testing::FLAGS_gtest_break_on_failure = false;
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook());
    // mock a not exists function should has fatal failure
    got_hook->MockFunction("not_exists_function", nullptr);
    if (testing::Test::HasFatalFailure()) {
        // test success
        exit(0);
    } else {
        // test failed
        exit(101);
    }
}

TEST_F(GotHookTest, MockNotExists) {
    // should exit with 0 when test success
    EXPECT_EXIT(MockNotExistsFunction(), testing::ExitedWithCode(0), "")
                    << "mock not exists function should has fatal failure";
}

// the time in us is used to test a thread is blocking by an another thread
constexpr time_t wait_time_us = 100 * 1000;

void GetLockAndHold(Barrier *barrier) {
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook(true));
    // notify the other thread lock has been token
    barrier->Wait();
    // hold the lock for a while
    usleep(wait_time_us);
}

void WaitForLock(Barrier *barrier) {
    // wait for the other thread get the lock first
    barrier->Wait();
    // should be blocked until the other thread release the lock
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook(true));
}

TEST_F(GotHookTest, WaitForLock) {
    struct timeval begin_time, end_time;
    gettimeofday(&begin_time, nullptr);

    Barrier barrier(2);
    // the first thread get the lock first
    std::thread t1(GetLockAndHold, &barrier);
    // the second thread wait for the lock
    std::thread t2(WaitForLock, &barrier);

    // wait for the second thread to finish, then check the time it used
    t2.join();
    gettimeofday(&end_time, nullptr);
    auto used_time_us = (end_time.tv_sec - begin_time.tv_sec) * 1000000L + end_time.tv_usec - begin_time.tv_usec;
    EXPECT_LT(wait_time_us, used_time_us) << "should wait for the other thread release lock";

    // the first thread should have been finished now
    t1.join();
}

void DoNotWaitForLock() {
    testing::FLAGS_gtest_break_on_failure = false;
    // get lock fail should has fatal failure
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook(false));
    if (testing::Test::HasFatalFailure()) {
        // test success
        exit(0);
    } else {
        // test failed
        exit(111);
    }
}

void NotWaitForLock(Barrier *barrier) {
    // wait for the other thread get the lock first
    barrier->Wait();
    // should exit with 0 when test success
    EXPECT_EXIT(DoNotWaitForLock(), testing::ExitedWithCode(0), "")
                << "not wait for lock should has fatal failure";
}

TEST_F(GotHookTest, NotWaitForLock) {
    //testing::FLAGS_gtest_death_test_style = "threadsafe";

    struct timeval begin_time, end_time;
    gettimeofday(&begin_time, nullptr);

    Barrier barrier(2);
    // the first thread get the lock first
    std::thread t1(GetLockAndHold, &barrier);
    // the second thread should not wait for the lock
    std::thread t2(NotWaitForLock, &barrier);

    // wait for the second thread to finish, then check the time it used
    t2.join();
    gettimeofday(&end_time, nullptr);
    auto used_time_us = (end_time.tv_sec - begin_time.tv_sec) * 1000000L + end_time.tv_usec - begin_time.tv_usec;
    EXPECT_GT(wait_time_us / 2, used_time_us) << "should not wait for the other thread release lock";

    // wait for the first thread to finish
    t1.join();
}

void DoGetLockFailed() {
    testing::FLAGS_gtest_break_on_failure = false;
    EXPECT_CALL(*g_mock, Time(_)).Times(0);
    time_t true_time = time(nullptr);
    // ignore leak in the child process
    testing::Mock::AllowLeak(g_mock);
    // get lock failed should has fatal failure
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook(false));
    if (!testing::Test::HasFatalFailure()) {
        // test failed
        exit(121);
    }
    // should not mock success when get lock failed
    void *original = nullptr;
    got_hook->MockFunction("time", (void*)&GotHookTest::Time, &original);
    if (original != nullptr) {
        // should not mock success
        exit(122);
    }
    // time(nullptr) should call the libc function
    if (labs(time(nullptr) - true_time) > 1) {
        // should not mock success
        exit(123);
    }
    // restore to original
    got_hook.reset();
    // should not has any error when a get lock failed object release
    if (testing::Test::HasNonfatalFailure()) {
        exit(124);
    }
    // test success
    exit(0);
}

void GetLockFailed() {
    // should exit with 0 when test success
    EXPECT_EXIT(DoGetLockFailed(), testing::ExitedWithCode(0), "")
                    << "get lock failed should not mock success";
}

TEST_F(GotHookTest, GetLockFailed) {
    //testing::FLAGS_gtest_death_test_style = "threadsafe";

    // main thread get lock first
    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook(true));
    // start a thread to fork a process to test
    std::thread t(GetLockFailed);
    // wait for the test thread to finish
    t.join();

    // main thread should test success
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("time", (void*)&Time));
    constexpr time_t fake_time = 300;
    EXPECT_CALL(*g_mock, Time(nullptr)).WillOnce(Return(fake_time));
    EXPECT_EQ(fake_time, time(nullptr));
}

void DoShareGotHook(testing::GotHook *got_hook) {
    testing::FLAGS_gtest_break_on_failure = false;
    EXPECT_CALL(*g_mock, Time(_)).Times(0);
    time_t true_time = time(nullptr);
    // ignore leak in the child process
    testing::Mock::AllowLeak(g_mock);
    if (testing::Test::HasFailure()) {
        // should not has any error for now
        exit(131);
    }
    // should not mock success when get lock failed
    void *original = nullptr;
    got_hook->MockFunction("time", (void*)&GotHookTest::Time, &original);
    // mock failed should has fatal failure
    if (!testing::Test::HasFatalFailure()) {
        // test failed
        exit(133);
    }
    if (original != nullptr) {
        // should not mock success
        exit(132);
    }
    // time(nullptr) should call the libc function
    if (labs(time(nullptr) - true_time) > 1) {
        // should not mock success
        exit(133);
    }
    // should not has any not fatal error for now
    if (testing::Test::HasNonfatalFailure()) {
        exit(134);
    }
    // other thread release the GotHook object show has non fatal failure
    delete got_hook;
    if (!testing::Test::HasNonfatalFailure()) {
        exit(135);
    }
    // test success
    exit(0);
}

void ShareGotHook(testing::GotHook *got_hook) {
    // should exit with 0 when test success
    EXPECT_EXIT(DoShareGotHook(got_hook), testing::ExitedWithCode(0), "")
                        << "the shared GotHook object should not mock success";
}

TEST_F(GotHookTest, ShareGotHook) {
    //testing::FLAGS_gtest_death_test_style = "threadsafe";

    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook());
    // share the got_hook with an other thread
    std::thread t(ShareGotHook, got_hook.get());
    // wait for the other thread to finish
    t.join();

    // main thread should test success
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("time", (void*)&Time));
    constexpr time_t fake_time = 500;
    EXPECT_CALL(*g_mock, Time(nullptr)).WillOnce(Return(fake_time));
    EXPECT_EQ(fake_time, time(nullptr));
}

void RecursiveMockTime(long);

void RecursiveMockClose(long count) {
    if (count-- <= 0) {
        return;
    }

    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook());

    // set the address to a new one
    void *my_addr = (void*) count;
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("close", my_addr));

    // recursive call
    RecursiveMockTime(count);

    // get the current address
    void *current_addr;
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("close", nullptr, &current_addr));

    EXPECT_EQ(my_addr, current_addr) << "the GOT value should not been changed after recursive call";
}

void RecursiveMockTime(long count) {
    if (count-- <= 0) {
        return;
    }

    std::unique_ptr<testing::GotHook> got_hook(new testing::GotHook());

    // set the address to a new one
    void *my_addr = (void*) count;
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("time", my_addr));

    // recursive call
    RecursiveMockClose(count);

    // get the current address
    void *current_addr;
    ASSERT_NO_FATAL_FAILURE(got_hook->MockFunction("time", nullptr, &current_addr));

    EXPECT_EQ(my_addr, current_addr) << "the GOT value should not been changed after recursive call";
}

TEST_F(GotHookTest, RecursiveCall) {
    time_t true_time = time(nullptr);
    // test recursive call
    RecursiveMockTime(10);
    // check the GOT is original glibc function address or not
    EXPECT_NEAR(true_time, time(nullptr), 1) << "the GOT value should not been changed after recursive call";
}
