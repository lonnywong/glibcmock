#include "got_hook.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include <mutex>
#include <memory>

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
    ASSERT_NO_FATAL_FAILURE(got_hook.MockFunction("malloc", (void*)&Malloc));
    // ... do your test here, for example:
    EXPECT_CALL(*g_mock, Malloc(testing::_)).WillOnce(testing::Return(nullptr));
    EXPECT_EQ(nullptr, malloc(1));
}
