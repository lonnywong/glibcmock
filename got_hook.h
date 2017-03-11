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

#ifndef GLIBC_MOCK_GOT_HOOK_H_
#define GLIBC_MOCK_GOT_HOOK_H_

#include <map>

namespace testing {

// Mock glibc function by changing GOT value to custom static function address.
//
// As we know, glibc function address is store in GOT (Global Offset Table).
// Change the GOT value to a custom static function address, then the glibc call
// will call the custom static function actually. In the custom static function,
// we make it to call a Google Mock method, then we have mocked the glibc function.
class GotHook {

public:

    // Mock glibc function by changing GOT value to custom static function address.
    // While an other thread is holding the lock, `wait` is true then the current
    // thread will be blocked, otherwise will has fatal failure.
    GotHook(bool wait = true);

    // Restore all GOT value to original.
    ~GotHook();

    // Mock a glibc function by changing GOT value to a static function address.
    // If success and `original` is not NULL, then the GOT old value will assign to it.
    void MockFunction(const char *name, void *func, void **original = nullptr);

private:

    // delete copy constructor
    GotHook(const GotHook&) = delete;

    // delete assignment operator
    GotHook& operator=(const GotHook&) = delete;

    // a unique id to support recursive call
    unsigned int object_id_;

    // key is the GOT entry address, value is the original function address
    std::map<void**, void*> original_addr_;

};

}

#endif // GLIBC_MOCK_GOT_HOOK_H_
