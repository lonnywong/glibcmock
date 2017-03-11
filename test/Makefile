# Copyright (c) 2017 Lonny Wang <lonnywang@qq.com>
# 
# URL: https://github.com/lonnywang/glibcmock
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# 
# Author: Lonny Wang <lonnywang@qq.com>
#
# Make the executable file to test glibc mock.
#

SRC_DIR = ..
TEST_DIR = .

TESTS = glibc_mock_test

CXX_FLAGS += -g -Wall -Wextra -std=c++11

SRC_OBJS  = $(patsubst $(SRC_DIR)/%.cc, $(SRC_DIR)/%.o, $(wildcard $(SRC_DIR)/*.cc))
TEST_OBJS = $(patsubst $(TEST_DIR)/%.cc, $(TEST_DIR)/%.o, $(wildcard $(TEST_DIR)/*.cc))

all : $(TESTS)

test : $(TESTS)
	./$(TESTS) --gtest_death_test_style=threadsafe

clean :
	rm -f $(TESTS) $(TEST_OBJS) $(SRC_OBJS)

$(SRC_DIR)/%.o : $(SRC_DIR)/%.cc
	$(CXX) -I$(SRC_DIR) -I$(TEST_DIR) $(CXX_FLAGS) -fprofile-arcs -ftest-coverage -c $< -o $@

$(TEST_DIR)/%.o : $(TEST_DIR)/%.cc
	$(CXX) -I$(SRC_DIR) -I$(TEST_DIR) $(CXX_FLAGS) -c $< -o $@

$(TESTS) : $(TEST_OBJS) $(SRC_OBJS)
	$(CXX) -z relro -z now $^ -o $@ -pthread -lgcov
