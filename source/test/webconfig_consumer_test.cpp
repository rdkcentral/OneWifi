#include "gtest/gtest.h"

int add(int num1,int num2)
{
    return (num1+num2);
}

TEST(Add, PositiveCase)
{
    EXPECT_EQ(30,add(10,20));
    EXPECT_EQ(50,add(30,20));
}
