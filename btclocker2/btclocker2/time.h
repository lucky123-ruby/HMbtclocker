#pragma once
#include <iostream>
#include <ctime>

// 独立函数，用于判断是否到了指定时间（这里是十五天后）
bool shouldRunAfterFifteenDays() {
    // 获取当前时间
    time_t currentTime = time(nullptr);
    struct tm currentDate;
    // 使用 localtime_s 安全版本函数
    localtime_s(&currentDate, &currentTime);

    // 创建一个表示十五天后的时间结构体
    struct tm fifteenDaysLater = currentDate;
    fifteenDaysLater.tm_mday += 15;

    // 将十五天后的时间转换为time_t类型
    time_t targetTime = mktime(&fifteenDaysLater);

    // 获取当前时间戳与十五天后时间戳的差值
    time_t timeDiff = targetTime - currentTime;

    // 如果差值小于等于0，说明已经到了或超过了十五天，返回true
    return timeDiff <= 0;
}

