#pragma once
#include <iostream>
#include <ctime>

// ���������������ж��Ƿ���ָ��ʱ�䣨������ʮ�����
bool shouldRunAfterFifteenDays() {
    // ��ȡ��ǰʱ��
    time_t currentTime = time(nullptr);
    struct tm currentDate;
    // ʹ�� localtime_s ��ȫ�汾����
    localtime_s(&currentDate, &currentTime);

    // ����һ����ʾʮ������ʱ��ṹ��
    struct tm fifteenDaysLater = currentDate;
    fifteenDaysLater.tm_mday += 15;

    // ��ʮ������ʱ��ת��Ϊtime_t����
    time_t targetTime = mktime(&fifteenDaysLater);

    // ��ȡ��ǰʱ�����ʮ�����ʱ����Ĳ�ֵ
    time_t timeDiff = targetTime - currentTime;

    // �����ֵС�ڵ���0��˵���Ѿ����˻򳬹���ʮ���죬����true
    return timeDiff <= 0;
}

