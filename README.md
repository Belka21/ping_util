# PingMAC Utility

## Описание
Утилита для определения MAC-адреса устройства по его IPv4-адресу с использованием ICMP-запросов. Программа:
1. Отправляет ICMP Echo Request (ping) на указанный адрес
2. Перехватывает ответ через libpcap
3. Извлекает MAC-адрес отправителя из Ethernet-фрейма
4. Выводит MAC-адрес в формате `XX:XX:XX:XX:XX:XX`

## Требования
- Linux (тестировалось на Ubuntu 20.04+)
- g++ (версия 9.4.0+)
- libpcap-dev
- Права root (для работы с raw-сокетами)

## Установка зависимостей
```bash
sudo apt-get update
sudo apt-get install g++ libpcap-dev
