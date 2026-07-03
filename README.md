# NetSpy - Network Scanner & Monitor

Утилита для сетевого аудита: многопоточное TCP-сканирование, UDP-пинг, мониторинг доступности узлов. Написана на Python с использованием `scapy` и `tqdm`.

## Возможности
- Быстрое TCP-сканирование портов (1-65535) с прогресс-баром
- UDP-пинг для проверки доступности хоста
- Пинг мониторинг с логированием в файл

## Установка
```bash
git clone https://github.com/stavrogin1821/netspy.git
cd netspy
pip install scapy tqdm
