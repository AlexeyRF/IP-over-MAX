import socket
import os

LOCAL_HOST = "127.0.0.1"
# Теперь все локальные порты - это TCP (Gateway)
PTCP_PORT = 10001
PUDP_PORT = 10002
UDP_PORT = 10003
CUDP_PORT = 10005

def send_to_gateway(message, port):
    # Локальный шлюз IP-over-MAX слушает TCP соединения
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((LOCAL_HOST, port))
        sock.sendall(message.encode())
        print(f"Sent to port {port}: {message[:50]}...")

if __name__ == "__main__":
    # Пример 1: Широковещательное сообщение (broadcast) через UDP
    send_to_gateway("Привет всем через Broadcast UDP!", UDP_PORT)

    # Пример 2: Сообщение через PUDP (ожидание подключения)
    send_to_gateway("Привет через PUDP (ожидание сети)!", PUDP_PORT)

    # Пример 3: Сообщение через PTCP (гарантированная доставка)
    send_to_gateway("Привет через PTCP (гарантированная доставка)!", PTCP_PORT)

    # Пример 4: Сообщение через CUDP (автоудаление через 1 минуту)
    send_to_gateway("Это сообщение самоуничтожится через 60 секунд!", CUDP_PORT)

    # Пример 5: Отправка большого сообщения через PTCP.
    large_msg = "A" * 72000  
    send_to_gateway(large_msg, PTCP_PORT)

    # Пример 6: Отправка файла в виде вложения
    test_file_path = "examples_send_output.txt"
    with open(test_file_path, "w", encoding="utf-8") as f:
        f.write("Это тестовый файл-вложение для IP-over-MAX!")
    abs_path = os.path.abspath(test_file_path)

    # Формат: [КТО|]FILE:путь_к_файлу[|текст_сообщения]
    send_to_gateway(f"broadcast|FILE:{abs_path}|Вот мой файл!", UDP_PORT)

    print("\nВсе примеры отправлены на локальный TCP-шлюз.")
