import socket

LOCAL_HOST = "127.0.0.1"
PTCP_PORT = 10001
PUDP_PORT = 10002
UDP_PORT = 10003
CUDP_PORT = 10005

def send_udp(message, port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode(), (LOCAL_HOST, port))
        print(f"Sent to port {port}: {message}")

if __name__ == "__main__":
    # Example 1: Broadcast message via UDP (no connection check, no encryption)
    # Format: "content"
    #send_udp("Hello Broadcast UDP!", UDP_PORT)

    # Example 2: Target message via UDP (no connection check, encrypted for recipient)
    # Format: "recipient_uuid_b64|content"
    # Note: recipient_uuid_b64 must be known to the IOTClient
    # send_udp("RECIPIENT_B64_UUID|Hello Target UDP!", UDP_PORT)

    # Example 3: Message via PUDP (wait for connection, then send)
    #send_udp("Hello via PUDP (wait for connect)!", PUDP_PORT)

    # Example 4: Message via PTCP (guaranteed delivery via history check)
    #send_udp("Hello via PTCP (guaranteed)!", PTCP_PORT)

    # Example 5: Message via CUDP (UDP-like, but auto-delete after 1 minute)
    send_udp("This message will self-destruct in 60s!", CUDP_PORT)

    print("\nAll examples sent to local ports.")
