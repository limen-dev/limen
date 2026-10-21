import pika
p = pika.ConnectionParameters("127.0.0.1", 61339, "/", pika.PlainCredentials("x","x"))
c = pika.BlockingConnection(p); ch = c.channel()
ch.queue_declare("orders.q")                      # accepted: configure
ch.basic_publish("", "orders.q", b"hello")        # accepted: write
print(ch.basic_get("orders.q"))
