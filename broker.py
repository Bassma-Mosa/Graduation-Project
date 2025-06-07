import time
import json
import paho.mqtt.client as paho
from paho import mqtt

# فلاغ علشان نخرج من اللوب بعد النشر
message_sent = False

def on_connect(client, userdata, flags, rc, properties=None):
    print("✅ Connected with result code: %s" % rc)

    # ابعت الرسالة بعد الاتصال
    alert_message = {
        "source": "SDN",
        "message": "🚨 DDoS attack successfully detected and mitigated – no service disruption occurred.",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
    }
    client.publish("cyborg/sdn/alert", payload=json.dumps(alert_message), qos=1)

def on_publish(client, userdata, mid, properties=None):
    global message_sent
    print("📤 Message published. MID:", mid)
    message_sent = True  # بعد النشر نخلي الفلاغ True

def on_subscribe(client, userdata, mid, granted_qos, properties=None):
    print("📩 Subscribed to topic:", mid, "QoS:", granted_qos)

def on_message(client, userdata, msg):
    print(f"📥 Received: {msg.topic} -> {msg.payload.decode()}")

# إعداد MQTT
client = paho.Client(client_id="cyborg_sdn", userdata=None, protocol=paho.MQTTv5)
client.on_connect = on_connect
#client.on_subscribe = on_subscribe
client.on_message = on_message
client.on_publish = on_publish

client.tls_set(tls_version=mqtt.client.ssl.PROTOCOL_TLS)
client.username_pw_set("Sabah", "Cyborg123")

# الاتصال بـ HiveMQ
client.connect("c294ca66dde64387afd4f37683e75520.s1.eu.hivemq.cloud", 8883)

# شغل الاتصال
client.loop_start()

# اشتراك في التوبيك
client.subscribe("cyborg/sdn/alert", qos=1)

# انتظر لحد ما الرسالة تبعت وبعدها اقفل
try:
    while not message_sent:
        time.sleep(0.5)
finally:
    #print("❌ Disconnecting...")
    client.loop_stop()
    client.disconnect()
