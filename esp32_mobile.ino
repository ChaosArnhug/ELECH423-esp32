#include <DHT.h>
#include <WiFi.h>
#include <PubSubClient.h>

// Pin definitions
#define BUTTON_PIN 27
#define RED_LED_PIN 32
#define WHITE_LED_PIN 33
#define DHT11_PIN 26

// const definition
#define SSID ""
#define WIFI_PWD ""
#define SRV ""
#define SRV_PORT 1883

#define humidity_topic "sensor/DHT11/humidity"
#define temperature_topic "sensor/DHT11/temperature"


// SRV connection
WiFiClient wifiClient;
PubSubClient client(wifiClient);

// Link temp/humidity sensor to its pin
DHT dht11(DHT11_PIN, DHT11);

// Feature led on/off on button press
void led_button_press() {
  if (digitalRead(BUTTON_PIN) == HIGH){
    Serial.println("INFO: Button Pressed");
    digitalWrite(WHITE_LED_PIN, HIGH);
    digitalWrite(RED_LED_PIN, LOW);
    
  } else {
    digitalWrite(WHITE_LED_PIN, LOW);
    digitalWrite(RED_LED_PIN, HIGH);
  }
}

// setup + connection to wifi
void wifi_reconnect() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, WIFI_PWD);
  Serial.print("INFO: Connecting to WiFi ..");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print('.');
    delay(1000);
  }
  Serial.println("INFO: Wifi connected");
  Serial.println(WiFi.localIP());
}

//setup + connection to thingsboard
void srv_reconnect() {
  while (!client.connected()) {
    Serial.print("Connecting to MQTT Broker...");
    if (client.connect("ESP32Client")) {
      Serial.println("Connected!");
    } else {
      Serial.print("Failed, rc=");
      Serial.print(client.state());
      Serial.println(" retrying in 5 seconds");
      delay(5000);
    }
  }
}

void setup() {
  Serial.begin(115200); //baud
  // Pin Setup
  pinMode(BUTTON_PIN, INPUT_PULLUP);
  pinMode(RED_LED_PIN, OUTPUT);
  pinMode(WHITE_LED_PIN, OUTPUT);

  // Default Led Values
  digitalWrite(RED_LED_PIN, HIGH);
  digitalWrite(WHITE_LED_PIN, LOW);
  dht11.begin();

  // SRV Link
  wifi_reconnect();
  client.setServer(SRV, SRV_PORT);
  srv_reconnect();
}

void loop() {
  led_button_press();

  //reestablish connection to wifi if lost
  if (WiFi.status() != WL_CONNECTED){
    delay(1000);
    wifi_reconnect();
  }

  // reestablish connection to thingboard if lost
  if (!client.connected()) {
    delay(1000);
    srv_reconnect();
  }

  // Humidity and Temperature
  float humi  = dht11.readHumidity();
  float tempC = dht11.readTemperature();
  // Check if readings are valid
  if (isnan(humi) || isnan(tempC)) {
    Serial.println("ERROR: Failed to read from DHT11 sensor!");
  } else {
    Serial.print("INFO: Humidity = ");
    Serial.print(humi);
    Serial.print(" %, Temperature = ");
    Serial.print(tempC);
    Serial.println(" °C");
    client.publish(humidity_topic, String(humi).c_str(), true);
    client.publish(temperature_topic, String(tempC).c_str(), true);
  }

  delay(100); //delay
}
