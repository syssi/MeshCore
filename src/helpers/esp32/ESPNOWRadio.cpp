#include "ESPNOWRadio.h"
#include <esp_now.h>
#include <WiFi.h>
#include <esp_wifi.h>

static uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static esp_now_peer_info_t peerInfo;
static volatile bool is_send_complete = false;
static esp_err_t last_send_result;
static uint8_t rx_buf[256];
static uint8_t last_rx_len = 0;
static uint8_t tx_buf[256];

// callback when data is sent
static void OnDataSent(const uint8_t *mac_addr, esp_now_send_status_t status) {
  is_send_complete = true;
  ESPNOW_DEBUG_PRINTLN("Send Status: %d", (int)status);
}

static void OnDataRecv(const uint8_t *mac, const uint8_t *data, int len) {
  ESPNOW_DEBUG_PRINTLN("Recv: len = %d", len);
  memcpy(rx_buf, data, len);
  last_rx_len = len;
}

void ESPNOWRadio::init() {
  // Set device as a Wi-Fi Station
  WiFi.mode(WIFI_STA);
  // Long Range mode
  esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_LR);

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("Error initializing ESP-NOW");
    return;
  }

  esp_wifi_set_max_tx_power(80);  // should be 20dBm

  esp_now_register_send_cb(OnDataSent);
  esp_now_register_recv_cb(OnDataRecv);

  // Register peer
  memcpy(peerInfo.peer_addr, broadcastAddress, 6);
  peerInfo.channel = 0;
  peerInfo.encrypt = false;

  is_send_complete = true;

  // Add peer        
  if (esp_now_add_peer(&peerInfo) == ESP_OK) {
    ESPNOW_DEBUG_PRINTLN("init success");
  } else {
   // ESPNOW_DEBUG_PRINTLN("Failed to add peer");
  }
}

void ESPNOWRadio::setTxPower(uint8_t dbm) {
  esp_wifi_set_max_tx_power(dbm * 4);
}

void ESPNOWRadio::xorCrypt(uint8_t* data, size_t len) {
  size_t keyLen = strlen(_bridge_secret);
  for (size_t i = 0; i < len; i++) {
    data[i] ^= _bridge_secret[i % keyLen];
  }
}

uint16_t ESPNOWRadio::fletcher16(const uint8_t* data, size_t len) {
  uint16_t sum1 = 0;
  uint16_t sum2 = 0;
  for (size_t i = 0; i < len; i++) {
    sum1 = (sum1 + data[i]) % 255;
    sum2 = (sum2 + sum1) % 255;
  }
  return (sum2 << 8) | sum1;
}

bool ESPNOWRadio::validateChecksum(const uint8_t* data, size_t len, uint16_t received_checksum) {
  uint16_t calculated = fletcher16(data, len);
  return calculated == received_checksum;
}

uint32_t ESPNOWRadio::intID() {
  uint8_t mac[8];
  memset(mac, 0, sizeof(mac));
  esp_efuse_mac_get_default(mac);
  uint32_t n, m;
  memcpy(&n, &mac[0], 4);
  memcpy(&m, &mac[4], 4);
  
  return n + m;
}

bool ESPNOWRadio::startSendRaw(const uint8_t* bytes, int len) {
  if (len > MAX_PAYLOAD_SIZE) {
    ESPNOW_DEBUG_PRINTLN("TX packet too large (payload=%d, max=%d)", len, MAX_PAYLOAD_SIZE);
    is_send_complete = true;
    return false;
  }

  tx_buf[0] = (BRIDGE_PACKET_MAGIC >> 8) & 0xFF;
  tx_buf[1] = BRIDGE_PACKET_MAGIC & 0xFF;

  const size_t packetOffset = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE;
  memcpy(tx_buf + packetOffset, bytes, len);

  uint16_t checksum = fletcher16(tx_buf + packetOffset, len);
  tx_buf[2] = (checksum >> 8) & 0xFF;
  tx_buf[3] = checksum & 0xFF;

  xorCrypt(tx_buf + BRIDGE_MAGIC_SIZE, len + BRIDGE_CHECKSUM_SIZE);

  const size_t totalPacketSize = BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE + len;

  is_send_complete = false;
  esp_err_t result = esp_now_send(broadcastAddress, tx_buf, totalPacketSize);
  if (result == ESP_OK) {
    n_sent++;
    ESPNOW_DEBUG_PRINTLN("TX, len=%d", len);
    return true;
  }
  last_send_result = result;
  is_send_complete = true;
  ESPNOW_DEBUG_PRINTLN("TX FAILED: %d", result);
  return false;
}

bool ESPNOWRadio::isSendComplete() {
  return is_send_complete;
}
void ESPNOWRadio::onSendFinished() {
  is_send_complete = true;
}

bool ESPNOWRadio::isInRecvMode() const {
  return is_send_complete;    // if NO send in progress, then we're in Rx mode
}

float ESPNOWRadio::getLastRSSI() const { return 0; }
float ESPNOWRadio::getLastSNR() const { return 0; }

int ESPNOWRadio::recvRaw(uint8_t* bytes, int sz) {
  if (last_rx_len == 0) {
    return 0;
  }

  if (last_rx_len < (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE)) {
    ESPNOW_DEBUG_PRINTLN("RX packet too small, len=%d", last_rx_len);
    n_recv_errors++;
    last_rx_len = 0;
    return 0;
  }

  if (last_rx_len > MAX_ESPNOW_PACKET_SIZE) {
    ESPNOW_DEBUG_PRINTLN("RX packet too large, len=%d", last_rx_len);
    n_recv_errors++;
    last_rx_len = 0;
    return 0;
  }

  uint16_t received_magic = (rx_buf[0] << 8) | rx_buf[1];
  if (received_magic != BRIDGE_PACKET_MAGIC) {
    ESPNOW_DEBUG_PRINTLN("RX invalid magic 0x%04X", received_magic);
    n_recv_errors++;
    last_rx_len = 0;
    return 0;
  }

  uint8_t decrypted[MAX_ESPNOW_PACKET_SIZE];
  const size_t encryptedDataLen = last_rx_len - BRIDGE_MAGIC_SIZE;
  memcpy(decrypted, rx_buf + BRIDGE_MAGIC_SIZE, encryptedDataLen);

  xorCrypt(decrypted, encryptedDataLen);

  uint16_t received_checksum = (decrypted[0] << 8) | decrypted[1];
  const size_t payloadLen = encryptedDataLen - BRIDGE_CHECKSUM_SIZE;

  if (!validateChecksum(decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen, received_checksum)) {
    ESPNOW_DEBUG_PRINTLN("RX checksum mismatch, rcv=0x%04X", received_checksum);
    n_recv_errors++;
    last_rx_len = 0;
    return 0;
  }

  if (payloadLen > sz) {
    ESPNOW_DEBUG_PRINTLN("RX buffer too small");
    n_recv_errors++;
    last_rx_len = 0;
    return 0;
  }

  memcpy(bytes, decrypted + BRIDGE_CHECKSUM_SIZE, payloadLen);
  last_rx_len = 0;
  n_recv++;
  ESPNOW_DEBUG_PRINTLN("RX, payload_len=%d", payloadLen);
  return payloadLen;
}

uint32_t ESPNOWRadio::getEstAirtimeFor(int len_bytes) {
  return 4;  // Fast AF
}
