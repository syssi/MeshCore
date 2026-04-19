#pragma once

#include <Mesh.h>

#ifndef ESPNOW_BRIDGE_SECRET
#define ESPNOW_BRIDGE_SECRET "LVSITANOS"
#endif

class ESPNOWRadio : public mesh::Radio {
protected:
  uint32_t n_recv, n_sent, n_recv_errors;
  const char* _bridge_secret;

  static constexpr uint16_t BRIDGE_PACKET_MAGIC = 0xC03E;
  static constexpr uint16_t BRIDGE_MAGIC_SIZE = 2;
  static constexpr uint16_t BRIDGE_CHECKSUM_SIZE = 2;
  static constexpr size_t MAX_ESPNOW_PACKET_SIZE = 250;
  static constexpr size_t MAX_PAYLOAD_SIZE = MAX_ESPNOW_PACKET_SIZE - (BRIDGE_MAGIC_SIZE + BRIDGE_CHECKSUM_SIZE);

  void xorCrypt(uint8_t* data, size_t len);
  static uint16_t fletcher16(const uint8_t* data, size_t len);
  bool validateChecksum(const uint8_t* data, size_t len, uint16_t received_checksum);

public:
  ESPNOWRadio() : n_recv(0), n_sent(0), n_recv_errors(0), _bridge_secret(ESPNOW_BRIDGE_SECRET) {}

  void init();
  int recvRaw(uint8_t* bytes, int sz) override;
  uint32_t getEstAirtimeFor(int len_bytes) override;
  bool startSendRaw(const uint8_t* bytes, int len) override;
  bool isSendComplete() override;
  void onSendFinished() override;
  bool isInRecvMode() const override;

  uint32_t getPacketsRecv() const { return n_recv; }
  uint32_t getPacketsSent() const { return n_sent; }
  uint32_t getPacketsRecvErrors() const { return n_recv_errors; }
  void resetStats() { n_recv = n_sent = n_recv_errors = 0; }

  virtual float getLastRSSI() const override;
  virtual float getLastSNR() const override;

  float packetScore(float snr, int packet_len) override { return 0; }

  /**
   * These two functions do nothing for ESP-NOW, but are needed for the
   * Radio interface.
   */
  virtual void setRxBoostedGainMode(bool) { }
  virtual bool getRxBoostedGainMode() const { return false; }

  uint32_t intID();
  void setTxPower(uint8_t dbm);
};

#if ESPNOW_DEBUG_LOGGING && ARDUINO
  #include <Arduino.h>
  #define ESPNOW_DEBUG_PRINT(F, ...) Serial.printf("ESP-Now: " F, ##__VA_ARGS__)
  #define ESPNOW_DEBUG_PRINTLN(F, ...) Serial.printf("ESP-Now: " F "\n", ##__VA_ARGS__)
#else
  #define ESPNOW_DEBUG_PRINT(...) {}
  #define ESPNOW_DEBUG_PRINTLN(...) {}
#endif
