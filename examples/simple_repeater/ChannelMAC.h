#pragma once

#include <Utils.h>

// mups: exact channel matching for the packet filter.
//
// A group packet names its channel only by payload[0], a one-byte hash of the
// channel key, so many unrelated channels share each value. The 2-byte MAC
// behind it is computed under the channel key, so it proves membership:
// a stored key plus a matching MAC means the packet really is on that channel.
//
// MACThenDecrypt() returns 0 when the MAC does not verify. The plaintext goes
// into a local buffer and is discarded; nothing is read or stored.

namespace ChannelMAC {

// payload: group payload (channel hash, MAC, ciphertext), len: its length
inline bool matches(const uint8_t* secret, const uint8_t* payload, int len) {
  if (len <= 1 + CIPHER_MAC_SIZE) return false;
  uint8_t data[MAX_PACKET_PAYLOAD + 1];
  return mesh::Utils::MACThenDecrypt(secret, data, &payload[1], len - 1) > 0;
}

}
