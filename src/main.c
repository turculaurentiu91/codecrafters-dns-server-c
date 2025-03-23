#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define HF_RECURSION_DESIRED 0b0000000100000000   // 0000 0001 0000 0000
#define HF_RECURSION_AVAILABLE 0b0000000010000000 // 0000 0000 1000 0000
#define HF_TRUNCATED_MESSAGE 0b0000001000000000   // 0000 0010 0000 0000
#define HF_AUTHORITATIVE_ANS 0b0000010000000000   // 0000 0100 0000 0000
#define HF_QUERY_RESPONSE 0b1000000000000000      // 1000 0000 0000 0000

struct header_t {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

/**
 * The out array must have space for 12 uint8_t or it will access memory out of
 * bounds
 */
void header_to_net(struct header_t header, uint16_t *out) {
  out[0] = htons(header.id);
  out[1] = htons(header.flags);
  out[2] = htons(header.qdcount);
  out[3] = htons(header.ancount);
  out[4] = htons(header.nscount);
  out[5] = htons(header.arcount);
}

uint8_t label_to_net(char *domain, uint8_t *out, size_t out_size) {
  uint8_t *out_ptr = out;
  const char *label_start = domain;
  const char *label_end;

  if (domain[0] == '.') {
    return 0;
  }

  while (*label_start) {
    label_end = strchr(label_start, '.');
    if (!label_end) {
      label_end = label_start + strlen(label_start);
    }

    uint8_t label_len = label_end - label_start;
    if (out_ptr - out + label_len + 1 + 4 > out_size) {
      return 0;
    }

    *out_ptr++ = label_len;

    memcpy(out_ptr, label_start, label_len);
    out_ptr += label_len;

    if (!*label_end) {
      break;
    }

    label_start = label_end + 1;
  }

  *out_ptr++ = 0;

  // Record type A
  uint16_t record_type = htons(1);
  memcpy(out_ptr, &record_type, 2);
  out_ptr += 2;

  // Record class IN
  uint16_t record_class = htons(1);
  memcpy(out_ptr, &record_class, 2);
  out_ptr += 2;

  return out_ptr - out;
}

int main() {
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  printf("Logs from your program will appear here!\n");

  int udpSocket, client_addr_len;
  struct sockaddr_in clientAddress;

  udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (udpSocket == -1) {
    printf("Socket creation failed: %s...\n", strerror(errno));
    return 1;
  }

  // Since the tester restarts your program quite often, setting REUSE_PORT
  // ensures that we don't run into 'Address already in use' errors
  int reuse = 1;
  if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) <
      0) {
    printf("SO_REUSEPORT failed: %s \n", strerror(errno));
    return 1;
  }

  struct sockaddr_in serv_addr = {
      .sin_family = AF_INET,
      .sin_port = htons(2053),
      .sin_addr = {htonl(INADDR_ANY)},
  };

  if (bind(udpSocket, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
    printf("Bind failed: %s \n", strerror(errno));
    return 1;
  }

  int bytesRead;
  char buffer[512];
  socklen_t clientAddrLen = sizeof(clientAddress);

  while (1) {
    // Receive data
    bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0,
                         (struct sockaddr *)&clientAddress, &clientAddrLen);
    if (bytesRead == -1) {
      perror("Error receiving data");
      break;
    }

    buffer[bytesRead] = '\0';
    printf("Received %d bytes: %s\n", bytesRead, buffer);

    // Create an empty response
    uint8_t response[512];
    size_t written = 0;
    struct header_t res_header = {
        .id = 1234,
        .flags = HF_QUERY_RESPONSE,
        .qdcount = 1,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    header_to_net(res_header, (uint16_t *)response);
    written = 12;
    written +=
        label_to_net("codecrafters.io", response + written, 512 - written);

    // Send response
    if (sendto(udpSocket, response, sizeof(uint8_t) * written, 0,
               (struct sockaddr *)&clientAddress,
               sizeof(clientAddress)) == -1) {
      perror("Failed to send response");
    }
  }

  close(udpSocket);

  return 0;
}
