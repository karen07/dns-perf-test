#include "dns-perf-test.h"

FILE *in_domains_fp;
FILE *cache_fp;
FILE *out_domains_fp;
FILE *ips_fp;

uint32_t dns_ip;
uint16_t dns_port;

uint32_t listen_ip;
uint16_t listen_port;

uint32_t rps;

int32_t is_domains_file_path;
char domains_file_path[PATH_MAX];

int32_t is_save;

int32_t sended;
int32_t readed;

double coeff = 1;

struct sockaddr_in repeater_addr, dns_addr;
int32_t repeater_socket;

void *send_dns(__attribute__((unused)) void *arg)
{
    char packet[PACKET_MAX_SIZE], line_buf[PACKET_MAX_SIZE];
    int32_t line_count = 0;

    while (fscanf(in_domains_fp, "%s", line_buf) != EOF) {
        line_count++;

        dns_header_t *header = (dns_header_t *)packet;
        uint16_t id = line_count;
        header->id = htons(id);
        header->flags = htons(0x0100);
        header->quest = htons(1);
        header->ans = htons(0);
        header->auth = htons(0);
        header->add = htons(0);

        int32_t k = 0;
        char *dot_pos_new = line_buf;
        char *dot_pos_old = line_buf;
        while ((dot_pos_new = strchr(dot_pos_old + 1, '.')) != NULL) {
            dot_pos_new++;
            packet[12 + k] = dot_pos_new - dot_pos_old - 1;
            memcpy(&packet[12 + k + 1], dot_pos_old, packet[12 + k]);
            k += packet[12 + k] + 1;
            dot_pos_old = dot_pos_new;
        }

        packet[12 + k] = strlen(line_buf) - k;
        memcpy(&packet[12 + k + 1], &line_buf[k], packet[12 + k]);
        k += packet[12 + k] + 1;
        packet[12 + k] = 0;

        dns_que_t *end_name = (dns_que_t *)&packet[12 + k + 1];
        end_name->type = htons(1);
        end_name->class = htons(1);

        if (sendto(repeater_socket, packet, 12 + k + 5, 0, (struct sockaddr *)&dns_addr,
                   sizeof(dns_addr)) < 0) {
            printf("Can't send %s\n", strerror(errno));
        }

        sended = line_count;

        usleep(1000000 / rps / coeff);
    }

    return NULL;
}

int32_t get_domain_from_packet(memory_t *receive_msg, char *cur_pos_ptr, char **new_cur_pos_ptr,
                               memory_t *domain)
{
    uint8_t two_bit_mark = FIRST_TWO_BITS_UINT8;
    int32_t part_len = 0;
    int32_t domain_len = 0;

    int32_t jump_count = 0;

    *new_cur_pos_ptr = NULL;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    while (true) {
        if (part_len == 0) {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return 1;
            }
            uint8_t first_byte_data = (*cur_pos_ptr) & (~two_bit_mark);

            if ((*cur_pos_ptr & two_bit_mark) == 0) {
                part_len = first_byte_data;
                cur_pos_ptr++;
                if (part_len == 0) {
                    break;
                } else {
                    if (domain_len >= (int32_t)domain->max_size) {
                        return 2;
                    }
                    domain->data[domain_len++] = '.';
                }
            } else if ((*cur_pos_ptr & two_bit_mark) == two_bit_mark) {
                if (cur_pos_ptr + sizeof(uint16_t) > receive_msg_end) {
                    return 3;
                }
                if (*new_cur_pos_ptr == NULL) {
                    *new_cur_pos_ptr = cur_pos_ptr + 2;
                }
                uint8_t second_byte_data = *(cur_pos_ptr + 1);
                int32_t padding = 256 * first_byte_data + second_byte_data;
                cur_pos_ptr = receive_msg->data + padding;
                if (jump_count++ > 100) {
                    return 4;
                }
            } else {
                return 5;
            }
        } else {
            if (cur_pos_ptr + sizeof(uint8_t) > receive_msg_end) {
                return 6;
            }
            if (domain_len >= (int32_t)domain->max_size) {
                return 7;
            }
            domain->data[domain_len++] = *cur_pos_ptr;
            cur_pos_ptr++;
            part_len--;
        }
    }

    if (*new_cur_pos_ptr == NULL) {
        *new_cur_pos_ptr = cur_pos_ptr;
    }

    if (domain_len >= (int32_t)domain->max_size) {
        return 8;
    }
    domain->data[domain_len] = 0;
    domain->size = domain_len;

    return 0;
}

int32_t dns_ans_check(memory_t *receive_msg, memory_t *que_domain, memory_t *ans_domain)
{
    char *cur_pos_ptr = receive_msg->data;
    char *receive_msg_end = receive_msg->data + receive_msg->size;

    // DNS HEADER
    if (cur_pos_ptr + sizeof(dns_header_t) > receive_msg_end) {
        return 1;
    }

    dns_header_t *header = (dns_header_t *)cur_pos_ptr;

    uint16_t first_bit_mark = FIRST_BIT_UINT16;
    uint16_t flags = ntohs(header->flags);
    if ((flags & first_bit_mark) == 0) {
        return 2;
    }

    uint16_t quest_count = ntohs(header->quest);
    if (quest_count != 1) {
        return 3;
    }

    uint16_t ans_count = ntohs(header->ans);
    if (ans_count == 0) {
        return 4;
    }

    cur_pos_ptr += sizeof(dns_header_t);
    // DNS HEADER

    // QUE DOMAIN
    char *que_domain_start = cur_pos_ptr;
    char *que_domain_end = NULL;
    if (get_domain_from_packet(receive_msg, que_domain_start, &que_domain_end, que_domain) != 0) {
        return 5;
    }
    cur_pos_ptr = que_domain_end;

    if (is_save) {
        fwrite(que_domain->data + 1, sizeof(char), strlen(que_domain->data), cache_fp);
        fwrite(&receive_msg->size, sizeof(int32_t), 1, cache_fp);
        fwrite(receive_msg->data, sizeof(char), receive_msg->size, cache_fp);
        fprintf(out_domains_fp, "%s\n", que_domain->data + 1);
    }

    // QUE DOMAIN

    // QUE DATA
    if (cur_pos_ptr + sizeof(dns_que_t) > receive_msg_end) {
        return 6;
    }

    cur_pos_ptr += sizeof(dns_que_t);
    // QUE DATA

    for (int32_t i = 0; i < ans_count; i++) {
        // ANS DOMAIN
        char *ans_domain_start = cur_pos_ptr;
        char *ans_domain_end = NULL;
        if (get_domain_from_packet(receive_msg, ans_domain_start, &ans_domain_end, ans_domain) !=
            0) {
            return 7;
        }
        cur_pos_ptr = ans_domain_end;
        // ANS DOMAIN

        // ANS DATA
        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) > receive_msg_end) {
            return 8;
        }

        dns_ans_t *ans = (dns_ans_t *)cur_pos_ptr;

        uint16_t ans_type = ntohs(ans->type);
        __attribute__((unused)) uint32_t ans_ttl = ntohl(ans->ttl);
        uint16_t ans_len = ntohs(ans->len);

        if (cur_pos_ptr + sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len > receive_msg_end) {
            return 9;
        }

        if (ans_type == DNS_TypeA) {
            struct in_addr new_ip;
            new_ip.s_addr = ans->ip4;

            if (is_save) {
                fprintf(ips_fp, "%s\n", inet_ntoa(new_ip));
            }
        }

        cur_pos_ptr += sizeof(dns_ans_t) - sizeof(uint32_t) + ans_len;
        // ANS DATA
    }

    return 0;
}

void *read_dns(__attribute__((unused)) void *arg)
{
    struct sockaddr_in receive_DNS_addr;
    uint32_t receive_DNS_addr_length = sizeof(receive_DNS_addr);

    memory_t receive_msg;
    receive_msg.size = 0;
    receive_msg.max_size = PACKET_MAX_SIZE;
    receive_msg.data = (char *)malloc(receive_msg.max_size * sizeof(char));
    if (receive_msg.data == 0) {
        printf("No free memory for receive_msg from DNS\n");
        exit(EXIT_FAILURE);
    }

    memory_t que_domain;
    que_domain.size = 0;
    que_domain.max_size = DOMAIN_MAX_SIZE;
    que_domain.data = (char *)malloc(que_domain.max_size * sizeof(char));
    if (que_domain.data == 0) {
        printf("No free memory for que_domain\n");
        exit(EXIT_FAILURE);
    }

    memory_t ans_domain;
    ans_domain.size = 0;
    ans_domain.max_size = DOMAIN_MAX_SIZE;
    ans_domain.data = (char *)malloc(ans_domain.max_size * sizeof(char));
    if (ans_domain.data == 0) {
        printf("No free memory for ans_domain\n");
        exit(EXIT_FAILURE);
    }

    while (true) {
        receive_msg.size = recvfrom(repeater_socket, receive_msg.data, receive_msg.max_size, 0,
                                    (struct sockaddr *)&receive_DNS_addr, &receive_DNS_addr_length);

        readed++;

        dns_ans_check(&receive_msg, &que_domain, &ans_domain);
    }

    return NULL;
}

void print_help(void)
{
    printf("\nCommands:\n"
           "  Required parameters:\n"
           "    -file /example.txt            Domains file path\n"
           "    -DNS 0.0.0.0:00               DNS address\n"
           "    -listen 0.0.0.0:00            Listen address\n"
           "    -RPS 00000                    Request per second\n"
           "  Optional parameters:\n"
           "    -save                         Save DNS answer data to cache.data,\n"
           "                                  DNS answer domains to out_domains.txt,\n"
           "                                  DNS answer IPs to ips.txt\n");
    exit(EXIT_FAILURE);
}

int32_t main(int32_t argc, char *argv[])
{
    printf("\nDNS perf test started\n\n");

    for (int32_t i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-file")) {
            if (i != argc - 1) {
                if (strlen(argv[i + 1]) < PATH_MAX - 100) {
                    is_domains_file_path = 1;
                    strcpy(domains_file_path, argv[i + 1]);
                    printf("Get domains from file %s\n", domains_file_path);
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-DNS")) {
            if (i != argc - 1) {
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &dns_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        dns_ip = inet_addr(argv[i + 1]);
                        struct in_addr dns_ip_in_addr;
                        dns_ip_in_addr.s_addr = dns_ip;
                        printf("DNS %s:%hu\n", inet_ntoa(dns_ip_in_addr), dns_port);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-listen")) {
            if (i != argc - 1) {
                char *colon_ptr = strchr(argv[i + 1], ':');
                if (colon_ptr) {
                    sscanf(colon_ptr + 1, "%hu", &listen_port);
                    *colon_ptr = 0;
                    if (strlen(argv[i + 1]) < INET_ADDRSTRLEN) {
                        listen_ip = inet_addr(argv[i + 1]);
                        struct in_addr listen_ip_in_addr;
                        listen_ip_in_addr.s_addr = listen_ip;
                        printf("Listen %s:%hu\n", inet_ntoa(listen_ip_in_addr), listen_port);
                    }
                    *colon_ptr = ':';
                }
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-RPS")) {
            if (i != argc - 1) {
                sscanf(argv[i + 1], "%u", &rps);
                printf("RPS %d\n", rps);
                i++;
            }
            continue;
        }
        if (!strcmp(argv[i], "-save")) {
            is_save = 1;
            continue;
        }
        printf("Error:\n");
        printf("Unknown command %s\n", argv[i]);
        print_help();
    }

    if (!is_domains_file_path) {
        printf("Error:\n");
        printf("Programm need domains file path\n");
        print_help();
    }

    if (dns_ip == 0) {
        printf("Error:\n");
        printf("Programm need DNS IP\n");
        print_help();
    }

    if (dns_port == 0) {
        printf("Error:\n");
        printf("Programm need DNS port\n");
        print_help();
    }

    if (listen_ip == 0) {
        printf("Error:\n");
        printf("Programm need listen IP\n");
        print_help();
    }

    if (listen_port == 0) {
        printf("Error:\n");
        printf("Programm need listen port\n");
        print_help();
    }

    if (rps == 0) {
        printf("Error:\n");
        printf("Programm need rps\n");
        print_help();
    }

    printf("\n");

    in_domains_fp = fopen(domains_file_path, "r");
    if (!in_domains_fp) {
        printf("Error opening file %s\n", domains_file_path);
        return 0;
    }

    if (is_save) {
        cache_fp = fopen("cache.data", "w");
        if (!cache_fp) {
            printf("Error opening file cache.data\n");
            return 0;
        }
        out_domains_fp = fopen("out_domains.txt", "w");
        if (!out_domains_fp) {
            printf("Error opening file out_domains.txt\n");
            return 0;
        }
        ips_fp = fopen("ips.txt", "w");
        if (!ips_fp) {
            printf("Error opening file ips.txt\n");
            return 0;
        }
    }

    repeater_addr.sin_family = AF_INET;
    repeater_addr.sin_port = htons(listen_port);
    repeater_addr.sin_addr.s_addr = listen_ip;

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_port = htons(dns_port);
    dns_addr.sin_addr.s_addr = dns_ip;

    repeater_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (repeater_socket < 0) {
        printf("Error while creating socket %s\n", strerror(errno));
        return 0;
    }

    if (bind(repeater_socket, (struct sockaddr *)&repeater_addr, sizeof(repeater_addr)) < 0) {
        printf("Couldn't bind to the port %s\n", strerror(errno));
        return 0;
    }

    pthread_t send_thread;
    if (pthread_create(&send_thread, NULL, send_dns, NULL)) {
        printf("Can't create send_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(send_thread)) {
        printf("Can't detach send_thread\n");
        exit(EXIT_FAILURE);
    }

    pthread_t read_thread;
    if (pthread_create(&read_thread, NULL, read_dns, NULL)) {
        printf("Can't create read_thread\n");
        exit(EXIT_FAILURE);
    }

    if (pthread_detach(read_thread)) {
        printf("Can't detach read_thread\n");
        exit(EXIT_FAILURE);
    }

    int32_t sended_old = 0;
    int32_t readed_old = 0;

    int32_t exit_wait = 0;

    printf("Send_RPS Read_RPS Sended Readed Diff\n");
    while (true) {
        sleep(1);

        time_t now = time(NULL);
        struct tm *tm_struct = localtime(&now);
        printf("\n%02d.%02d.%04d %02d:%02d:%02d\n", tm_struct->tm_mday, tm_struct->tm_mon + 1,
               tm_struct->tm_year + 1900, tm_struct->tm_hour, tm_struct->tm_min, tm_struct->tm_sec);
        printf("%08d %08d %06d %06d %04d\n", sended - sended_old, readed - readed_old, sended,
               readed, sended - readed);

        if (readed == readed_old) {
            exit_wait++;
        } else {
            exit_wait = 0;
        }

        if (exit_wait >= EXIT_WAIT_SEC) {
            return 0;
        }

        coeff *= (1.0 * rps) / (sended - sended_old);

        sended_old = sended;
        readed_old = readed;
    }

    return 0;
}
