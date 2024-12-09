#include "mud.c"
#include "aegis256/aegis256.c"

#include <stdio.h>
#include <poll.h>

int
main(int argc, char **argv)
{
    if (argc > 2)
        return -1;

    int client = argc == 2;

    // local address
    union mud_sockaddr local = {
        .sin = {
            .sin_family = AF_INET,
            .sin_port = htons(client + 20000),
            .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        },
    };

    // 加密密钥key
    unsigned char key[] = "0123456789ABCDEF0123456789ABCDEF";
    int aes = 1;

    // 创建mud实例，创建了UDP套接字，并进行了bind
    struct mud *mud = mud_create(&local, key, &aes);

    if (!mud) {
        perror("mud_create");
        return -1;
    }

    // client端需要指定本地地址和远端地址
    if (client) {
        struct mud_path_conf path_conf = {
            .local = local,
            .remote.sin = {
                .sin_family = AF_INET,
                .sin_port = htons(20000),
                .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
            },
            .state = MUD_UP,     // 对于UDP来说，只要本地地址bind成功，就认为连接已建立
            .tx_max_rate = 1000 * 1000,     // 最大发送速率
            .rx_max_rate = 1000 * 1000,     // 最大接收速率
            // use default beat, fixed_rate, loss_limit
        };
        if (mud_set_path(mud, &path_conf)) {
            perror("mud_set_path");
            return -1;
        }
    }

    unsigned char buf[1500];

    for (;;) {
        // mandatory, mud have lot of work to do.
        if (mud_update(mud))
            usleep(100000); // don't use all the cpu

        if (client) {
            // when there is data, mud_recv() is mandatory
            struct pollfd pollfd = {
                .fd = mud_get_fd(mud),
                .events = POLLIN,
            };
            switch (poll(&pollfd, 1, 0)) {
            case -1:
                perror("poll");
                return -1;
            case 1:
                if (mud_recv(mud, buf, sizeof(buf)) == -1) {
                    perror("mud_recv");
                    return -1;
                }
            }

            // we can safely call mud_send()
            // even if the link is not ready
            int r = mud_send(mud, argv[1], strlen(argv[1]));

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("mud_send");
                return -1;
            }
            if (r) break;  // we sent everything, bye :)
        } else {
            int r = mud_recv(mud, buf, sizeof(buf));

            if (r == -1) {
                if (errno == EAGAIN)
                    continue;

                perror("mud_recv");
                return -1;
            }
            if (r) {
                buf[r] = 0;
                printf("%s\n", buf);
            }
        }
    }
    mud_delete(mud);

    return 0;
}
