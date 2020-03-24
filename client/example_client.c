/*
 * Copyright 2019 Two Sigma Investments, LP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <err.h>
#include <string.h>

struct ns_last_pid_context {
    int client_fd;
    struct sockaddr_un serv_addr;
};

static int init_ns_last_pid_ctx(struct ns_last_pid_context *ctx, const char *socket_path)
{
    if (strlen(socket_path)+1 > sizeof(ctx->serv_addr.sun_path)) {
        fprintf(stderr, "Socket path too long\n");
        return -1;
    }

    ctx->client_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ctx->client_fd == -1) {
        warn("Can't create socket");
        return -1;
    }

    /*
     * The client binds a socket to get replies. It uses the abstract
     * namespace (its sun_path[0] is 0), and should be unique.
     */

    pid_t pid = getpid();
    struct sockaddr_un client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sun_family = AF_UNIX;
    memcpy(&client_addr.sun_path[1], "test", 4);
    memcpy(&client_addr.sun_path[5], &pid, sizeof(pid));

    if (bind(ctx->client_fd, (struct sockaddr *)&client_addr, sizeof(client_addr)) == -1) {
        warn("Can't bind socket");
        return -1;
    }


    memset(&ctx->serv_addr, 0, sizeof(ctx->serv_addr));
    ctx->serv_addr.sun_family = AF_UNIX;
    strcpy(ctx->serv_addr.sun_path, socket_path);

    return 0;
}

static void fini_ns_last_pid_ctx(struct ns_last_pid_context *ctx)
{
    close(ctx->client_fd);
}

static int set_ns_last_pid(struct ns_last_pid_context *ctx, pid_t pid)
{
    if (sendto(ctx->client_fd, (uint32_t *)&pid, sizeof(uint32_t), 0,
               (struct sockaddr *)&ctx->serv_addr, sizeof(ctx->serv_addr)) != sizeof(uint32_t)) {
        warn("Can't send on ns_last_pid socket");
        return -1;
    }

    char r;
    if (recvfrom(ctx->client_fd, &r, sizeof(r), 0, NULL, NULL) != 1) {
        warn("Can't receive on ns_last_pid socket");
        return -1;
    }

    if (r) {
        warnx("ns_last_pid server replied with a failure");
        return -1;
    }

    return 0;
}

int main(int argc, const char *argv[])
{
    if (argc != 3) {
        warnx("test_client SOCKET_PATH PID");
        return 1;
    }

    struct ns_last_pid_context ctx;
    const char *socket_path = argv[1];
    pid_t pid = atoi(argv[2]);

    if (init_ns_last_pid_ctx(&ctx, socket_path) == -1)
        return 1;

    if (set_ns_last_pid(&ctx, pid) == -1) {
        fini_ns_last_pid_ctx(&ctx);
        return 1;
    }

    fini_ns_last_pid_ctx(&ctx);
    return 0;
}
