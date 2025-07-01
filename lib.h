/*
 ============================================================================
 Name        : lib.h
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check tcp_probe log stats in C, Ansi-style
 ============================================================================
 */

#ifndef LIB_H_
#define LIB_H_

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

enum {
    NAME_LEN = 32,
    MAX_NAME_LEN = NAME_LEN * 8,
    MAX_LINE_LEN = 1024,
    INET6_ADDR_LEN = 46,
    TCP_PORT_LEN = 5,
    SRC_STR_LEN = (INET6_ADDR_LEN + TCP_PORT_LEN + 2),  // count a trailing '\0'
    DEST_STR_LEN = SRC_STR_LEN,
    PROTOCOL_STR_LEN = 10,
    HASH_SIZE = 1024,
};

typedef struct FlowInfo {
    uint64_t sock_cookie;
    char src[SRC_STR_LEN];
    char dest[DEST_STR_LEN];
    char family[PROTOCOL_STR_LEN];  // big enough for "AF_INET6\0"
    int record_count;
    uint64_t srtt_sum;
    uint32_t srtt_min;
    uint32_t srtt_max;
    uint64_t cwnd_sum;
    uint32_t cwnd_min;
    uint32_t cwnd_max;
    uint32_t last_cwnd;
    uint32_t counter;
    FILE* out_fp;
    struct FlowInfo* next;
} FlowInfo;

FlowInfo* hashed_flow_table[HASH_SIZE] = {NULL};
const char plot_dir_name[] = "plot_files";
char output_dir[NAME_LEN] = {};

void clean_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        perror("opendir");
        return;
    }

    struct dirent *entry = NULL;
    char file_path[MAX_LINE_LEN] = {};

    while ((entry = readdir(dir)) != NULL) {
        // Skip "." and ".."
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        int len = snprintf(file_path, sizeof(file_path), "%s/%s", dir_path,
                           entry->d_name);
        if (len < 0 || len >= (int)sizeof(file_path)) {
            fprintf(stderr, "%s Error: path too long\n", __FUNCTION__);
            continue;
        }
        if (unlink(file_path) != 0) {
            perror("unlink");
        }
    }

    closedir(dir);
}

unsigned
hash_sock_cookie(uint64_t sock_cookie)
{
    return (unsigned)(sock_cookie % HASH_SIZE);
}

FlowInfo*
find_or_create_flow(uint64_t sock_cookie, const char* src, const char* dest,
                    const char*  family, bool write_all)
{
    unsigned idx = hash_sock_cookie(sock_cookie);
    FlowInfo* curr = hashed_flow_table[idx];
    while (curr) {
        if (curr->sock_cookie == sock_cookie) {
            return curr;
        }
        curr = curr->next;
    }

    FlowInfo* new_flow = calloc(1, sizeof(FlowInfo));
    if (!new_flow) {
        perror("calloc");
        exit(EXIT_FAILURE);
    }

    new_flow->sock_cookie = sock_cookie;
    strncpy(new_flow->src, src, SRC_STR_LEN - 1);
    strncpy(new_flow->dest, dest, DEST_STR_LEN - 1);
    strncpy(new_flow->family, family, PROTOCOL_STR_LEN - 1);
    new_flow->record_count = 0;
    new_flow->srtt_sum = 0;
    new_flow->srtt_min = UINT32_MAX;
    new_flow->srtt_max = 0;
    new_flow->cwnd_sum = 0;
    new_flow->cwnd_min = UINT32_MAX;
    new_flow->cwnd_max = 0;
    new_flow->last_cwnd = 0;
    new_flow->counter = 0;

    if (write_all) {
        char fname[MAX_NAME_LEN];
        snprintf(fname, sizeof(fname), "%s/%" PRIu64 ".txt", output_dir,
                 sock_cookie);
        new_flow->out_fp = fopen(fname, "w");
        if (!new_flow->out_fp) {
            perror("fopen output");
            exit(EXIT_FAILURE);
        }
    }

    new_flow->next = hashed_flow_table[idx];
    hashed_flow_table[idx] = new_flow;

    return new_flow;
}

/* collect flows into a continued block of memory and then free the memory
 * for the hashed_flow_table[]
 */
void
collect_flows_and_free_flow_table(FlowInfo** list, size_t* flow_count,
                                  size_t* total_records)
{
    for (int i = 0; i < HASH_SIZE; i++) {
        for (FlowInfo* curr = hashed_flow_table[i]; curr; curr = curr->next) {
            (*flow_count)++;
            (*total_records) += curr->record_count;
        }
    }

    *list = malloc(*flow_count * sizeof(FlowInfo));
    if (!*list) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    size_t idx = 0;
    for (int i = 0; i < HASH_SIZE; i++) {
        FlowInfo* curr = hashed_flow_table[i];
        while (curr != NULL) {
            FlowInfo* tmp = curr;
            curr = curr->next;
            (*list)[idx++] = *tmp;
            free(tmp);
        }
    }
}

int
cmp_by_record_count(const void* a, const void* b)
{
    FlowInfo* f1 = (FlowInfo*)a;
    FlowInfo* f2 = (FlowInfo*)b;
    return f2->record_count - f1->record_count;
}

void
print_usage(const char* prog)
{
    fprintf(stderr, "Usage: %s -f trace_file [-p name] [-c] [-a] "
            "[-s sock_cookie]\n", prog);
    exit(EXIT_FAILURE);
}

void
summary()
{
    FlowInfo* all_flows = NULL;
    size_t flow_count = 0;
    size_t total_cnts = 0;
    collect_flows_and_free_flow_table(&all_flows, &flow_count, &total_cnts);
    qsort(all_flows, flow_count, sizeof(FlowInfo), cmp_by_record_count);

    printf("\nSorted Flow Summary:\n"
           "    flow_count: %zu\n    total_cnts: %zu\n",
           flow_count, total_cnts);
    for (unsigned i = 0; i < flow_count; i++) {
        printf("    flowid: %" PRIu64 ", family: %s, addr: %s<->%s, cnts: %d, "
               "avg_srtt: %" PRIu64 ", min_srtt: %u, max_srtt: %u µs, "
               "avg_cwnd: %" PRIu64 ", min_cwnd: %u, max_cwnd: %u segments\n",
            all_flows[i].sock_cookie, all_flows[i].family, all_flows[i].src,
            all_flows[i].dest, all_flows[i].record_count,
            all_flows[i].srtt_sum / all_flows[i].record_count,
            all_flows[i].srtt_min, all_flows[i].srtt_max,
            all_flows[i].cwnd_sum / all_flows[i].record_count,
            all_flows[i].cwnd_min, all_flows[i].cwnd_max);

        if (all_flows[i].out_fp) {
            fclose(all_flows[i].out_fp);
        }
    }
    free(all_flows);
}

#endif /* LIB_H_ */
