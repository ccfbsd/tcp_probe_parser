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
    FILE* out_fp;
    struct FlowInfo* next;
} FlowInfo;

FlowInfo* hashed_flow_table[HASH_SIZE] = {NULL};
const char plot_dir_name[] = "plot_files";
char output_dir[NAME_LEN] = {};

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
cmp_by_record_count(const void* a, const void* b) {
    FlowInfo* f1 = (FlowInfo*)a;
    FlowInfo* f2 = (FlowInfo*)b;
    return f2->record_count - f1->record_count;
}

void
print_usage(const char* prog) {
    fprintf(stderr, "Usage: %s -f trace_file [-p name] [-a] [-s sock_cookie]\n",
            prog);
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
        printf("    flowid: %" PRIu64 ", family: %s, addr: %s<->%s, cnts: %d\n",
            all_flows[i].sock_cookie, all_flows[i].family, all_flows[i].src,
            all_flows[i].dest, all_flows[i].record_count);

        if (all_flows[i].out_fp) {
            fclose(all_flows[i].out_fp);
        }
    }
    free(all_flows);
}

#endif /* LIB_H_ */
