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

#define MAX_ADDR_LEN 128

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

FlowInfo* flow_table[HASH_SIZE] = {NULL};
const char plot_dir_name[] = "plot_files";
char output_dir[NAME_LEN] = {};

void
free_flow_table(void)
{
    for (int i = 0; i < HASH_SIZE; i++) {
        FlowInfo* curr = flow_table[i];
        while (curr != NULL) {
            FlowInfo* tmp = curr;
            curr = curr->next;
            free(tmp);
        }
    }
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
    FlowInfo* curr = flow_table[idx];
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

    new_flow->next = flow_table[idx];
    flow_table[idx] = new_flow;

    return new_flow;
}

void
collect_flows(FlowInfo** list, size_t* flow_count, size_t* total_records)
{
    for (int i = 0; i < HASH_SIZE; i++) {
        for (FlowInfo* curr = flow_table[i]; curr; curr = curr->next) {
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
        for (FlowInfo* curr = flow_table[i]; curr; curr = curr->next) {
            (*list)[idx] = *curr;
            idx++;
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

int
main(int argc, char* argv[]) {
    /* Record the start time */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    char* trace_file = NULL;
    bool output_all = false;
    uint64_t specific_cookie = 0;
    bool specific_cookie_set = false;

    /* default output directory name */
    snprintf(output_dir, sizeof(output_dir), "%s", plot_dir_name);

    int opt;
    while ((opt = getopt(argc, argv, "f:p:as:")) != -1) {
        switch (opt) {
            case 'f':
                trace_file = optarg;
                break;
            case 'p':
                printf("The prefix for the plot file is: %s\n", optarg);
                snprintf(output_dir, sizeof(output_dir), "%s.%s", optarg,
                         plot_dir_name);
                break;
            case 'a':
                output_all = true;
                break;
            case 's':
                specific_cookie = strtoull(optarg, NULL, 0);
                specific_cookie_set = true;
                break;
            default:
                print_usage(argv[0]);
        }
    }

    if (!trace_file) {
        print_usage(argv[0]);
    }

    FILE* trace_fp = fopen(trace_file, "r");
    if (!trace_fp) {
        perror("fopen trace file");
        exit(EXIT_FAILURE);
    }
    if (output_all || specific_cookie_set) {
        if (mkdir(output_dir, 0755) == -1 && errno != EEXIST) {
            perror("mkdir failed");
            exit(EXIT_FAILURE);
        }
    }

    FILE* specific_out = NULL;
    if (specific_cookie_set) {
        char fname[MAX_NAME_LEN];
        snprintf(fname, sizeof(fname), "%s/%" PRIu64 ".txt", output_dir,
                 specific_cookie);
        specific_out = fopen(fname, "w");
        if (!specific_out) {
            perror("fopen specific out");
            exit(EXIT_FAILURE);
        }
    }

    char line[MAX_LINE_LEN];
    double first_timestamp = -1.0;
    char af_fmt[NAME_LEN] = {};
    snprintf(af_fmt, sizeof(af_fmt), "family=%%%ds", PROTOCOL_STR_LEN - 1);
    char src_fmt[NAME_LEN] = {};
    snprintf(src_fmt, sizeof(src_fmt), "src=%%%ds", SRC_STR_LEN - 1);
    char dest_fmt[NAME_LEN] = {};
    snprintf(dest_fmt, sizeof(dest_fmt), "dest=%%%ds", DEST_STR_LEN - 1);

    while (fgets(line, sizeof(line), trace_fp)) {
        char* pos;
        double timestamp, relative_ts;
        char family[PROTOCOL_STR_LEN] = {};
        char src[SRC_STR_LEN] = {};
        char dest[DEST_STR_LEN] = {};
        uint64_t sock_cookie = 0;
        uint32_t cwnd = 0, srtt = 0;

        // Extract timestamp from the beginning (e.g., "3335.244969:")
        if (sscanf(line, "%*s %*s %*s %lf", &timestamp) != 1) {
            fprintf(stderr, "Failed to parse timestamp: %s", line);
            continue;
        }

        // First timestamp reference
        if (first_timestamp < 0) {
            first_timestamp = timestamp;
        }
        relative_ts = timestamp - first_timestamp;

        pos = strstr(line, "family=");
        if (pos) {
            sscanf(pos, af_fmt, family); // sizeof(family) is PROTOCOL_STR_LEN
        }

        pos = strstr(line, "src=");
        if (pos) {
            sscanf(pos, src_fmt, src);
        }

        pos = strstr(line, "dest=");
        if (pos) {
            sscanf(pos, dest_fmt, dest);
        }

        pos = strstr(line, "snd_cwnd=");
        if (pos) {
            sscanf(pos, "snd_cwnd=%u", &cwnd);
        }

        pos = strstr(line, "srtt=");
        if (pos) {
            sscanf(pos, "srtt=%u", &srtt);
        }

        pos = strstr(line, "sock_cookie=");
        if (pos) {
            sscanf(pos, "sock_cookie=%" SCNu64, &sock_cookie);
        }

        FlowInfo* flow = find_or_create_flow(sock_cookie, src, dest, family,
                                             output_all);
        flow->record_count++;

        if (output_all && flow->out_fp) {
            fprintf(flow->out_fp, "%.6f %u %u\n", relative_ts, cwnd, srtt);
        } else if (specific_cookie_set && sock_cookie == specific_cookie &&
                   specific_out) {
            fprintf(specific_out, "%.6f %u %u\n", relative_ts, cwnd, srtt);
        }
    }

    fclose(trace_fp);
    if (specific_out) {
        fclose(specific_out);
    }

    FlowInfo* all_flows = NULL;
    size_t flow_count = 0;
    size_t total_cnts = 0;
    collect_flows(&all_flows, &flow_count, &total_cnts);
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
    free_flow_table();

    // Record the end time
    gettimeofday(&end, NULL);
    // Calculate the time taken in seconds and microseconds
    double seconds = (end.tv_sec - start.tv_sec);
    double micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

    printf("\nthis program execution time: %.3f seconds\n", micros / 1000000.0);
    return 0;
}
