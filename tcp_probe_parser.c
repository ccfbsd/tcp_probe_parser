/*
 ============================================================================
 Name        : tcp_probe_parser.c
 Author      : Cheng Cui
 Version     :
 Copyright   : see the LICENSE file
 Description : Check tcp_probe log stats in C, Ansi-style
 ============================================================================
 */

#include "lib.h"

int
main(int argc, char* argv[]) {
    /* Record the start time */
    struct timeval start, end;
    gettimeofday(&start, NULL);

    char* trace_file = NULL;
    bool output_all = false;
    uint64_t specific_cookie = 0;
    bool specific_cookie_set = false;
    bool cwnd_filter = false;
    /* if cwnd_filter on, number of events between generating a log message */
    uint32_t events_per_log = 100;

    /* default output directory name */
    snprintf(output_dir, sizeof(output_dir), "%s", plot_dir_name);

    int opt;
    while ((opt = getopt(argc, argv, "f:p:cas:")) != -1) {
        switch (opt) {
            case 'f':
                trace_file = optarg;
                break;
            case 'p':
                printf("The prefix for the plot file is: %s\n", optarg);
                snprintf(output_dir, sizeof(output_dir), "%s.%s", optarg,
                         plot_dir_name);
                break;
            case 'c':
                cwnd_filter = true;
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

    /* try to create the plot directory (ignore if it already exists) */
    if (output_all || specific_cookie_set) {
        if (mkdir(output_dir, 0755) == -1 && errno != EEXIST) {
            perror("mkdir failed");
            exit(EXIT_FAILURE);
        }
        /* clean the directory before writing */
        clean_directory(output_dir);
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

        /* extract timestamp from the beginning */
        if (sscanf(line, "%*s %*s %*s %lf", &timestamp) != 1) {
            continue;
        }

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
            sscanf(pos, "sock_cookie=%" SCNx64, &sock_cookie);
        }

        FlowInfo* flow = find_or_create_flow(sock_cookie, src, dest, family,
                                             output_all);
        flow->record_count++;
        flow->srtt_sum += srtt;
        if (flow->srtt_min > srtt) {
            flow->srtt_min = srtt;
        }
        if (flow->srtt_max < srtt) {
            flow->srtt_max = srtt;
        }
        flow->cwnd_sum += cwnd;
        if (flow->cwnd_min > cwnd) {
            flow->cwnd_min = cwnd;
        }
        if (flow->cwnd_max < cwnd) {
            flow->cwnd_max = cwnd;
        }

        if (cwnd_filter) {
            if (flow->last_cwnd == cwnd) {
                flow->counter = (flow->counter + 1) % events_per_log;
                if (flow->counter > 0) {
                    continue;
                }
            } else {
                flow->last_cwnd = cwnd;
                flow->counter = 0;
            }
        }

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

    summary();

    // Record the end time
    gettimeofday(&end, NULL);
    // Calculate the time taken in seconds and microseconds
    double seconds = (end.tv_sec - start.tv_sec);
    double micros = ((seconds * 1000000) + end.tv_usec) - (start.tv_usec);

    printf("\nthis program execution time: %.3f seconds\n", micros / 1000000.0);
    return 0;
}
