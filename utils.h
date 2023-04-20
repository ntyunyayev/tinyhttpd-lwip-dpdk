#include <stdint.h>
#include <rte_flow.h>
#define MAX_PATTERN_NUM 10
#define MAX_ACTION_NUM 10

#define HIGH_PRIORITY_DSCP 1
#define LOW_PRIORITY_DSCP 2

struct rte_flow *
generate_dscp_rule(uint16_t port_id, uint16_t rx_q, uint8_t dscp, struct rte_flow_error *error);