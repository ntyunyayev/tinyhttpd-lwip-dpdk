#include "utils.h"


struct rte_flow *
generate_dscp_rule(uint16_t port_id, uint16_t rx_q, uint8_t dscp, struct rte_flow_error *error)
{
    // printf("rx_q : %d\n", rx_q);
    /* Declaring structs being used. 8< */
    struct rte_flow_attr attr;
    struct rte_flow_item pattern[MAX_PATTERN_NUM];
    struct rte_flow_action action[MAX_ACTION_NUM];
    struct rte_flow *flow = NULL;
    struct rte_flow_action_queue queue = {.index = rx_q};
    struct rte_flow_item_ipv4 ip_spec;
    struct rte_flow_item_ipv4 ip_mask;

    /* >8 End of declaring structs being used. */
    int res;

    memset(pattern, 0, sizeof(pattern));
    memset(action, 0, sizeof(action));

    /* Set the rule attribute, only ingress packets will be checked. 8< */
    memset(&attr, 0, sizeof(struct rte_flow_attr));
    attr.ingress = 1;
    /* >8 End of setting the rule attribute. */

    /*
     * create the action sequence.
     * one action only,  move packet to queue
     */
    action[0].type = RTE_FLOW_ACTION_TYPE_QUEUE;
    action[0].conf = &queue;
    action[1].type = RTE_FLOW_ACTION_TYPE_END;

    /*
     * set the first level of the pattern (ETH).
     * since in this example we just want to get the
     * ipv4 we set this level to allow all.
     */

    /* Set this level to allow all. 8< */
    pattern[0].type = RTE_FLOW_ITEM_TYPE_ETH;

    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;

    memset(&ip_spec, 0, sizeof(struct rte_flow_item_ipv4));
    memset(&ip_mask, 0, sizeof(struct rte_flow_item_ipv4));
    ip_spec.hdr.type_of_service = dscp << 2;
    ip_mask.hdr.type_of_service = (uint8_t)(0xFF << 2);
    pattern[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
    pattern[1].spec = &ip_spec;
    pattern[1].mask = &ip_mask;


    /* The final level must be always type end. 8< */
    pattern[2].type = RTE_FLOW_ITEM_TYPE_END;
    /* >8 End of final level must be always type end. */

    /* Validate the rule and create it. 8< */
    res = rte_flow_validate(port_id, &attr, pattern, action, error);
    if (!res)
        flow = rte_flow_create(port_id, &attr, pattern, action, error);
    /* >8 End of validation the rule and create it. */

    return flow;
}