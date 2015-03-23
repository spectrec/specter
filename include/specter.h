#ifndef __SPECTER_H__
#define __SPECTER_H__

struct libev_conn;
void specter_new_node_conn_init(struct libev_conn *cn);
void specter_new_client_conn_init(struct libev_conn *cn);

#endif
