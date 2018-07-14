#ifndef _ADMIN_MYSQL_H_
#define _ADMIN_MYSQL_H_

#include <mysql.h>
int mysql_login_my(const char*host, const char* user, const char* passwd, const char*db);
void mysql_close_my();
int mysql_query_prikey(char* prikey, int* p_prikeylen);
int mysql_insert_info_to_radpostauth(char* username, char* useripv6, char* mac, char *time);

#endif
