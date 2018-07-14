#ifndef _ADMIN_MYSQL_H_
#define _ADMIN_MYSQL_H_

#include <mysql.h>
int mysql_login_my(MYSQL *mysql, const char*host, const char* user, const char* passwd, const char*db);
void mysql_close_my(MYSQL *mysql);
int mysql_query_prikey(MYSQL *mysql, char* prikey, int* p_prikeylen);
int mysql_insert_info_to_radpostauth(MYSQL *mysql, char* username, char* useripv6, char* mac, char *time);

#endif
