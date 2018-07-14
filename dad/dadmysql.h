#ifndef _DADMYSQL_H_
#define _DADMYSQL_H_

//extern MYSQL mysql;
int dad_mysql_login(const char*host, const char* user, const char* passwd, const char*db);
void dad_mysql_close();
char* dad_mysql_get_user(unsigned char* mac);

#endif
