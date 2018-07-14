#include <my_global.h>
#include <mysql.h>
#include <string.h>
#include <time.h>

#include "admin_mysql.h"

MYSQL mysql;
#define TIMEBUFLEN 256

int mysql_login_my(const char*host, const char* user, const char* passwd, const char*db)
{
	mysql_init(&mysql);
	
	
	/*if(!mysql_real_connect(mysql,host,user,passwd,db,3306,NULL,0))
	{
		fprintf(stderr,"Failedtoconnecttodatabase:Error:%s\n",mysql_error(&mysql));
	}*/
	
	if(mysql_real_connect(&mysql,host,user,passwd,db,3306,NULL,0)==NULL)
	{

		printf("mysql_real_connect fail\n");
		exit(-1);
	}
	printf("mysql_login_my success\n");
	return 0;
}

void mysql_close_my(){
    mysql_close(&mysql);
	printf("mysql_close\n");
	//mysql=NULL;
	//mysql_library_end();
}

int mysql_query_prikey(char* prikey, int* p_prikeylen)
{
	printf("mysql_query_prikey\n");

	MYSQL_RES* res;
    MYSQL_ROW row;

	time_t tnow = time(NULL);
	struct tm ptm = { 0 };  
	localtime_r(&tnow,&ptm);
	//struct tm* tmlocal = localtime(&datetime);
	char tmpBuf[TIMEBUFLEN];

	strftime(tmpBuf,TIMEBUFLEN,"%Y-%m-%d %H:%M:%S", &ptm);
	printf("time is [%s]",tmpBuf);  
	
	//const char *str_sql="select IDEA_KEY from NA_IDEA where tmpBuf between START_TIME and END_TIME";
	char str[1028]={0};
	sprintf(str,"select IDEA_KEY from NA_IDEA where '%s' between START_TIME and END_TIME",tmpBuf);
	printf("str=%s\n",str);

	if(mysql_query(&mysql,str) != 0)
	{
		fprintf(stderr, "fail to query!\n"); 
		exit(1); 
	}
	
	res = mysql_store_result(&mysql);
	while((row = mysql_fetch_row(res))!=NULL){
		strcpy(prikey,row[0]);
		*p_prikeylen=strlen(row[0]);
		mysql_free_result(res);
		return 0;
	}
	mysql_free_result(res);
	return -1;
}

int mysql_query_radpostauth_is_exist(char* username,char* useripv6)
{
	char str_sql[1028]={0};
	sprintf(str_sql,"select * from radpostauth where username='%s' and user_ipv6_address='%s'",username, useripv6);
	if(mysql_query(&mysql,str_sql)!=0)
	{
		fprintf(stderr, "fail to query if exist!\n");
		exit(1);
	}
	
	MYSQL_RES* res;
	MYSQL_ROW row;
	res = mysql_store_result(&mysql);
	if((row = mysql_fetch_row(res))!=NULL)
		return 0;//存在
	else
		return 1;//不存在
}

int mysql_insert_info_to_radpostauth(char* username, char* useripv6, char* mac, char *time)
{
	//const char* str_sql = "insert into `radpostauth` values(NULL,username,NULL,NULL,time,NULL,NULL,useripv6,mac,NULL,NULL)"
	char str_sql[1028]={0};
	sprintf(str_sql,"insert into radpostauth(username,authdate,user_ipv6_address,user_mac) values('%s','%s','%s','%s')",username,time,useripv6,mac);
	printf("mysql_insert_info_to_radpostauth str_sql:%s\n",str_sql);
	//const char* str_sql = "insert into `radpostauth(username,authdata,user_ipv6_address,user_mac)` values(username,time,useripv6,mac);";
	if(mysql_query(&mysql,str_sql)!=0)
	{
		fprintf(stderr, "fail to insert!\n");
		exit(1);
	}
	my_ulonglong affected_row = mysql_affected_rows(&mysql);
	{
		printf("%d rows affected.\n", (int)affected_row);  
		return 0;  
	}
}

int mysql_update_radpostauth(char* username, char* useripv6, char* mac, char *time)
{
	char str_sql[1028]={0};
	sprintf(str_sql,"UPDATE radpostauth SET authdate='%s',user_mac='%s' WHERE username='%s' AND user_ipv6_address='%s'",time,mac,username,useripv6);
	printf("mysql_update_radpostauth str_sql:%s\n",str_sql);
	if(mysql_query(&mysql,str_sql)!=0)
    {
        fprintf(stderr, "fail to insert!\n");
        exit(1);
    }
    my_ulonglong affected_row = mysql_affected_rows(&mysql);
    {
        printf("%d rows affected.\n", (int)affected_row);
        return 0;
    }
}


