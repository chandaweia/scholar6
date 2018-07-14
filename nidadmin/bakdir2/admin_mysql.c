#include <my_global.h>
#include <mysql.h>
#include <string.h>
#include <time.h>

#include "admin_mysql.h"

MYSQL mysql;
#define TIMEBUFLEN 256

int mysql_login_my(const char*host, const char* user, const char* passwd, const char*db)
{
	printf("mysql_login_my\n");
	mysql_init(&mysql);
	printf("mysql_init sucess\n");
	
	
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

	printf("mysql_query_prikey11111111111\n");
	strftime(tmpBuf,TIMEBUFLEN,"%Y-%m-%d %H:%M:%S", &ptm);
	printf("mysql_query_prikey22222222222\n");
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
		printf("mysql_query_prikey 11111111\n");
		strcpy(prikey,row[0]);
		printf("mysql_query_prikey prikey:%s\n",prikey);
		*p_prikeylen=strlen(row[0]);
		mysql_free_result(res);
		return 0;
	}
	printf("mysql_query_prikey222222\n");
	mysql_free_result(res);
	return -1;
}

int mysql_insert_info_to_radpostauth(char* username, char* useripv6, char* mac, char *time)
{
	//const char* str_sql = "insert into `radpostauth` values(NULL,username,NULL,NULL,time,NULL,NULL,useripv6,mac,NULL,NULL)"
	printf("mysql_insert_info_to_radpostauth\n");
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


