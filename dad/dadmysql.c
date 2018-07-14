#include <my_global.h>
#include <mysql.h>
#include <string.h>
#include <time.h>

#include "dadmysql.h"
MYSQL mysql;

int dad_mysql_login(const char*host, const char* user, const char* passwd, const char*db)
{
    printf("dad_mysql_login_my\n");
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

void dad_mysql_close(){
    mysql_close(&mysql);
	 //mysql=NULL;
	 //mysql_library_end();
}
char* dad_mysql_get_user(unsigned char* mac)
{
	printf("dad_mysql_query\n");
	
	MYSQL_RES* res;
    MYSQL_ROW row;
	char *username;
	
	char str[1028]={0};
	sprintf(str,"SELECT username FROM radpostauth WHERE callingstationid='%s' ORDER BY authdate DESC",mac);
	printf("str=%s\n",str);

	if(mysql_query(&mysql,str) != 0)
	{
        fprintf(stderr, "fail to get user by mac!\n");
        exit(1);
    }
	
	res = mysql_store_result(&mysql);
	while((row = mysql_fetch_row(res))!=NULL){
		username = (char*)malloc(sizeof(char)*strlen(row[0]));
		strcpy(username,row[0]);
		printf("dad_mysql_get_user username:%s\n",username);
		mysql_free_result(res);
		return username;
	}
	mysql_free_result(res);
	
	return NULL;

}


