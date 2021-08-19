
ADD_DEFINITIONS(-DMYSQL_SERVER)

MYSQL_ADD_PLUGIN(reuse_password_check reuse_password_check.c MODULE_ONLY)
