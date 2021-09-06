/* Copyright (c) 2021, Oleksandr Byelkin and MariaDB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335  USA */

#include <mysqld_error.h>
#include <my_attribute.h>
#include <mysql/plugin_password_validation.h>


#include <my_config.h>
//#include <assert.h>
#include <my_global.h>
#include <my_base.h>
//#include <typelib.h>
//#include <ctype.h>
//#include <string.h>
//#include <mysql/plugin.h>
//#include <mysql/plugin_audit.h>

#include <mysql.h>
#include <mysql_com.h>

#include <mysql/service_sha2.h>

#define HISTORY_DB_NAME "reuse_password_check_history"

#define SQL_BUFF_LEN 2048

// 0 - unlimit, otherwise number of days to check
static unsigned interval= 0;

static char digits[]= "0123456789ABCDEF";

static void bin_to_hex512(char *to, const unsigned char *str)
{
  const unsigned char *str_end= str + (512/8);
  for (; str != str_end; ++str)
  {
    *to++= digits[((uchar) *str) >> 4];
    *to++= digits[((uchar) *str) & 0x0F];
  }
}

static void report_sql_error(MYSQL *mysql)
{
  my_printf_error(ER_UNKNOWN_ERROR, "[%d] %s", ME_WARNING,
                  mysql_errno(mysql), mysql_error(mysql));
}

static int create_table(MYSQL *mysql)
{
  if (mysql_real_query(mysql,
        // 512/8 = 64
        STRING_WITH_LEN("CREATE TABLE mysql." HISTORY_DB_NAME
                        " ( hash binary(64),"
                        " time timestamp,"
                        " primary key (hash), index tm (time) )"
                        " ENGINE=Aria")))
  {
    report_sql_error(mysql);
    return 1;
  }
  return 0;
}


/**
  Run this query and create table if needed for it

  @param mysql           connection handler
  @param query           The query to run
  @param len             length of the query text

  @retval 1 - Error
  @retval 0 - OK
*/

static int run_query_with_table_creation(MYSQL *mysql, const char *query,
                                         size_t len)
{
  if (unlikely(mysql_real_query(mysql, query, len)))
  {
    unsigned int rc= mysql_errno(mysql);
    if (rc != ER_NO_SUCH_TABLE)
    {
      // supress this error in case of try to add the same password twice
      if (rc != ER_DUP_ENTRY)
        report_sql_error(mysql);
      return 1;
    }
    if (create_table(mysql))
      return 1;
    if (unlikely(mysql_real_query(mysql, query, len)))
    {
      report_sql_error(mysql);
      return 1;
    }
  }
  return 0;
}

static int validate(const MYSQL_CONST_LEX_STRING *username,
                    const MYSQL_CONST_LEX_STRING *password,
                    const MYSQL_CONST_LEX_STRING *hostname)
{
  MYSQL *mysql= NULL;
  size_t key_len= username->length + password->length + hostname->length;
  size_t buff_len= (key_len > SQL_BUFF_LEN ? key_len : SQL_BUFF_LEN);
  size_t len;
  char *buff= malloc(buff_len);
  unsigned char hash[512/8];
  char escaped_hash[512/8*2 + 1];
  if (!buff)
    return 1;

  mysql= mysql_init(NULL);
  if (!mysql)
  {
    free(buff);
    return 1;
  }

  memcpy(buff, hostname->str, hostname->length);
  memcpy(buff + hostname->length, username->str, username->length);
  memcpy(buff + hostname->length + username->length, password->str,
          password->length);
  buff[key_len]= 0;
  bzero(hash, sizeof(hash));
  my_sha512(hash, buff, key_len);
  /*
  my_printf_error(ER_UNKNOWN_ERROR,
                  "user (%d): '%s'", ME_WARNING,
                  username->length, username->str);
  my_printf_error(ER_UNKNOWN_ERROR,
                  "host (%d): '%s'", ME_WARNING,
                  hostname->length, hostname->str);
  my_printf_error(ER_UNKNOWN_ERROR,
                  "pswd (%d): '%s'", ME_WARNING,
                  password->length, password->str);
  my_printf_error(ER_UNKNOWN_ERROR,
                  "key (%d): '%s'", ME_WARNING,
                  key_len, buff);
  */
  if (mysql_real_connect_local(mysql, NULL, NULL, NULL, 0) == NULL)
    goto sql_error;

  if (interval)
  {
    // trim the table
    len= snprintf(buff, buff_len,
                  "DELETE FROM mysql." HISTORY_DB_NAME
                  " WHERE time < DATE_SUB(NOW(), interval %d day)",
                  interval);
    if (unlikely(run_query_with_table_creation(mysql, buff, len)))
      goto sql_error;
  }

  bin_to_hex512(escaped_hash, hash);
  escaped_hash[512/8*2]= '\0';
  len= snprintf(buff, buff_len,
                "INSERT INTO mysql." HISTORY_DB_NAME "(hash) "
                "values (x'%s')",
                escaped_hash);
  if (unlikely(run_query_with_table_creation(mysql, buff, len)))
    goto sql_error;

  free(buff);
  mysql_close(mysql);
  return 0; // OK

sql_error:
  free(buff);
  if (mysql)
    mysql_close(mysql);
  return 1; // Error
}

static MYSQL_SYSVAR_UINT(interval, interval, PLUGIN_VAR_RQCMDARG,
  "How old (in days) passwords to check (0 means infinity)", NULL, NULL,
  0, 0, 365*10, 1);


static struct st_mysql_sys_var* sysvars[]= {
  MYSQL_SYSVAR(interval),
  NULL
};

static struct st_mariadb_password_validation info=
{
  MariaDB_PASSWORD_VALIDATION_INTERFACE_VERSION,
  validate
};

maria_declare_plugin(simple_password_check)
{
  MariaDB_PASSWORD_VALIDATION_PLUGIN,
  &info,
  "reuse_password_check",
  "Oleksandr Byelkin",
  "Reusage of password check",
  PLUGIN_LICENSE_GPL,
  NULL,
  NULL,
  0x0100,
  NULL,
  sysvars,
  "1.0",
  MariaDB_PLUGIN_MATURITY_ALPHA
}
maria_declare_plugin_end;
