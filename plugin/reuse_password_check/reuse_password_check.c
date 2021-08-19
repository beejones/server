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

// 0 - off, otherwise how many previouse passwords check
static unsigned history= 0;
// 0 - off, otherwise number of days to check
static unsigned interval= 0;

static int validate(const MYSQL_CONST_LEX_STRING *username,
                    const MYSQL_CONST_LEX_STRING *password)
{
  MYSQL *mysql;
  //MYSQL_RES *res;
  mysql= mysql_init(NULL);
  /*
  my_printf_error(ER_UNKNOWN_ERROR,
                  username->str, ME_WARNING);
  my_printf_error(ER_UNKNOWN_ERROR,
                  password->str, ME_WARNING);
  */
  if (mysql_real_connect_local(mysql, NULL, NULL, NULL, 0) == NULL)
    return 1;

  if (mysql_real_query(mysql,
        STRING_WITH_LEN("select Password from mysql.password_history")))
    return 1;

  return 1; // fail
  return 0; // pass
}

static MYSQL_SYSVAR_UINT(history, history, PLUGIN_VAR_RQCMDARG,
  "How many previous passwords to check (0 means off)", NULL, NULL,
  0, 0, 1000, 1);

static MYSQL_SYSVAR_UINT(interval, interval, PLUGIN_VAR_RQCMDARG,
  "How old (in days) passwords to check (0 means off)", NULL, NULL,
  0, 0, 365*10, 1);


static struct st_mysql_sys_var* sysvars[]= {
  MYSQL_SYSVAR(history),
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
