# Best-Nginx-WAF概述

Best-Nginx-WAF是一款基于Nginx的使用Lua语言开发的灵活高效的Web应用层防火墙。Lua语言的灵活和不亚于C语言的执行效率，保证了在做为网站应用层防火墙时，功能和性能之间完美的平衡，整个防火墙系统对性能的消耗几乎可以忽略不计。

# 主要特性

防火墙只是一个框架，核心是rule规则，源码中规则文件仅供参考，在实际的使用过程中，接合自己的业务特点，可以灵活开关各项功能，以及增添各种规则。

- 支持对特定站点特定IP和特定URL组合的访问频率控制，即可以通过配置的百分比控制返回真实数据或预先配置的JSON字符串，该功能通常用于希望控制访问频率的接口，不希望客户端高频访问，以优雅的方式减少服务端不必要的性能开销
- Nginx工作于web服务器模式，可以有多个不同的站点，仅需要配置hostname就可以对不同的站点应用不同的规则，或者使用全局的规则
- 规则使用正则匹配，灵活性高
- 支持IP白名单、IP黑名单、UserAgent、URL白名单、URL、Cookie、请求参数、POST级别的过滤，每个功能均有独立开关，可以自由启用需要的过滤功能，并且在规则层面都是可以基于站点的
- 支持对CC攻击的防护
- 完整的日志记录功能，JSON格式日志，方便后期通过ELK集中管理
- 匹配规则后，支持回显html字符串、跳转到指定URL和不处理三种模式，其不设置为不处理后，仅记录日志，并不真正执行拦截动作，方便在生产环境中调试，不影响业务
- 安装、部署和维护非常简单
- 重载规则不会中断正常业务
- 跨平台，Nginx可以运行在哪里，WAF就可以运行在哪里

# 安装部署

## 以CentOS 7为例

### 编译安装openresty

从[openresty](http://openresty.org/cn/download.html)官方下载最新版本的源码包。

01、编译安装openresty：

```bash
#安装工具
yum -y install wget
#准备编译环境
yum -y install gcc
#准备依赖包
yum -y install install perl openssl openssl-devel
#下载并解压源码包
wget https://github.com/zylhahah/best-nginx-waf/archive/refs/heads/master.zip
tar zxf openresty-1.13.6.1.tar.gz
#编译安装
cd openresty-1.13.6.1
./configure
make
make install
#默认openresty会安装到/usr/local/openresty目录
#nginx配置文件位置:/usr/local/openresty/nginx/conf/nginx.conf
#nginx站点目录:/usr/local/openresty/nginx/html
#nginx可执行文件位置:/usr/local/openresty/nginx/sbin/nginx



#启动nginx
/usr/local/openresty/nginx/sbin/nginx -t  #检查配置文件语法是否正确
/usr/local/openresty/nginx/sbin/nginx     #启动nginx
```

# 02、部署Best-Nginx-Waf

## 安装工具

```
yum -y install unzip
```

## 下载Best-Nginx-Waf

```
wget https://github.com/ddonline/nginx-lua-waf/archive/master.zip
```

## 解压缩

```
unzip master.zip  #解压后得到文件夹 best-nginx-waf
```

## 将best-nginx-waf文件夹复制到openresty目录下

```
cp -r best-nginx-waf /usr/local/openresty

```

## 三方包安装

```
cd best-nginx-waf 目录下
cp http_headers.lua /usr/local/openresty/lualib/resty/
cp http.lua /usr/local/openresty/lualib/resty/

cd best-nginx-waf/luasocket-2.0.2
1、执行 make 命令
2、mkdir -p /usr/local/openresty/luajit/lib/lua/5.1/socket   
   cp src/socket.so.2.0.2 /usr/local/openresty/luajit/lib/lua/5.1/socket/core.so
   mkdir -p /usr/local/openresty/luajit/lib/lua/5.1/mime
   cp src/mime.so.1.0.2 /usr/local/openresty/luajit/lib/lua/5.1/mime/core.so


```

## 在nginx目录下的nginx.conf中添加配置

```bash
vi /usr/local/openresty/nginx/conf/nginx.conf
在http级别添加以下内容:
        lua_package_path "/usr/local/openresty/best-nginx-waf/?.lua;/usr/local/openresty/best-nginx-waf/lua-resty-redis/lib/?.lua;/usr/local/openresty/best-nginx-waf/lua-resty-lrucache/lib/?.lua;/usr/local/openresty/best-nginx-waf/luasocket-2.0.2/src/?.lua;/usr/local/openresty/lualib/?.lua;";
        lua_shared_dict limit 50m;
        lua_code_cache on;
        lua_regex_cache_max_entries 4096;
        init_worker_by_lua_file   /usr/local/openresty/best-nginx-waf/job.lua;
        access_by_lua_file /usr/local/openresty/best-nginx-waf/access.lua;
    
    在server级别修改server_name:
    #在每个vhost中(server级别)定义server_name时，建议设置一个以上的主机名，默认第一个将做为规则中的主机区别标志，例如
    server_name  api api.test.com;
    
# 修改日志目录权限,使nginx对目录可写
mkdir -p /var/log/best-nginx-waf/
chmod o+w /var/log/best-nginx-waf/
# 重载nginx使配置生效
/usr/local/openresty/nginx/sbin/nginx -t  #检查配置文件语法是否正确
/usr/local/openresty/nginx/sbin/nginx -s reload    #重载nginx

```

## 使用中注意事项

- waf配置文件：best-nginx-waf/config.lua，各项配置均有注释说明
- 使用前请检查过滤规则是否符合自己实际情况，根据实际增删条目，防止误伤
- 规则文件除frequency.rule外全部为正则表达式，除frequency.rule、whiteip.rule、blackip.rule、whiteurl.rule外全部不区分大小写
- 规则文件中以"--"开头的为注释内容，除最后一行外，不能留有空行，且结尾字符应为LF
- 在用于生产环境时，可先将模式设置为观察模式并检查拦截日志，确认有无误伤，该模式仅记录日志，不实际进行拦截(对IP黑名单和CC攻击过滤不适用，详见处理流程图)
- 更新规则文件后，使用reload命令(/usr/local/openresty/nginx/sbin/nginx -s reload)使用配置生效，该命令不会中断服务，不建议使用restart
- 部署过程中对openresty的安装使用的是默认选项，如果需要自定义，可以参考我的博文:[编译Nginx(OpenResty)支持Lua扩展](http://pdf.us/2018/03/19/742.html)

# 致谢

感谢春哥开源的[openresty](https://openresty.org)

