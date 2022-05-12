<p align="center">
  <br> 中文 | <a href="README-EN.md">English</a>
  <h1 align="center">欢迎使用Best-Nginx-WAF 👋</h1>
  <br/>
  <p align="center">
  <img align="center" src="https://img.shields.io/badge/release-v1.0.0-green" />
  <img align="center" src="https://img.shields.io/badge/documentation-yes-ff69b4" />
  <img align="center" src="https://img.shields.io/badge/license-Apache%202-blue" />
  </p>
</p>


> ⭐️Best-Nginx-WAF是一款基于Nginx的使用Lua语言开发的灵活高效的Web应用层防火墙。Lua语言的灵活和不亚于C语言的执行效率，保证了在做为网站应用层防火墙时，功能和性能之间完美的平衡，整个防火墙系统对性能的消耗几乎可以忽略不计。

## 📝 主要特性

- **支持丰富的特性**

1. **跨平台**： Nginx可以运行在哪里，WAF就可以运行在哪里
2. **高度可配置**： 对于攻击的处理有拦截、跳转、观察等处理模式
3. **支持流量攻击防护**： 支持对ip访问频次拦截限制、CC攻击防护
4. **规则多维度**： 支持IP黑白名单、URI黑白名单、支持UserAgent/Request Body/Header/Request Params等进行规则匹配防护
5. **日志完备**： 攻击日志、流量日志以JSON格式日志保存; 方便后续管理
6. **超高的性能和稳定性**： 规则重载不中断业务; 非攻击请求处理耗时在3ms之内; 攻击请求处理耗时在20ms之内;
7. **支持策略更新**： 支持本地规则加载或从server中动态更新;
8. **支持健康检查**： 支持nginx配置的upstream健康检查; 定时心跳配合server支持waf自身健康检测;
9. **支持钉钉告警**： 对server和waf的故障能够通过钉钉进行及时告警;

## 🔧 安装部署

## 以CentOS 7为例

### 编译安装openresty

从[openresty](http://openresty.org/cn/download.html)官方下载最新版本的源码包。

### Step1 编译安装openresty：

```bash
#准备依赖包
yum -y install  wget gcc perl unzip openssl openssl-devel
#下载并解压源码包
wget https://github.com/zylhahah/best-nginx-waf/archive/refs/heads/master.zip
tar zxf openresty-1.13.6.1.tar.gz
#编译安装
cd openresty-1.13.6.1
./configure
make
make install   #默认会安装到/usr/local/openresty目录
#启动nginx
/usr/local/openresty/nginx/sbin/nginx -t  #检查配置文件语法是否正确
/usr/local/openresty/nginx/sbin/nginx     #启动nginx
```

### Step2 部署Best-Nginx-Waf

#### 下载 Best-Nginx-Waf

```
wget https://github.com/ddonline/nginx-lua-waf/archive/master.zip
```

#### 解压缩

```
unzip master.zip  #解压后得到文件夹 best-nginx-waf
```

#### 将best-nginx-waf文件夹复制到openresty目录下

```
cp -r best-nginx-waf /usr/local/openresty
```

#### 三方包安装

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

#### 在nginx目录下的nginx.conf中添加配置

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
    
# 修改日志目录权限,使nginx对目录可写 具体目录位置可在conf.lua文件中修改
mkdir -p /var/log/best-nginx-waf/
chmod o+w /var/log/best-nginx-waf/
# 重载nginx使配置生效
/usr/local/openresty/nginx/sbin/nginx -t  #检查配置文件语法是否正确
/usr/local/openresty/nginx/sbin/nginx -s reload    #重载nginx
```

#### 使用中注意事项

- waf配置文件：best-nginx-waf/config.lua，各项配置均有注释说明
- 使用前请检查过滤规则是否符合自己实际情况，根据实际增删条目，防止误伤; 不确定需要观察的规则可先配置rule.action为Record 进行观察;规则的观察模式不进行拦截;
- 规则文件全部支持正则表达式，但不区分大小写
- 更新规则文件后，使用reload命令(/usr/local/openresty/nginx/sbin/nginx -s reload)使用配置生效，该命令不会中断服务，不建议使用restart
- 所有规则在rules文件夹下, 具体配置可参考已有的规则

#### 🙏 讨论区

如有问题可以在 GitHub 提 issue, 或者直接联系我，问题我都会及时处理

1. GitHub issue: [创建issue](https://github.com/zylhahah/best-nginx-waf/issues )
2. 作者QQ : 24417148
3. 邮箱: 24417148@qq.com
