
local _M = {
    -- 防火墙开关
    waf_enable = "on",
    -- WAF 拦截开关
    attack_block_enable = "on",
    -- 健康检查开关
    health_check_enable = "off",
    -- WAF 本身日志级别
    log_enable = "on",
    -- 日志文件存放目录 结尾不带/
    log_dir = "/var/log/nginx",
    -- 规则文件存放目录 结尾不带/
    policy_dir = "/usr/local/openresty/nginx-waf/rules",
    -- 上报攻击信息开关
    attack_upload_enable = "on",
    -- 上报攻击信息后端HOST
    server_addr = "http://nginxwafng.testk8s.tsign.cn",
    -- 上报攻击信息后端API
    attack_upload_uri = "/api/public/attack-record",
    -- 上报响应信息后端API
    resp_upload_uri = "/api/public/response-record",
    -- 心跳间隔 单位: 秒
    heart_beat_interval_second = 15,
    -- 上报心跳息后端API
    heart_beat_upload_uri = "/api/public/client/heartbeat",
    -- 钉钉告警群Token配置
    ding_ding_enable = "on",
    -- 钉钉告警群Token配置
    ding_ding_token = "/robot/send?access_token=e335459260ff1f712da8d49cc12540266b64112823c80984332544f007289bf4",
    -- 规则加载配置 local: 本地rules文件夹  remote: 从server心跳返回拉取
    rules_load_mode = "local",

    -- 频率控制开关
    frequency_control_check = "on",
    -- 频率控制模式,watch/deny
    frequency_mode = "deny",

    -- IP白名单开关
    white_ip_check = "on",
    -- IP黑名单开关
    black_ip_check = "on",

    -- URL白名单开关
    white_url_check = "on",
    black_url_check = "on",

    cc_check = "off",

    -- 攻击检测开关
    attack_check = "on",
    head_check = "on",
    user_agent_check = "on",
    url_check = "on",
    param_check = "on",
    body_check = "on",


    -- 处理方式 redirect(重定向)/watch(模式只记录日志)
    waf_model = "deny",
    -- 当配置为redirect时跳转到的URL
    waf_redirect_url = "https://www.esign.cn/",

    -- 拦截页面
    config_output_html = [[
        <html>
         <head>
          <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
          <title>网站防火墙</title>
          <style>      p {        line-height: 20px;      }      ul {        list-style-type: none;      }      li {        list-style-type: none;      }</style>
         </head>
         <body style="      padding: 0;      margin: 0;      font: 14px/1.5 Microsoft Yahei, 宋体, sans-serif;      color: #555;    ">
          <div style="margin: 0 auto; width: 100vh; padding-top: 100px; overflow: hidden">
           <div style="width: 600px;margin: 0 auto;">
            <div style="            height: 40px;            line-height: 40px;            color: #fff;            font-size: 16px;            overflow: hidden;            background: #e50012;            padding-left: 20px;          ">
             <img src="https://www.esign.cn/images/whitelogo.png" width="110px" height="30px" style="margin-top: 5px;" />
            </div>
            <div style="            border: 1px dashed #cdcece;            border-top: none;            font-size: 14px;            background: #fff;            color: #555;            line-height: 24px;            height: 220px;            padding: 20px 20px 0 20px;            overflow-y: auto;            background: #f3f7f9;          ">
             <p style="              margin-top: 0px;              margin-bottom: 0px;              margin-left: 0px;              margin-right: 0px;              -qt-block-indent: 0;              text-indent: 0px;            "><span style="font-weight: 600; color: #fc4f03">您的请求不符合WAF规则，已被网站管理员设置拦截！</span></p>
             <p style="              margin-top: 0px;              margin-bottom: 0px;              margin-left: 0px;              margin-right: 0px;              -qt-block-indent: 0;              text-indent: 0px;            "> 可能原因：您提交的内容包含危险的攻击请求</p>
             <p style="              margin-top: 12px;              margin-bottom: 12px;              margin-left: 0px;              margin-right: 0px;              -qt-block-indent: 1;              text-indent: 0px;            "> 如何解决：</p>
             <ul style="              margin-top: 0px;              margin-bottom: 0px;              margin-left: 0px;              margin-right: 0px;              -qt-list-indent: 1;            ">
              <li style="                margin-top: 12px;                margin-bottom: 0px;                margin-left: 0px;                margin-right: 0px;                -qt-block-indent: 0;                text-indent: 0px;              "> 1）检查提交内容；</li>
              <li style="                margin-top: 0px;                margin-bottom: 0px;                margin-left: 0px;                margin-right: 0px;                -qt-block-indent: 0;                text-indent: 0px;              "> 2）如网站托管，请联系空间提供商；</li>
              <li style="                margin-top: 0px;                margin-bottom: 0px;                margin-left: 0px;                margin-right: 0px;                -qt-block-indent: 0;                text-indent: 0px;              "> 3）普通网站访客，请联系网站管理员huanyu@tsign.cn；</li>
             </ul>
            </div>
           </div>
          </div>
         </body>
        </html>
    ]],
}

return _M