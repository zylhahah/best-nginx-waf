local io = require("io")
local cjson = require("cjson.safe")
local string = require("string")
local config = require("config")
local socket = require("socket.core")

local _M = {
    version = "0.14",
}

function _M.print_table(t)
    local function parse_array(key, tab)
        local str = ''
        for _, v in pairs(tab) do
            str = str .. key .. ' ' .. v .. '\r\n'
        end
        return str
    end

    local str = ''
    for k, v in pairs(t) do
        if type(v) == "table" then
            str = str .. parse_array(k, v)
        else
            str = str .. k .. ' ' .. v .. '\r\n'
        end
    end
    return str
end


-- 记录JSON格式日志
function _M.log(msg)
    if config.log_enable ~= "on" then
        return
    end
    local line_num = debug.getinfo(2).currentline
    local method_name = debug.getinfo(2).name
    local log_line = string.format("[%s]-%s()%s #:: %s; %s, %s:%s; ", ngx.localtime(), method_name, line_num, msg, _M.get_client_ip(), ngx.req.get_method(), ngx.var.uri)
    local log_name = string.format("%s/%s_waf.log", config.log_dir, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        ngx.log(ngx.ERR, "open nginx-waf log file err:" .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(log_line, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
end


-- 记录JSON格式日志
function _M.pure_log(msg)
    if config.log_enable ~= "on" then
        return
    end
    local line_num = debug.getinfo(2).currentline
    local method_name = debug.getinfo(2).name
    local log_line = string.format("[%s]-%s()%s #:: %s;", ngx.localtime(), method_name, line_num, msg)
    local log_name = string.format("%s/%s_waf.log", config.log_dir, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        ngx.log(ngx.ERR, "open nginx-waf log file (" .. log_name .. ") err:" .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(log_line, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
end

function _M.get_local_ip()
    local MyHostName = socket.dns.gethostname() --本机名
    return socket.dns.toip(MyHostName) --本机IP
end

function _M.get_local_host_name()
    return socket.dns.gethostname() --本机名
end

-- 获取来访IP
function _M.get_client_ip()
    local CLIENT_IP = ngx.req.get_headers()["X_real_ip"]
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.req.get_headers()["X_Forwarded_For"]
    end
    if CLIENT_IP == nil then
        CLIENT_IP = ngx.var.remote_addr
    end

    -- 判断CLIENT_IP是否为table类型，table类型即获取到多个ip的情况
    if type(CLIENT_IP) == "table" then
        --取外网请求IP
        CLIENT_IP = table.concat(CLIENT_IP, ",")
    end

    if type(CLIENT_IP) ~= "string" then
        CLIENT_IP = "0.0.0.0"
    end

    return CLIENT_IP
end

-- 获取UserAgnet
function _M.get_user_agent()
    local USER_AGENT = ngx.var.http_user_agent
    if USER_AGENT == nil then
        USER_AGENT = "unknown"
    end
    return USER_AGENT
end

function _M.send_ding_talk(msg)
    _M.pure_log("----------------send_ding_ding_msg ------------------")
    _M.pure_log("msg: " .. msg)

    if config.ding_ding == "off" then
        _M.pure_log("config is off for send_ding_ding_msg")
        return
    end
    local http = require("resty.http")
    local ltn12 = require("ltn12")
    local ding = {}
    local ctext = {}
    ding.msgtype = "text"
    ctext.content = string.format("nginx-waf[%s]: \n \n %s", MyIP, msg)
    ding.text = ctext
    local dat = cjson.encode(ding)
    local t = {}
    local client = http:new()
    client:set_timeout(15000)
    client:set_keepalive(30000, 100)
    local res, err = client:request_uri("https://oapi.dingtalk.com", {
        ssl_verify = false,
        path = config.ding_ding_token,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
            ["Content-Length"] = #dat,
        },
        body = dat,
        source = ltn12.source.string(dat),
        sink = ltn12.sink.table(t)
    })
    client:close()
    if err ~= nil then
        _M.pure_log(err)
    end
    if res ~= nil then
        _M.pure_log("send_ding_talk status: " .. res.status .. " body: " .. res.body)
    end
end


-- 异步执行http 发送数据 失败需要停止发送
function _M.http_post(attackRecord, url)
    local record_start_time = ngx.now()
    local http = require("resty.http")
    local client = http:new()
    local res, err = client:request_uri(config.server_addr, {
        ssl_verify = false,
        path = url,
        method = "POST",
        headers = {
            ["Content-Type"] = "application/json",
        },
        body = attackRecord
    })
    if err ~= nil then
        _M.pure_log(err)
        if config.ding_ding == "on" then
            local msg = string.format("upload attack log err: [%s]\n", err)
            _M.send_ding_talk(msg)
            return nil
        end
    end
    if res ~= nil then
        _M.pure_log("http post host[" .. config.server_addr .. "] [" .. url .. "] status: " .. res.status .. " body: " .. res.body .. " cost: " .. (ngx.now() - record_start_time))
        return res.body
    end
end

function _M.unsafe_http_post(premature, body, uri)
    if premature then
        return
    end
    _M.http_post(body, uri)
end

function _M.log_response(waf_token)
    ngx.update_time()
    if waf_token == nil then
        return
    end
    _M.pure_log("starting record response body by waf-token: " .. waf_token)
    local record_start_time = ngx.now()
    local user_agent = _M.get_user_agent()
    local server_name = ngx.var.server_name
    local RESP_BODY
    if "POST" == ngx.req.get_method() then
        RESP_BODY = string.sub(ngx.arg[1], 1, 1000)
        local buffered = (ngx.ctx.buffered or "") .. RESP_BODY
        if ngx.arg[2] then
            RESP_BODY = buffered
        end
    end

    if RESP_BODY == nil or RESP_BODY == "" then
        RESP_BODY = ""
    end
    _M.pure_log("log_response status: " .. ngx.status .. " body: " .. RESP_BODY)
    local response_obj = {
        attackIp = _M.get_client_ip(),
        attackTime = string.sub(ngx.localtime(), 1, 10) .. "T" .. string.sub(ngx.localtime(), 12, -1) .. "+08:00",
        reqMethod = ngx.req.get_method(),
        reqUri = ngx.var.uri,
        respBody = RESP_BODY,
        respStatus = ngx.status,
        respHeaders = _M.print_table(ngx.resp.get_headers(0, true)),
        recordType = "RESP",
        wafToken = waf_token
    }

    local line_num = debug.getinfo(2).currentline
    local method_name = debug.getinfo(2).name
    local response_obj_raw = cjson.encode(response_obj)
    local log_line = string.format("[%s]-%s()%s #:: %s; %s, %s:%s; ", ngx.localtime(), method_name, line_num, response_obj_raw, _M.get_client_ip(), ngx.req.get_method(), ngx.var.uri)
    local log_name = string.format("%s/%s_waf.log", config.log_dir, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        _M.pure_log("file (" .. log_name .. ") open err:" .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(log_line, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
    _M.pure_log(log_line)
    if config.attack_upload == "on" then
        local ok, err = ngx.timer.at(0, _M.unsafe_http_post, response_obj_raw, config.resp_upload_uri)
        if not ok then
            util.pure_log("failed to unsafe_http_post response")
            util.pure_log(err)
            return
        end
    end
    _M.pure_log("response record post cost time:" .. (ngx.now() - record_start_time))
end

function _M.record_attack(config_log_dir, policy, pattern, action, attack_type, url, data, match, stage)
    ngx.update_time()
    local resp_status = ngx.HTTP_FORBIDDEN
    if action == "RECORD" then
        local uuid = require("uuid")
        ngx.ctx.waf_token = uuid.generate()
        _M.log("record policy: " .. policy .. " waf-token: " .. ngx.ctx.waf_token)
        resp_status = 200
    end
    local record_start_time = ngx.now()
    local log_path = config_log_dir
    local user_agent = _M.get_user_agent()
    local server_name = ngx.var.server_name
    local POST_ARGS
    if "POST" == ngx.req.get_method() then
        ngx.req.read_body()
        POST_ARGS = ngx.req.get_body_data()
        if POST_ARGS == nil then
            POST_ARGS = ngx.req.get_body_file()
        end
    end

    local attack_report_obj = {
        attackIp = _M.get_client_ip(),
        attackTime = string.sub(ngx.localtime(), 1, 10) .. "T" .. string.sub(ngx.localtime(), 12, -1) .. "+08:00",
        attackPayload = data,
        matchedPolicy = policy,
        matchedStage = stage,
        matchedPattern = pattern,
        matchData = match,
        reqArgs = cjson.encode(ngx.req.get_uri_args()),
        reqMethod = ngx.req.get_method(),
        reqUri = ngx.var.uri,
        reqHost = ngx.var.host,
        reqBody = POST_ARGS,
        reqHeaders = _M.print_table(ngx.req.get_headers(0, true)),
        recordType = attack_type,
        respStatus = resp_status,
        stage = stage,
        sourceIp = _M.get_local_ip(),
        wafToken = ngx.ctx.waf_token
    }

    local attack_report_raw = cjson.encode(attack_report_obj)
    local log_name = string.format("%s/%s_attack.log", log_path, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        _M.log("file (" .. log_name .. ") open err:" .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(attack_report_raw, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
    _M.log(attack_report_raw)
    if config.attack_upload == "on" then
        _M.http_post(attack_report_raw, config.attack_upload_uri)
    end
    _M.log("attack record post cost time:" .. (ngx.now() - record_start_time))
end


-- 恶意访问处理函数
-- 使用观察模式模式时，仅记录ip到共享存储
function _M.block_attack()

    if config.attack_block_enable == "off" then
        return
    end

    if config.waf_model == "redirect" then
        ngx.redirect(config.waf_redirect_url, 301)
    else
        ngx.header.content_type = "text/html"
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.say(string.format(config.block_output_html, _M.get_client_ip()))
        ngx.exit(ngx.HTTP_FORBIDDEN)
    end
end

local base_char = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/' -- for encoding/decoding

-- decoding
function _M.base64_dec(data)
    data = string.gsub(data, '[^' .. base_char .. '=]', '')
    return (data:gsub('.', function(x)
        if (x == '=') then
            return ''
        end
        local r, f = '', (base_char:find(x) - 1)
        for i = 6, 1, -1 do
            r = r .. (f % 2 ^ i - f % 2 ^ (i - 1) > 0 and '1' or '0')
        end
        return r;
    end)        :gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if (#x ~= 8) then
            return ''
        end
        local c = 0
        for i = 1, 8 do
            c = c + (x:sub(i, i) == '1' and 2 ^ (8 - i) or 0)
        end
        return string.char(c)
    end))
end

return _M
