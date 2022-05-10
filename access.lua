local rule_match = ngx.re.match
local unescape = ngx.unescape_uri
local config = require("config")
local policy = require("policy")
local util = require("util")
local cjson = require("cjson.safe")
local cache = require("lru_cache")
local string = require("string")
local function table_len(t)
    if t == nil then
        return 0
    end
    local len = 0
    for k, v in pairs(t) do
        len = len + 1
    end
    return len;
end

local function parseReqHeaders(headers)
    local request_headers_all = ""
    for k, v in pairs(headers) do
        local row_text = ""
        if type(v) == "table" then
            row_text = table.concat(v, ",")
            row_text = string.format("[%s %s]\n", k, row_text)
        else
            row_text = string.format("[%s %s]\n", k, v)
        end

        request_headers_all = request_headers_all .. row_text
    end
    return request_headers_all
end


-- 判断正则表达式
local function rule_regex_match(data, rules, stage)
    local matchedRuleTable = {}
    for _, rule in pairs(rules) do
        if rule ~= nil and policy.pattern ~= nil then
            local m = rule_match(data, rule.rule_regex, 'jio')
            if m then --如果匹配到敏感信息
            if rule.action == "DENY" or rule.action == "RECORD" then
                util.record_attack(config.log_dir, rule.rule_id, rule.rule_regex, rule.action, rule.class, ngx.var.request_uri, data, m[0], stage)
            end
            if rule.action == "DENY" then
                util.log(string.format("================== Waf Block Triggered By Rule [%s] ===================", rule.rule_id))
                util.block_attack()
                return
            end
            matchedRuleTable[rule.rule_id] = rule
        end
    end
    return matchedRuleTable
end


local function data_check(data, ROOT_RULES, stage)
    --父策略

    local ROOT_POLICY_MATCHED_TABLE
    if data ~= nil and ROOT_RULES ~= nil and table_len(ROOT_RULES) > 0 then
        ROOT_RULE_MATCHED_TABLE = rule_regex_match(unescape(data), ROOT_RULES, stage)
    end
    --子策略
    if table_len(ROOT_RULE_MATCHED_TABLE) > 0 then
        for _, ROOT_RULE in pairs(ROOT_RULE_MATCHED_TABLE) do
            local SON_RULES = policy.CHILD_RULES_MAP[ROOT_RULE.rule_id]
            if data ~= nil and SON_RULES ~= nil then
                local CHILD_RULE_TABLE = rule_regex_match(unescape(data), SON_RULES, stage)
                if table_len(CHILD_RULE_TABLE) > 0 then
                    return true
                end
            end
        end
    end
    return false
end


-- Http Header检查
local function head_attack_check()
    if config.headers_check == "on" and policy.ROOT_HEADER_RULES ~= nil and #policy.ROOT_HEADER_RULES > 0 then
        local headers = ngx.req.get_headers()
        local request_headers_all = ""
        for k, v in pairs(headers) do
            local rowtext = ""
            if type(v) == "table" then
                rowtext = table.concat(v, ",")
                rowtext = string.format("[%s %s]\n", k, rowtext)
            else
                rowtext = string.format("[%s %s]\n", k, v)
            end
            request_headers_all = request_headers_all .. rowtext
        end
        if request_headers_all ~= nil then
            local result = data_check(unescape(request_headers_all), policy.ROOT_HEADER_RULES, "HEAD_CHECK")
            return result
        end
    end
    return false
end

-- UserAgent检查
-- 匹配字段式样:api-Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0
local function user_agent_attack_check()
    if config.user_agent_check == "on" and policy.ROOT_USER_AGENT_RULES ~= nil and #policy.ROOT_USER_AGENT_RULES > 0 then
        local USER_AGENT = ngx.var.http_user_agent
        if USER_AGENT ~= nil then
            return data_check(unescape(USER_AGENT), policy.ROOT_USER_AGENT_RULES, "USER_AGENT_CHECK")
        end
    end
    return false
end


-- URL检查
-- 匹配字段式样:api-index.html
local function url_attack_check()
    if config.url_check == "on" and policy.ROOT_URL_RULES ~= nil then
        local REQ_URI = ngx.var.request_uri
        if REQ_URI ~= nil and policy.ROOT_URL_RULES ~= nil then
            return data_check(unescape(REQ_URI), policy.ROOT_URL_RULES, "URL_CHECK")
        end
    end
    return false
end

-- 请求参数检查
-- 匹配字段式样:api-3
-- ?a   不检查,REQ_ARGS => table;ARGS_DATA => boolean
-- ?a=3 检查的是3
local function param_attack_check()
    if config.param_check == "on" and policy.ROOT_ARGS_RULES ~= nil then
        local REQ_ARGS = ngx.req.get_uri_args()
        if policy.ROOT_ARGS_RULES ~= nil and REQ_ARGS ~= nil then
            for key, val in pairs(REQ_ARGS) do
                local ARGS_DATA = {}
                if type(val) == 'table' then
                    ARGS_DATA = table.concat(val, " ")
                elseif type(val) == "boolean" and ngx ~= nil then
                    ARGS_DATA = key .. "=" .. key
                else
                    ARGS_DATA = key .. "=" .. val
                end
                if ARGS_DATA and type(ARGS_DATA) == "string" then
                    return data_check(unescape(ARGS_DATA), policy.ROOT_ARGS_RULES, "PARAM_CHECK")
                end
            end
        end
    end
    return false
end

-- POST检查
-- 匹配字段式样:api-txt
-- multipart/form-data方式的数据，只要其中带有文件，则不检查
-- application/x-www-form-urlencoded二进制模式发送的文件会被检查
-- 日志中的post_data并非完整的POST数据
local function body_attack_check()
    if config.body_check == "on" and #policy.ROOT_BODY_RULES > 0 and (ngx.req.get_method() == "POST" or ngx.req.get_method() == "PUT") then
        local request_headers = ngx.req.get_headers()
        local content_type_header = request_headers["content-type"]

        if type(content_type_header) ~= "string" then
            return false
        end

        if content_type_header ~= nil and ((ngx.re.find(content_type_header, [=[^multipart/form-data; boundary=]=], 'jio') or ngx.re.find(content_type_header, "application/x-www-form-urlencoded") ~= nil or string.find(content_type_header, "application/json") ~= nil)) then
            ngx.req.read_body()
            local POST_ARGS = ngx.req.get_post_args()
            if POST_ARGS == nil then
                POST_ARGS = ngx.req.get_body_data()
            end
            if POST_ARGS == nil then
                POST_ARGS = ngx.req.get_body_file()
            end

            if POST_ARGS ~= nil then
                if type(POST_ARGS) == "table" then
                    for k, v in pairs(POST_ARGS) do
                        local post_data = ""
                        if type(v) == "table" then
                            if type(v[1]) ~= "boolean" then
                                post_data = ngx.var.server_name .. "-" .. table.concat(v, ", ")
                            end
                        elseif type(v) == "boolean" and ngx ~= nil then
                            post_data = post_data .. "-" .. k
                        else
                            post_data = post_data .. "-" .. v
                        end

                        if #post_data > 10 and #post_data < 1000 and type(post_data) == "string" then
                            return data_check(unescape(post_data), policy.ROOT_BODY_RULES, "BODY_CHECK")
                        end
                    end
                elseif type(POST_ARGS) == "string" then
                    local post_data = "" .. POST_ARGS
                    if #post_data > 10 and #post_data < 5000 then
                        return data_check(unescape(post_data), policy.ROOT_BODY_RULES, "BODY_CHECK")
                    end
                end
            end
        end
        return false
    end
end

local function black_ip_check()
    if config.black_ip_check == "on" and policy.IP_BLACK_LIST ~= nil and #policy.IP_BLACK_LIST > 0 then
        --代理后，无法直接拿到源IP
        local client_ip = util.get_client_ip()
        if client_ip == "0.0.0.0" then
            util.pure_log(string.format("client ip is nil, req uri: %s", ngx.var.request_uri))
            return false
        end
        for _, black_ip in pairs(policy.IP_BLACK_LIST) do
            if client_ip == black_ip then
                util.block_attack()
                return true
            end
        end
    end
    return false
end

local function white_ip_check()
    if config.white_ip_check == "on" and policy.IP_WHITE_LIST ~= nil and #policy.IP_WHITE_LIST > 0 then
        local client_ip = util.get_client_ip()
        if client_ip == "0.0.0.0" then
            util.pure_log(string.format("client ip is nil, req uri: %s", ngx.var.request_uri))
            return false
        end
        for _, white_ip in pairs(policy.IP_WHITE_LIST) do
            if client_ip == white_ip then
                return true
            end
        end
    end
    return false
end

local function white_url_check()
    if config.white_url_check == "on" and policy.URL_WHITE_LIST ~= nil and #policy.URL_WHITE_LIST > 0 then
        local REQ_URI = ngx.var.request_uri
        if policy.URL_WHITE_LIST ~= nil and REQ_URI ~= nil then
            for _, rule in pairs(policy.URL_WHITE_LIST) do
                local m = rule_match(REQ_URI, rule, "joi")
                if m then
                    return true
                end
            end
        end
    end
    return false
end

local function black_url_check()
    if config.black_url_check == "on" and policy.URL_BLACK_LIST ~= nil and #policy.URL_BLACK_LIST > 0 then
        local REQ_URI = ngx.var.request_uri
        if policy.URL_BLACK_LIST ~= nil and REQ_URI ~= nil then
            for _, rule in pairs(policy.URL_BLACK_LIST) do
                local m = rule_match(REQ_URI, rule, "joi")
                if m then
                    util.block_attack()
                    return true
                end
            end
        end
    end
    return false
end

local function frequency_control_check()
    if config.frequency_control_check == "on" then
        --代理后，无法直接拿到源IP
        local remote_addr = util.get_client_ip()
        if remote_addr == "0.0.0.0" then
            util.pure_log(string.format("remote_addr is nil, req uri: %s", ngx.var.request_uri))
            return false
        end

        for ipKey, ipVal in pairs(policy.FREQUENCY_IP_BLACK_LIST) do
            if remote_addr == ipKey then
                return false
            end
        end

        local identityKey = remote_addr .. math.random(70)

        local findCount = cache.find(identityKey)

        cache.add(identityKey)

        if findCount == -1 then
            return false
        end
        if findCount >= policy.SECOND_MAX_VISITS then
            util.log(string.format("COMPARE IP findCount [%s] AND MAX_VISITS [%s]============", findCount, policy.SECOND_MAX_VISITS))
        end
        if findCount >= policy.SECOND_MAX_VISITS then -- 超过最大频次 TODO 需要根据换算 得出
            -- 加入 ip 黑名单
            local ip_block_time = ngx.now + policy.IP_BLOCK_TIME
            policy.FREQUENCY_IP_BLACK_LIST[remote_addr] = ip_block_time
            util.log(string.format("CREATE NOW FREQUENCY IP BLOCK IP [%s] AND EXPIRE AT [%s]============ FREQUENCY_IP_BLACK_LIST SIZE:[%d]  ", remote_addr, ip_block_time, #policy.FREQUENCY_IP_BLACK_LIST))
            return true
        end
    end
    return false
end

local function cc_attack_check()
    if config.cc_check == "on" then
        -- 对ngx.var.request_uri限制长度为最大40字符 避免key太长
        local remote_addr = util.get_client_ip()
        if remote_addr == "0.0.0.0" then
            util.pure_log(string.format("remote_addr is nil, req uri: %s", ngx.var.request_uri))
            return false
        end
        local ATTACK_URI = string.sub(ngx.var.request_uri, 1, 40)
        local CC_TOKEN = ngx.var.server_name .. "-" .. util.get_client_ip() .. "-" .. ATTACK_URI
        local limit = ngx.shared.limit
        local CCcount = tonumber(string.match(config.cc_rate, '(.*)/'))
        local CCseconds = tonumber(string.match(config.cc_rate, '/(.*)'))
        local req, _ = limit:get(CC_TOKEN)
        -- 打印目标限制字符串
        if req then
            if req > CCcount then
                util.record_attack(config.log_dir, 'CC攻击' .. config.cc_rate .. "/时间(" .. config.cc_rate .. "秒)", "", "", "CC攻击", ngx.var.request_uri, remote_addr, "", "CC攻击")
                util.block_attack()
                return true
            else
                limit:incr(CC_TOKEN, 1)
            end
        else
            limit:set(CC_TOKEN, 1, CCseconds)
        end
    end
    return false
end

local function ends(str, substr)
    return substr == '' or str:sub(-substr:len()) == substr
end


local function attack_check()
    if config.attack_check == "on" and policy.ENABLE == "Enable" then
        if head_attack_check() then
        elseif user_agent_attack_check() then
        elseif url_attack_check() then
        elseif param_attack_check() then
        elseif body_attack_check() then
        else
            return
        end
    end
    return false
end


local function waf()

    if config.waf_enable ~= "on" or policy.ENABLE ~= "Enable" then
        return
    end

    local uri = ngx.var.uri:lower()
    local ignore = ends(uri, ".jpg") or ends(uri, ".jpeg")
            or ends(uri, ".js") or ends(uri, ".css")
             or ends(uri, ".gif") or ends(uri, ".png")
    if ignore then
        return
    end
    if white_ip_check() then
    elseif black_ip_check() then
    elseif white_url_check() then
    elseif black_url_check() then
    elseif frequency_control_check() then
    elseif cc_attack_check() then
    elseif attack_check() then
    else
        return
    end
end

waf()