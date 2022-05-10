local string = require("string")
local config = require("config")
local policy = require("policy")
local cjson = require("cjson.safe")
local util = require("util")
local rule = require("rule")
local register_waf_client = false


local function init_health_check()
    local hc = require "resty.upstream.healthcheck"
    if config.config_health_check ~= "on" then
        return
    end

    util.pure_log("init health check job.... ")

    local health_check_config_objs = cjson.decode(health_check_config)

    for _, health_check_config_obj in pairs(health_check_config_objs) do
        util.pure_log("====== set spawn_checker for " .. health_check_config_obj.upstream)
        local ok, err = hc.spawn_checker {
            shm = "healthcheck", -- defined by "lua_shared_dict"
            upstream = health_check_config_obj.upstream, -- defined by "upstream"
            type = "http",
            http_req = string.format("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", health_check_config_obj.checkPath, health_check_config_obj.host),
            -- raw HTTP request for checking
            interval = 3000, -- run the check cycle every 2 sec
            timeout = 1000, -- 1 sec is the timeout for network operations
            fall = 3, -- # of successive failures before turning a peer down
            rise = 2, -- # of successive successes before turning a peer up
            valid_statuses = { 200, 302 }, -- a list valid HTTP status code
            concurrency = 10, -- concurrency level for test requests
        }
        if not ok then
            util.pure_log("failed to create the health check timer"..err)
            return
        end
    end
end



-- update
local function refresh_policy(new_policy)
    policy.ENABLE = new_policy.ENABLE
    policy.RULE_LOAD_MODE = new_policy.RULE_LOAD_MODE
    policy.CONFIG_VERSION = new_policy.CONFIG_VERSION
    policy.SECOND_MAX_VISITS = new_policy.SECOND_MAX_VISITS
    policy.IP_BLOCK_TIME = new_policy.IP_BLOCK_TIME
    policy.URL_WHITE_LIST = new_policy.URL_WHITE_LIST
    policy.URL_BLACK_LIST = new_policy.URL_BLACK_LIST
    policy.IP_WHITE_LIST = new_policy.IP_WHITE_LIST
    policy.IP_BLACK_LIST = new_policy.IP_BLACK_LIST
    policy.ROOT_URI_RULES = new_policy.ROOT_URI_RULES
    policy.ROOT_PARAM_RULES = new_policy.ROOT_PARAM_RULES
    policy.ROOT_BODY_RULES = new_policy.ROOT_BODY_RULES
    policy.ROOT_HEADER_RULES = new_policy.ROOT_HEADER_RULES
    policy.ROOT_USER_AGENT_RULES = new_policy.ROOT_USER_AGENT_RULES
    policy.CHILD_RULES_MAP = new_policy.CHILD_RULES_MAP
    rule.rewrite_policy(policy)
end



local function init_rules_by_local()
   base = rule.read_rule('base')
   ip = rule.read_rule('ip')
   rules = rule.read_rule('rule')
   uri = rule.read_rule('uri')
   local base_config_obj = cjson.decode(base)
   local ip_config_obj = cjson.decode(ip)
   local rules_config_obj = cjson.decode(rules)
   local uri_config_obj = cjson.decode(uri)
   local new_policy = {}
   new_policy.ROOT_USER_AGENT_RULES = {}
   new_policy.ROOT_URI_RULES = {}
   new_policy.ROOT_PARAM_RULES = {}
   new_policy.ROOT_BODY_RULES = {}
   new_policy.ROOT_HEADER_RULES = {}
   new_policy.CHILD_RULES_MAP = {}

   if base_config_obj ~= nil then
       new_policy.SECOND_MAX_VISITS = base_config_obj.second_max_visits
       new_policy.IP_BLOCK_SECOND = base_config_obj.ip_block_second
   end

   if ip_config_obj ~= nil then
       new_policy.IP_WHITE_LIST = ip_config_obj.white_ip
       new_policy.IP_BLACK_LIST = ip_config_obj.black_ip
   end

   if uri_config_obj ~= nil then
       new_policy.URL_WHITE_LIST = uri_config_obj.white_uri
       new_policy.URL_BLACK_LIST = uri_config_obj.black_uri
   end

   if rules_config_obj == nil then
       return
   end

   -- build root rules
   for _, rule in pairs(rules_config_obj) do
       if rule ~= nil then
           if rule.father_rule == nil or rule.father_rule == "" then
               if string.find(rule.rule_range, "URI") ~= nil then
                   table.insert(new_policy.ROOT_URI_RULES, rule)
               end
               if string.find(rule.rule_range, "PARAM") ~= nil then
                   table.insert(new_policy.ROOT_PARAM_RULES, rule)
               end
               if string.find(rule.rule_range, "BODY") ~= nil then
                   table.insert(new_policy.ROOT_BODY_RULES, rule)
               end
               if string.find(rule.rule_range, "HEADER") ~= nil then
                   table.insert(new_policy.ROOT_HEADER_RULES, rule)
               end
               if string.find(rule.rule_range, "USER_AGENT") ~= nil then
                   table.insert(new_policy.ROOT_USER_AGENT_RULES, rule)
               end
           else
                new_policy.CHILD_RULES_MAP[rule.father_rule] = rule  -- key is father_rule rule_id
           end
       end
   end
   new_policy.RULE_LOAD_MODE = "local"
   refresh_policy(new_policy)
end

local function policy_update_from_remote(strategy_base64_str)
    local record_start_time = ngx.now()
    util.pure_log(string.format("[----- current redis waf config version [%s], and start update policy]", redis_waf_config_version))
    if strategy_base64_str == nil then
        util.pure_log(string.format("[----- [ redis get nil by key ".. strategy_key .." ] -----"))
        return
    end
    local policy_str = util.base64_dec(strategy_base64_str)
    local policy_obj = cjson.decode(policy_str)
    util.pure_log(policyStr)
    if policy_obj ~= nil and policy_obj.CONFIG_VERSION > 0 then
        policy_switch(policy_obj)
        util.pure_log(string.format("[----- successful update policy, current version [%s]] cost: [%s]", policy.CONFIG_VERSION, (ngx.now() - record_start_time)))
    else
    util.pure_log(string.format("[----- [ update policy err ] -----"))
    end
end



local function send_heart_beat()
    local heart_beat_body = {}
    heart_beat_body.clientId = ""
    heart_beat_body.status = "Online"
    heart_beat_body.clientIp = util.get_local_ip()
    heart_beat_body.clientHostName = util.get_local_host_name()
    heart_beat_body.configVersion = policy.CONFIG_VERSION
    heart_beat_body.wafEnable  = policy.ENABLE
    local heart_beat_body_str = cjson.encode(heart_beat_body)
    local resp_body = util.http_post(heart_beat_body_str, config.config_heart_beat_upload_uri)
    if resp_body ~= nil and config.rules_load_mode == "remote" then
        policy_update_from_remote(resp_body)
    end
end

local function send_heart_beat_job(premature)
    local record_start_time = ngx.now()
    if premature then
        return
    end
    local ok, err = ngx.timer.at(0, send_heart_beat)
    if not ok then
        util.pure_log("failed to create the send_heart_beat timer")
        util.pure_log(err)
        return
    end
    util.pure_log("send_heart_beat_job cost time:" .. (ngx.now() - record_start_time))
end


local function init_jobs()

    local record_start_time = ngx.now()

    if config.rules_load_mode == "local" then
        init_rules_by_local()
    end

    send_heart_beat_job()

    local ok, err = ngx.timer.every(10, send_heart_beat_job)
    if not ok then
       util.pure_log("failed to create the send heartbeat job timer ".. err)
    end
    util.pure_log("init_jobs cost time:" .. (ngx.now() - record_start_time))
end

init_jobs()

