local string = require("string")
local config = require("config")
local policy = require("policy")
local cjson = require("cjson.safe")
local util = require("util")
local logger = require("logger")
local rule_util = require("rule_util")

local function init_health_check()
    logger.log("init health check job ....")
    local hc = require "resty.upstream.healthcheck"
    local health_check_config = rule_util.read_rule('health_check_config')
    local health_check_config_obj_array = cjson.decode(health_check_config)
    for _, health_check_config_obj in pairs(health_check_config_obj_array) do
        logger.log("====== set spawn_checker for " .. health_check_config_obj.upstream)
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
            logger.log("failed to create the health check timer" .. err)
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
    rule_util.rewrite_policy(policy)
end

local function init_rules_by_local()
    local base = rule_util.read_rule('base')
    local ip = rule_util.read_rule('ip')
    local rules = rule_util.read_rule('rule')
    local uri = rule_util.read_rule('uri')
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
    new_policy.RULE_LOAD_MODE = "local"
    new_policy.ENABLE = "Enable"
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
    for _, rule_obj in pairs(rules_config_obj) do
        if rule_obj.father_rule == nil or rule_obj.father_rule == "" then
            if string.find(rule_obj.rule_range, "URI") ~= nil then
                table.insert(new_policy.ROOT_URI_RULES, rule_obj)
            end
            if string.find(rule_obj.rule_range, "PARAM") ~= nil then
                table.insert(new_policy.ROOT_PARAM_RULES, rule_obj)
            end
            if string.find(rule_obj.rule_range, "BODY") ~= nil then
                table.insert(new_policy.ROOT_BODY_RULES, rule_obj)
            end
            if string.find(rule_obj.rule_range, "HEADER") ~= nil then
                table.insert(new_policy.ROOT_HEADER_RULES, rule_obj)
            end
            if string.find(rule_obj.rule_range, "USER_AGENT") ~= nil then
                table.insert(new_policy.ROOT_USER_AGENT_RULES, rule_obj)
            end
        else
            if new_policy.CHILD_RULES_MAP[rule_obj.father_rule] == nil then
                new_policy.CHILD_RULES_MAP[rule_obj.father_rule] = {}  -- key is father_rule rule_id
            end
            table.insert(new_policy.CHILD_RULES_MAP[rule_obj.father_rule], rule_obj)
        end
    end

    refresh_policy(new_policy)
end

local function policy_update_from_remote(policy_base64_str)
    local record_start_time = ngx.now()
    if policy_base64_str == nil then
        return
    end
    local policy_str = util.base64_dec(policy_base64_str)
    local policy_obj = cjson.decode(policy_str)
    logger.log(policy_str)
    if policy_obj ~= nil and policy_obj.CONFIG_VERSION > 0 then
        refresh_policy(policy_obj)
        logger.log(string.format("[----- successful update policy, current version [%s]] cost: [%s]", policy.CONFIG_VERSION, (ngx.now() - record_start_time)))
    else
        logger.log(string.format("[----- [ update policy err ] -----"))
    end
end

local function send_heart_beat()
    local heart_beat_body = {}
    heart_beat_body.clientId = ""
    heart_beat_body.status = "Online"
    heart_beat_body.clientIp = util.get_local_ip()
    heart_beat_body.clientHostName = util.get_local_host_name()
    heart_beat_body.configVersion = policy.CONFIG_VERSION
    heart_beat_body.wafEnable = policy.ENABLE
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
        logger.log("failed to create the send_heart_beat timer")
        logger.log(err)
        return
    end
    logger.log("send_heart_beat_job cost time:" .. (ngx.now() - record_start_time))
end

local function init_jobs()

    local record_start_time = ngx.now()

    if config.rules_load_mode == "local" then
        init_rules_by_local()
    end
    if config.heart_beat_enable == "on" then
        local ok, err = ngx.timer.every(10, send_heart_beat_job)
        if not ok then
            logger.log("failed to create the send heartbeat job timer " .. err)
        end
    end

    if config.health_check_enable ~= "on" then
        init_health_check()
    end

    logger.log("init_jobs cost time:" .. (ngx.now() - record_start_time))
end

init_jobs()

