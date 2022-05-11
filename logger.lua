local io = require("io")
local cjson = require("cjson.safe")
local string = require("string")
local config = require("config")
local socket = require("socket.core")

local _M = {
    version = "0.14",
}

function _M.log_upload(msg)
    local log_name = string.format("%s/%s_upload.log", config.log_dir, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        ngx.log(ngx.ERR, "open best-nginx-waf upload file err: " .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(msg, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
end

-- 记录JSON格式日志
function _M.request_log(msg)
    if config.log_enable ~= "on" then
        return
    end
    ngx.update_time()
    local line_num = debug.getinfo(2).currentline
    local method_name = debug.getinfo(2).name
    local log_line = string.format("[%s]-%s()%s #:: %s; %s:%s; ", ngx.localtime(), method_name, line_num, msg, ngx.req.get_method(), ngx.var.uri)
    local log_name = string.format("%s/%s_waf.log", config.log_dir, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        ngx.log(ngx.ERR, "open best-nginx-waf log file err: " .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(log_line, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
end


-- 记录JSON格式日志
function _M.log(msg)
    if config.log_enable ~= "on" then
        return
    end
    ngx.update_time()
    local line_num = debug.getinfo(2).currentline
    local method_name = debug.getinfo(2).name
    local log_line = string.format("[%s]-%s()%s #:: %s;", ngx.localtime(), method_name, line_num, msg)
    local log_name = string.format("%s/%s_waf.log", config.log_dir, ngx.today())
    local file, err = io.open(log_name, "a+")
    if err ~= nil or file == nil then
        ngx.log(ngx.ERR, "open best-nginx-waf log file (" .. log_name .. ") err: " .. err)
        return
    end
    file:write(string.format("%s\n", string.gsub(string.gsub(log_line, "\\\"", ""), "\\", "")))
    file:flush()
    file:close()
end

return _M
