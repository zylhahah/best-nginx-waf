local util = require("util")
local lrucache = require "resty.lrucache" -- 读次数远大于增删情况下使用
-- local lrucache = require "resty.lrucache.pureffi" -- 增删较多情况下使用
local cache, err = lrucache.new(50) -- allow up to 50 items in the cache


if not cache then
    ngx.log(ngx.ERR, "failed to create the cache: " .. (err or "unknown"))
end

local _M = {
    version = "0.14",
}


function _M.add(ip)
    local count = cache:get(ip)
    local time_out = 1
    if count == nil then
        time_out = 10
        count = 0
    end
    count = count + 1
    cache:set(ip, count, time_out) -- 每次+ 1 从 1 开始
end

function _M.find(ip)
    local count = cache:get(ip)
    if count == nil then
        return -1
    end
    return count
end


return _M
