--
-- Created by IntelliJ IDEA.
-- User: sihan
-- Date: 2022/2/16
-- Time: 16:54
-- To change this template use File | Settings | File Templates.
--
local util = require("util")
local function response_log()
    local waf_token = ngx.ctx.waf_token
    if waf_token ~= nil then
        util.log_response(waf_token)
    end
end

response_log()