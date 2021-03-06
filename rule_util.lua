local _M = {
    version = "0.14",
}
local cjson = require("cjson.safe")
local config = require("config")

function _M.read_rule(rule_name)
    local file = io.open(config.policy_dir .. '/' .. rule_name .. '.json', "r")
    if file == nil then
        ngx.log(ngx.ERR, "open best nginx waf file (" .. rule_name .. ") err")
        return nil
    end
    local text = ""
    for line in file:lines() do
        text = text .. line
    end
    file:close()
    return text
end

function _M.rewrite_policy(policy)
    local policy_file_name = config.policy_dir .. '/policy.json'
    local file = io.open(policy_file_name, "w+")
    if file == nil then
        _M.build_file(policy_file_name)
    end
    file = io.open(policy_file_name, "w+")
    if file == nil then
        ngx.log(ngx.ERR, "fail open file [" .. policy_file_name .. "]")
        return nil
    end
    local policy_str = cjson.encode(policy)
    file:write(policy_str)
    file:flush()
    file:close()
end

function _M.build_file(file_name)
    local file = io.open(file_name, "a+")
    if file == nil then
        ngx.log(ngx.ERR, "fail create file [" .. file_name .. "]")
        return nil
    end
    file:write("")
    file:flush()
    file:close()

end

return _M









