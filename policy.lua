local _M = {
    _VERSION = '0.14',
    ENABLE = "Enable",
    CONFIG_VERSION = -1,
    RULE_LOAD_MODE = 'local',
    SECOND_MAX_VISITS = 500,
    IP_BLOCK_SECOND = 180,
    URL_WHITE_LIST = {},
    URL_BLACK_LIST = {},
    IP_WHITE_LIST = {},
    IP_BLACK_LIST = {},
    ROOT_URI_RULES = {},
    ROOT_PARAM_RULES = {},
    ROOT_BODY_RULES = {},
    ROOT_HEADER_RULES = {},
    ROOT_USER_AGENT_RULES = {},
    CHILD_RULES_MAP = {}
}

return _M