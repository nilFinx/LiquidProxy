-- by thenumbernine: github.com/thenumbernine/lua-url/blob/master/unfacebook.lua
-- slightly, slightly modified

-- because socket.url is another library
-- meh
local class = require 'ext.class'
local table = require 'ext.table'
--local assert = require 'ext.assert'
local string = require 'ext.string'


local defaultescapechars = "!#$&'()*+,/:;=?@[]%"
local escapecharsets = {}
local function escape(s, escapechars)
	escapechars = escapechars or defaultescapechars
	local escapecharset = escapecharsets[escapechars]
	if not escapecharset then
		escapecharset = string.split(escapechars):mapi(function(ch) return true, ch end):setmetatable(nil)
		escapecharsets[escapechars] = escapecharset
	end
	return (s:gsub('.', function(ch)
		if escapecharset[ch] then
			return ('%%%02X'):format(ch:byte())
		end
		return ch	-- necessary?
	end))
end

local function unescape(s)
	return (s:gsub('%%%x%x', function(s)
		local n = tonumber(s:sub(2), 16)
		if not n then return s end
		local ch = string.char(n)
		if not ch then return s end
		return ch
	end))
end
--[[
't' handles *BOTH* pairs k=v and ipairs {k,v}
first it processes ipairs
then it processes all pairs that are non-integer keys
this way you can pass it either pairs for quick Lua handling
or ipairs if you care about the order
--]]
local escapekeychars = "!#$&'()*+,:;=?@%"	-- key doesn't need /[] escaped ...
local function argsToStr(t)
	t = table(t):setmetatable(nil)
	local s = table()
	local sep
	for i=1,#t do
		local kv = t[i]
		-- TODO still, what to do for key without value?
		local k,v = tostring(kv[1]), tostring(kv[2])
		if sep then s:insert(sep) end
		sep = '&'
		s:insert(escape(k, escapekeychars))
		s:insert'='
		s:insert(escape(v))
		-- clear as you go
		t[i] = nil
		t[k] = nil
	end
	-- process whats left of ipairs
	for k,v in pairs(t) do
		if sep then s:insert(sep) end
		sep = '&'
		s:insert(escape(tostring(k), escapekeychars))
		s:insert'='
		s:insert(escape(tostring(v)))
	end
	return s:concat()
end

local URL = class()

URL.escape = escape
URL.unescape = unescape
URL.argsToStr = argsToStr

local function parseArgs(kvstr)
	-- also return in-order list
	local kvs = table()
	for _,kv in ipairs(string.split(kvstr, '&')) do
		local k,v = kv:match'^([^=]+)=(.*)$'

		-- what if there's no "=" ? then what?
		if not k then k,v = kv, '' end

		k = unescape(k) or k
		v = unescape(v) or v

		kvs:insert{k, v}
		kvs[k] = v
	end
	return kvs
end

URL.parseArgs = function(self,kvstr)
	if not kvstr then return parseArgs(self) else return parseArgs(kvstr) end
end


--[[
args as a string parses the fields.
args as a table copies the fields.

fields are:
	scheme
	host
	user
	pass
	port
	path
	params
	query
	fragment

	userinfo
--]]
function URL:init(args)
	if type(args) == 'string' then
		local url = args

		-- <scheme>://<username>:<password>@<host>:<port>/<path>;<parameters>?<query>#<fragment>
		-- [<scheme>://][<username>[:<password>]@]<host>[:<port>][/<path>][;<parameters>][?<query>][#<fragment>]

		-- parse scheme
		local scheme, rest = url:match'^([^:]+)://(.*)$'
		rest = rest or url
		self.scheme = scheme

		-- parse authority vs path+query+params+fragment
		local authority, pathqueryparamsfragment = rest:match'^([^/;?#]+)[/;?#](.*)$'	-- expect host to end at /;?#
		authority = authority or rest

		local userinfo, hostandport = authority:match'^([^@]+)@(.*)$'
		if userinfo then
			local user, pass = userinfo:match'^([^:]*):(.*)$'
			user = user or userinfo
			self.user = user
			self.pass = pass
		else
			hostandport = authority
		end

		local host, port = hostandport:match'^([^:]+):(.*)$'
		host = host or hostandport
		self.host = host
		self.port = port

		print "awawa"
		if pathqueryparamsfragment then
			-- /path;params?query#fragment
			-- what if you get ;abc/def?  then it's still the params
			local prevrest = pathqueryparamsfragment
			rest, self.fragment = prevrest:match'^([^#]+)#(.*)$'
			prevrest = rest or prevrest
			rest, self.query = prevrest:match'^([^?]+)?(.*)$'
			prevrest = rest or prevrest
			rest, self.params = prevrest:match'^([^;]+);(.*)$'
			prevrest = rest or prevrest
			self.path = prevrest

			if self.query then self.query = parseArgs(self.query) end
			if self.params then self.params = parseArgs(self.params) end
		elseif args:sub(1,1) == "?" then
			self.query = parseArgs(args)
			self.params = nil
		end

	elseif type(args) == 'table' then
		for k,v in pairs(args) do self[k] = v end
	elseif type(args) == 'nil' then
	else
		error("idk how to build a URL from this")
	end
end

URL.__concat = string.concat

-- tostring or another function?
function URL:__tostring()
	local s = table()
	if self.scheme then
		s:insert(self.scheme)
		s:insert'://'
	end
	if self.user then
		s:insert(self.user)
		if self.pass then
			s:insert':'
			s:insert(self.pass)
		end
		s:insert'@'
	end
	s:insert(self.host)
-- TODO escape path?  except /'s ?
	if self.path then
		s:insert'/'
		s:insert(self.path)
	end
	if self.params then
		s:insert';'
		s:insert(argsToStr(self.params))
	end
	if self.query then
		s:insert'?'
		s:insert(argsToStr(self.query))
	end
	if self.fragment then
		s:insert'#'
		s:insert(self.fragment)
	end
	return s:concat()
end

-- shorthand
URL.tostring = URL.__tostring

return URL
