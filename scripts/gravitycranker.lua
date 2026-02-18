local lu = require "lua-url"
local json = require "json"

return nil, {["gravitybox.ceco.sk.eu.org"] = function(req, res, go)
	if req.path == "/service.php" then
		if not (req.body and req.body ~= "") then
			res.code = 400
			return true
		end
		local q = lu.parseArgs(req.body)
		-- Has to be caps for some reason.
		if q and q.transactionId == "YES" then
			res.code = 200
			res.headers["Content-Type"] = "application/json"
			res.body = json.encode({
				message = "henlo :3",
				status = "OK",
				-- TRANSACTION_VALID, TRANSACTION_INVALID, TRANSACTION_VIOLATION, TRANSACTION_BLOCKED
				trans_status = "TRANSACTION_VALID"
			})
		else
			res.code = 400
			res.headers["Content-Type"] = "application/json"
			res.body = json.encode({
				message = "henlo :3",
				status = "OK",
				trans_status = "TRANSACTION_INVALID"
			})
		end
	else
		res.code = 404
	end
	return true
end}