local stringio = require("pl.stringio")
local objects = require("resty.openssl.objects")
local base64 = require("ngx.base64")
local cipher = require("resty.openssl.cipher")
local digest = require("resty.openssl.digest")
local cjson = require("cjson.safe")
local lpack = require("lua_pack")
local zlib = require("ffi-zlib")
local pkey = require("resty.openssl.pkey")
local rand = require("resty.openssl.rand")
local encode_base64url = base64.encode_base64url
local decode_base64url = base64.decode_base64url
local encode_json = cjson.encode
local decode_json = cjson.decode
local randombytes = rand.bytes
local nid2table = objects.nid2table
local tostring = tostring
local assert = assert
local concat = table.concat
local bpack = lpack.pack
local find = string.find
local type = type
local sub = string.sub
local fmt = string.format
local PADDING = {
	["RSA-OAEP"] = pkey.PADDINGS.RSA_PKCS1_OAEP_PADDING
}
local ALGORITHM = {
	["ECDH-ES"] = true,
	["RSA-OAEP"] = true
}
local ENCRYPTION = {
	A256GCM = true
}
local CIPHER = {
	A256GCM = "aes-256-gcm"
}
local KEYSIZE = {
	A256GCM = 32
}
local IVSIZE = {
	A256GCM = 12
}
local TAGSIZE = {
	A256GCM = 16
}
local CURVE = {
	[715.0] = "P-384",
	[716.0] = "P-521",
	[415.0] = "P-256"
}
local CURVE2OPENSSL = {
	["P-521"] = "secp521r1",
	["P-384"] = "secp384r1",
	["P-256"] = "prime256v1"
}
local KEYTYPE = {
	[6.0] = "RSA",
	[408.0] = "EC"
}
local DEFAULT_ALGORITHM = {
	RSA = "RSA-OAEP",
	EC = "ECDH-ES"
}
local DEFLATE_WINDOW_BITS = -15
local DEFLATE_CHUNK_SIZE = 8192
local DEFLATE_OPTIONS = {
	windowBits = DEFLATE_WINDOW_BITS
}

local function errmsg(msg, err_or_req, val)
	if err_or_req == nil then
		return msg
	end

	if val == nil then
		return fmt("%s (%s)", msg, tostring(err_or_req))
	end

	return fmt("%s (%s != %s)", msg, tostring(err_or_req), tostring(val))
end

local function gzip(inflate_or_deflate, input, chunk_size, window_bits_or_options)
	local stream = stringio.open(input)
	local output = {}
	local n = 0
	local ok, err = inflate_or_deflate(function (size)
		return stream:read(size)
	end, function (data)
		n = n + 1
		output[n] = data
	end, chunk_size, window_bits_or_options)

	if not ok then
		return nil, err
	end

	if n == 0 then
		return ""
	end

	return concat(output, nil, 1, n)
end

local function encode_coordinate(name, parameters)
	local coordinate = parameters[name]

	if not coordinate then
		return nil, fmt("unable to read %s coordinate of ephemeral public key", name)
	end

	local err = nil
	coordinate, err = coordinate:to_binary()

	if not coordinate then
		return nil, errmsg(fmt("unable to convert %s coordinate of ephemeral public key to binary format", name), err)
	end

	coordinate, err = encode_base64url(coordinate)

	if not coordinate then
		return nil, errmsg(fmt("unable to base64url encode %s coordinate", name), err)
	end

	coordinate, err = encode_json(coordinate)

	if not coordinate then
		return nil, errmsg(fmt("unable to json encode x coordinate", name), err)
	end

	return coordinate
end

local jwe = {
	deflate = function (data, chunk_size)
		assert(type(data) == "string", "invalid data argument")
		assert(chunk_size == nil or type(chunk_size) == "number", "invalid chunk_size argument")

		return gzip(zlib.deflateGzip, data, chunk_size or DEFLATE_CHUNK_SIZE, DEFLATE_OPTIONS)
	end,
	inflate = function (data, chunk_size)
		assert(type(data) == "string", "invalid data argument")
		assert(chunk_size == nil or type(chunk_size) == "number", "invalid chunk_size argument")

		return gzip(zlib.inflateGzip, data, chunk_size or DEFLATE_CHUNK_SIZE, DEFLATE_WINDOW_BITS)
	end
}

function jwe.key(key, alg)
	assert(type(key) == "string" or type(key) == "table", "invalid key argument")
	assert(alg == nil or type(alg) == "string", "invalid alg argument")

	if alg then
		assert(ALGORITHM[alg], "invalid alg argument")
	end

	local err = nil

	if not pkey.istype(key) then
		local jwk = nil

		if type(key) == "table" then
			jwk = key
		else
			jwk = decode_json(key)
		end

		local format = nil

		if jwk then
			format = "JWK"

			if alg == "RSA-OAEP" then
				if jwk.kty and jwk.kty ~= "RSA" then
					return nil, errmsg("key type mismatch", "RSA", jwk.kty)
				end
			elseif alg == "ECDH-ES" and jwk.kty and jwk.kty ~= "EC" then
				return nil, errmsg("key type mismatch", "EC", jwk.kty)
			end

			if alg and jwk.alg and jwk.alg ~= alg then
				return nil, errmsg("algorithm mismatch", alg, jwk.alg)
			end

			if type(key) == "table" then
				key, err = encode_json(key)

				if not key then
					return nil, errmsg("unable to encode jwk key", err)
				end
			end
		end

		key, err = pkey.new(key, {
			format = format or "*"
		})

		if not key then
			return nil, errmsg("unable to load encryption key", err)
		end
	end

	local keytype = nil
	keytype, err = jwe.keytype(key, alg)

	if not keytype then
		return nil, err
	end

	if alg == "RSA-OAEP" and keytype ~= "RSA" then
		return nil, errmsg("invalid key type for RSA-OAEP", "RSA", keytype)
	elseif alg == "ECDH-ES" and keytype ~= "EC" then
		return nil, errmsg("invalid key type for ECDH-ES", "EC", keytype)
	end

	return key, nil, keytype
end

function jwe.keytype(key, alg)
	assert(type(key) == "string" or type(key) == "table", "invalid key argument")
	assert(alg == nil or type(alg) == "string", "invalid alg argument")

	if alg then
		assert(ALGORITHM[alg], "invalid alg argument")
	end

	if not pkey.istype(key) then
		local err = nil
		key, err = jwe.key(key, alg)

		if not key then
			return nil, err
		end
	end

	local keytype, err = key:get_key_type()

	if not keytype then
		return nil, errmsg("unable to read key type", err)
	end

	local supported_keytype = KEYTYPE[keytype.nid or ""]

	if not supported_keytype then
		return nil, errmsg("unsupported key type", keytype.sn)
	end

	return supported_keytype, nil, keytype
end

function jwe.key2alg(key, alg)
	assert(type(key) == "string" or type(key) == "table", "invalid key argument")
	assert(alg == nil or type(alg) == "string", "invalid alg argument")

	if alg then
		assert(ALGORITHM[alg], "invalid alg argument")
	end

	local keytype, err = jwe.keytype(key, alg)

	if not keytype then
		return nil, err
	end

	return DEFAULT_ALGORITHM[keytype], nil, keytype
end

function jwe.curve(key, alg)
	assert(type(key) == "string" or type(key) == "table", "invalid key argument")
	assert(alg == nil or alg == "ECDH-ES", "invalid alg argument")

	local err = nil

	if not pkey.istype(key) then
		key, err = jwe.key(key, alg)

		if not key then
			return nil, err
		end
	end

	local keytype = nil
	keytype, err = jwe.keytype(key, alg)

	if not keytype then
		return nil, err
	end

	if keytype ~= "EC" then
		return nil, errmsg("non-elliptic curve key provided", keytype)
	end

	local parameters = nil
	parameters, err = key:get_parameters()

	if not parameters then
		return nil, errmsg("unable to read key parameters", err)
	end

	local group = parameters.group
	local curve = CURVE[group or ""]

	if not curve then
		local nid = nid2table(group)

		return nil, errmsg("unsupported curve", nid and nid.sn or group)
	end

	return curve, nil, keytype
end

function jwe.concatkdf(z, enc, apu, apv)
	assert(type(z) == "string", "invalid z argument")
	assert(ENCRYPTION[enc], "invalid enc argument")
	assert(apu == nil or type(apu) == "string", "invalid apu argument")
	assert(apv == nil or type(apv) == "string", "invalid apv argument")

	apu = apu or ""
	apv = apv or ""
	local input = bpack(">i", 1) .. z .. bpack(">i", #enc) .. enc .. bpack(">i", #apu) .. apu .. bpack(">i", #apv) .. apv .. bpack(">i", 256)
	local sha256, err = digest.new("sha256")

	if not sha256 then
		return nil, err
	end

	local ok = nil
	ok, err = sha256:update(input)

	if not ok then
		return nil, err
	end

	local hash = nil
	hash, err = sha256:final()

	if not hash then
		return nil, err
	end

	return hash
end

function jwe.split(token)
	assert(type(token) == "string", "invalid token argument")

	local t = {}
	local i = 1
	local b = 1
	local e = find(token, ".", b, true)

	while e do
		if i > 4 then
			return nil, "invalid jwe token"
		end

		t[i] = sub(token, b, e - 1)
		i = i + 1
		b = e + 1
		e = find(token, ".", b, true)
	end

	t[i] = sub(token, b)

	return t
end

function jwe.decode(token)
	assert(type(token) == "string", "invalid token argument")

	local parts, err = jwe.split(token)

	if not parts then
		return nil, err
	end

	local protected = parts[1]
	local encrypted_key = parts[2]
	local iv = parts[3]
	local ciphertext = parts[4]
	local tag = parts[5]
	protected, err = decode_base64url(protected)

	if not protected then
		return nil, errmsg("unable to base64url decode protected header", err)
	end

	protected, err = decode_json(protected)

	if not protected then
		return nil, errmsg("unable to json decode protected header", err)
	end

	if type(protected) ~= "table" then
		return nil, errmsg("invalid protected header", err)
	end

	if encrypted_key ~= "" then
		encrypted_key, err = decode_base64url(encrypted_key)

		if not encrypted_key then
			return nil, errmsg("unable to base64url decode content encryption key", err)
		end
	end

	if iv == "" then
		return nil, "invalid initialization vector (empty)"
	end

	iv, err = decode_base64url(iv)

	if not encrypted_key then
		return nil, errmsg("unable to base64url decode initialization vector", err)
	end

	if ciphertext ~= "" then
		ciphertext, err = decode_base64url(ciphertext)

		if not ciphertext then
			return nil, errmsg("unable to base64url decode ciphertext", err)
		end
	end

	if tag == "" then
		return nil, "invalid authentication tag (empty)"
	end

	tag, err = decode_base64url(tag)

	if not tag then
		return nil, errmsg("unable to base64url decode authentication tag", err)
	end

	parts.protected = protected
	parts.encrypted_key = encrypted_key
	parts.iv = iv
	parts.ciphertext = ciphertext
	parts.tag = tag
	parts.aad = parts[1]

	return parts
end

function jwe.decrypt(key, token)
	assert(type(key) == "string" or type(key) == "table", "invalid key argument")
	assert(type(token) == "string", "invalid token argument")

	local err = nil
	token, err = jwe.decode(token)

	if not token then
		return nil, errmsg("unable to decode token", err)
	end

	local alg = token.protected.alg
	local enc = token.protected.enc

	assert(ALGORITHM[alg], "invalid alg argument")
	assert(ENCRYPTION[enc], "invalid enc argument")

	local protected = token.protected

	if enc ~= protected.enc then
		return nil, errmsg("encryption algorithm mismatch", enc, protected.enc)
	end

	key, err = jwe.key(key, alg)

	if not key then
		return nil, err
	end

	if not key:is_private() then
		return nil, errmsg("invalid decryption key (public key was provided)")
	end

	local cek = nil

	if alg == "RSA-OAEP" then
		local encrypted_key = token.encrypted_key

		if encrypted_key == "" then
			return nil, "invalid content encryption key (empty)"
		end

		cek, err = key:decrypt(token.encrypted_key, PADDING[alg])

		if not cek then
			return nil, errmsg("unable to decrypt content encryption key", err)
		end
	else
		local epk = protected.epk

		if type(epk) ~= "table" then
			return nil, "invalid ephemeral public key"
		end

		if epk.kty ~= "EC" then
			return nil, "invalid ephemeral public key kty-parameter"
		end

		if type(epk.x) ~= "string" or #epk.x == 0 then
			return nil, "invalid ephemeral public key x-coordinate"
		end

		if type(epk.y) ~= "string" or #epk.y == 0 then
			return nil, "invalid ephemeral public key y-coordinate"
		end

		if epk.d then
			return nil, "invalid ephemeral public key (private key was provided)"
		end

		local crv = epk.crv

		if type(crv) ~= "string" then
			return nil, "invalid ephemeral public key curve"
		end

		if not CURVE2OPENSSL[crv] then
			return nil, errmsg("unsupported ephemeral public key curve", crv)
		end

		epk, err = jwe.key(epk, alg)

		if not epk then
			return nil, errmsg("unable to load ephemeral public key", err)
		end

		if epk:is_private() then
			return nil, "invalid ephemeral public key (private key was provided)"
		end

		local keycurve = nil
		keycurve, err = jwe.curve(key, alg)

		if not keycurve then
			return nil, err
		end

		local pubcurve = nil
		pubcurve, err = jwe.curve(epk, alg)

		if not pubcurve then
			return nil, err
		end

		if pubcurve ~= keycurve then
			return nil, errmsg("curve mismatch with private key", keycurve, pubcurve)
		end

		if pubcurve ~= crv then
			return nil, errmsg("curve mismatch with protected header", pubcurve, epk.crv)
		end

		local z = nil
		z, err = key:derive(epk)

		if not z then
			return nil, errmsg("unable to derive agreement output from ephemeral key", err)
		end

		local apu = protected.apu

		if apu ~= nil and type(apu) ~= "string" then
			return nil, errmsg("invalid Agreement PartyUInfo header parameter", apu)
		end

		if apu and apu ~= "" then
			apu, err = decode_base64url(apu)

			if not apu then
				return nil, errmsg("unable to base64url decode Agreement PartyUInfo header parameter", err)
			end
		end

		local apv = protected.apv

		if apv ~= nil and type(apv) ~= "string" then
			return nil, errmsg("invalid Agreement PartyVInfo header parameter", apv)
		end

		if apv and apv ~= "" then
			apv, err = decode_base64url(apv)

			if not apv then
				return nil, errmsg("unable to base64url decode Agreement PartyVInfo header parameter", err)
			end
		end

		cek, err = jwe.concatkdf(z, enc, apu, apv)

		if not cek then
			return nil, errmsg("unable to derive content encryption key", err)
		end
	end

	local cip = nil
	cip, err = cipher.new(CIPHER[enc])

	if not cip then
		return nil, errmsg("unable to initialize cipher", err)
	end

	local plaintext = nil
	plaintext, err = cip:decrypt(cek, token.iv, token.ciphertext, false, token.aad, token.tag)

	if not plaintext then
		return nil, errmsg("unable to decrypt ciphertext", err)
	end

	local zip = protected.zip

	if zip then
		if zip ~= "DEF" then
			return nil, errmsg("unsupported compression algorithm", zip)
		end

		plaintext, err = jwe.inflate(plaintext)

		if not plaintext then
			return nil, errmsg("unable to decompress plaintext", err)
		end
	end

	return plaintext
end

function jwe.encrypt(alg, enc, key, plaintext, options)
	assert(ALGORITHM[alg], "invalid alg argument")
	assert(ENCRYPTION[enc], "invalid enc argument")
	assert(type(key) == "string" or type(key) == "table", "invalid key argument")
	assert(type(plaintext) == "string", "invalid plaintext argument")
	assert(options == nil or type(options) == "table", "invalid options argument")

	local kid = ""

	if key.kid then
		kid = fmt(",\"kid\":\"%s\"", key.kid)
	end

	local err = nil
	key, err = jwe.key(key, alg)

	if not key then
		return nil, err
	end

	if key:is_private() then
		local pub_pem = key:to_PEM("public")
		key = pkey.new(pub_pem)

		if not key then
			return nil, "could not retrieve pubkey from private key"
		end
	end

	local cek, epk, encrypted_key = nil

	if alg == "RSA-OAEP" then
		cek, err = randombytes(KEYSIZE[enc])

		if not cek then
			return nil, errmsg("unable to generate content encryption key", err)
		end

		encrypted_key, err = key:encrypt(cek, PADDING[alg])

		if not encrypted_key then
			return nil, errmsg("unable to encrypt content encryption key", err)
		end

		encrypted_key, err = encode_base64url(encrypted_key)

		if not encrypted_key then
			return nil, errmsg("unable to base64url encode encrypted content encryption key", err)
		end
	else
		encrypted_key = ""
		local curve = nil
		curve, err = jwe.curve(key, alg)

		if not curve then
			return nil, err
		end

		epk, err = pkey.new({
			type = "EC",
			curve = CURVE2OPENSSL[curve]
		})

		if not epk then
			return nil, errmsg("unable to generate key for ephemeral public key derivation", err)
		end

		local z = nil
		z, err = epk:derive(key)

		if not z then
			return nil, errmsg("unable to derive agreement output from ephemeral key", err)
		end

		local apu = options and options.apu

		if apu == nil or apu == true then
			apu, err = randombytes(16)

			if not apu then
				return nil, errmsg("unable to generate Agreement PartyUInfo header parameter", err)
			end
		elseif apu == false then
			apu = nil
		end

		local apv = options and options.apv

		if apv == nil or apv == true then
			apv, err = randombytes(16)

			if not apv then
				return nil, errmsg("unable to generate Agreement PartyVInfo header parameter", err)
			end
		elseif apv == false then
			apv = nil
		end

		cek, err = jwe.concatkdf(z, enc, apu, apv)

		if not cek then
			return nil, errmsg("unable to derive content encryption key", err)
		end

		if apu then
			if apu ~= "" then
				apu, err = encode_base64url(apu)

				if not apu then
					return nil, errmsg("unable to base64url encode Agreement PartyUInfo header parameter", err)
				end
			end

			apu, err = encode_json(apu)

			if not apu then
				return nil, errmsg("unable to json encode Agreement PartyUInfo header parameter", err)
			end
		end

		if apv then
			if apv ~= "" then
				apv, err = encode_base64url(apv)

				if not apv then
					return nil, errmsg("unable to base64url encode Agreement PartyVInfo header parameter", err)
				end
			end

			apv, err = encode_json(apv)

			if not apv then
				return nil, errmsg("unable to json encode Agreement PartyVInfo header parameter", err)
			end
		end

		local api = nil

		if apu and apv then
			api = fmt(",\"apu\":%s,\"apv\":%s", apu, apv)
		elseif apu then
			api = fmt(",\"apu\":%s", apu)
		elseif apv then
			api = fmt(",\"apv\":%s", apv)
		else
			api = ""
		end

		curve, err = encode_json(curve)

		if not curve then
			return nil, errmsg("unable to json encode curve", err)
		end

		local parameters = nil
		parameters, err = epk:get_parameters()

		if not parameters then
			return nil, errmsg("unable to read ephemeral public key parameters", err)
		end

		local x = nil
		x, err = encode_coordinate("x", parameters)

		if not x then
			return nil, err
		end

		local y = nil
		y, err = encode_coordinate("y", parameters)

		if not y then
			return nil, err
		end

		epk = fmt("%s,\"epk\":{\"kty\":\"EC\",\"crv\":%s,\"x\":%s,\"y\":%s}", api, curve, x, y)
	end

	local cip = nil
	cip, err = cipher.new(CIPHER[enc])

	if not cip then
		return nil, errmsg("unable to initialize cipher", err)
	end

	local iv = nil
	iv, err = randombytes(IVSIZE[enc])

	if not iv then
		return nil, errmsg("unable to generate initialization vector", err)
	end

	alg, err = encode_json(alg)

	if not alg then
		return nil, errmsg("unable to json encode algorithm", err)
	end

	enc, err = encode_json(enc)

	if not enc then
		return nil, errmsg("unable to json encode encryption algorithm", err)
	end

	local zip = options and options.zip

	if zip then
		if zip ~= "DEF" then
			return nil, errmsg("invalid compression algorithm", zip)
		end

		plaintext, err = jwe.deflate(plaintext)

		if not plaintext then
			return nil, errmsg("unable to compress plaintext", err)
		end

		zip = ",\"zip\":\"DEF\""
	else
		zip = ""
	end

	local aad = nil

	if epk then
		aad = fmt("{\"alg\":%s,\"enc\":%s%s%s%s}", alg, enc, zip, epk, kid)
	else
		aad = fmt("{\"alg\":%s,\"enc\":%s%s%s}", alg, enc, zip, kid)
	end

	aad, err = encode_base64url(aad)

	if not aad then
		return nil, errmsg("unable to base64url encode authentication tag", err)
	end

	local ciphertext = nil
	ciphertext, err = cip:encrypt(cek, iv, plaintext, false, aad)

	if not ciphertext then
		return nil, errmsg("unable to encrypt plaintext", err)
	end

	if ciphertext ~= "" then
		ciphertext, err = encode_base64url(ciphertext)

		if not ciphertext then
			return nil, errmsg("unable to base64url encode ciphertext", err)
		end
	end

	iv, err = encode_base64url(iv)

	if not iv then
		return nil, errmsg("unable to base64url encode initialization vector", err)
	end

	local tag = nil
	tag, err = cip:get_aead_tag(TAGSIZE[enc])

	if not tag then
		return nil, errmsg("unable to get authentication tag", err)
	end

	tag, err = encode_base64url(tag)

	if not tag then
		return nil, errmsg("unable to base64url encode authentication tag", err)
	end

	return aad .. "." .. encrypted_key .. "." .. iv .. "." .. ciphertext .. "." .. tag
end

return jwe
