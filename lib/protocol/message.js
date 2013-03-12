/*
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 */

var util = require('util');
var ASN1 = require('asn1').Ber;
var lexer = require('../lexer');
var PDU = require('./pdu');
var varbind = require('./varbind');
var data = require('./data');
var parser = require('../parser').parser;
var EmptyMessageError = require('../errors/message').EmptyMessageError;
var MessageParseError = require('../errors/message').MessageParseError;
var NoSupportError = require('../errors/message').NoSupportError;

function
_set_bind(msg, key, primitive, type) {
	return (function (v) {
		if (typeof (v) === primitive) {
			v = data.createData({ value: v,
			    type: type });
		}
		if (typeof (v) !== 'object' || !data.isSnmpData(v) ||
		    v.typename != type) {
			throw new TypeError(key + ' must be a ' + primitive +
			    ' or SNMP data object of type ' + type);
		}

		msg[key] = v;
	});
}

function
SnmpMessage(arg)
{
	//console.log("SnmpMessage : arg = " , arg);
	var self = this;
	var version, community , v3;

	if (typeof (arg) !== 'object')
		throw new TypeError('arg must be an object');

	if (typeof (arg.version) === 'undefined')
		throw new TypeError('arg.version is required');
	if (typeof (arg.version) === 'object' && data.isSnmpData(arg.version))
		version = arg.version;
	else
		version = data.createData({ value: arg.version,
		    type: 'Integer' });
	if (typeof (version) !== 'object' || !data.isSnmpData(version) ||
	    version.typename != 'Integer') {
		throw new TypeError('arg.version must be an integer or ' +
		    ' an SNMP data object of type Integer');
	}
	
	switch (version.value) {
	case 0:
	case 1:
		if (typeof (arg.community) === 'undefined')
			throw new TypeError('arg.community is required');
		if (typeof (arg.community) === 'object' &&
		    data.isSnmpData(arg.community))
			community = arg.community;
		else
			community = data.createData({ value: arg.community,
			    type: 'OctetString' });
		if (typeof (community) !== 'object' || !data.isSnmpData(community) ||
		    community.typename != 'OctetString') {
			throw new TypeError('arg.community must be a string or ' +
			    ' an SNMP data object of type OctetString');
		}
		break;
	case 3:
		if (arg.v3 != null) {
		  v3 = arg.v3;
		} else if (arg.pdu.v3 != null) {
		  v3 = arg.pdu.v3;
		} else {
		  throw new TypeError('arg.pdu.v3 or arg.v3 is required');
		}
    break;
	default:
		throw new NoSupportError('Unknown SNMP version: '+version.value);
	}

	this._version = version;
	this._community = community;
	this._v3 = v3;
	this._raw = this._src = undefined;

	this.__defineGetter__('version', function () {
		return (self._version.value);
	});
	this.__defineGetter__('community', function () {
		return (self._community.value);
	});
	this.__defineGetter__('v3', function () {
		return (self.v3);
	});
	this.__defineGetter__('raw', function () {
		return (self._raw);
	});
	this.__defineGetter__('src', function () {
		return (self._src);
	});
	this.__defineGetter__('pdu', function () {
		return (self._pdu);
	});
	this.__defineSetter__('pdu', function (v) {
		if (typeof (v) !== 'object' || !PDU.isSnmpPDU(v))
			throw new TypeError('pdu must be an object');

		self._pdu = v;
	});

	if (arg.pdu)
		this.pdu = arg.pdu;
}

SnmpMessage.prototype.__snmpjs_magic = 'SnmpMessage';

SnmpMessage.prototype._setOrigin = function _setOrigin(raw, src)
{
	this._raw = raw;
	this._src = src;
};

SnmpMessage.prototype.encode = function encode()
{
	
	var writer = new ASN1.Writer();
	//console.log("writer = ",writer);
	if(this.version != 3){
		if (!this._community)
			throw new TypeError('Message is missing a community');
	}
	
	if (!this._pdu)
		throw new TypeError('Message contains no PDU');
	if (this._raw)
		throw new TypeError('Message has already been encoded');

	writer.startSequence();
	//console.log("[STA] encode = ", writer.buffer);
	//console.log("encode : _version = " ,this._version);
	this._version.encode(writer);
	//console.log("_community writer = ",writer);
	if(this.version != 3){
		this._community.encode(writer);
		this._pdu.encode(writer);
	}
	else{
		//console.log("encode : v3 = " ,this._v3);
		//this._v3.encode(writer);
		
		writer.startSequence();
		this._v3.header.id.encode(writer);
		this._v3.header.maxsize.encode(writer);
		this._v3.header.flags.encode(writer);
		this._v3.header.secmodel.encode(writer);
		writer.endSequence();
		
		time_value = this._v3.secmsg.EngineTime._value;
		
		cal_time_len = function(i) {
			var buf, offset, sz;
			offset = 0;
			buf = new Buffer(10);
			buf.fill(0x00);
			sz = 4;
			while ((((i & 0xff800000) === 0) || ((i & 0xff800000) === 0xff800000)) && (sz > 1)) {
				sz--;
				i <<= 8;
			}
			buf[offset++] = 4;
			buf[offset++] = sz;
			while (sz-- > 0) {
				buf[offset++] = (i & 0xff000000) >> 24;
				i <<= 8;
			}
			return buf[1];
		};
		
		//console.log("time : ",time_value , cal_time_len(time_value));
		len = 2 + 12;
		len += this._v3.secmsg.EngineID._value.length + /*EngineBoots*/ 1 + /*EngineTime*/cal_time_len(time_value) + this._v3.secmsg.userName._value.length + this._v3.secmsg.params._value.length + this._v3.secmsg.privacyParams._value.length;
		
		//console.log("len = " , len);
		writer.paddingv3(4,len);
		writer.startSequence();
		this._v3.secmsg.EngineID.encode(writer);
		this._v3.secmsg.EngineBoots.encode(writer);
		this._v3.secmsg.EngineTime.encode(writer);
		this._v3.secmsg.userName.encode(writer);
		this._v3.secmsg.params.encode(writer);
		this._v3.secmsg.privacyParams.encode(writer);
		writer.endSequence();
		
		writer.startSequence();
		this._v3.context.engineID.encode(writer);
		this._v3.context.name.encode(writer);
		this._pdu.encode(writer);
		writer.endSequence();
	}
	//console.log("_pdu writer = ",writer);
	//this._pdu.encode(writer);
	//console.log("version writer = ",writer);
	writer.endSequence();
	//console.log("[END] encode = ", writer.buffer);

	this._raw = {
		buf: writer.buffer,
		len: writer.buffer.length
	};
};

function
ParseContext()
{
	this.ASN1 = ASN1;
	this.pdu = PDU;
	this.varbind = varbind;
	this.data = data;
	this.message = module.exports;
	this.content = undefined;
}

ParseContext.prototype.parse = function parse(raw, src)
{
	/*
	 * This is vile.  Unfortunately, the parser generated by Jison isn't an
	 * object instance, nor is it anything that can construct one.  This
	 * doesn't really matter because we don't do anything asynchronous
	 * during parsing, but it's still wrong.
	 */
	parser.yy = this;

	parser.parse(raw.buf);
	if (!this.content)
		throw new EmptyMessageError();

	this.content._setOrigin(raw, src);
	return (this.content);
};

ParseContext.prototype.parseError = function parseError(str, hash)
{
	throw new MessageParseError(str, hash);
};

ParseContext.prototype.setContent = function setContent(content)
{
	this.content = content;
};

function next_token_value( l)
{
  var dtype='OCTET_STRING';
  var tok=l.lex();
  var reader = new ASN1.Reader(l.yytext);
  if (tok=='INTEGER') {
    dtype='Integer';
  }else if (tok=='OCTET_STRING') {
    dtype = 'OctetString';
  }
  return data.createData({ value: reader, type: dtype});
}


function processV3sec( buf)
{
  var l = new lexer();
  l.setInput(buf);
  var tok=l.lex();
  /* skip the SEQUENCE */

  var msg={};
  msg.EngineID = next_token_value(l);
  msg.EngineBoots = next_token_value(l);
  msg.EngineTime = next_token_value(l);
  msg.userName = next_token_value(l);
  msg.params = next_token_value(l);
  msg.privacyParams = next_token_value(l);

  return msg;
}

function processV3( v3)
{
  v3.secmsg = processV3sec( v3.sec.value);
}


function
parseMessage(arg)
{
	var ctx;

	if (typeof (arg) !== 'object')
		throw new TypeError('arg (object) is required');
	if (typeof (arg.raw) !== 'object')
		throw new TypeError('arg.raw (object) is required');
	if (Buffer.isBuffer(arg.raw)) {
		arg.raw = {
			buf: arg.raw,
			len: arg.raw.length
		};
	}
	if (typeof (arg.raw.buf) !== 'object' || !Buffer.isBuffer(arg.raw.buf))
		throw new TypeError('arg.raw does not contain a Buffer');

	ctx = new ParseContext();
  req = ctx.parse(arg.raw, arg.src);
  if (req.version==3){
    processV3( req.pdu.v3);
    //console.log("parseMsg V3 = " , req);
  }

	return req;
}

function
createMessage(arg)
{
	return (new SnmpMessage(arg));
}

function
strversion(ver)
{
	if (typeof (ver) !== 'number')
		throw new TypeError('ver (number) is required');
	switch (ver) {
	case 0:
		return ('v1(0)');
	case 1:
		return ('v2c(1)');
	case 3:
		return ('v3(3)');
	default:
		return ('<unknown>(' + ver + ')');
	}
}

function
bunyan_serialize_snmpmsg(snmpmsg)
{
	var i;
	var obj = {
		version: strversion(snmpmsg.version),
		community: snmpmsg.community.toString()
	};

	obj.pdu = {
		op: PDU.strop(snmpmsg.pdu.op),
		request_id: snmpmsg.pdu.request_id,
		error_status: PDU.strerror(snmpmsg.pdu.error_status),
		error_index: snmpmsg.pdu.error_index,
		varbinds: []
	};
	for (i = 0; i < snmpmsg.pdu.varbinds.length; i++) {
		var dv = snmpmsg.pdu.varbinds[i].data.value;
		var type = snmpmsg.pdu.varbinds[i].data.typename;
		var datastr = type + ': ' + dv;
		var vb = {
			oid: snmpmsg.pdu.varbinds[i].oid,
			typename: snmpmsg.pdu.varbinds[i].typename,
			value: datastr
		};
		obj.pdu.varbinds.push(vb);
	}

	return (obj);
}

module.exports = function _message_init() {
	var message = {
		parseMessage: parseMessage,
		createMessage: createMessage,
		strversion: strversion,
		serializer: bunyan_serialize_snmpmsg
	};

	message.isSnmpMessage = function (m) {
		return ((typeof (m.__snmpjs_magic) === 'string' &&
		    m.__snmpjs_magic === 'SnmpMessage') ? true : false);
	};

	parser.lexer = new lexer();

	return (message);
}();
