/*
 * Copyright (c) 2012 Joyent, Inc.	All rights reserved.
 */

var assert = require('assert');
var dgram = require('dgram');
var util = require('util');
var message = require('./protocol/message');
var PDU = require('./protocol/pdu');
var varbind = require('./protocol/varbind');
var data = require('./protocol/data');
var MIB = require('./mib');
var ProviderRequest = require('./provider').ProviderRequest;
var crypto = require("crypto");

var AGENT_PROBES = {
	/* id, op, srcaddr */
	'agent-req-start': [ 'int', 'int', 'char *' ],
	/* id, op, srcaddr, status, index */
	'agent-req-done': [ 'int', 'int', 'char *', 'int', 'int' ],
	/* id, op, index, oid */
	'agent-varbind-dispatch': [ 'int', 'int', 'int', 'char *' ],
	/* id, op, index, oid, result */
	'agent-varbind-result': [ 'int', 'int', 'int', 'char *', 'char *' ]
};

function
AgentMIBDecor(prov, column)
{
	this._scalar = (prov.columns) ? false : true;
	this._column = (column === true) ? true : false;

	if (util.isArray(prov.handler))
		this._handler = prov.handler;
	else
		this._handler = [ prov.handler ];
}

AgentMIBDecor.prototype.instancePossible = function () {
	return (this._scalar || this._column);
};

Agent.prototype._add_provider = function _add_provider(prov) {
	var self = this;
	var decor;
	var node;

	if (typeof (prov) !== 'object')
		throw new TypeError('prov (object) is required');
	if (typeof (prov.oid) !== 'string')
		throw new TypeError('prov.oid (string) is required');
	if (typeof (prov.handler) !== 'function' &&
			(typeof (prov.handler) !== 'object' || !util.isArray(prov.handler)))
		throw new TypeError('prov.handler (function) is required');
	if (typeof (prov.columns) !== 'undefined' &&
			(typeof (prov.columns) !== 'object' || !util.isArray(prov.columns)))
		throw new TypeError('prov.columns must be an array');

	node = this._mib.add(prov);
	decor = new AgentMIBDecor(prov);
	node.decorate({ tag: '_agent', obj: decor });

	if (prov.columns) {
		prov.columns.forEach(function (c) {
			node = self._mib.add(prov.oid + '.' + c);
			decor = new AgentMIBDecor(prov, true);
			node.decorate({ tag: '_agent', obj: decor });
		});
	}
};

Agent.prototype.addProviders = function addProviders(prov) {
	var self = this;

	if (typeof (prov) !== 'object')
		throw new TypeError('prov (object) is required');

	if (util.isArray(prov)) {
		prov.forEach(function (p) {
			self._add_provider(p);
		});
	} else {
		this._add_provider(prov);
	}
};

function
Agent(options)
{
	var self = this;

	if (typeof (options) !== 'object')
		throw new TypeError('options (object) is required');
	if (typeof (options.log) !== 'object')
		throw new TypeError('options.log (object) is required');
	if (typeof (options.dtrace) !== 'object')
		throw new TypeError('options.dtrace (object) is required');

	this._log = options.log;
	this._dtrace = options.dtrace;
	this._name = options.name || 'snmpjs';
	this._connections = [];

	Object.keys(AGENT_PROBES).forEach(function (p) {
		var args = AGENT_PROBES[p].splice(0);
		args.unshift(p);

		self._dtrace.addProbe.apply(self._dtrace, args);
	});

	this._dtrace.enable();

	this._mib = new MIB();
	this._malformed_messages = 0;
}

/*
 * The provider is expected to provide one of three things for each iteration
 * requested of it:
 *
 * - undefined, meaning that there is no matching instance.	 This should happen
 *	 only for tabular providers; scalar providers are never passed GetNext
 *	 requests nor any Get or Set with an instance other than 0.
 *
 * - an integer, representing an error status from the set of errors enumerated
 *	 in protocol/pdu.js.
 *
 * - an instance of SnmpVarbind containing the data requested.
 *
 * These end up here, one way or another, and we just stuff them into the
 * response object.
 */
Agent.prototype._varbind_set_single =
		function _varbind_set_single(req, rsp, idx, vb) {
	if (typeof (vb) === 'undefined' && req.pdu.op == PDU.GetNextRequest) {
		rsp.pdu.varbinds[idx] = req.pdu.varbinds[idx].clone();
		rsp.pdu.varbinds[idx].data = data.createData({ type: 'Null',
				value: data.noSuchInstance });
	} else if (typeof (vb) === 'number') {
		if (req.pdu.op != PDU.SetRequest && vb != PDU.genErr) {
			this.log.warn({ snmpmsg: req },
					'provider attempted to set prohibited ' +
					'error code ' + vb + ' for varbind ' + idx);
			vb = PDU.genErr;
		}
		rsp.pdu.varbinds[idx] = req.pdu.varbinds[idx].clone();
		if (!rsp.pdu.error_status || idx + 1 < rsp.pdu.error_index) {
			rsp.pdu.error_status = vb;
			rsp.pdu.error_index = idx + 1;
		}
	} else if (typeof (vb) !== 'object' || !varbind.isSnmpVarbind(vb)) {
		throw new TypeError('Response data is of incompatible type');
	} else {
		rsp.pdu.varbinds[idx] = vb;
	}
	//console.log("_varbind_set_single",rsp.pdu);
};

Agent.prototype._transmit_response = function _transmit_response(rsp,error) {
	//console.log("Agent._transmit_response , rsp=",rsp);
	var sock;
	var dst = rsp.dst;

	rsp.encode();
	if (typeof error !== "undefined" && error !== null){
	}
	else{
		if(rsp.version === 3){
			if(rsp._v3.header.flags._value[0] & 2){
				var key, x, _i, _len , find_params_pos;
			
				for (_i = 0, _len = this._users.length; _i < _len; _i++) {
					x = this._users[_i];
					if (x.name === rsp._v3.secmsg.userName._value.toString()) {
						key = x.privacy_key;
					}
				}
			
				if (typeof key !== "undefined" && key !== null) {
					v3_start = this._find_version_pos(rsp.raw.buf, new Buffer([0x02, 0x01, 0x03]));
					global_data_start = v3_start + 2 + rsp.raw.buf[v3_start + 1];
					v3_sec_start = global_data_start + 2 + rsp.raw.buf[global_data_start + 1];
					msg_data_start = v3_sec_start + 2 + rsp.raw.buf[v3_sec_start + 1];
					need_encrypted_pdu = rsp.raw.buf.slice(msg_data_start,rsp.raw.buf.length-1);
					//console.log("need_encrypted_pdu = " , need_encrypted_pdu.length);
					encrypted_pdu = this._encrypt(need_encrypted_pdu , key , rsp._v3.secmsg.privacyParams._value);
					//console.log("encrypted_pdu.length=",encrypted_pdu.length , encrypted_pdu);
					//console.log("total=",msg_data_start + 2 + encrypted_pdu.length);
					if(rsp.raw.buf[1] === 0x81){
						rsp.raw.buf[2] +=  encrypted_pdu.length - need_encrypted_pdu.length + 1;
					}
					else if(rsp.raw.buf[1] === 0x82){
						rsp.raw.buf[3] +=  encrypted_pdu.length - need_encrypted_pdu.length + 2;
					}
					buf = new Buffer(msg_data_start + 2 + encrypted_pdu.length).clear();
					//console.log("buf.length=",buf.length);
					var offset = 0;
					offset += rsp.raw.buf.slice(0,msg_data_start).copy(buf,offset);
					padding_pdu = new Buffer(2).clear();
					padding_pdu[0] = 0x04;
					padding_pdu[1] = encrypted_pdu.length;
					offset += padding_pdu.copy(buf,offset);
					offset += encrypted_pdu.copy(buf,offset);
					//require('fs').writeFileSync("test.dat", buf.toString("hex"), 'hex');
					rsp.raw.buf = buf;
					rsp.raw.len = buf.length;
				}
			}
		
			if(rsp._v3.header.flags._value[0] & 1){
				var key, x, _i, _len , find_params_pos;
			
				for (_i = 0, _len = this._users.length; _i < _len; _i++) {
					x = this._users[_i];
					if (x.name === rsp._v3.secmsg.userName._value.toString()) {
						key = x.authentication_key;
					}
				}
			
				if (typeof key !== "undefined" && key !== null) {
					var params = new Buffer(crypto.createHmac('md5', key).update(rsp.raw.buf).digest("hex") , "hex");
				
					find_params_pos = function(raw) {
						var count, find_count, pos, x, _i, _len;
						pos = 0;
						count = 0;
						find_count = 0;
						for (_i = 0, _len = raw.length; _i < _len; _i++) {
							x = raw[_i];
							if (x === 0x00) {
								if (find_count === 0) {
									pos = count;
								}
								find_count++;
							} else {
								if (find_count === 12) {
									return pos;
								}
								find_count = 0;
								pos = 0;
							}
							count++;
						}
						return pos;
					};
				
					params.slice(0, 12).copy(rsp.raw.buf, find_params_pos(rsp.raw.buf));
				}
			}
		}
	}
	this._log.trace({ raw: rsp.raw, dst: dst, snmpmsg: rsp },
					'Sending SNMP response message');
	sock = dgram.createSocket(dst.family);
	console.log("_transmit_response rsp.raw.len=",rsp.raw.len,"rsp.raw.buf = ", rsp.raw.buf);
	sock.send(rsp.raw.buf, 0, rsp.raw.len, dst.port, dst.address);
};

Agent.prototype._do_error = function _do_error(req, rsp , usm_stats) {
	console.log("_do_error");
	var self = this;
	var nvb = req.pdu.varbinds.length;
	var ndone = 0;
	
	var oid;
	if(usm_stats === 'unsupported_security_level'){
		oid = '1.3.6.1.6.3.15.1.1.1.0';
	}
	else if(usm_stats === 'unknown_user_name'){
		oid = '1.3.6.1.6.3.15.1.1.3.0';
	}
	else if(usm_stats === 'unknown_engine_id'){
		oid = '1.3.6.1.6.3.15.1.1.4.0';
	}
	else if(usm_stats === 'authentication_failure'){
		oid = '1.3.6.1.6.3.15.1.1.5.0';
	}
	else if(usm_stats === 'decrypt_failure'){
		oid = '1.3.6.1.6.3.15.1.1.6.0';
	}
	
	
	var node = self._mib.lookup(oid);
	var prq = new ProviderRequest(req.pdu.op, oid, node); 
	var decor = node.decor('_agent');
	var handler;
	if (!node || !decor || !decor.instancePossible()) {
		handler = [ function _getset_nsohandler(pr) {
			//console.log("_getset_nsohandler ");
			var rsd = data.createData({ type: 'Null',
					value: data.noSuchObject });
			var rsvb = varbind.createVarbind({
					oid: pr.oid, data: rsd });
			pr.done(rsvb);
		} ];
	} else {
		if (!prq.instance || decor._scalar &&
				(prq.instance.length > 1 || prq.instance[0] != 0)) {
			handler = [ function _getset_nsihandler(pr) {
				//console.log("_getset_nsihandler");
				var rsd = data.createData({
						type: 'Null',
						value: data.noSuchInstance
				});
				var rsvb = varbind.createVarbind({
						oid: pr.oid, data: rsd });
				pr.done(rsvb);
			} ];
		} else {
			//console.log("_do_getset XXX else = " , prq.op == PDU.SetRequest);
			if (prq.op == PDU.SetRequest)
				prq._value = null;
			handler = decor._handler;
		}
	}

	prq._done = function _getset_done(rsvb) {
		//console.log("_getset_done");
		self._varbind_set_single(req, rsp, 0, rsvb);
		self._transmit_response(rsp,true);
	};
	//console.log ("prq = " , prq);
	//console.log("handler = " , handler);
	handler.forEach(function (h) {
		//console.log("_do_error handler :",h);
		h(prq);
	});
};

Agent.prototype._do_getset = function _do_getset(req, rsp) {
	//console.log("Agent._do_getset");
	var self = this;
	var nvb = req.pdu.varbinds.length;
	var ndone = 0;
	
	//console.log("nvb = ", nvb);
	if (nvb === 0) {
			var node = self._mib.lookup('1.3.6.1.6.3.15.1.1.4.0');
			var prq = new ProviderRequest(req.pdu.op, '1.3.6.1.6.3.15.1.1.4.0', node);
			var decor = node.decor('_agent');
			var handler;
			//console.log("node=",node);
			if (!node || !decor || !decor.instancePossible()) {
				handler = [ function _getset_nsohandler(pr) {
					//console.log("_getset_nsohandler ");
					var rsd = data.createData({ type: 'Null',
							value: data.noSuchObject });
					var rsvb = varbind.createVarbind({
							oid: pr.oid, data: rsd });
					pr.done(rsvb);
				} ];
			} else {
				if (!prq.instance || decor._scalar &&
						(prq.instance.length > 1 || prq.instance[0] != 0)) {
					handler = [ function _getset_nsihandler(pr) {
						//console.log("_getset_nsihandler");
						var rsd = data.createData({
								type: 'Null',
								value: data.noSuchInstance
						});
						var rsvb = varbind.createVarbind({
								oid: pr.oid, data: rsd });
						pr.done(rsvb);
					} ];
				} else {
					//console.log("_do_getset XXX else = " , prq.op == PDU.SetRequest);
					if (prq.op == PDU.SetRequest)
						prq._value = null;
					handler = decor._handler;
				}
			}
		
			prq._done = function _getset_done(rsvb) {
				//console.log("_getset_done");
				self._varbind_set_single(req, rsp, 0, rsvb);
				self._transmit_response(rsp);
			};
			//console.log ("prq = " , prq);
			//console.log("handler = " , handler);
			handler.forEach(function (h) {
				//console.log("_do_getset handler :",h);
				h(prq);
			});
	}
	else{
		req.pdu.varbinds.forEach(function (vb, i) {
			//console.log("i=",i,"vb=",vb);
			//console.log("vb.oid = " , vb.oid , typeof vb.oid);
			var node = self._mib.lookup(vb.oid);
			var prq = new ProviderRequest(req.pdu.op, vb.oid, node);
			var decor = node.decor('_agent');
			var handler;
			//console.log("node=",node);
			if (!node || !decor || !decor.instancePossible()) {
				handler = [ function _getset_nsohandler(pr) {
					//console.log("_getset_nsohandler ");
					var rsd = data.createData({ type: 'Null',
							value: data.noSuchObject });
					var rsvb = varbind.createVarbind({
							oid: pr.oid, data: rsd });
					pr.done(rsvb);
				} ];
			} else {
				if (!prq.instance || decor._scalar &&
						(prq.instance.length > 1 || prq.instance[0] != 0)) {
					handler = [ function _getset_nsihandler(pr) {
						//console.log("_getset_nsihandler");
						var rsd = data.createData({
								type: 'Null',
								value: data.noSuchInstance
						});
						var rsvb = varbind.createVarbind({
								oid: pr.oid, data: rsd });
						pr.done(rsvb);
					} ];
				} else {
					//console.log("_do_getset XXX else = " , prq.op == PDU.SetRequest);
					if (prq.op == PDU.SetRequest)
						prq._value = vb.data;
					handler = decor._handler;
				}
			}
		
			prq._done = function _getset_done(rsvb) {
				//console.log("_getset_done");
				self._varbind_set_single(req, rsp, i, rsvb);
				if (++ndone == nvb)
					self._transmit_response(rsp);
			};
			//console.log ("prq = " , prq);
			//console.log("handler = " , handler);
			handler.forEach(function (h) {
				//console.log("_do_getset handler :",h);
				h(prq);
			});
		
		});
	}
};

Agent.prototype._getnext_lookup = function _getnext_lookup(oid, exactok) {
	//console.log("Agent._getnext_lookup , oid = " ,oid ,"exactok=",exactok);
	var node;
	var addr = data.canonicalizeOID(oid);
	var match;
	var decor;

	oid = addr.join('.');
	node = this._mib.lookup(oid);

	if (!node)
		return (null);

	decor = node.decor('_agent');
	match = function (n) {
		var d = n.decor('_agent');

		return (d && d.instancePossible() || false);
	};

	/*
	 * Please note that this code is optimised for readability because the
	 * logic for choosing where to look for the next instance is somewhat
	 * complex.	 It should be very apparent from this that we are in fact
	 * covering all possible cases, and doing the right thing for each.
	 */

	/*
	 * Exact match, the node is a column.	 Use the node if an exact match is
	 * ok; the provider will figure out the first row, or else we'll end up
	 * right back here with exactok clear.
	 */
	if (node.oid === oid && decor && decor._column && exactok)
		return (node);

	/*
	 * Exact match, the node is a column but we need the next subtree.
	 * Walk the parent starting from the next sibling.
	 */
	if (node.oid === oid && decor && decor._column) {
		return (this._mib.next_match({
			node: node.parent,
			match: match,
			start: node.addr[node.addr.length - 1] + 1
		}));
	}

	/*
	 * Exact match, the node is a scalar.	 Use it; we want the instance,
	 * becuase it follows this OID in the lexicographical order.
	 */
	if (node.oid === oid && decor && decor._scalar)
		return (node);

	/*
	 * Exact match, the node is just an OID.	Walk the node from the
	 * beginning to find any instances within this subtree.	 If there aren't
	 * any, the walk will proceed back up and on to the next sibling.
	 */
	if (node.oid === oid && (!decor || !decor.instancePossible())) {
		return (this._mib.next_match({
			node: node,
			match: match
		}));
	}

	/*
	 * Ancestor, and the node is just an OID.	 Walk the node from the first
	 * child after the first non-matching component.
	 *
	 * Ex: GetNext(.1.3.3.6.2) finds (.1.3); walk (.1.3), 4
	 */
	if (!decor || !decor.instancePossible()) {
		return (this._mib.next_match({
			node: node,
			match: match,
			start: addr[node.addr.length] + 1
		}));
	}

	/*
	 * Ancestor, and the node is a scalar.	Walk the parent starting from
	 * the next sibling, because there can be only one intance below this
	 * node.	So no matter what the instance portion of the OID is, the next
	 * instance in the MIB can't be in this subtree.
	 */
	if (decor._scalar) {
		return (this._mib.next_match({
			node: node.parent,
			match: match,
			start: node.addr[node.addr.length - 1] + 1
		}));
	}

	/*
	 * Ancestor, and the node is a column.	Use the node if an exact match
	 * is ok, otherwise keep going.	 Note that this is the same as the very
	 * first case above; we don't actually care whether we're being asked
	 * for the first row in the column or the next one after some identified
	 * instance, because that's the provider's job to figure out.
	 */
	if (exactok)
		return (node);

	/*
	 * Ancestor, and the node is a column.	An exact match is not ok, so
	 * walk the parent starting from the next sibling.	Again, this is the
	 * same as the case in which we hit the exact match -- we know we've
	 * already asked this provider and we need to advance to another one.
	 */
	return (this._mib.next_match({
		node: node.parent,
		match: match,
		start: node.addr[node.addr.length - 1] + 1
	}));
};

Agent.prototype._do_getnext_one =
		function (req, rsp, i, oid, cookie, first) {
	//console.log("Agent._do_getnext_one , req = " ,req , "rsp=",rsp, "i=",i, "oid=",oid, "cookie=",cookie,"first=", first);
	//console.log("Agent._do_getnext_one");
	var self = this;
	var node = this._getnext_lookup(oid, first);
	var nvb = req.pdu.varbinds.length;
	var prq = new ProviderRequest(req.pdu.op, oid, node);
	var handler;

	if (!node || !node.decor('_agent').instancePossible()) {
		handler = [ function _getset_nsohandler(pr) {
			//console.log("Agent._do_getnext_one._getset_nsohandler");
			var rsd = data.createData({ type: 'Null',
					value: data.endOfMibView });
			var rsvb = varbind.createVarbind({
					oid: pr.oid, data: rsd });
			pr.done(rsvb);
		} ];
	} else {
		handler = node.decor('_agent')._handler;
	}

	prq._done = function _getnext_done(rsvb) {
		//console.log("Agent._do_getnext_one._getnext_done , rsvb = " ,rsvb);
		if (rsvb !== undefined) {
			self._varbind_set_single(req, rsp, i, rsvb);
			if (++cookie.ndone == nvb)
				self._transmit_response(rsp);
			return;
		}
		self._do_getnext_one(req, rsp, i, prq.node.oid, cookie, false);
	};

	handler.forEach(function (h) {
		h(prq);
	});
};

Agent.prototype._do_getnext = function _do_getnext(req, rsp) {
	//console.log("Agent._do_getnext , req = " ,req , "rsp=",rsp);
	//console.log("Agent._do_getnext ");
	var self = this;
	var cookie = { ndone: 0 };

	req.pdu.varbinds.forEach(function (vb, i) {
		//console.log("Agent._do_getnext.forEach , vb = " ,vb , "i=",i);
		self._do_getnext_one(req, rsp, i, vb.oid, cookie, true);
	});
};

Agent.prototype._do_getbulk = function _do_getbulk(req, rsp) {
	console.log("Agent._do_getbulk , req = " ,req , "rsp=",rsp);
	/* XXX yuck */
};

Agent.prototype._check_error = function _check_error(req,pass_auth) {
	var error_action = 'none';
	if (typeof req.pdu.v3.secmsg.EngineID._value[0] !== "undefined" && req.pdu.v3.secmsg.EngineID._value[0] !== null){
		if(req.pdu.v3.secmsg.EngineID._value.toString() !== this._engine_id.toString()){
			error_action = 'unknown_engine_id';
			return error_action;
		}
	}
	
	if (typeof req.pdu.v3.secmsg.userName._value[0] !== "undefined" && req.pdu.v3.secmsg.userName._value[0] !== null){
		if(!this._user_match(req.pdu.v3.secmsg.userName._value.toString())){
			error_action = 'unknown_user_name';
			return error_action;
		}
	}
	
	var level = '';
	if(req.pdu.v3.header.flags._value[0] === 0){
		level = 'noauth_nopriv';
	}
	else if(req.pdu.v3.header.flags._value[0] === 1){
		level = 'auth_nopriv';
	}
	else if(req.pdu.v3.header.flags._value[0] === 3){
		level = 'auth_priv';
	}
	
	console.log("user=",req.pdu.v3.secmsg.userName._value.toString());
	console.log("level=",level);
	if (typeof req.pdu.v3.secmsg.userName._value[0] !== "undefined" && req.pdu.v3.secmsg.userName._value[0] !== null){
		if(!this._user_match(req.pdu.v3.secmsg.userName._value.toString(),level)){
			error_action = 'unsupported_security_level';
			return error_action;
		}
	}
	
	//console.log("_check_error,req.pdu.v3.secmsg.params._value = ",req.pdu.v3.secmsg.params._value);
	if(pass_auth == false){
		if (typeof req.pdu.v3.secmsg.params._value[0] !== "undefined" && req.pdu.v3.secmsg.params._value[0] !== null){
			if(req.pdu.v3.header.flags._value[0] & 1){
				var key, x, _i, _len , find_params_pos;
		
				find_params = function(raw , params) {
					var count, find_count, pos, x, _i, _len;
					pos = 0;
					count = 0;
					find_count = 0;
					for (_i = 0, _len = raw.length; _i < _len; _i++) {
						x = raw[_i];
						if (x === params[find_count]) {
							if (find_count === 0) {
								pos = count;
							}
							find_count++;
						} else {
							if (find_count === 12) {
								return pos;
							}
							find_count = 0;
							pos = 0;
						}
						count++;
					}
					return pos;
				};
		
				for (_i = 0, _len = this._users.length; _i < _len; _i++) {
					x = this._users[_i];
					if (x.name === req.pdu.v3.secmsg.userName._value.toString()) {
						key = x.authentication_key;
					}
				}
			
				pos = find_params(req.raw.buf , req.pdu.v3.secmsg.params._value);
				buf = new Buffer(req.raw.buf);
				//require('fs').writeFileSync("test.dat", buf.toString("hex"), 'hex');
				clear_buf = new Buffer(12).clear();
				clear_buf.copy(buf,pos);
				//console.log("buf=",buf);
				//console.log("key",key);
				if (typeof key !== "undefined" && key !== null) {
					var params = new Buffer(crypto.createHmac('md5', key).update(buf).digest("hex"),"hex");
					//console.log("params=",params.slice(0,12).toString("hex"));
					//console.log("req.pdu.v3.secmsg.params._value.toString()=",req.pdu.v3.secmsg.params._value.toString("hex"));
					if(params.slice(0,12).toString("hex") !== req.pdu.v3.secmsg.params._value.toString("hex")){
						error_action = 'authentication_failure';
						return error_action;
					}
				}
			}
		}
	}
	
	return error_action;
	
};

Agent.prototype._process_req = function _process_req(req,action) {
	//console.log("Agent._process_req , req = " ,req);
	var rsp;
	if (!(typeof req.version === "undefined" && req.version === null)){
		return;
	}
	if (req.version >= 0 && req.version <= 1) {
		console.log("req.community = " , req.community.toString());
		/* XXX check community here */
		var auth_community_state, x, _i, _len, _ref;

		auth_community_state = false;

		_ref = this._community;
		for (_i = 0, _len = _ref.length; _i < _len; _i++) {
			x = _ref[_i];
			if (req.community.toString() === x.community) {
				auth_community_state = true;
			}
		}

		if (!auth_community_state) {
			return;
		}

		rsp = message.createMessage({ version: req.version,
				community: req.community });
		rsp.dst = req.src;

		rsp.pdu = PDU.createPDU({ op: PDU.Response,
				request_id: req.pdu.request_id });
		rsp.pdu.error_status = 0;
		rsp.pdu.error_index = 0;
		
		//show req.pdu.op
		console.log("op = ",req.pdu.op);
		
		switch (req.pdu.op) {
			case PDU.GetRequest:
			case PDU.SetRequest:
				this._do_getset(req, rsp);
				break;
			case PDU.GetNextRequest:
				this._do_getnext(req, rsp);
				break;
			case PDU.GetBulkRequest:
				this._do_getbulk(req, rsp);
				break;
			case PDU.Response:
			case PDU.Trap:
			case PDU.InformRequest:
			case PDU.SNMPv2_Trap:
			case PDU.Report:
			default:
				this._log.debug({
					raw: req.raw,
					origin: req.src,
					snmpmsg: req
						}, 'Ignoring PDU of inappropriate type ' +
								PDU.strop(req.pdu.op));
				break;
		}
	} else {
		//console.log("v3 " , req);
		var op = 0;
		var error_action;
		
		req.pdu.v3.header.maxsize._value = 1400;
		req.pdu.v3.header.flags._value[0] &= 0xfb;
		
		console.log("action=",action);
		if(action === 'none'|| action === 'wait_decrypted'){
			if(action === 'wait_decrypted'){
				error_action = this._check_error(req,true);
			}
			else{
				error_action = this._check_error(req,false);
			}
			
		}
		else{
			error_action = action;
		}
		
		if(req.pdu.v3.header.flags._value[0] === 0){
			this._salt_random = Math.floor(Math.random() * 1000000000);
		}
		if(action === 'none'|| action === 'wait_decrypted'){
			req.pdu.v3.secmsg.EngineID._value = this._engine_id;
			req.pdu.v3.secmsg.EngineBoots._value = this._EngineBoots;
			req.pdu.v3.secmsg.EngineTime._value = this._uptime;
		
			if (typeof req.pdu.v3.secmsg.params._value[0] !== "undefined" && req.pdu.v3.secmsg.params._value[0] !== null){
				req.pdu.v3.secmsg.params._value = new Buffer(12).clear();
			}
			
			if (typeof req.pdu.v3.secmsg.privacyParams._value[0] !== "undefined" && req.pdu.v3.secmsg.privacyParams._value[0] !== null){
				req.pdu.v3.secmsg.privacyParams._value = new Buffer(8).clear();
				req.pdu.v3.secmsg.privacyParams._value.writeInt32BE(this._EngineBoots,0);
				req.pdu.v3.secmsg.privacyParams._value.writeInt32BE(this._salt_random,4);
				this._salt_random++;
			}
			
			req.pdu.v3.context.engineID._value = this._engine_id;
			//req.pdu.v3.context.name._value = new Buffer(this._context_name);
		}
		
		rsp = message.createMessage({ version: req.version , v3:req.pdu.v3});
		rsp.dst = req.src;
		
		if (req.pdu.op === PDU.GetRequest) {
			if (typeof req.pdu.varbinds[0] !== "undefined" && req.pdu.varbinds[0] !== null){
				if(action === 'none'|| action === 'wait_decrypted'){
					op = PDU.Response;
				}
				else{
					op = PDU.Report;
				}
			}
			else{
				op = PDU.Report;
			}
		} else if (req.pdu.op === PDU.GetNextRequest) {
			if(action === 'none'|| action === 'wait_decrypted'){
				op = PDU.Response;
			}
			else{
				op = PDU.Report;
			}
		}
		
		if(action === 'none'|| action === 'wait_decrypted'){
			rsp.pdu = PDU.createPDU({ op: op,
					request_id: req.pdu.request_id });
		}
		else{
			rsp.pdu = PDU.createPDU({ op: op,
					request_id: 0 });
		}
		rsp.pdu.error_status = 0;
		rsp.pdu.error_index = 0;
		//console.log("rsp=",rsp);
		console.log("error_action=",error_action);
		if(action === 'none'|| action === 'wait_decrypted'){
			switch (req.pdu.op) {
				case PDU.GetRequest:
				case PDU.SetRequest:
					this._do_getset(req, rsp);
					break;
				case PDU.GetNextRequest:
					this._do_getnext(req, rsp);
					break;
				case PDU.GetBulkRequest:
					this._do_getbulk(req, rsp);
					break;
				case PDU.Response:
				case PDU.Trap:
				case PDU.InformRequest:
				case PDU.SNMPv2_Trap:
				case PDU.Report:
				default:
					this._log.debug({
						raw: req.raw,
						origin: req.src,
						snmpmsg: req
							}, 'Ignoring PDU of inappropriate type ' +
									PDU.strop(req.pdu.op));
					break;
			}
		}
		else{
			req.pdu.v3.header.flags._value[0] = 0;
			req.pdu.v3.secmsg.params._value = new Buffer(0);
			req.pdu.v3.secmsg.privacyParams._value = new Buffer(0);
			this._do_error(req, rsp , error_action);
		}
	}
	
};

Agent.prototype._is_v3_process = function _is_v3_process(snmp_pdu){ 
	var encrypted_pdu, flag, global_data_start, msg_data_start, privacy_data, v3_sec_start, v3_start;
	var security = {};
	security.error_action = 'none';
	error_padding_pdu = new Buffer("301404000400a00e02044177b20c0201000201003000","hex");
	
	v3_start = this._find_version_pos(snmp_pdu, new Buffer([0x02, 0x01, 0x03]));
	if (v3_start !== 0) {
		global_data_start = v3_start + 2 + snmp_pdu[v3_start + 1];
		flag = this._process_flag(snmp_pdu.slice(global_data_start));
		if (flag & 0x01) {
			var keep_offest=0;
			v3_sec_start = global_data_start + 2 + snmp_pdu[global_data_start + 1];
			msg_data_start = v3_sec_start + 2 + snmp_pdu[v3_sec_start + 1];
			keep_pdu = snmp_pdu.slice(0,msg_data_start);
			error_keep_pdu = new Buffer(keep_pdu.length + error_padding_pdu.length);
			keep_offest += keep_pdu.copy(error_keep_pdu,keep_offest);
			keep_offest += error_padding_pdu.copy(error_keep_pdu,keep_offest);
			
			auth_data = this._process_auth(snmp_pdu.slice(v3_sec_start));
			if ((auth_data.key != null) && (auth_data.auth_params != null)) {
				find_params = function(raw , params) {
					var count, find_count, pos, x, _i, _len;
					pos = 0;
					count = 0;
					find_count = 0;
					for (_i = 0, _len = raw.length; _i < _len; _i++) {
						x = raw[_i];
						if (x === params[find_count]) {
							if (find_count === 0) {
								pos = count;
							}
							find_count++;
						} else {
							if (find_count === 12) {
								return pos;
							}
							find_count = 0;
							pos = 0;
						}
						count++;
					}
					return pos;
				};
				
				pos = find_params(snmp_pdu ,auth_data.auth_params);
				buf = new Buffer(snmp_pdu);
				//require('fs').writeFileSync("test.dat", buf.toString("hex"), 'hex');
				clear_buf = new Buffer(12).clear();
				clear_buf.copy(buf,pos);
				
				var params = new Buffer(crypto.createHmac('md5', auth_data.key).update(buf).digest("hex"),"hex");
				if(params.slice(0,12).toString("hex") !== auth_data.auth_params.toString("hex")){
					security.error_action = 'authentication_failure';
					security.keep_buf = error_keep_pdu;
					return security;
				}
			}
		}
		
		if (flag & 0x02) {
			var keep_offest=0;
			v3_sec_start = global_data_start + 2 + snmp_pdu[global_data_start + 1];
			privacy_data = this._process_privacy(snmp_pdu.slice(v3_sec_start));
			if ((privacy_data.key != null) && (privacy_data.privacy_params != null)) {
				msg_data_start = v3_sec_start + 2 + snmp_pdu[v3_sec_start + 1];
				keep_pdu = snmp_pdu.slice(0,msg_data_start);
				error_keep_pdu = new Buffer(keep_pdu.length + error_padding_pdu.length);
				keep_offest += keep_pdu.copy(error_keep_pdu,keep_offest);
				keep_offest += error_padding_pdu.copy(error_keep_pdu,keep_offest);
								
				encrypted_pdu = snmp_pdu.slice(msg_data_start + 2, (msg_data_start + 2 + snmp_pdu[msg_data_start + 1] - 1) + 1 || 9e9);
				buf = this._decrypt(encrypted_pdu, privacy_data.key, privacy_data.privacy_params);
				//snmp_pdu[1] += 2;
				
				decrypted_pdu = new Buffer(snmp_pdu.slice(0,snmp_pdu.length - (encrypted_pdu.length+2 - buf.length)));
				//console.log("encrypted_pdu",encrypted_pdu.length,encrypted_pdu);
				//console.log("buf",buf.length,buf);
				//console.log("last",decrypted_pdu.slice(80));
				buf.copy(decrypted_pdu, msg_data_start)
				//console.log("last",decrypted_pdu.slice(80));
				security.error_action = 'wait_decrypted';
				security.keep_buf = error_keep_pdu;
				security.decrypted_buf = decrypted_pdu;
				return security;
			}
		}
	}
	return security;
};

Agent.prototype._find_version_pos = function _find_version_pos(raw , specific) { 
	var count, find_count, pos, x, _i, _len, _ref;
	pos = 0;
	count = 0;
	find_count = 0;
	_ref = raw.slice(0, 11);
	for (_i = 0, _len = _ref.length; _i < _len; _i++) {
		x = _ref[_i];
		if (x === specific[find_count]) {
			if (find_count === 0) {
				pos = count;
			}
			find_count++;
		} else {
			if (find_count === specific.length) {
				return pos;
			}
			find_count = 0;
			pos = 0;
		}
		count++;
	}
	return pos;
};

Agent.prototype._process_flag = function _process_flag(raw) { 
	var global_data_length, msg_flag, msg_flag_pos_length, msg_flag_pos_length_pos, msg_id_length, msg_id_length_pos, msg_max_size_length, msg_max_size_length_pos;
	if (raw[0] === 0x30) {
		global_data_length = raw[1];
		msg_id_length_pos = 3;
		msg_id_length = raw[msg_id_length_pos];
		msg_max_size_length_pos = 2 + 2 + msg_id_length + 1;
		msg_max_size_length = raw[msg_max_size_length_pos];
		msg_flag_pos_length_pos = msg_max_size_length_pos + msg_max_size_length + 2;
		msg_flag_pos_length = raw[msg_flag_pos_length_pos];
		msg_flag = raw[msg_flag_pos_length_pos + 1];
		return msg_flag;
	} else {
		return -1;
	}
};

Agent.prototype._process_auth = function _process_auth(raw) { 
	var auth_params_length, auth_params_length_pos, crypt_data, engine_boot_length, engine_boot_length_pos, engine_id_length, engine_id_length_pos, engine_time_length, engine_time_length_pos, privacy_params_length, privacy_params_length_pos, sec_start, user_name_length, user_name_length_pos;
	if (raw[0] === 0x04) {
		if (raw[2] === 0x30) {
			auth_data = {};
			sec_start = 4;
			engine_id_length_pos = sec_start + 1;
			engine_id_length = raw[engine_id_length_pos];
			engine_boot_length_pos = engine_id_length_pos + engine_id_length + 2;
			engine_boot_length = raw[engine_boot_length_pos];
			engine_time_length_pos = engine_boot_length_pos + engine_boot_length + 2;
			engine_time_length = raw[engine_time_length_pos];
			user_name_length_pos = engine_time_length_pos + engine_time_length + 2;
			user_name_length = raw[user_name_length_pos];
			user_name = raw.slice(user_name_length_pos + 1, (user_name_length_pos + user_name_length) + 1 || 9e9);
			
			var key, x, _i, _len, _ref;
			_ref = this._users;
			for (_i = 0, _len = _ref.length; _i < _len; _i++) {
				x = _ref[_i];
				if (x.name === user_name.toString()) {
					auth_data.key = x.authentication_key;
				}
			}
			
			auth_params_length_pos = user_name_length_pos + user_name_length + 2;
			auth_params_length = raw[auth_params_length_pos];
			if (auth_params_length !== 12) {
				return {};
			}
			auth_data.auth_params = raw.slice(auth_params_length_pos + 1, (auth_params_length_pos + auth_params_length) + 1 || 9e9);
			return auth_data;
		}
	}
	return {};
};

Agent.prototype._process_privacy = function _process_privacy(raw) { 
	var auth_params_length, auth_params_length_pos, crypt_data, engine_boot_length, engine_boot_length_pos, engine_id_length, engine_id_length_pos, engine_time_length, engine_time_length_pos, privacy_params_length, privacy_params_length_pos, sec_start, user_name_length, user_name_length_pos;
	if (raw[0] === 0x04) {
		if (raw[2] === 0x30) {
			crypt_data = {};
			sec_start = 4;
			engine_id_length_pos = sec_start + 1;
			engine_id_length = raw[engine_id_length_pos];
			engine_boot_length_pos = engine_id_length_pos + engine_id_length + 2;
			engine_boot_length = raw[engine_boot_length_pos];
			engine_time_length_pos = engine_boot_length_pos + engine_boot_length + 2;
			engine_time_length = raw[engine_time_length_pos];
			user_name_length_pos = engine_time_length_pos + engine_time_length + 2;
			user_name_length = raw[user_name_length_pos];
			user_name = raw.slice(user_name_length_pos + 1, (user_name_length_pos + user_name_length) + 1 || 9e9);
			
			var key, x, _i, _len, _ref;
			_ref = this._users;
			for (_i = 0, _len = _ref.length; _i < _len; _i++) {
				x = _ref[_i];
				if (x.name === user_name.toString()) {
					crypt_data.key = x.privacy_key;
				}
			}
			
			auth_params_length_pos = user_name_length_pos + user_name_length + 2;
			auth_params_length = raw[auth_params_length_pos];
			privacy_params_length_pos = auth_params_length_pos + auth_params_length + 2;
			privacy_params_length = raw[privacy_params_length_pos];
			if (privacy_params_length !== 8) {
				return {};
			}
			crypt_data.privacy_params = raw.slice(privacy_params_length_pos + 1, (privacy_params_length_pos + privacy_params_length) + 1 || 9e9);
			return crypt_data;
		}
	}
	return {};
};

Agent.prototype._decrypt = function _decrypt(data, key, salt) { 
	var buf, decipher, des_key, iv, pre_iv, x, _i;
	des_key = key.slice(0, 8);
	pre_iv = key.slice(8);
	iv = new Buffer(8).clear();
	for (x = _i = 0; _i <= 7; x = ++_i) {
		iv[x] = pre_iv[x] ^ salt[x];
	}
	decipher = crypto.createDecipheriv("des-cbc", des_key.toString("binary"), iv.toString("binary"));
	buf = decipher.update(data);
	buf += decipher.final();
	return new Buffer(buf, "binary");
};

Agent.prototype._encrypt = function _encrypt(data, key, salt) { 
	var buf, cipher, des_key, iv, pre_iv, x, _i;
	des_key = key.slice(0, 8);
	pre_iv = key.slice(8);
	iv = new Buffer(8).clear();
	for (x = _i = 0; _i <= 7; x = ++_i) {
		iv[x] = pre_iv[x] ^ salt[x];
	}
	cipher = crypto.createCipheriv("des-cbc", des_key.toString("binary"), iv.toString("binary"));
	buf = cipher.update(data);
	buf += cipher.final();
	return new Buffer(buf, "binary");
};


Agent.prototype._recv = function _recv(raw, src) {
	//console.log("Agent._recv , raw = " ,raw , "src = " , src);
	var req;
	var is_encrypted = false;
	var action = 'none';
	try {
		this._process_action = this._is_v3_process(raw.buf);
		if (this._process_action.error_action === 'wait_decrypted') {
			is_encrypted = true;
			req = message.parseMessage({ raw: {buf:this._process_action.decrypted_buf}, src: src });
			//console.log("parseMessage : req = " ,req);
		}
		else if (this._process_action.error_action === 'authentication_failure') {
			req = message.parseMessage({ raw: {buf:this._process_action.keep_buf}, src: src });
			//console.log("parseMessage : req = " ,req);
		}
		else{
			req = message.parseMessage({ raw: raw, src: src });
		}
	} catch (err) {
		/* XXX in some cases we can reply with an error */
		console.log("XXX in some cases we can reply with an error , err = ", err ); 
		console.log("catch , process_action = ",this._process_action);
		if (this._process_action.error_action !== 'wait_decrypted'){
			this.malformed_messages++;
			this._log.debug({
				err: err,
				raw: raw,
				origin: src }, 'Invalid SNMP message');
			return;
		}
		else{
			this._process_action.error_action = 'decrypt_failure';
			req = message.parseMessage({ raw: {buf:this._process_action.keep_buf}, src: src });
		}
	}

	this._log.trace({ raw: raw, origin: src, snmpmsg: req },
			'Received SNMP message');
	console.log("_recv process_action = ",this._process_action);
	this._process_req(req,this._process_action.error_action);
};

Agent.prototype.update_info = function update_info(engine_id,context_name,uptime) {
	this._engine_id = engine_id; 
	this._context_name = context_name;
	this._uptime = uptime;
	if(uptime >= 2147483647){
		this._EngineBoots++;
	}
};

Agent.prototype._user_match = function _user_match(name,level) {
	var x, _i, _len, _ref;
	_ref = this._users;
	for (_i = 0, _len = _ref.length; _i < _len; _i++) {
		x = _ref[_i];
		if (x.name === name) {
			if (typeof level !== "undefined" && level !== null) {
				if (x.security_level === level){
					return true;
				}
				else{
					return false;
				}
			}
			else{
				return true;
			}
		}
	}
	return false;
};

Agent.prototype.access_users = function(action, name, security_level, authentication_protocol, authentication_password, privacy_protocol, privacy_password,snmp_engine_id) {
	var self, x , AuthMD5_password_to_key;
	console.log("access_users = ", action, name, security_level, authentication_protocol, authentication_password, privacy_protocol, privacy_password);
	self = this;
	
	authMD5_password_to_key = function(pwd, engine_id) {
		//console.log("authMD5_password_to_key : pwd =" , pwd , "engine_id = " , engine_id);
		var count, key, md5_sum, offset, password, password_buf, password_index, x, _i;
		md5_sum = crypto.createHash("md5");
		password = new Buffer(pwd);
		count = 0;
		password_index = 0;
		offset = 0;
		password_buf = new Buffer(65);
		while (count < 1048576) {
			for (x = _i = 0; _i <= 63; x = ++_i) {
				password_buf[x] = password[(password_index++) % password.length];
			}
			md5_sum.update(password_buf.slice(0, 64));
			count += 64;
		}
		
		key = new Buffer(md5_sum.digest("hex"), "hex");
		//console.log("part1 , key = ", key);
		offset += key.copy(password_buf, offset);
		offset += engine_id.copy(password_buf, offset);
		offset += key.copy(password_buf, offset);
		key = new Buffer(crypto.createHash("md5").update(password_buf.slice(0, (offset - 1) + 1 || 9e9)).digest("hex"), "hex");
		//console.log("part2 , key = ", key);
		return key;
	};
	
	if (action === 'join' && !this._user_match(name)) {
		tmp = {
			name: name,
			security_level: security_level,
			authentication_protocol: authentication_protocol,
			authentication_password: authentication_password,
			privacy_protocol: privacy_protocol,
			privacy_password: privacy_password
		};
		if (tmp.security_level === 'noauth_nopriv'){
			tmp.authentication_key = null
		}
		else if (tmp.security_level === 'auth_nopriv'){
			tmp.authentication_key = authMD5_password_to_key(tmp.authentication_password, snmp_engine_id);
		}
		else if (tmp.security_level === 'auth_priv'){
			tmp.authentication_key = authMD5_password_to_key(tmp.authentication_password, snmp_engine_id);
			tmp.privacy_key = authMD5_password_to_key(tmp.privacy_password, snmp_engine_id);
		}
		return this._users.push(tmp);
	} else if (action === 'leave' && this._user_match(name)) {
		return this._users = (function() {
			var _i, _len, _ref, _results;
			_ref = this._users;
			_results = [];
			for (_i = 0, _len = _ref.length; _i < _len; _i++) {
				x = _ref[_i];
				if (x.name !== name) {
					_results.push(x);
				}
			}
			return _results;
		}).call(this);
	}
};

Agent.prototype.access_community = function access_community(action , community,readonly) {
		console.log("Agent.access_community , action = " ,action , "community = ",community ,"readonly= ",readonly);
		var community_match, x;
		var self = this;
		community_match = function(remote_community) {
			//console.log("this._community = " , self._community);
			//console.log("remote_community = " , remote_community);
			var x, _i, _len, _ref;
			_ref = self._community;
			for (_i = 0, _len = _ref.length; _i < _len; _i++) {
				x = _ref[_i];
				if (x.community === remote_community) {
					return true;
				}
			}
			return false;
		};
		
		if ((action === 'join') && (!community_match(community))) {
			//console.log("join1");
			self._community.push({
				community: community,
				readonly: readonly
			});
		} else if ((action === 'leave') && (community_match(community))) {
			self._community = (function() {
				var _i, _len, _ref, _results;
				_ref = self._community;
				_results = [];
				for (_i = 0, _len = _ref.length; _i < _len; _i++) {
					x = _ref[_i];
					if (x.community !== community) {
						_results.push(x);
					}
				}
				return _results;
			}).call(self);
		} 
}

Agent.prototype.bind = function bind(arg) {
	console.log("Agent.bind , arg = " ,arg);
	var self = this;
	var conn;
	this._community = [];
	this._users = [];
	this._EngineBoots = 1;
	this._salt_random = 0;
	this._process_action = {};
	if (typeof (arg) !== 'object')
		throw new TypeError('arg (object) is required');
	if (typeof (arg.family) !== 'string')
		throw new TypeError('arg.family (string) is required');
	if (typeof (arg.port) !== 'number')
		throw new TypeError('arg.port (number) is required');
	if (typeof (arg.addr) !== 'undefined' &&
			typeof (arg.addr) !== 'string')
		throw new TypeError('arg.addr must be a string');

	conn = dgram.createSocket(arg.family);
	conn.on('message', function _recv_binder(msg, rinfo) {
		//console.log("Agent.bind._recv_binder , msg = " ,msg,"rinfo=",rinfo);
		var raw = {
			buf: msg,
			len: rinfo.size
		};
		var src = {
			family: arg.family,
			address: rinfo.address,
			port: rinfo.port
		};
		self._recv(raw, src);
	});
	this._connections.push(conn);

	conn.bind(arg.port, arg.addr);
	this._log.info('Bound to ' + conn.address().address + ':' +
			conn.address().port);
};

Agent.prototype.request = function request(oid, handler, columns) {
	//console.log("Agent.request , oid = " ,oid,"handler=", handler, "columns=",columns);
	var prov;

	if (typeof (oid) === 'string') {
		if (typeof (handler) !== 'function')
			throw new TypeError('handler must be a function');

		this.addProviders({
			oid: oid,
			handler: handler,
			columns: columns
		});

		return;
	}

	prov = oid;
	if (typeof (prov) === 'object') {
		this.addProviders(prov);
		return;
	}

	throw new TypeError('MIB provider must be specified');
};

Agent.prototype.close = function close() {
	console.log("Agent.close");
	this._connections.forEach(function (c) {
		this._log.info('Shutting down endpoint ' + c.address().address +
				':' + c.address().port);
		c.close();
	});
};

module.exports = Agent;
