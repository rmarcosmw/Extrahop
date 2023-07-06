//HTTP_RESPONSE
if (event == 'HTTP_RESPONSE') {
	var date = new Date();
	var payloadHTTP = {
		'ts' : date.toISOString(),
		'eh_event' : 'http',
		'src_port' : Flow.client.port,
		'src_ip' : Flow.client.ipaddr.toString(),
		'dest_port' : Flow.server.port,
		'dest_ip' : Flow.server.ipaddr.toString(),
		'uri' : HTTP.uri,
		'query' : HTTP.query,
		'userAgent' : HTTP.userAgent,
		'clt_zero_Wind' : HTTP.reqZeroWnd,
		'svr_zero_Wind' : HTTP.rspZeroWnd,
		'content_type' : HTTP.contentType,
		'host' : HTTP.host,
		'pipelined' : HTTP.isPipelined,
		'isReqAborted' : HTTP.isReqAborted,
		'isDesync' : HTTP.isDesync,
		'isEncrypted' : HTTP.isEncrypted,
		'isServerPush' : HTTP.isServerPush,
		'isSQLi' : HTTP.isSQLi,
		'isXSS' : HTTP.isXSS,
		'method' : HTTP.method,
		'path' : HTTP.path,
		'referer' : HTTP.referer,
		'reqSize' : HTTP.reqSize,
		'rspSize' : HTTP.rspSize,
		'reqTimeToLastByte' : HTTP.reqTimeToLastByte,
		'sqli' : HTTP.sqli,
		'streamId' : HTTP.streamId,
		'thinkTime' : HTTP.thinkTime,
		'title' : HTTP.title,
		'age' : HTTP.age,
		'cookies' : HTTP.cookies,
		'headers' : HTTP.headers,
		'headersRaw' : HTTP.headersRaw,
		'reqBytes' : HTTP.reqBytes,
		'rspBytes' : HTTP.rspBytes};

var obj = {
		'path' : '/extrahop/http',
		'headers' : {},
		'payload' : JSON.stringify(payloadHTTP)};
Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}

//EVENT DNS
if (event == "DNS_RESPONSE") {
	var date = new Date();
	var payloadDNS = {
		'ts' : date.toISOString(),
		'eh_event' : 'dns',
		'src_ip' : Flow.client.ipaddr.toString(),
		'dest_ip' : Flow.server.ipaddr.toString(),
		'qname' : DNS.qname,
		'qtype' : DNS.qtype,
		'opcode' : DNS.opcode,
		'tprocess' : DNS.processingTime,
		'isAuthenticData' : DNS.isAuthenticData,
		'isAuthoritative' : DNS.isAuthoritative,
		'isRspTruncated' : DNS.isRspTruncated,
		'txId' : DNS.txId,
		'reqZeroWnd' : DNS.reqZeroWnd,
		'rspBytes' : DNS.rspBytes,
		'rspL2Bytes' : DNS.rspL2Bytes,
		'rspPkts' : DNS.rspPkts,
		'rspZeroWnd' : DNS.rspZeroWnd
		};

var answer = DNS.answers[0];
if (answer !== undefined) {
	payloadDNS.ans_name = answer.name;
	payloadDNS.ans_ttl = answer.ttl;
	payloadDNS.ans_type = answer.type;
	if (answer.data !== null) {
		payloadDNS.ans_data = answer.data;
	}
}
if (DNS.error !== null) {
payloadDNS.error = DNS.error;
}
var obj = {
'path' : '/extrahop/dns',
'headers' : {},
'payload' : JSON.stringify(payloadDNS)};

Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}

// Event: DB_REQUEST, DB_RESPONSE
// Set to true for full SQL statements
var SHOW_FULL_STATEMENT = true;
if (event == 'DB_REQUEST' && SHOW_FULL_STATEMENT) {
	Flow.store.db_statement = DB.statement || DB.procedure;
} 
else if (event == 'DB_RESPONSE') {
var date = new Date();
var payloadDB = {
	'ts' : date.toISOString(),
	'eh_event' : 'database',
	'appName' : DB.appName,
	'method' : DB.method,
	'user' : DB.user,
	'database' :DB.database,
	'errors' : DB.errors,
	'isReqAborted' : DB.isReqAborted,
	'isRspAborted' : DB.isRspAborted,
	'params' : DB.params,
	'record' : DB.record,
	'reqBytes' : DB.reqBytes,
	'reqPkts' : DB.reqPkts,
	'req_L2bytes' : DB.reqL2Bytes,
	'rsp_L2bytes' : DB.rspL2Bytes,
	'reqSize' : DB.reqSize,
	'reqTimeToLastByte' : DB.reqTimeToLastByte,
	'reqZeroWnd' : DB.reqZeroWnd,
	'rspBytes' : DB.rspBytes,
	'rspPkts' : DB.rspPkts,
	'rspRTO' : DB.rspRTO,
	'rspSize' : DB.rspSize,
	'rspTimeToFirstByte' : DB.rspTimeToFirstByte,
	'rspTimeToLastByte' : DB.rspTimeToLastByte,
	'rspZeroWnd' : DB.rspZeroWnd,
	'serverVersion' : DB.serverVersion,
	'table' : DB.table	
	};

if (Flow.store.db_statement !== null && SHOW_FULL_STATEMENT) {
	payloadDB.query = Flow.store.db_statement;
	Flow.store.db_statement = null;
}
if (DB.error != null) {
	payloadDB.error = DB.error;
} 
if (DB.processingTime) {
	payloadDB.tprocess = DB.processingTime;
}

var obj = {
	'path' : '/extrahop/database',
	'headers' : {},
	'payload' : JSON.stringify(payloadDB)};

Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}

// Event: CIFS_RESPONSE
if (event == "CIFS_RESPONSE") {
var date = new Date();
var payloadCIFS = {
	"ts" : date.toISOString(),
	"eh_event" : "cifs",
	"method" : CIFS.method,
	"user" : CIFS.user,
	"access_time" : CIFS.accessTime,
	"dialect" : CIFS.dialect,
	"encryptedBytes" : CIFS.encryptedBytes,
	"isCommandCreate" : CIFS.isCommandCreate,
	"isCommandDelete" : CIFS.isCommandDelete,
	"isCommandFileInfo" : CIFS.isCommandFileInfo,
	"isCommandLock" : CIFS.isCommandLock,
	"isCommandRead" : CIFS.isCommandRead,
	"isCommandRename" : CIFS.isCommandRename,
	"isCommandWrite" : CIFS.isCommandWrite,
	"msgId" : CIFS.msgId,
	"payloadOffset" : CIFS.payloadOffset,
	"processingTime" : CIFS.processingTime,
	"req_L2bytes" : CIFS.reqL2Bytes,
	"rsp_L2bytes" : CIFS.rspL2Bytes,
	"reqPkts" : CIFS.reqPkts,
	"rspPkts" : CIFS.rspPkts,
	"reqRTO" : CIFS.reqRTO,
	"reqSize" : CIFS.reqSize,
	"reqTransferTime" : CIFS.reqTransferTime,
	"reqVersion" : CIFS.reqVersion,
	"reqZeroWnd" : CIFS.reqZeroWnd,
	"share" : CIFS.share,
	"statusCode" : CIFS.statusCode,
	"roundTripTime" : CIFS.roundTripTime,
	"rspBytes" : CIFS.rspBytes,
	"rspRTO" : CIFS.rspRTO,
	"rspSize" : CIFS.rspSize,
	"rspTransferTime" : CIFS.rspTransferTime,
	"rspVersion" : CIFS.rspVersion,
	"rspZeroWnd" : CIFS.rspZeroWnd,
	"isRspAborted" : CIFS.isRspAborted,
	"warning" : CIFS.warning,
	};
if (CIFS.resource != null) {
	payloadCIFS.filename = CIFS.resource;
}
if (CIFS.error != null) {
	payloadCIFS.error= CIFS.error;
} 
var obj = {
	'path' : '/extrahop/storage',
	'headers' : {},
	'payload' : JSON.stringify(payloadCIFS)};
Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}

//event  SSL_OPEN
if (event == "SSL_OPEN") {
var date = new Date();
var payloadSSL = {
	'ts' : date.toISOString(),
	'eh_event' : 'SSL',
	'src_ip' : Flow.client.ipaddr,
	'src_port' : Flow.client.port,
	'dest_ip' : Flow.server.ipaddr,
	'dest_port' : Flow.server.port,
	'certificate' : SSL.certificate,
	'certificates' : SSL.certificates,
	'cipherSuite' : SSL.cipherSuite,
	'cipherSuiteType' : SSL.cipherSuiteType,
	'cipherSuitesSupported' : SSL.cipherSuitesSupported,
	'clientCertificate' : SSL.clientCertificate,
	'clientCertificateRequested' : SSL.clientCertificateRequested,
	'clientCertificates' : SSL.clientCertificates,
	'clientExtensions' : SSL.clientExtensions,
	'clientHelloVersion' : SSL.clientHelloVersion,
	'clientSessionId' : SSL.clientSessionId,
	'getClientExtensionData' : SSL.getClientExtensionData,
	'getServerExtensionData' : SSL.getServerExtensionData,
	'host' : SSL.host,
	'handshakeTime' : SSL.handshakeTime,
	'isCompressed' : SSL.isCompressed,
	'isResumed' : SSL.isResumed,
	'isStartTLS' : SSL.isStartTLS,
	'isV2ClientHello' : SSL.isV2ClientHello,
	'isWeakCipherSuite' : SSL.isWeakCipherSuite,
	'ja3Hash' : SSL.ja3Hash,
	'ja3Text' : SSL.ja3Text,
	'ja3sHash' : SSL.ja3sHash,
	'ja3sText' : SSL.ja3sText,
	'privateKeyId' : SSL.privateKeyId,
	'record' : SSL.record,
	'serverExtensions' : SSL.serverExtensions,
	'serverHelloVersion' : SSL.serverHelloVersion,
	'serverSessionId' : SSL.serverSessionId,
	'startTLSProtocol' : SSL.startTLSProtocol,
	'version' : SSL.version
};
var obj = {
	'path' : '/extrahop/ssl',
	'headers' : {},
	'payload' : JSON.stringify(payloadSSL)};

Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}

//event ICMP
if (event == "ICMP_MESSAGE") {
var date = new Date();
var payloadICMP = {
	'ts' : date.toISOString(),
	'src_ip' : Flow.sender.ipaddr,
	'src_port' : Flow.sender.port,
	'dest_ip' : Flow.receiver.ipaddr,
	'dest_port' : Flow.receiver.port,
	'gwAddr' : ICMP.gwAddr,
	'version' : ICMP.version,
	'msgId' : ICMP.msgId,
	'msgCode' : ICMP.msgCode,
	'msgType' : ICMP.msgType,
	'msg' : ICMP.msg,
	'msgText' : ICMP.msgText,
	'nextHopMTU' : ICMP.nextHopMTU,
	'original' : ICMP.original,
	'isQuery' : ICMP.isQuery,
	'isError' : ICMP.isError,
	'isReply' : ICMP.isReply
};
var obj = {
	'path' : '/extrahop/icmp',
	'headers' : {},
	'payload' : JSON.stringify(payloadICMP)};

Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}

//event FLOW
if (event != "HTTP_RESPONSE" || 'DB_RESPONSE' || 'DNS_RESPONSE' || 'ICMP_MESSAGE' || 'SSL_OPEN' || 'CIFS_RESPONSE') {
if (event == "FLOW_TICK") {
var date = new Date();
var payloadFLOW = {
	'ts' : date.toISOString(),
	'client' : Flow.client.ipaddr,
	'client_port' : Flow.client.port,
	'server' : Flow.server.ipaddr,
	'server_port' : Flow.server.port,
	'store' : Flow.store,
	'dscpName1' : Flow.dscpName1,
	'bytes1' : Flow.bytes1,
	'customDevices1' : Flow.customDevices1,
	'device1' : Flow.device1,
	'dscp1' : Flow.dscp1,
	'dscpBytes1' : Flow.dscpBytes1,
	'dscpPkts1' : Flow.dscpPkts1,
	'l2Bytes1' : Flow.l2Bytes1,
	'totalL2Bytes1' : Flow.totalL2Bytes1,
	'fragPkts2' : Flow.fragPkts2,
	'id' : Flow.id,
	'ipaddr1' : Flow.ipaddr1,
	'nagleDelay2' : Flow.nagleDelay2,
	'dscpName2' : Flow.dscpName2,
	'dscpBytes2' : Flow.dscpBytes2,
	'bytes2' : Flow.bytes2,
	'customDevices2' : Flow.customDevices2,
	'device2' : Flow.device2,
	'dscp2' : Flow.dscp2,
	'dscpPkts2' : Flow.dscpPkts2,
	//'fragPkts2' : Flow.fragPkts2,
	'ipaddr2' : Flow.ipaddr2,
	'l2Bytes2' : Flow.l2Bytes2,
	'totalL2Bytes2' : Flow.totalL2Bytes2,
	//'nagleDelay2' : Flow.nagleDelay2,
	'ipproto' : Flow.ipproto,
	'ipver' : Flow.ipver,
	'isAborted' : Flow.isAborted,
	//'isClientAborted' : Flow.isClientAborted,
	'isExpired' : Flow.isExpired,
	//'isServerAborted' : Flow.isServerAborted,
	'l7proto' : Flow.l7proto,
	'roundTripTime' : Flow.roundTripTime,
	'vlan' : Flow.vlan,
	'rcvWndThrottle1' : Flow.rcvWndThrottle1,
	'rcvWndThrottle2' : Flow.rcvWndThrottle2,
};
var obj = {
	'path' : '/extrahop/FLOW',
	'headers' : {},
	'payload' : JSON.stringify(payloadFLOW)};

Remote.Syslog("ELK-Record").notice(JSON.stringify(obj));
}
}