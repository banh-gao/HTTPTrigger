var pcap = require("pcap");
var HTTPTrace = require("http_trace");
var EventEmitter = require("events").EventEmitter;
var inherits = require("util").inherits;

function HTTPTrigger(matchers,netIf,port) {
	this.matchers = matchers;
	netIf = netIf || "";
	filterRule = "tcp port " + (port || 80);
	tcp_tracker = new pcap.TCPTracker();

	//Start packet capturing
	pcap.createSession(netIf, filterRule).on("packet", function(raw_packet) {
	  packet = pcap.decode.packet(raw_packet);
	  tcp_tracker.track_packet(packet);
	});

	self = this;

	tcp_tracker.on("session", function (tcp_session) {
		http_trace = new HTTPTrace(tcp_session);
		http_trace.on("http request", function (http_session) {
			headers = http_session.request.headers;
			if(self.pattern_matches(headers))
				self.emit("match", http_session.tcp_session.src, headers);
		});
	});

	EventEmitter.call(this);
}
inherits(HTTPTrigger, EventEmitter);

HTTPTrigger.prototype.pattern_matches = function (headers) {
	return 	Object.keys(headers).every(function(el, i, arr) {
		return this.check_header(el,headers[el]);
	}, this);
}

HTTPTrigger.prototype.check_header = function (name, value) {
	pattern = this.matchers[name];

	if(!pattern)
		return true;

	return value.match(pattern);
}

module.exports = HTTPTrigger;
