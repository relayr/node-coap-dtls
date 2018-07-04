/*
 * Copyright (c) 2013-2015 node-coap contributors.
 *
 * node-coap is licensed under an MIT +no-false-attribs license.
 * All rights not explicitly granted in the MIT license are reserved.
 * See the included LICENSE file for more details.
 */

require('./polyfill')

var dgram = require('dgram'),
  net = require('net'),
  util = require('util'),
  dtls = require('@gpolakow/node-mbed-dtls'),
  series = require('fastseries'),
  crypto = require('crypto'),
  events = require('events'),
  LRU = require('lru-cache'),
  parse = require('coap-packet').parse,
  generate = require('coap-packet').generate,
  IncomingMessage = require('./incoming_message'),
  OutgoingMessage = require('./outgoing_message'),
  ObserveStream = require('./observe_write_stream'),
  parameters = require('./parameters'),
  RetrySend = require('./retry_send'),
  parseBlock2 = require('./helpers').parseBlock2,
  createBlock2 = require('./helpers').createBlock2,
  getOption = require('./helpers').getOption,
  isNumeric = require('./helpers').isNumeric,
  isBoolean = require('./helpers').isBoolean,
  middlewares = require('./middlewares'),
  debug = require('debug')('CoAP Server')


function handleEnding(err) {
  var request = this
  if (err) {
    request.server._sendError(new Buffer(err.message), request.rsinfo, request.packet)
  }
}

function CoAPServer(options, listener) {
  if (!(this instanceof CoAPServer)) {
    return new CoAPServer(options, listener)
  }

  if (typeof options === 'function') {
    listener = options
    options = null
  }

  if (!options)
    options = {}

  this._options = options
  this._proxiedRequests = {}

  this._middlewares = [
    middlewares.parseRequest
  ]

  if (options.proxy) {
    this._middlewares.push(middlewares.proxyRequest)
    this._middlewares.push(middlewares.handleProxyResponse)
  }

  if (!this._options.piggybackReplyMs || !isNumeric(this._options.piggybackReplyMs)) {
    this._options.piggybackReplyMs = parameters.piggybackReplyMs
  }

  if (!isBoolean(this._options.sendAcksForNonConfirmablePackets)) {
    this._options.sendAcksForNonConfirmablePackets = parameters.sendAcksForNonConfirmablePackets
  }
  this._middlewares.push(middlewares.handleServerRequest)

  // Multicast settings
  this._multicastAddress = options.multicastAddress ? options.multicastAddress : null
  this._multicastInterface = options.multicastInterface ? options.multicastInterface : null

  // We use an LRU cache for the responses to avoid
  // DDOS problems.
  // max packet size is 1280
  // 32 MB / 1280 = 26214
  // The max lifetime is roughly 200s per packet.
  // Which gave us 131 packets/second guarantee
  this._lru = LRU({
    max: options.cacheSize || (32768 * 1024),
    length: function(n) {
      return n.length
    },
    maxAge: parameters.exchangeLifetime,
    dispose: function(key, value) {
      if (value.sender)
        value.sender.reset()
    }
  })

  this._series = series()
  this._block2Cache = {}

  if (listener)
    this.on('request', listener)
  debug('initialized');
}


util.inherits(CoAPServer, events.EventEmitter)

CoAPServer.prototype._sendError = function(payload, rsinfo, packet) {
  var message = generate({
    code: '5.00',
    payload: payload,
    messageId: (packet) ? packet.messageId : undefined,
    token: (packet) ? packet.token : undefined
  })

  if (this._sock) {
    this._sock.send(message, 0, message.length, rsinfo.port)
  }
}

function removeProxyOptions(packet) {
  var cleanOptions = []

  for (var i = 0; i < packet.options.length; i++) {
    if (packet.options[i].name.toLowerCase() !== 'proxy-uri' && packet.options[i].name.toLowerCase() !== 'proxy-scheme') {
      cleanOptions.push(packet.options[i])
    }
  }

  packet.options = cleanOptions

  return packet;
}

CoAPServer.prototype._sendProxied = function(packet, proxyUri, callback) {
  var url = require('url').parse(proxyUri),
    host = url.hostname,
    port = url.port,
    message = generate(removeProxyOptions(packet))

  if (this._sock) {
    this._sock.send(message, 0, message.length, port, host, callback)
  }
}

CoAPServer.prototype._sendReverseProxied = function(packet, rsinfo, callback) {
  var host = rsinfo.address,
    port = rsinfo.port,
    message = generate(packet)

  if (this._sock) {
    this._sock.send(message, 0, message.length, port, host, callback)
  }
}

function handleRequest(server) {
  return function(msg, rsinfo) {
    var request = {
        raw: msg,
        rsinfo: rsinfo,
        server: server
      },
      activeMiddlewares = []

    for (var i = 0; i < server._middlewares.length; i++) {
      activeMiddlewares.push(server._middlewares[i])
    }

    server._series(request, activeMiddlewares, request, handleEnding)
  }
}

CoAPServer.prototype.listen = function(done) {
  var that = this

  if (this._options.port == undefined) {
    this._port = (this._options.dtls) ? parameters.coapSecPort : parameters.coapPort
  }
  else {
    this._port = this._options.port;
  }

  if (this._options.address == undefined) {
    this._address = '0.0.0.0';
  }
  else {
    this._address = this._options._address;
  }

  if (this._options.dtls) {
    this._options.dtls.port = this._port;
    this._options.dtls.host = this._address;
  }

  if (this._sock) {
    if (done)
      done(new Error('Already listening'))
    else
      throw new Error('Already listening')

    return this
  }

  if (this._address && net.isIPv6(this._address)) {
    this._options.type = 'udp6'
  }
  if (!this._options.type) {
    this._options.type = 'udp4'
  }

  // There are two independent workflows when DTLS is factored in. If DTLS, then we don't use
  //   the same listener.
  if (this._options.dtls) {
    // Now we get DTLS involved...
    this._options.dtls.port = this._port;
    this._options.dtls.host = this._address;
    console.log(JSON.stringify(this._options.dtls));
    this._dtls_server = dtls.createServer(this._options.dtls, socket => {
      console.log(`secure connection from ${socket.remoteAddress}:${socket.remotePort}`);
      console.log("...on socket:\n"+util.inspect(socket, {depth: 0}));
      //console.log("...on socket:\n"+JSON.stringify(socket));

      socket.on('data', msg => {
        console.log('received:', msg.toString('utf8'));
        //var request = {
        //  raw:    msg,
        //  rsinfo: {address: socket.remoteAddress, port: socket.remotePort},
        //  server: that
        //};
        var packet  = parse(msg);
        this._handle(packet, {address: socket.remoteAddress, port: socket.remotePort}, socket)
        //var request = {
          //raw:         msg,
          //rsinfo:      0,
          //server:      that
        //};
        //var activeMiddlewares = [];

        //for (var i = 0; i < that._middlewares.length; i++) {
          //activeMiddlewares.push(that._middlewares[i])
        //}

        //that._series(request, activeMiddlewares, request, handleEnding)
      });
      socket.once('error', (err) => {
        console.error(`socket error on ${socket.remoteAddress}:${socket.remotePort}: ${err}`);
      });
      socket.once('close', () => {
        console.log(`closing socket from ${socket.remoteAddress}:${socket.remotePort}`);
      });
    });

    this._sock = null // We don't have this yet. We get one on connection callback.
    this._dtls_server.on('listening', () => {
      const addr = that._dtls_server.address();
      console.log(`dtls listening on ${addr.address}:${addr.port}`);
    });
    this._dtls_server.on('clientError', err => {
      console.error(`clientError: ${err}`);
    });
    this._dtls_server.on('error', err => {
      console.error(`server error: ${err}`);
    });
    this._dtls_server.on('newSession', (sessionId, sessionData, callback) => {
      console.log('*** new session callback ***', sessionId);
      process.nextTick(() => {  callback(); });
    });
    this._dtls_server.on('resumeSession', (sessionId, callback) => {
      console.log('*** resume session callback ***', sessionId);
      process.nextTick(() => {  callback(null, null); });
    });

    this._dtls_server.listen(this._port);
  }
  else {
    // Non- DTLS workflow...
    if (process.version.indexOf('v0.10') === -1) {
      this._sock = dgram.createSocket({
        type: this._options.type,
        reuseAddr: true
      }, handleRequest(this))
    }
    else {
      this._sock = dgram.createSocket(this._options.type, handleRequest(this))
    }

    this._sock.on('error', function(error) {
      that.emit('error', error)
    })

    this._sock.bind(this._port, this._address || null, function() {
      if (that._multicastAddress) {
        that._sock.setMulticastLoopback(true)

        if (that._multicastInterface) {
          that._sock.addMembership(that._multicastAddress, that._multicastInterface)
        } else {
          that._sock.addMembership(that._multicastAddress)
        }
      }
      if (done) done()
    })
    console.log("Created non-secure server.\n");
  }
  return this
}

CoAPServer.prototype.close = function(done) {
  if (done) {
    setImmediate(done)
  }

  if (this._dtls_server) {
    // If we don't have a listening socket because we are using DTLS...
    this._dtls_server.close(() => {
      this._dtls_server = null;
      this._sock        = null;
      this.emit('close')
    });
  }
  else if (this._sock) {
    this._sock.close()
    this._sock = null
    this.emit('close')
  }

  this._lru.reset()

  // cancel cache entry expiry timers
  for (var k in this._block2Cache) {
    if (this._block2Cache.hasOwnProperty(k)) {
      debug('clean-up cache expiry timer, key:', k)
      clearTimeout(this._block2Cache[k].timeoutId)
      delete this._block2Cache[k]
    }
  }

  return this
}

function expiry(block2cache, k) {
  debug('delete expired cache entry, key:', k)
  delete block2cache[k]
}

CoAPServer.prototype._handle = function(packet, rsinfo, sock_pass_in) {
  var sock = (sock_pass_in ? sock_pass_in : this._sock),
    lru = this._lru,
    acks = this._acks,
    cached = lru.peek(toKey(rsinfo.address, rsinfo.port, packet, true)),
    Message = OutMessage,
    that = this,
    request, response

  if (cached && !packet.ack && !packet.reset) {
    return sock.send(cached, 0, cached.length, rsinfo.port, rsinfo.address)
  }
  else if (cached && (packet.ack || packet.reset)) {
    if (cached.response && packet.reset) {
      cached.response.end()
    }
    return lru.del(toKey(rsinfo.address, rsinfo.port, packet, false))
  }
  else if (packet.ack || packet.reset) {
    return // nothing to do, ignoring silently
  }

  request = new IncomingMessage(packet, rsinfo)

  if (request.headers['Observe'] === 0) {
    Message = ObserveStream
    if (packet.code !== '0.01')
    // it is not a GET
      return this._sendError(new Buffer('Observe can only be present with a GET'), rsinfo)
  }

  packet.piggybackReplyMs = this._options.piggybackReplyMs;
  response = new Message(packet, function(response, packet) {
    var buf, sender = new RetrySend(sock, rsinfo.port, rsinfo.address)

    try {
      buf = generate(packet)
    } catch (err) {
      return response.emit('error', err)
    }

    if (Message === OutMessage) {
      sender.on('error', response.emit.bind(response, 'error'))
    } else {
      buf.response = response
      sender.on('error', function() {
        response.end()
      })
    }

    lru.set(toKey(rsinfo.address, rsinfo.port,
      packet, packet.ack || !packet.confirmable), buf)
    buf.sender = sender

    if (that._options.sendAcksForNonConfirmablePackets || packet.confirmable) {
      sender.send(buf, packet.ack || packet.reset || packet.confirmable === false)
    } else {
      debug('OMIT ACK PACKAGE')
    }
  })

  request.rsinfo = rsinfo
  response.statusCode = '2.05'
  response._request = request._packet
  response._cachekey = toCacheKey(rsinfo.address, rsinfo.port, packet)

  var block2cache = this._block2Cache
    //inject this function so the response can add an entry to the cache
  response._addCacheEntry = function(key, payload) {
    if (block2cache.hasOwnProperty(key)) {
      debug('reuse old cache entry, key:', key)
      clearTimeout(block2cache[key].timeoutId) // cancel old expiry timer
      block2cache[key].payload = payload
    } else {
      debug('add payload to cache, key:', key)
      block2cache[key] = {
        payload: payload
      }
    }
    // setup new expiry timer
    block2cache[key].timeoutId = setTimeout(expiry, parameters.exchangeLifetime * 1000, block2cache, key)
  }

  //return cached value for blockwise requests
  var cachedResponseSend = false
  if (packet.token && packet.token.length > 0) {
    // return cached value only if this request is not the first block request
    var block2Buff = getOption(response._request.options, 'Block2')
    var requestedBlockOption
    if (block2Buff) {
      requestedBlockOption = parseBlock2(block2Buff)
    }
    if (!requestedBlockOption) {
      requestedBlockOption = {
        num: 0
      }
    }

    if (requestedBlockOption.num < 1) {
      if (this._block2Cache.hasOwnProperty(response._cachekey)) {
        debug('first block2 request, remove old entry from cache, key:', response._cachekey)
        clearTimeout(this._block2Cache[response._cachekey].timeoutId)
        delete this._block2Cache[response._cachekey]
      }
    } else {
      debug('check if packet token is in cache, key:', response._cachekey)
      if (this._block2Cache.hasOwnProperty(response._cachekey)) {
        debug('found cached payload, key:', response._cachekey)
        response.end(this._block2Cache[response._cachekey].payload)
        cachedResponseSend = true
      }
    }
  }

  if (!cachedResponseSend) {
    debug('no cached entry found, emit request to upper layer');
    this.emit('request', request, response)
  }
}

function toCacheKey(address, port, packet) {
  if (packet.token && packet.token.length > 0) {
    return packet.token.toString('hex') + '/' + address + ':' + port
  }

  return null
}

function toKey(address, port, packet, appendToken) {
  var result = address + port + packet.messageId

  if (appendToken & packet.token) {
    result += packet.token.toString('hex');
  }

  return result
}

/*
new out message
inherit from OutgoingMessage
to handle cached answer and blockwise (2)
*/
function OutMessage() {
  OutgoingMessage.apply(this, Array.prototype.slice.call(arguments));
}
util.inherits(OutMessage, OutgoingMessage)

// maxBlock2 is in formular 2**(i+4), and must <= 2**(6+4)
var maxBlock2 = Math.pow(2, Math.floor(Math.log(parameters.maxPacketSize) / Math.log(2)))
if (maxBlock2 > Math.pow(2, (6 + 4)))
  maxBlock2 = Math.pow(2, (6 + 4))

OutMessage.prototype.end = function(payload) {
  var that = this

  var block2Buff = getOption(this._request.options, 'Block2')
  var requestedBlockOption
    // if we got blockwise (2) resquest
  if (block2Buff) {
    requestedBlockOption = parseBlock2(block2Buff)
      // bad option
    if (!requestedBlockOption) {
      that.statusCode = '4.02'
      return OutgoingMessage.prototype.end.call(that)
    }
  }

  // if payload is suitable for ONE message, shoot it out
  if (!payload ||
    ((!requestedBlockOption) && (payload.length < parameters.maxPacketSize)))
    return OutgoingMessage.prototype.end.call(this, payload)

  // for the first request, block2 option may be missed
  if (!requestedBlockOption)
    requestedBlockOption = {
      size: maxBlock2,
      num: 0
    }

  // block2 size should not bigger than maxBlock2
  if (requestedBlockOption.size > maxBlock2)
    requestedBlockOption.size = maxBlock2

  // block number should have limit
  // 0 base counter for totalBlock, hence use floor (vs ceil)
  var totalBlock = Math.floor(payload.length / requestedBlockOption.size)
  var isLastBlock
  if (requestedBlockOption.num < totalBlock)
    isLastBlock = false
  else if (requestedBlockOption.num == totalBlock)
    isLastBlock = true
  else {
    // precondition fail, may request for out of range block
    that.statusCode = '4.02'
    return OutgoingMessage.prototype.end.call(that)
  }

  var block2 = createBlock2({
    moreBlock2: isLastBlock,
    num: requestedBlockOption.num,
    size: requestedBlockOption.size
  })
  if (!block2) {
    // this catch never be match,
    // since we're gentleman, just handle it
    that.statusCode = '4.02'
    return OutgoingMessage.prototype.end.call(that)
  }
  this.setOption('Block2', block2)
  this.setOption('ETag', _toETag(payload))

  // cache it
  if (this._request.token && this._request.token.length > 0) {
    this._addCacheEntry(this._cachekey, payload)
  }
  OutgoingMessage.prototype.end.call(this, payload.slice((requestedBlockOption.num) * requestedBlockOption.size, (requestedBlockOption.num + 1) * requestedBlockOption.size))
};

/*
calculate id of a payload by xor each 2-byte-block from it
use to generate etag
  payload         an input buffer, represent payload need to generate id (hash)
  id              return var, is a buffer(2)
*/
function _toETag(payload) {
  var id = new Buffer([0, 0])
  var i = 0
  do {
    id[0] ^= payload[i]
    id[1] ^= payload[i + 1]
    i += 2
  } while (i < payload.length)
  return id
}

module.exports = CoAPServer
