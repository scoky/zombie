# Retrieve resources (HTML pages, scripts, XHR, etc).
#
# If count is unspecified, defaults to at least one.
#
# Each browser has a resources objects that allows you to:
# - Inspect the history of retrieved resources, useful for troubleshooting
#   issues related to resource loading
# - Simulate a failed server
# - Change the order in which resources are retrieved, or otherwise introduce
#   delays to simulate a real world network
# - Mock responses from servers you don't have access to, or don't want to
#   access from test environment
# - Request resources directly, but have Zombie handle cookies,
#   authentication, etc
# - Implement new mechanism for retrieving resources, for example, add new
#   protocols or support new headers


iconv       = require("iconv-lite")
File        = require("fs")
HTML        = require("jsdom").defaultLevel
Path        = require("path")
QS          = require("querystring")
HTTP        = require('http')
HTTPS       = require('https')
HTTP2       = require('./node-http2')
SPDY        = require('spdy')
URL         = require("url")
HTTPStatus  = require('http-status');
Zlib        = require("zlib")
assert      = require("assert")
Concat	    = require("concat-stream")
{ Promise } = require("bluebird")

# Ignore cert errors
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

# Each browser has a resources object that provides the means for retrieving
# resources and a list of all retrieved resources.
#
# The object is an array, and its elements are the resources.
class Resources extends Array
  constructor: (browser)->
    @browser = browser
    @callbacks = {}
    @pipeline = Resources.pipeline.slice()
    @urlMatchers = []
    @spdy_agents = []
    @h1_avail_connections = {}
    @h1_total_connections = {}
    @h1_agent = undefined
    @h1s_agent = undefined
    @connIndex = 0
    @headersSize = (headers)->
      str = ''
      for key, value of headers
        str += key + ': ' + value + '\n\r'
      str += '\n\r'
      return Buffer.byteLength(str, 'utf8')

  # Make an HTTP request (also supports file: protocol).
  #
  # method    - Request method (GET, POST, etc)
  # url       - Request URL
  # options   - See below
  # callback  - Called with error, or null and response
  #
  # Without callback, returns a promise.
  #
  # Options:
  #   headers   - Name/value pairs of headers to send in request
  #   params    - Parameters to pass in query string or document body
  #   body      - Request document body
  #   timeout   - Request timeout in milliseconds (0 or null for no timeout)
  #
  # Response contains:
  #   url         - Actual resource URL (changed by redirects)
  #   statusCode  - Status code
  #   statusText  - HTTP status text ("OK", "Not Found" etc)
  #   headers     - Response headers
  #   body        - Response body
  #   redirects   - Number of redirects followed
  request: (method, url, options = {}, callback)->
    if !callback && typeof(options) == 'function'
      [options, callback] = [{}, options]

    request =
      method:     method.toUpperCase()
      url:        url
      headers:    options.headers || {}
      params:     options.params
      body:       options.body
      time:       Date.now()
      timeout:    options.timeout || 0
      strictSSL:  @browser.strictSSL
      localAddress: @browser.localAddress || 0

    resource =
      request:    request
      target:     options.target
    @push(resource)
    @browser.emit("request", request)

    promise = new Promise((resolve, reject)=>
      @runPipeline request, (error, response)=>
        if error
          resource.error = error
          reject(error)
        else
          response.url        ||= request.url
          response.statusCode ||= 200
          response.statusText = HTTP.STATUS_CODES[response.statusCode] || "Unknown"
          response.headers    ||= {}
          response.redirects  ||= 0
          response.time       = Date.now()
          resource.response = response

          @browser.emit("response", request, response)
          resolve(resource.response)
    )

    if callback
      promise.done(
        (response)-> callback(null, response),
        callback)
    else
      return promise



  # GET request.
  #
  # url       - Request URL
  # options   - See request() method
  # callback  - Called with error, or null and response
  get: (url, options, callback)->
    return @request("get", url, options, callback)

  # HTTP request.
  #
  # url       - Request URL
  # options   - See request() method
  # callback  - Called with error, or null and response
  post: (url, options, callback)->
    return @request("post", url, options, callback)


  # You can use this to make a request to a given URL fail.
  #
  # url     - URL to fail
  # message - Optional error message
  fail: (url, message)->
    failTheRequest = (request, next)->
      next(new Error(message || "This request was intended to fail"))
    @urlMatchers.push([url, failTheRequest])
    return

  # You can use this to delay a response from a given URL.
  #
  # url   - URL to delay
  # delay - Delay in milliseconds (defaults to 10)
  delay: (url, delay = 10)->
    delayTheResponse = (request, next)->
      setTimeout(next, delay)
    @urlMatchers.push([url, delayTheResponse])
    return

  # You can use this to return a particular result for a given URL.
  #
  # url     - The URL to mock
  # result  - The result to return (statusCode, headers, body)
  mock: (url, result = {})->
    mockTheResponse = (request, next)->
      next(null, result)
    @urlMatchers.push([url, mockTheResponse])
    return

  # You can use this to restore default behavior to after using fail, delay or
  # mock.
  restore: (url)->
    @urlMatchers = @urlMatchers.filter(([match, _])-> match != url)
    return


  # Human readable resource listing.  With no arguments, write it to stdout.
  dump: (output = process.stdout)->
    for resource in this
      { request, response, error, target } = resource
      # Write summary request/response header
      if response
        output.write "#{request.method} #{response.url} - #{response.statusCode} #{response.statusText} - #{response.time - request.time}ms\n"
      else
        output.write "#{resource.request.method} #{resource.request.url}\n"

      # Tell us which element/document is loading this.
      if target instanceof HTML.Document
        output.write "  Loaded as HTML document\n"
      else if target
        if target.id
          output.write "  Loading by element ##{target.id}\n"
        else
          output.write "  Loading as #{target.tagName} element\n"

      # If response, write out response headers and sample of document entity
      # If error, write out the error message
      # Otherwise, indicate this is a pending request
      if response
        if response.redirects
          output.write "  Followed #{response.redirects} redirects\n"
        for name, value of response.headers
          output.write "  #{name}: #{value}\n"
        output.write "\n"
        sample = response.body.slice(0, 250).toString("utf8")
          .split("\n").map((line)-> "  #{line}").join("\n")
        output.write sample
      else if error
        output.write "  Error: #{error.message}\n"
      else
        output.write "  Pending since #{new Date(request.time)}\n"
      # Keep them separated
      output.write "\n\n"


  # Add a request/response handler.  This handler will only be used by this
  # browser.
  addHandler: (handler)->
    assert handler.call, "Handler must be a function"
    assert handler.length == 2 || handler.length == 3, "Handler function takes 2 (request handler) or 3 (response handler) arguments"
    @pipeline.push(handler)

  # Processes the request using the pipeline.
  runPipeline: (request, callback)->
    requestHandlers = @pipeline.filter((fn)-> fn.length == 2)
    requestHandlers.push(Resources.makeHTTPRequest)
    responseHandlers = @pipeline.filter((fn)-> fn.length == 3)
    response = null

    # Called to execute the next request handler.
    nextRequestHandler = (error, responseFromHandler)=>
      if error
        callback(error)
      else if responseFromHandler
        # Received response, switch to processing request
        response = responseFromHandler
        # If we get redirected and the final handler doesn't provide a URL (e.g.
        # mock response), then without this we end up with the original URL.
        response.url ||= request.url
        nextResponseHandler()
      else
        # Use the next request handler.
        handler = requestHandlers.shift()
        try
          handler.call(@browser, request, nextRequestHandler)
        catch error
          callback(error)

    # Called to execute the next response handler.
    nextResponseHandler = (error, responseFromHandler)=>
      if error
        callback(error)
      else
        if responseFromHandler
          response = responseFromHandler
        handler = responseHandlers.shift()
        if handler
          # Use the next response handler
          try
            handler.call(@browser, request, response, nextResponseHandler)
          catch error
            callback(error)
        else
          # No more handlers, callback with response.
          callback(null, response)

    # Start with first request handler
    nextRequestHandler()
    return

# -- Handlers

# Add a request/response handler.  This handler will be used in all browsers.
Resources.addHandler = (handler)->
  assert handler.call, "Handler must be a function"
  assert handler.length == 2 || handler.length == 3, "Handler function takes 2 (request handler) or 3 (response handler) arguments"
  @pipeline.push(handler)


# This handler normalizes the request URL.
#
# It turns relative URLs into absolute URLs based on the current document URL
# or base element, or if no document open, based on browser.site property.
#
# Also handles file: URLs and creates query string from request.params for
# GET/HEAD/DELETE requests.
Resources.normalizeURL = (request, next)->
  if /^file:/.test(request.url)
    # File URLs are special, need to handle missing slashes and not attempt
    # to parse (downcases path)
    request.url = request.url.replace(/^file:\/{1,3}/, "file:///")
  else
    # Resolve URL relative to document URL/base, or for new browser, using
    # Browser.site
    if @document
      request.url = HTML.resourceLoader.resolve(@document, request.url)
    else
      request.url = URL.resolve(@site || "http://localhost", request.url)

  if request.params
    method = request.method
    if method == "GET" || method == "HEAD" || method == "DELETE"
      # These methods use query string parameters instead
      uri = URL.parse(request.url, true)
      for name, value of request.params
        uri.query[name] = value
      request.url = URL.format(uri)

  next()
  return


# This handler mergers request headers.
#
# It combines headers provided in the request with custom headers defined by
# the browser (user agent, authentication, etc).
#
# It also normalizes all headers by down-casing the header names.
Resources.mergeHeaders = (request, next)->
  # Header names are down-cased and over-ride default
  headers =
    "user-agent":       @userAgent

  # Merge custom headers from browser first, followed by request.
  for name, value of @headers
    headers[name.toLowerCase()] = value
  if request.headers
    for name, value of request.headers
      headers[name.toLowerCase()] = value

  { host } = URL.parse(request.url)

  # Depends on URL, don't allow over-ride.
  headers.host = host

  # Apply authentication credentials
  if credentials = @authenticate(host, false)
    credentials.apply(headers)

  request.headers = headers
  next()
  return


# Depending on the content type, this handler will create a request body from
# request.params, set request.multipart for uploads.
Resources.createBody = (request, next)->
  method = request.method
  if method == "POST" || method == "PUT"
    headers = request.headers
    # These methods support document body.  Create body or multipart.
    headers["content-type"] ||= "application/x-www-form-urlencoded"
    mimeType = headers["content-type"].split(";")[0]
    unless request.body
      switch mimeType
        when "application/x-www-form-urlencoded"
          request.body = QS.stringify(request.params || {})
          headers["content-length"] = request.body.length
        when "multipart/form-data"
          params = request.params || {}
          if Object.keys(params).length == 0
            # Empty parameters, can't use multipart
            headers["content-type"] = "text/plain"
            request.body = ""
          else
            boundary = "#{new Date().getTime()}.#{Math.random()}"
            headers["content-type"] += "; boundary=#{boundary}"
            multipart = []
            for name, values of params
              for value in values
                disp = "form-data; name=\"#{name}\""
                if value.read
                  binary = value.read()
                  multipart.push
                    "Content-Disposition":  "#{disp}; filename=\"#{value}\""
                    "Content-Type":         value.mime || "application/octet-stream"
                    "Content-Length":       binary.length
                    body:                   binary
                else
                  multipart.push
                    "Content-Disposition":        disp
                    "Content-Type":               "text/plain; charset=utf8"
                    "Content-Length":             value.length
                    body:                         value
            request.multipart = multipart
        when "text/plain"
          # XHR requests use this by default
        else
          next(new Error("Unsupported content type #{mimeType}"))
          return

  next()
  return


# Special URL handlers can be used to fail or delay a request, or mock a
# response.
Resources.specialURLHandlers = (request, next)->
  for [url, handler] in @resources.urlMatchers
    if URL.resolve(request.url, url) == request.url
      handler(request, next)
      return
  next()


Resources.handleHTTPResponse = (request, response, callback)->
  { protocol, hostname, pathname } = URL.parse(request.url)
  unless protocol == "http:" or protocol == "https:"
    callback()
    return

  # Set cookies from response
  setCookie = response.headers and response.headers["set-cookie"]
  if setCookie
    @cookies.update(setCookie, hostname, pathname)

  # Number of redirects so far.
  redirects = request.redirects || 0
  redirectUrl = null

  # Determine whether to automatically redirect and which method to use
  # based on the status code
  switch response.statusCode
    when 301, 307
      # Do not follow POST redirects automatically, only GET/HEAD
      if request.method == "GET" || request.method == "HEAD"
        redirectUrl = URL.resolve(request.url, response.headers.location)
    when 302, 303
      # Follow redirect using GET (e.g. after form submission)
      redirectUrl = URL.resolve(request.url, response.headers.location)

  if redirectUrl
    response.url = redirectUrl
    # Handle redirection, make sure we're not caught in an infinite loop
    ++redirects
    if redirects > @maxRedirects
      callback(new Error("More than #{@maxRedirects} redirects, giving up"))
      return

    redirectHeaders = {}
    for name, value of request.headers
      redirectHeaders[name] = value
    # This request is referer for next
    redirectHeaders.referer = request.url
    # These headers exist in POST request, do not pass to redirect (GET)
    delete redirectHeaders["content-type"]
    delete redirectHeaders["content-length"]
    delete redirectHeaders["content-transfer-encoding"]
    # Redirect must follow the entire chain of handlers.
    redirectRequest =
      method:     "GET"
      url:        response.url
      headers:    redirectHeaders
      redirects:  redirects
      strictSSL:  request.strictSSL
      time:       request.time
      timeout:    request.timeout
    @emit("redirect", request, response, redirectRequest)
    @resources.runPipeline(redirectRequest, callback)

  else
    response.redirects = redirects
    callback()
  return


# Handle deflate and gzip transfer encoding.
Resources.decompressBody = (request, response, next)->
  if response.body && response.headers
    transferEncoding = response.headers["transfer-encoding"]
    contentEncoding = response.headers["content-encoding"]
    response.headers["transfer-encoding"] = response.headers["content-encoding"] = undefined
  if ( (contentEncoding == "deflate") || (transferEncoding == "deflate") )
    Zlib.inflate response.body, (error, buffer)->
      unless error
        response.body = buffer
      next(error)
  else if ( (contentEncoding == "gzip") || (transferEncoding == "gzip") )
    Zlib.gunzip response.body, (error, buffer)->
      unless error
        response.body = buffer
      next(error)
  else
    next()
  return


# Find the charset= value of the meta tag
MATCH_CHARSET = /<meta(?!\s*(?:name|value)\s*=)[^>]*?charset\s*=[\s"']*([^\s"'\/>]*)/i;

# This handler decodes the response body based on the response content type.
Resources.decodeBody = (request, response, next)->
  # If Content-Type header specifies charset, use that
  contentType = response.headers && response.headers["content-type"]
  if contentType && Buffer.isBuffer(response.body)
    [mimeType, typeOptions...]  = contentType.split(/;\s*/)
    [type, subtype]             = contentType.split(/\//,2);

  # Images, binary, etc keep response body a buffer
  if type && type != "text"
    next()
    return

  if Buffer.isBuffer(response.body)
    # Pick charset from content type
    if mimeType
      for typeOption in typeOptions
        if /^charset=/i.test(typeOption)
          charset = typeOption.split("=")[1]
          break

    isHTML = /html/.test(subtype) || /\bhtml\b/.test(request.headers.accept)

    # Otherwise, HTML documents only, pick charset from meta tag
    if !charset && isHTML
      match = response.body.toString().match(MATCH_CHARSET)
      charset = match && match[1]

    # Otherwise, HTML documents only, default charset in US is windows-1252
    if !charset && isHTML
      charset = charset || "windows-1252"

    if charset
      response.body = iconv.decode(response.body, charset)
  next()


# All browsers start out with this list of handler.
Resources.pipeline = [
  Resources.normalizeURL
  Resources.mergeHeaders
  Resources.createBody
  Resources.specialURLHandlers
  Resources.handleHTTPResponse
  Resources.decompressBody
  Resources.decodeBody
]


# -- Make HTTP request

# Used to perform HTTP request (also supports file: resources).  This is always
# the last request handler.
Resources.makeHTTPRequest = (request, callback)->
  { protocol, hostname, pathname } = URL.parse(request.url)
  if protocol == "file:"
    # If the request is for a file:// descriptor, just open directly from the
    # file system rather than getting node's http (which handles file://
    # poorly) involved.
    if request.method == "GET"
      filename = Path.normalize(decodeURI(pathname))
      File.exists filename, (exists)=>
        if exists
          File.readFile filename, (error, buffer)=>
            # Fallback with error -> callback
            if error
              request.error = error
              callback(error)
            else
              callback(null, body: buffer)
        else
          callback(null, statusCode: 404)
    else
      callback(resource.error)

  else

    # We're going to use cookies later when recieving response.
    cookies = @cookies
    request.headers.cookie = cookies.serialize(hostname, pathname)

    request.headers.host = request.headers.host.split(':')[0]
    httpRequest = require('url').parse(request.url)
    httpRequest.method =         request.method
    httpRequest.url =            request.url
    httpRequest.headers =        request.headers
    httpRequest.body =           request.body
    httpRequest.multipart =      request.multipart
    #httpRequest.proxy =          @proxy
    #httpRequest.jar =            false
    #httpRequest.followRedirect = false
    #httpRequest.encoding =       null
    #httpRequest.strictSSL =      request.strictSSL
    #httpRequest.localAddress =   request.localAddress || 0
    #httpRequest.timeout =        request.timeout || 0    
    httpRequest.servername =     hostname
    httpRequest.plain =          httpRequest.protocol == 'http:'
    if httpRequest.plain
      port = 80
    else
      port = 443
    httpRequest.port =           httpRequest.port || port
    #httpRequest.protocol =	 'https:'
    console.log JSON.stringify(httpRequest, null, '\t')

    entry =
      startedDateTime:  new Date()
      time:             null
      request:
        method:           httpRequest.method
        url:              httpRequest.url
        httpVersion:      null
        cookies:          [httpRequest.headers.cookie]
        headers:          httpRequest.headers
        queryString:      httpRequest.query
        headersSize:      @resources.headersSize(httpRequest.headers)
        bodySize:         0
      response:         null
      #serverIPAddress:  null
      #connection:       @resources.connIndex

      # timings:          
      #   blocked:          -1
      #   dns:              -1
      #   connect:          -1
      #   send:             -1
      #   wait:             -1
      #   receive:          -1
      #   ssl:              -1

    protocol = @resources.browser.getProtocol()
    # http is always http/1.1
    if httpRequest.plain
      protocol = 'http/1.1'

    prxy = @resources.browser.getProxy()
    if prxy
      httpRequest.host = httpRequest.hostname = prxy.split(':')[0]
      httpRequest.port = prxy.split(':')[1]

    # Handle multiple callbacks for same request
    # First request, set up state
    if ! @resources.callbacks[request.url]
      @resources.callbacks[request.url] = 
        callbacks:	[]
        request:	request
        response:	undefined
    callStruct = @resources.callbacks[request.url]

    # Response already receive, callback immediately
    if callStruct.response
      makeTheCall(callback, callStruct.response)
      return

    callStruct.callbacks.push(callback)
    if callStruct.callbacks.length != 1
      return

    #console.log 'REQUEST '+Date.now()+' '+request.url
    if protocol == 'h2'
      httpRequest.headers = HTTP2.convertHeadersToH2(request.headers)
      if httpRequest.plain
        req = HTTP2.raw.request httpRequest
      else
        req = HTTP2.request httpRequest
    else if protocol == 'http/1.1'

      if ! @resources.h1_total_connections[httpRequest.host+httpRequest.port]
        @resources.h1_avail_connections[httpRequest.host+httpRequest.port] = 0
        @resources.h1_total_connections[httpRequest.host+httpRequest.port] = 1
        @resources.browser.emit("newConnection", {}, httpRequest.host, httpRequest.port)
      else if @resources.h1_avail_connections[httpRequest.host+httpRequest.port] > 0
        @resources.h1_avail_connections[httpRequest.host+httpRequest.port] = @resources.h1_avail_connections[httpRequest.host+httpRequest.port] - 1
      else if @resources.browser.tcpLimit == 0 || @resources.browser.tcpLimit > @resources.h1_total_connections[httpRequest.host+httpRequest.port]
        @resources.h1_total_connections[httpRequest.host+httpRequest.port] = @resources.h1_total_connections[httpRequest.host+httpRequest.port] + 1
        @resources.browser.emit("newConnection", {}, httpRequest.host, httpRequest.port)

      if httpRequest.plain
        if @resources.browser.tcpLimit > 0
          if ! @resources.h1_agent
            @resources.h1_agent = new HTTP.Agent({ 
                maxSockets: @resources.browser.tcpLimit
              })
          httpRequest.agent = @resources.h1_agent

        req = HTTP.request httpRequest
      else
        if @resources.browser.tcpLimit > 0
          if ! @resources.h1s_agent
            @resources.h1s_agent = new HTTPS.Agent({ 
                maxSockets: @resources.browser.tcpLimit
              })
          httpRequest.agent = @resources.h1s_agent

        req = HTTPS.request httpRequest
    else if protocol == 'spdy'
      cagent = null
      for agent in @resources.spdy_agents
#         console.log agent
         if (agent.options.host == httpRequest.host && agent.options.port == httpRequest.port)
            cagent = agent
            break

      if ! cagent
        cagent = SPDY.createAgent({
           host:  httpRequest.host
           port:  httpRequest.port
#           spdy:  {
#                     plain:    false
#                     ssl:      true
#                     version:  3
#                  }
           })

        # Report the new connection
        @resources.connIndex += 1
        entry.connection = @resources.connIndex
        @resources.browser.emit("newConnection", {}, httpRequest.host, httpRequest.port)
        @resources.spdy_agents.push(cagent)

      httpRequest.agent = cagent
      if httpRequest.plain
        req = HTTP.request httpRequest
      else
        req = HTTPS.request httpRequest
    else
      throw new Error

    req.on("response", (response)=>
      #console.log 'BEGIN RESPONSE'
      if protocol == 'http/1.1'
        @resources.h1_avail_connections[httpRequest.host+httpRequest.port] = @resources.h1_avail_connections[httpRequest.host+httpRequest.port] + 1
      
      ccat = new Concat((bdy)=>
        #console.log 'RESPONSE '+Date.now()+' '+request.url+' '+bdy.length

        #console.log JSON.stringify(response, null, '\t')
        #console.log require('util').inspect(response)
        response.body = bdy
        callStruct.response = response

        entry.request.httpVersion = response.httpVersion
        entry.time = new Date() - entry.startedDateTime
        entry.startedDateTime = entry.startedDateTime.toISOString()
        entry.response = 
          status:            response.statusCode
          statusText:        HTTPStatus[response.statusCode]
          httpVersion:       response.httpVersion
          cookies:           [response.headers.cookie]
          headers:           response.headers
          redirectURL:       response.headers['location']
          headersSize:       @resources.headersSize(response.headers)
          bodySize:          bdy.length
          #content:           null
        # Add to HAR
        @resources.browser.har.log.entries.push(entry)

        callStruct.callbacks.forEach( (cbak)=>
          makeTheCall(cbak, response)
        )
      )
      response.pipe(ccat)
    )

    makeTheCall = (cbak, response)->
      #console.log response.body.toString()
      resp =
        url:          request.url
        statusCode:   response.statusCode
        headers:      response.headers
        body:         response.body
        redirects:    request.redirects || 0

      if protocol == 'h2'
        resp.headers = HTTP2.convertHeadersFromH2(response.headers)

      setImmediate(cbak, null, resp)

    # TODO: Handle push!
    req.on "push", (push)=>
      @resources.browser.emit("push", push)

    req.on "newConnection", (endpoint)=>
      @resources.connIndex += 1
      entry.connection = @resources.connIndex
      @resources.browser.emit("newConnection", endpoint, httpRequest.host, httpRequest.port)

    req.on "protocolNegotiated", (protocol)=>
      @resources.browser.emit("protocolNegotiated", protocol, httpRequest.host, httpRequest.port)

    req.on "error", (error)=>
      #console.log error
      if error
        callStruct.callbacks.forEach( (cbak)=>
          cbak(error)
        )
      return

    if request.body
      req.write(request.body)
    req.end()
  return

module.exports = Resources
