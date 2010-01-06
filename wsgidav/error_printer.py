"""
error_printer
=============

:Author: Ho Chun Wei, fuzzybr80(at)gmail.com (author of original PyFileServer)
:Author: Martin Wendt, moogle(at)wwwendt.de 
:Copyright: Licensed under the MIT license, see LICENSE file in this package.


WSGI middleware to catch application thrown DAVErrors and return proper 
responses.

+-------------------------------------------------------------------------------+
| The following documentation was taken over from PyFileServer and is outdated! |
+-------------------------------------------------------------------------------+

Usage::

   from wsgidav.processrequesterrorhandler import ErrorPrinter
   WSGIApp = ErrorPrinter(ProtectedWSGIApp, server_descriptor, catchall)

   where:
      ProtectedWSGIApp is the application throwing HTTPRequestExceptions, 
   
      server_descriptor is an optional html string to be included as the 
      footer of any html response sent  
   
      catchall is an optional boolean. if True, ErrorPrinter will catch all
      other exceptions and print a trace to sys.stderr stream before sending
      a 500 Internal Server Error response (default = False)


   Within ProtectedWSGIApp:
   
      from pyfileserver import processrequesterrorhandler
      from wsgidav.processrequesterrorhandler import HTTPRequestException
      ...
      ...
      raise HTTPRequestException(404)
         or
      raise HTTPRequestException(processrequesterrorhandler.HTTP_BAD_REQUEST)
      #escape the existing application and return the 404 Bad Request immediately

Occasionally it may be useful for an internal ProtectedWSGIApp method to catch the
HTTPRequestException (for compiling into a multi-status, for example). The response 
code of the error can be returned as:: 
   
   from pyfileserver import processrequesterrorhandler
   from wsgidav.processrequesterrorhandler import HTTPRequestException
   
   try:
      ...
      raise HTTPRequestException(processrequesterrorhandler.HTTP_BAD_REQUEST)
      ...
   except HTTPRequestException, e:
      numberCode = processrequesterrorhandler.getErrorCodeFromException(e)
      textCode = processrequesterrorhandler.getHttpStatusString(e)

Interface
---------

Classes:

+ 'ErrorPrinter': WSGI Middleware to catch HTTPRequestExceptions and return 
  proper responses 

Exception(s):

+ 'HTTPRequestException': Raised with error code integer (1xx-5xx) within protected 
  application to be caught by ErrorPrinter

Function(s):

+ 'getHttpStatusString(e)': Returns response code string for HTTPRequestException
  e. 

+ 'getErrorCodeFromException(e)': Returns the response code number (1xx-5xx) for 
  HTTPRequestException e

See DEVELOPERS.txt_ for more information about the WsgiDAV architecture.

.. _DEVELOPERS.txt: http://wiki.wsgidav-dev.googlecode.com/hg/DEVELOPERS.html  
"""

__docformat__ = "reStructuredText"

import util
from dav_error import DAVError, getHttpStatusString, asDAVError,\
    HTTP_INTERNAL_ERROR, ERROR_RESPONSES
import traceback
import sys

_logger = util.getModuleLogger(__name__)

#===============================================================================
# ErrorPrinter
#===============================================================================
class ErrorPrinter(object):
    def __init__(self, application, server_descriptor=None, catchall=False):
        self._application = application
        self._server_descriptor = server_descriptor
        self._catch_all_exceptions = catchall

    def __call__(self, environ, start_response):      
        try:
            try:
                # request_server app may be a generator (for example the GET handler)
                # So we must iterate - not return self._application(..)!
                # Otherwise the we could not catch exceptions here. 
#                return self._application(environ, start_response)
                for v in self._application(environ, start_response):
                    yield v
#            except GeneratorExit:
#                # TODO: required?
#                util.debug("GeneratorExit", module="sc")
#                raise
            except DAVError, e:
                _logger.debug("re-raising %s" % e)
                raise
            except Exception, e:
                # Caught a non-DAVError 
                if self._catch_all_exceptions:
                    # Catch all exceptions to return as 500 Internal Error
                    traceback.print_exc(10, environ.get("wsgi.errors") or sys.stderr) 
                    raise asDAVError(e)               
                else:
                    util.log("ErrorPrinter: caught Exception")
                    traceback.print_exc(10, sys.stderr) 
                    raise
        except DAVError, e:
            _logger.debug("caught %s" % e)
            respcode = getHttpStatusString(e)
            datestr = util.getRfc1123Time()

            # Dump internal errors to console
            if e.value == HTTP_INTERNAL_ERROR:
                print >>sys.stderr, "ErrorPrinter: caught HTTPRequestException(HTTP_INTERNAL_ERROR)"
                traceback.print_exc(10, environ.get("wsgi.errors") or sys.stderr)
                print >>sys.stderr, "e.srcexception:\n%s" % e.srcexception

            # If exception has pre-/post-condition: return as XML response 
            if e.errcondition:
                start_response(respcode, [("Content-Type", "application/xml"), 
                                          ("Date", datestr)
                                          ]) 
                yield e.errcondition.as_string()
                return

            # Else return as HTML 
            respbody = [] 
            respbody.append("<html><head><title>" + respcode + "</title></head>") 
            respbody.append("<body><h1>" + respcode + "</h1>") 
            if e.value in ERROR_RESPONSES:                  
                respbody.append("<p>" + ERROR_RESPONSES[e.value] + "</p>")         
            if e.contextinfo:
                respbody.append("%s" % e.contextinfo)
            respbody.append("<hr>") 
            if self._server_descriptor:
                respbody.append(self._server_descriptor + "<hr>")
            respbody.append(datestr) 
            respbody.append("</body></html>") 

            start_response(respcode, [("Content-Type", "text/html"), 
                                      ("Date", datestr)
                                      ],
#                          sys.exc_info() # TODO: Always provide exc_info when beginning an error response?
                           ) 
            yield "\n".join(respbody)
