import ckan.lib.base as base
from six.moves.urllib import parse

import re
from re import IGNORECASE, MULTILINE
import logging
from ckan.common import config, request


CSRF_ERR = 'CSRF authentication failed. Token missing or invalid.'

domain = config.get('ckan.fortify.csrf_domain', '')

RAW_RENDER = base.render
RAW_RENDER_JINJA = base.render_jinja2
#RAW_BEFORE = base.BaseController.__before__

""" Used as the cookie name and input field name.
"""
TOKEN_FIELD_NAME = 'token'

""" Used to rotate the token cookie periodically.
If the freshness cookie doesn't appear, the token cookie is still OK,
but we'll set a new one for next time.
"""
TOKEN_FRESHNESS_COOKIE_NAME = 'token-fresh'

# We need to edit confirm-action links, which get intercepted by JavaScript,
# regardless of which order their 'data-module' and 'href' attributes appear.
CONFIRM_LINK = re.compile(r'(<a [^>]*data-module=["\']confirm-action["\'][^>]*href=["\']([^"\']+))(["\'])', IGNORECASE | MULTILINE)
CONFIRM_LINK_REVERSED = re.compile(r'(<a [^>]*href=["\']([^"\']+))(["\'][^>]*data-module=["\']confirm-action["\'])', IGNORECASE | MULTILINE)

"""
This will match a POST form that has whitespace after the opening tag (which all existing forms do).
Once we have injected a token immediately after the opening tag,
it won't match any more, which avoids redundant injection.
"""
POST_FORM = re.compile(r'(<form [^>]*method=["\']post["\'][^>]*>)([^<]*\s<)', IGNORECASE | MULTILINE)

"""The format of the token HTML field.
"""
HEX_PATTERN = re.compile(r'^[0-9a-z]+$')
TOKEN_PATTERN = r'<input type="hidden" name="' + TOKEN_FIELD_NAME + '" value="{token}"/>'
TOKEN_SEARCH_PATTERN = re.compile(TOKEN_PATTERN.format(token=r'([0-9a-f]+)'))
API_URL = re.compile(r'^/api\b.*')


log = logging.getLogger(__name__)


def _apply_token(html, token):
    """ Rewrite HTML to insert tokens if applicable.
    """

    token_match = TOKEN_SEARCH_PATTERN.search(html)
    if token_match:
        token = token_match.group(1)

    def insert_form_token(form_match):
        return form_match.group(1) + TOKEN_PATTERN.format(token=token) + form_match.group(2)

    def insert_link_token(link_match):
        if '?' in link_match.group(2):
            separator = '&'
        else:
            separator = '?'
        return link_match.group(1) + separator + TOKEN_FIELD_NAME + '=' + token + link_match.group(3)

    return CONFIRM_LINK_REVERSED.sub(insert_link_token, CONFIRM_LINK.sub(insert_link_token, POST_FORM.sub(insert_form_token, html)))


def get_cookie_token(request):
    """Retrieve the token expected by the server.
    This will be retrieved from the 'token' cookie, if it exists.
    If not, an error will occur.
    """
    token = None
    if request.cookies.has_key(TOKEN_FIELD_NAME):
        log.debug("Obtaining token from cookie")
        token = request.cookies.get(TOKEN_FIELD_NAME)
    if token is None or token.strip() == "":
        csrf_fail("CSRF token is blank")
    return token


def _get_response_token(request, response):
    """Retrieve the token to be injected into pages.
    This will be retrieved from the 'token' cookie, if it exists and is fresh.
    If not, a new token will be generated and a new cookie set.
    """
    # ensure that the same token is used when a page is assembled from pieces
    if TOKEN_FIELD_NAME in request.cookies and TOKEN_FRESHNESS_COOKIE_NAME in request.cookies:
        log.debug("Obtaining token from cookie")
        token = request.cookies.get(TOKEN_FIELD_NAME)
        if not HEX_PATTERN.match(token):
            log.debug("Invalid cookie token; making new token cookie")
            token = create_response_token(response)
    else:
        log.debug("No fresh token found; making new token cookie")
        token = create_response_token(response)
    return token


def create_response_token(response):
    site_url = parse.urlparse(config.get('ckan.site_url', ''))
    import binascii
    import os
    token = binascii.hexlify(os.urandom(32)).decode('ascii')
    if site_url.scheme == 'https':
        log.debug("Securing CSRF token cookie for site %s", site_url)
        secure_cookies = True
    else:
        log.warn("Site %s is not secure! CSRF token may be exposed!", site_url)
        secure_cookies = False
    response.set_cookie(TOKEN_FRESHNESS_COOKIE_NAME, '1', max_age=600, secure=secure_cookies, httponly=True)
    response.set_cookie(TOKEN_FIELD_NAME, token, secure=secure_cookies, httponly=True)
    
    return token


def csrf_fail(message):
    from flask import abort
    log.error(message)
    abort(403, "Your form submission could not be validated")


def after_request_function(response):
    resp = response
    # direct_passthrough is set when a file is being downloaded, we do not need to apply a token for file downloads
    if response.direct_passthrough == False and 'text/html' in resp.headers.get('Content-type', ''):
        # Workaround for config page
        # config_option_update is trying to update token so we need to skip applying the token 
        # to this form
        # TODO: Fix me!
        if request.endpoint in ('admin.config'):
            return response
        token = _get_response_token(request, resp)
        new_response = _apply_token(resp.get_data(as_text=True), token)
        resp.set_data(new_response)
        return resp

    else:
        return response


def is_valid():
    return is_safe() or unsafe_request_is_valid()


def unsafe_request_is_valid():
    return check_token()


def is_secure():
    # allow requests which have the x-forwarded-proto of https (inserted by nginx)
    if request.headers.get('X-Forwarded-Proto') == 'https':
        return True
    return request.scheme == 'https'


def is_safe():
    "Check if the request is 'safe', if the request is safe it will not be checked for csrf"
    # api requests are exempt from csrf checks
    if request.path.startswith("/api") or request.endpoint in ('admin.config'):
        return True

    # get/head/options/trace are exempt from csrf checks
    return request.method in ('GET', 'HEAD', 'OPTIONS', 'TRACE')


def good_referer():
    "Returns true if the referrer is https and matching the host"
    if not request.headers.get('Referer'):
        return False
    else:
        match = "https://{}".format(domain)
        return request.headers.get('Referer').startswith(match)


def good_origin():
    """
    checks if the origin header is present and matches the header"
    :param domain: string: the expected origin domain
    :return: boolean: true if the origin header is present and matches the expected domain
    """
    origin = request.headers.get('origin', None)
    if not origin:
        log.warning("Potentially unsafe CSRF request is missing the origin header")
        return True
    else:
        match = "https://{}".format(domain)
        return origin.startswith(match)


def _get_post_token():
    """Retrieve the token provided by the client. Or return None if not present
        This is normally a single 'token' parameter in the POST body.
        However, for compatibility with 'confirm-action' links,
        it is also acceptable to provide the token as a query string parameter,
        if there is no POST body.
    """
    if TOKEN_FIELD_NAME in request.environ['werkzeug.request'].cookies:
        return request.cookies['token']
    # handle query string token if there are no POST parameters
    # this is needed for the 'confirm-action' JavaScript module
    if not request.method == 'POST' and (request.args.get(TOKEN_FIELD_NAME) and len(request.args.get(TOKEN_FIELD_NAME)) == 1):
        token = request.args.get(TOKEN_FIELD_NAME)
        return token
    post_tokens = request.form.getlist(TOKEN_FIELD_NAME)
    if not post_tokens or len(post_tokens) != 1:
        return None
    token = post_tokens[0]
    return token


def get_cookie_token():
    """Retrieve the token expected by the server.
       This will be retrieved from the 'token' cookie
       """
    if TOKEN_FIELD_NAME in request.cookies:
        log.debug("Obtaining token from cookie")
        return request.cookies.get(TOKEN_FIELD_NAME)
    else:
        return None


def check_token():
    log.debug("Checking token matches Token {}, cookie_token: {}".format(_get_post_token(), get_cookie_token()))
    return _get_post_token() is not None and _get_post_token() == get_cookie_token()
