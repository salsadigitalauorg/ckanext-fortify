import logging
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dictization_functions

from ckan.views.user import PerformResetView
from flask import Blueprint
from flask.views import MethodView
from six import text_type
from ckanext.fortify import validators
from ckanext.fortify.csrf import anti_csrf3

log = logging.getLogger(__name__)
get_action = toolkit.get_action
NotAuthorized = toolkit.NotAuthorized
NotFound = toolkit.ObjectNotFound
ValidationError = toolkit.ValidationError
Invalid = toolkit.Invalid
request = toolkit.request
render = toolkit.render
g = toolkit.g
h = toolkit.h
_ = toolkit._

fortify = Blueprint(u'fortify', __name__)


@fortify.before_app_request
def before_app_request():
    if not anti_csrf3.is_valid():
        log.debug("Invalid CSRF attempt.")
        extra_vars = {'code': [403], 'content': 'Your form submission could not be validated.'}
        return render('error_document_template.html', extra_vars=extra_vars)


@fortify.after_app_request
def after_app_request(response):
    '''Update every Flask response with CSRF token.
    '''
    anti_csrf3.after_request_function(response)
    return response


def _get_form_password():
    '''
    This method is copied from the ckan user view class method PerformResetView._get_form_password
    It is a exact copy so will need to be checked and updated if necessary on any CKAN upgrades
    There are a few modifications to validate the users password
    '''
    password1 = request.form.get(u'password1')
    password2 = request.form.get(u'password2')
    if (password1 is not None and password1 != u''):
        # Modifications begin
        if validators.user_password_has_repeated_chars(password1):
            raise ValueError(_(validators.REPEATING_CHAR_ERROR))
        if validators.user_password_noncompliant(password1):
            raise ValueError(_(validators.MIN_LEN_ERROR.format(validators.MIN_PASSWORD_LENGTH)))
        # Modifications end
        if password1 != password2:
            raise ValueError(
                _(u'The passwords you entered'
                    u' do not match.'))
        return password1
    msg = _(u'You must provide a password')
    raise ValueError(msg)


def reset_password(id):
    '''
    This method is copied from the ckan user view class method PerformResetView.post
    It is a exact copy so will need to be checked and updated if necessary on any CKAN upgrades
    This method is used to update the internal method _get_form_password()
    '''
    context, user_dict = PerformResetView._prepare(PerformResetView(), id)
    context[u'reset_password'] = True
    user_state = user_dict[u'state']
    try:
        # Modifications begin
        new_password = _get_form_password()
        # Modifications end
        user_dict[u'password'] = new_password
        username = request.form.get(u'name')
        if (username is not None and username != u''):
            user_dict[u'name'] = username
        user_dict[u'reset_key'] = g.reset_key
        user_dict[u'state'] = model.State.ACTIVE
        get_action(u'user_update')(context, user_dict)
        mailer.create_reset_key(context[u'user_obj'])

        h.flash_success(_(u'Your password has been reset.'))
        return h.redirect_to(u'home.index')
    except NotAuthorized:
        h.flash_error(_(u'Unauthorized to edit user %s') % id)
    except NotFound:
        h.flash_error(_(u'User not found'))
    except dictization_functions.DataError:
        h.flash_error(_(u'Integrity Error'))
    except ValidationError as e:
        h.flash_error(u'%r' % e.error_dict)
    except ValueError as e:
        h.flash_error(text_type(e))
    user_dict[u'state'] = user_state
    return render(u'user/perform_reset.html', {
        u'user_dict': user_dict
    })


fortify.add_url_rule(
    u'/user/reset/<id>', view_func=reset_password, methods=[u'POST'])
