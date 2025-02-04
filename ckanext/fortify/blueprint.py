import logging
import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.lib.mailer as mailer
import ckan.lib.navl.dictization_functions as dictization_functions
import ckan.lib.uploader as uploader
from ckan.lib import signals
import flask

from ckan.views.user import PerformResetView
from six import text_type
from ckanext.fortify import validators, anti_csrf

Blueprint = flask.Blueprint
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
config = toolkit.config
asbool = toolkit.asbool
abort = toolkit.abort

fortify = Blueprint(u'fortify', __name__)


if asbool(config.get('ckan.fortify.enable_anti_csrf_tokens', False)):
    @fortify.before_app_request
    def before_app_request():
        if not anti_csrf.is_valid():
            log.debug("Invalid CSRF attempt.")
            extra_vars = {'code': [403], 'content': 'Your form submission could not be validated.'}
            return render('error_document_template.html', extra_vars=extra_vars)

    @fortify.after_app_request
    def after_app_request(response):
        '''Update every Flask response with CSRF token.
        '''
        anti_csrf.after_request_function(response)
        return response


if asbool(config.get('ckan.fortify.enable_password_policy', False)):
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
            updated_user = get_action(u"user_update")(context, user_dict)
            # Users can not change their own state, so we need another edit
            if (updated_user[u"state"] == model.State.PENDING):
                patch_context = {
                    u'user': get_action(u"get_site_user")(
                        {u"ignore_auth": True}, {})[u"name"]
                }
                get_action(u"user_patch")(
                    patch_context,
                    {u"id": user_dict[u'id'], u"state": model.State.ACTIVE}
                )
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
        u'/user/reset/<id>',
        view_func=reset_password,
        methods=[u'POST'])


if asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):
    def download(package_type, id, resource_id, filename=None):
        """
        Provides a direct download by either redirecting the user to the url
        stored or downloading an uploaded file directly.
        This method is copied from the ckan user view class method resource.download
        It is a exact copy so will need to be checked and updated if necessary on any CKAN upgrades
        There are a few modifications to force HTML files to be downloaded as an attachment
        """
        context = {
            u'model': model,
            u'session': model.Session,
            u'user': g.user,
            u'auth_user_obj': g.userobj
        }

        try:
            rsc = get_action(u'resource_show')(context, {u'id': resource_id})
            get_action(u'package_show')(context, {u'id': id})
        except (NotFound, NotAuthorized):
            return abort(404, _(u'Resource not found'))

        if rsc.get(u'url_type') == u'upload':
            upload = uploader.get_resource_uploader(rsc)
            filepath = upload.get_path(rsc[u'id'])
            # Fortify updates begin
            if upload.mimetype == 'text/html':
                # Set as_attachment to force download
                # This will set the header headers.add('Content-Disposition', 'attachment', filename=attachment_filename)
                return flask.send_file(filepath, mimetype=upload.mimetype, as_attachment=True, attachment_filename=filename)
            else:
                resp = flask.send_file(filepath, download_name=filename)
                if rsc.get('mimetype'):
                    resp.headers['Content-Type'] = rsc['mimetype']
                signals.resource_download.send(resource_id)
                return resp
            # Fortify updates end
        elif u'url' not in rsc:
            return abort(404, _(u'No download is available'))
        return h.redirect_to(rsc[u'url'])

    fortify.add_url_rule(
        u'/dataset/<id>/resource/<resource_id>/download',
        view_func=download,
        defaults={u'package_type': u'dataset'}
    )
    fortify.add_url_rule(
        u'/dataset/<id>/resource/<resource_id>/download/<filename>',
        view_func=download,
        defaults={u'package_type': u'dataset'}
    )
