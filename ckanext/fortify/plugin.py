import ckan.authz as authz
import ckan.logic.schema
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import mimetypes
import logging

from flask import make_response
from ckan.views.resource import download as core_resource_download
from ckanext.fortify import helpers, schema, anti_csrf

config = toolkit.config
NotAuthorized = toolkit.NotAuthorized
NotFound = toolkit.ObjectNotFound
ValidationError = toolkit.ValidationError
get_action = toolkit.get_action
response = make_response
log = logging.getLogger(__name__)


class FortifyPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.ITemplateHelpers)

    if toolkit.asbool(config.get('ckan.fortify.check_parent_org_allowed', False)):
        plugins.implements(plugins.IOrganizationController, inherit=True)

    if toolkit.asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):
        plugins.implements(plugins.IResourceController, inherit=True)

    if toolkit.asbool(config.get('ckan.fortify.enable_anti_csrf_tokens', False)):
        plugins.implements(plugins.IRoutes, inherit=True)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')

        if toolkit.asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):
            log.debug('force_html_resource_downloads')
            core_resource_download = self.resource_download

        if toolkit.asbool(config.get('ckan.fortify.enable_password_policy', False)):
            # Monkeypatching all user schemas in order to enforce a stronger password
            ckan.logic.schema.default_user_schema = schema.default_user_schema
            ckan.logic.schema.user_new_form_schema = schema.user_new_form_schema
            ckan.logic.schema.user_edit_form_schema = schema.user_edit_form_schema
            ckan.logic.schema.default_update_user_schema = schema.default_update_user_schema

    # IOrganizationController

    if toolkit.asbool(config.get('ckan.fortify.check_parent_org_allowed', False)):

        def create(self, entity):
            user = toolkit.c.userobj

            if authz.is_sysadmin(user.name):
                return

            parents = entity.get_parent_group_hierarchy('organization')

            if parents:
                parent = parents[-1]
                role = authz.users_role_for_group_or_org(parent.id, user.name)

                if not role or role != 'admin':
                    raise ValidationError(
                        {'parent': ['You do not belong to the selected parent organisation']}
                    )

    # IResourceController

    if toolkit.asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):

        def resource_download(self, package_type, id, resource_id, filename=None):
            try:
                log.debug('resource_download: {}'.format(resource_id))
                resource = get_action('resource_show')({}, {'id': resource_id})
                content_type, content_enc = mimetypes.guess_type(
                    resource.get('url', ''))
                if content_type and content_type == 'text/html':
                    response.headers['Content-disposition'] = 'attachment'
            except (NotFound, NotAuthorized):
                pass
            log.debug('resource_download: {}'.format(content_type))
            log.debug('resource_download: {}'.format(response.headers))
            return core_resource_download(package_type, id, resource_id, filename)

    # IRoutes

    if toolkit.asbool(config.get('ckan.fortify.enable_anti_csrf_tokens', False)):

        def after_map(self, map):
            anti_csrf.intercept_csrf()
            return map

    # ITemplateHelpers

    def get_helpers(self):
        return {
            'get_password_error_message': helpers.get_password_error_message
        }
