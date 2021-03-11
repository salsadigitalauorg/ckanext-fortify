import ckan.authz as authz
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import logging

from ckanext.fortify import helpers, validators, blueprint
from ckanext.fortify.logic.auth import (
    create as auth_create,
    update as auth_update
)
from ckan.lib.uploader import ALLOWED_UPLOAD_TYPES

config = toolkit.config
ValidationError = toolkit.ValidationError
asbool = toolkit.asbool
log = logging.getLogger(__name__)


class FortifyPlugin(plugins.SingletonPlugin):

    if asbool(config.get('ckan.fortify.check_parent_org_allowed', False)):
        plugins.implements(plugins.IOrganizationController, inherit=True)
        # IOrganizationController

        def create(self, entity):
            user = toolkit.g.userobj

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

    if asbool(config.get('ckan.fortify.block_html_resource_uploads', False)):
        plugins.implements(plugins.IUploader, inherit=True)
        plugins.implements(plugins.IAuthFunctions)

        # IUploader

        def get_resource_uploader(self, data_dict):
            upload = data_dict.get('upload', None)
            if upload and isinstance(upload, ALLOWED_UPLOAD_TYPES) and upload.mimetype == 'text/html':
                raise ValidationError({'upload': ['Invalid file type']})
            else:
                # Returning None will make sure it uses the CKAN default uploader ResourceUpload
                return None

        # IAuthFunctions

        def get_auth_functions(self):
            return {
                # Create auth function overrides
                'group_create': auth_create.fortify_group_create,
                'organization_create': auth_create.fortify_organization_create,
                'user_create': auth_create.fortify_user_create,
                # Update auth function overrides
                'group_update': auth_update.fortify_group_update,
                'organization_update': auth_update.fortify_organization_update,
                'user_update': auth_update.fortify_user_update,
            }

    if asbool(config.get('ckan.fortify.enable_anti_csrf_tokens', False)) \
            or asbool(config.get('ckan.fortify.enable_password_policy', False)) \
            or asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):
        plugins.implements(plugins.IBlueprint)
        # IBlueprint

        def get_blueprint(self):
            return blueprint.fortify

    if asbool(config.get('ckan.fortify.enable_password_policy', False)):
        plugins.implements(plugins.IValidators)
        # IValidators

        def get_validators(self):
            return {
                'user_password_validator': validators.user_password_validator
            }
