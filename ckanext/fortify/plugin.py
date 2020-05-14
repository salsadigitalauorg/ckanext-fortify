import ckan.authz as authz
import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
import mimetypes

from ckan.common import config, response
from ckan.controllers.package import PackageController
from ckan.logic import NotAuthorized, NotFound, ValidationError, get_action

core_resource_download = PackageController.resource_download


class FortifyPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)

    if toolkit.asbool(config.get('ckan.fortify.check_parent_org_allowed', False)):
        plugins.implements(plugins.IOrganizationController, inherit=True)

    if toolkit.asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):
        plugins.implements(plugins.IResourceController, inherit=True)

    # IConfigurer
    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')

        if toolkit.asbool(config.get('ckan.fortify.force_html_resource_downloads', False)):
            PackageController.resource_download = self.resource_download

    # IOrganizationController
    if toolkit.asbool(config.get('ckan.fortify.check_parent_org_allowed', False)):

        def create(self, entity):
            user = toolkit.c.userobj
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

        def resource_download(self, id, resource_id, filename=None):
            try:
                resource = get_action('resource_show')({}, {'id': resource_id})
                content_type, content_enc = mimetypes.guess_type(
                    resource.get('url', ''))
                if content_type and content_type == 'text/html':
                    response.headers['Content-disposition'] = 'attachment'
            except (NotFound, NotAuthorized):
                pass

            return core_resource_download(PackageController(), id, resource_id, filename)
