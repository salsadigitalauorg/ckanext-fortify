import ckan.plugins.toolkit as toolkit

from ckanext.fortify.logic.auth import helpers


@toolkit.chained_auth_function
def fortify_group_create(next_auth, context, data_dict):
    return helpers.disallow_non_image_uploads(next_auth, context, data_dict)


@toolkit.chained_auth_function
def fortify_organization_create(next_auth, context, data_dict):
    return helpers.disallow_non_image_uploads(next_auth, context, data_dict)


@toolkit.chained_auth_function
def fortify_user_create(next_auth, context, data_dict):
    return helpers.disallow_non_image_uploads(next_auth, context, data_dict)
