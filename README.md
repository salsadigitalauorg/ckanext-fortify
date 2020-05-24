# ckanext-fortify

A suite of features to make your CKAN instance a little bit more secure.

## Installation

1. Clone this repository into your extension directory, e.g.

    ```
    cd /usr/lib/ckan/default/src
    python setup.py develop
    ```

## Configuration

Add the `fortify` extension to `ckan.plugins` in your CKAN `.ini` file:

    ckan.plugins = ... fortify ...

Enable each feature through the `ckan.plugins` config setting in your CKAN `.ini` file: 

### Force uploaded HTML resource files to download  

    ckan.fortify.force_html_resource_downloads = True

Defaults to False.

### Check a user belongs to parent organisation when adding child organisation

    ckan.fortify.check_parent_org_allowed = True

Defaults to False.

### Add an anti-CSRF token to all forms and important action buttons

    ckan.fortify.enable_anti_csrf_tokens = True

Defaults to False.

### Add a password policy to CKAN

    ckan.fortify.enable_password_policy = True

Defaults to False.

    ckan.fortify.password_policy.min_length = 12

Defaults to 12

    ckan.fortify.password_policy.allow_repeated_chars = True

Defaults to true (i.e. sequentially repeating characters allowed in passwords)
