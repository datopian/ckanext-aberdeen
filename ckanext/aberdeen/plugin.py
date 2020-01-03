import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from ckanext.aberdeen import actions


class AberdeenPlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    plugins.implements(plugins.IActions)

    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, 'templates')
        toolkit.add_public_directory(config_, 'public')
        toolkit.add_resource('fanstatic', 'aberdeen')

    # IActions
    def get_actions(self):
        '''
        Define custom functions (or ovveride existing ones).
        Availbale via API /api/action/{action-name}
        '''
        return {
            'organization_delete': actions.organization_delete,
            'group_delete': actions.group_delete,
            'organization_purge': actions.organization_purge,
            'group_purge': actions.group_purge,
            'inactive_users': actions.inactive_users,
            'send_inactive_users_email': actions.send_inactive_users_email
        }
