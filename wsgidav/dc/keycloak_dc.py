# -*- coding: utf-8 -*-
# (c) 2009-2023 Martin Wendt and contributors; see WsgiDAV https://github.com/mar10/wsgidav
# Licensed under the MIT license: http://www.opensource.org/licenses/mit-license.php
"""
Implementation of a domain controller that allows users to authenticate against
a Keycloak OIDC.

"""

from keycloak import KeycloakOpenID


from wsgidav import util
from wsgidav.dc.base_dc import BaseDomainController

__docformat__ = "reStructuredText" 
_logger = util.get_module_logger(__name__)


class KeycloakDomainController(BaseDomainController):
    def __init__(self, wsgidav_app, config):
        print(config)
        super().__init__(wsgidav_app, config) 
        
        dc_cfg = util.get_dict_value(config, "keycloak_dc", as_dict=True)

        self.openid = KeycloakOpenID(server_url=dc_cfg.get("OIDC_OP_BASE")+"/auth/",
                                 client_id=dc_cfg.get("OIDC_RP_CLIENT_ID"),
                                 realm_name=dc_cfg.get("REALM"),
                                 verify=False,
                                 client_secret_key=dc_cfg.get("OIDC_RP_CLIENT_SECRET"))
        self.realm=dc_cfg.get("REALM")
        self.config=config

    def __str__(self):
        return f"{self.__class__.__name__}"

    def get_domain_realm(self, path_info, environ):
        return self.realm

    def require_authentication(self, realm, environ):
        return True
        
    def bearer_auth_user(self, access_token, environ):
        try:
            cfg = util.get_dict_value(self.config, "dev", as_dict=True)
            if cfg.get("token") and cfg["token"]==access_token: 
                return dict(email="devmode")
            # TODO: cache accesskey 
            userinfo = self.openid.userinfo(access_token)
            #print(userinfo)
            _logger.debug(f"User {userinfo} logged on.")
            return userinfo
        except Exception as  ex:
            _logger.warning(
                    f"keycloak.authenticate {str(ex)}"
            )
            return False

    def basic_auth_user(self, realm, user_name, password, environ):
        cfg = util.get_dict_value(self.config, "dev", as_dict=True)
        return (user_name==cfg.get("user") and password==cfg.get("password"))

    def supports_http_digest_auth(self):
        # We don't have access to a plaintext password (or stored hash)
        return False
