"""Fixed V1 check catalogue."""

from rift.engine.checks import authn, authz, config

CHECKS = {
    authn.IDENTIFIER: authn.run,
    authz.IDENTIFIER: authz.run,
    config.IDENTIFIER: config.run,
}
CHECK_VERSION = "1.0"

__all__ = ["CHECKS", "CHECK_VERSION"]
