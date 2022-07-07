#!/usr/bin/env python
#
# Copyright 2019 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import importlib
import pkgutil

from angr import SimProcedure


class InvalidPluginException(Exception):
    pass


loaded = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules(__path__, __name__ + ".")
}

# validate hook plugins
for name in loaded:
    module = loaded[name]
    if not hasattr(module, "is_main_object") or not isinstance(
        module.is_main_object, bool
    ):
        raise InvalidPluginException(
            "%s must have the boolean attribute 'is_main_object'" % name
        )
    if not hasattr(module, "hook_condition"):
        raise InvalidPluginException(
            "%s missing required attribute: hook_condition" % name
        )
    if not isinstance(module.hook_condition, tuple) or len(module.hook_condition) != 2:
        raise InvalidPluginException(
            "%s.hook_condition must contain two elements: (str, dict)" % name
        )
    if not isinstance(module.hook_condition[0], str):
        raise InvalidPluginException(
            "%s.hook_condition[0] must be a string representing the object's name"
            % name
        )
    if not isinstance(module.hook_condition[1], dict):
        raise InvalidPluginException(
            "%s.hook_condition[1] must be a dictionary of hooks" % name
        )
    for hook_name in module.hook_condition[1]:
        hook_func = module.hook_condition[1][hook_name]
        if not isinstance(hook_name, str):
            raise InvalidPluginException(
                "%s's dictionary contains invalid key: %s" % (name, hook_name)
            )
