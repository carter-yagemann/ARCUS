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


class InvalidPluginException(Exception):
    pass


loaded = {
    name: importlib.import_module(name)
    for finder, name, ispkg in pkgutil.iter_modules(__path__, __name__ + ".")
}

# validate explorer plugins
for name in loaded:
    module = loaded[name]
    attr_checks = [("explorer", type)]

    for attr, attr_type in attr_checks:
        if not hasattr(module, attr):
            raise InvalidPluginException(
                "%s missing required attribute: %s" % (name, attr)
            )
        if not isinstance(getattr(module, attr), attr_type):
            raise InvalidPluginException(
                "Attribute %s in %s must be %s, found %s"
                % (attr, name, str(attr_type), str(type(getattr(module, attr))))
            )
