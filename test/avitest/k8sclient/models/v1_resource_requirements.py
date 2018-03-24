

############################################################################
#
# AVI CONFIDENTIAL
# __________________
#
# [2013] - [2018] Avi Networks Incorporated
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property
# of Avi Networks Incorporated and its suppliers, if any. The intellectual
# and technical concepts contained herein are proprietary to Avi Networks
# Incorporated, and its suppliers and are covered by U.S. and Foreign
# Patents, patents in process, and are protected by trade secret or
# copyright law, and other laws. Dissemination of this information or
# reproduction of this material is strictly forbidden unless prior written
# permission is obtained from Avi Networks Incorporated.
###

# coding: utf-8

"""
Copyright 2016 SmartBear Software

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

    Ref: https://github.com/swagger-api/swagger-codegen
"""

from pprint import pformat
from six import iteritems
import re


class V1ResourceRequirements(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        V1ResourceRequirements - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'limits': 'object',
            'requests': 'object'
        }

        self.attribute_map = {
            'limits': 'limits',
            'requests': 'requests'
        }

        self._limits = None
        self._requests = None

    @property
    def limits(self):
        """
        Gets the limits of this V1ResourceRequirements.
        Limits describes the maximum amount of compute resources allowed. More info: http://releases.k8s.io/HEAD/docs/design/resources.md#resource-specifications

        :return: The limits of this V1ResourceRequirements.
        :rtype: object
        """
        return self._limits

    @limits.setter
    def limits(self, limits):
        """
        Sets the limits of this V1ResourceRequirements.
        Limits describes the maximum amount of compute resources allowed. More info: http://releases.k8s.io/HEAD/docs/design/resources.md#resource-specifications

        :param limits: The limits of this V1ResourceRequirements.
        :type: object
        """
        
        self._limits = limits

    @property
    def requests(self):
        """
        Gets the requests of this V1ResourceRequirements.
        Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. More info: http://releases.k8s.io/HEAD/docs/design/resources.md#resource-specifications

        :return: The requests of this V1ResourceRequirements.
        :rtype: object
        """
        return self._requests

    @requests.setter
    def requests(self, requests):
        """
        Sets the requests of this V1ResourceRequirements.
        Requests describes the minimum amount of compute resources required. If Requests is omitted for a container, it defaults to Limits if that is explicitly specified, otherwise to an implementation-defined value. More info: http://releases.k8s.io/HEAD/docs/design/resources.md#resource-specifications

        :param requests: The requests of this V1ResourceRequirements.
        :type: object
        """
        
        self._requests = requests

    def to_dict(self):
        """
        Returns the model properties as a dict
        """
        result = {}

        for attr, _ in iteritems(self.swagger_types):
            value = getattr(self, attr)
            if isinstance(value, list):
                result[attr] = list(map(
                    lambda x: x.to_dict() if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                result[attr] = value.to_dict()
            elif isinstance(value, dict):
                result[attr] = dict(map(
                    lambda item: (item[0], item[1].to_dict())
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[attr] = value

        return result

    def to_str(self):
        """
        Returns the string representation of the model
        """
        return pformat(self.to_dict())

    def __repr__(self):
        """
        For `print` and `pprint`
        """
        return self.to_str()

    def __eq__(self, other):
        """
        Returns true if both objects are equal
        """
        return self.__dict__ == other.__dict__

    def __ne__(self, other):
        """
        Returns true if both objects are not equal
        """
        return not self == other
