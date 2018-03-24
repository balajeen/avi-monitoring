

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


class V1ComponentCondition(object):
    """
    NOTE: This class is auto generated by the swagger code generator program.
    Do not edit the class manually.
    """
    def __init__(self):
        """
        V1ComponentCondition - a model defined in Swagger

        :param dict swaggerTypes: The key is attribute name
                                  and the value is attribute type.
        :param dict attributeMap: The key is attribute name
                                  and the value is json key in definition.
        """
        self.swagger_types = {
            'type': 'str',
            'status': 'str',
            'message': 'str',
            'error': 'str'
        }

        self.attribute_map = {
            'type': 'type',
            'status': 'status',
            'message': 'message',
            'error': 'error'
        }

        self._type = None
        self._status = None
        self._message = None
        self._error = None

    @property
    def type(self):
        """
        Gets the type of this V1ComponentCondition.
        Type of condition for a component. Valid value: \"Healthy\"

        :return: The type of this V1ComponentCondition.
        :rtype: str
        """
        return self._type

    @type.setter
    def type(self, type):
        """
        Sets the type of this V1ComponentCondition.
        Type of condition for a component. Valid value: \"Healthy\"

        :param type: The type of this V1ComponentCondition.
        :type: str
        """
        
        self._type = type

    @property
    def status(self):
        """
        Gets the status of this V1ComponentCondition.
        Status of the condition for a component. Valid values for \"Healthy\": \"True\", \"False\", or \"Unknown\".

        :return: The status of this V1ComponentCondition.
        :rtype: str
        """
        return self._status

    @status.setter
    def status(self, status):
        """
        Sets the status of this V1ComponentCondition.
        Status of the condition for a component. Valid values for \"Healthy\": \"True\", \"False\", or \"Unknown\".

        :param status: The status of this V1ComponentCondition.
        :type: str
        """
        
        self._status = status

    @property
    def message(self):
        """
        Gets the message of this V1ComponentCondition.
        Message about the condition for a component. For example, information about a health check.

        :return: The message of this V1ComponentCondition.
        :rtype: str
        """
        return self._message

    @message.setter
    def message(self, message):
        """
        Sets the message of this V1ComponentCondition.
        Message about the condition for a component. For example, information about a health check.

        :param message: The message of this V1ComponentCondition.
        :type: str
        """
        
        self._message = message

    @property
    def error(self):
        """
        Gets the error of this V1ComponentCondition.
        Condition error code for a component. For example, a health check error code.

        :return: The error of this V1ComponentCondition.
        :rtype: str
        """
        return self._error

    @error.setter
    def error(self, error):
        """
        Sets the error of this V1ComponentCondition.
        Condition error code for a component. For example, a health check error code.

        :param error: The error of this V1ComponentCondition.
        :type: str
        """
        
        self._error = error

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

