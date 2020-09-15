#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# The MIT License (MIT)
#
# Copyright (c) 2017 Matthew Pare (paretech@gmail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from klvdata.common import hexstr_to_bytes
from klvdata.element import UnknownElement
from klvdata.elementparser import BytesElementParser
from klvdata.misb0601 import UASLocalMetadataSet
from klvdata.setparser import SetParser
from klvdata.elementparser import StringElementParser

_classifying_country_coding = {
    b'\x01': 'ISO-3166 Two Letter',
    b'\x02': 'ISO-3166 Three Letter',
    b'\x03': 'FIPS 10-4 Two Letter',
    b'\x04': 'FIPS 10-4 Four Letter',
    b'\x05': 'ISO-3166 Numeric',
    b'\x06': '1059 Two Letter',
    b'\x07': '1059 Three Letter',
    b'\x08': 'Omitted Value',
    b'\x09': 'Omitted Value',
    b'\x0A': 'FIPS 10-4 Mixed',
    b'\x0B': 'ISO 3166 Mixed',
    b'\x0C': 'STANAG 1059 Mixed',
    b'\x0D': 'GENC Two Letter',
    b'\x0E': 'GENC Three Letter',
    b'\x0F': 'GENC Numeric',
    b'\x10': 'GENC Mixed',
}


_object_country_coding = {
    b'\x01': 'ISO-3166 Two Letter',
    b'\x02': 'ISO-3166 Three Letter',
    b'\x03': 'ISO-3166 Numeric',
    b'\x04': 'FIPS 10-4 Two Letter',
    b'\x05': 'FIPS 10-4 Four Letter',
    b'\x06': '1059 Two Letter',
    b'\x07': '1059 Three Letter',
    b'\x08': 'Omitted Value',
    b'\x09': 'Omitted Value',
    b'\x0A': 'Omitted Value',
    b'\x0B': 'Omitted Value',
    b'\x0C': 'Omitted Value',
    b'\x0D': 'GENC Two Letter',
    b'\x0E': 'GENC Three Letter',
    b'\x0F': 'GENC Numeric',
    b'\x40': 'GENC AdminSub',
}


class UnknownElement(UnknownElement):  # pylint: disable=function-redefined
    """ Class UnkknownElement
    """


@UASLocalMetadataSet.add_parser
class SecurityLocalMetadataSet(SetParser):
    """MISB ST0102 Security Metadata nested local set parser.
    The Security Metdata set comprise information needed to
    comply with CAPCO, DoD Information Security Program and
    other normatively referenced security directives.
    Must be a subclass of Element or duck type Element.
    """
    key, name = b'\x30', "Security Local Metadata Set"
    key_length = 1
    TAG = 48
    UDSKey = hexstr_to_bytes('06 0E 2B 34 - 02 03 01 01 – 0E 01 03 03 - 02 00 00 00')
    LDSName = "Security Local Metadata Set"
    ESDName = ""
    UDSName = ""

    parsers = {}

    _unknown_element = UnknownElement


@SecurityLocalMetadataSet.add_parser
class ClassifyingCountry(StringElementParser):
    """
    This metadata element contains a value for the classifying country code preceded by a double
    slash "//."
    Example of classifying country: //CZE (Example of GENC code)
                                    //GB (Example of ISO-3166 code)
    """
    key = b'\x03'
    TAG = 3
    UDSKey = "-"
    LDSName = "Classifying Country"
    ESDName = "Classifying Country"
    UDSName = "Classifying Country"


@SecurityLocalMetadataSet.add_parser
class ClassifyingCountryAndReleasingInstructionsCountryCodingMethod(BytesElementParser):
    """
    This is the effective date (promulgation date) of the source (FIPS 10-4, ISO 3166, GENC 2.0, or
    STANAG 1059) used for the Object Country Coding Method. Since ISO 3166 is updated by
    dated circulars, not by version revision, the ISO 8601 YYYY-MM-DD formatted date is used.
    All remaining security metadata elements are optional unless specific additional requirements
    are levied on a system. If a system is required to implement any of the additional security
    metadata elements in this standard, they shall be implemented as described by this standard.
    Implementations are always encouraged to include as complete a security metadata set as
    possible.
    """
    key = b'\x02'

    TAG = 2
    UDSKey = ""
    LDSName = "Classifying Country And Releasing Instructions Country Coding Method"
    ESDName = "Classifying Country And Releasing Instructions Country Coding Method"
    UDSName = "Classifying Country And Releasing Instructions Country Coding Method"

    _classification = _classifying_country_coding


@SecurityLocalMetadataSet.add_parser
class ObjectCountryCodingMethod(BytesElementParser):
    """
    This metadata element identifies the coding method for the Object Country Code (Par. 6.1.13)
    metadata. The Object Country Coding Method allows use of FIPS 10-4 two-letter or four-letter
    alphabetic country code (legacy systems only); ISO-3166 two-letter, three-letter, or
    three-digit numeric; STANAG 1059 two-letter or three-letter codes; and GENC two-letter,
    three-letter,three-digit numeric or administrative subdivisions. Use of this element in version
    6 of this Standard and later is mandatory. In version 5 and earlier, it was optional; its
    absence indicates that the default GENC two-letter coding method was used in the Object Country
    Code element. See also Section 6.9
    """
    key = b'\x0C'
    TAG = 12
    UDSKey = "-"
    LDSName = "Object Country Coding Method"
    ESDName = "Object Country Coding Method"
    UDSName = "Object Country Coding Method"

    _classification = _object_country_coding


@SecurityLocalMetadataSet.add_parser
class ObjectCountryCodes(StringElementParser):
    """
    This metadata element contains a value identifying the country (or countries) that is the
    object of the video or metadata in the transport stream or file.
    """
    key = b'\x0D'
    TAG = 13
    UDSKey = "-"
    LDSName = "Object Country Codes"
    ESDName = "Object Country Codes"
    UDSName = "Object Country Codes"


@SecurityLocalMetadataSet.add_parser
class SecurityClassification(BytesElementParser):
    """MISB ST0102 Security Classification value interpretation parser.
    The Security Classification metadata element contains a value
    representing the entire security classification of the file in
    accordance with U.S. and NATO classification guidance.
    """
    key = b'\x01'
    TAG = 1
    UDSKey = "-"
    LDSName = "Security Classification"
    ESDName = "Security Classification"
    UDSName = "Security Classification"

    _classification = {
        b'\x01': 'UNCLASSIFIED',
        b'\x02': 'RESTRICTED',
        b'\x03': 'CONFIDENTIAL',
        b'\x04': 'SECRET',
        b'\x05': 'TOP SECRET',
    }


@SecurityLocalMetadataSet.add_parser
class Version(BytesElementParser):
    """
    The version number of the Security Metadata Universal and Local Set for Digital Motion
    Imagery is indicated via the Version Key.
    """
    key = b'\x16'
    TAG = 22
    UDSKey = "-"
    LDSName = 'Version'
    ESDName = "Version"
    UDSName = "Version"


@SecurityLocalMetadataSet.add_parser
class Caveats(BytesElementParser):
    """
    This metadata element set contains a value representing all pertinent caveats (or code words)
    from each category of the appropriate security entity register. Entries in this field may be
    abbreviated or spelled out as free text [22] entries.
    """
    key = b'\x05'

    TAG = 5
    UDSKey = ""
    LDSName = "Caveats"
    ESDName = "Caveats"
    UDSName = "Caveats"
