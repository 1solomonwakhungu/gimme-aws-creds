"""Tests for bounded, DTD-free parsing of IdP-supplied SAML assertions."""
import base64
import os
import tempfile
import textwrap
import unittest
from unittest import mock

from gimme_aws_creds import common, errors
from gimme_aws_creds.alibaba_cloud import AlibabaCloudClient
from gimme_aws_creds.common import SamlAssertionError, parse_saml_role_attributes
from gimme_aws_creds.default import DefaultResolver

AWS_ROLE_ATTRIBUTE = 'https://aws.amazon.com/SAML/Attributes/Role'

ROLE_ADMIN = ('arn:aws:iam::123456789012:saml-provider/Okta,'
              'arn:aws:iam::123456789012:role/Admin')
ROLE_READ = ('arn:aws:iam::210987654321:saml-provider/Okta,'
             'arn:aws:iam::210987654321:role/ReadOnly')

VALID_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol"
                 xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                 ID="id1" Version="2.0">
  <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">http://idp.example.test</saml2:Issuer>
  <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="id2" Version="2.0">
    <ds:Signature>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>TUlJQ0VYQU1QTEU=</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>
    <saml2:AttributeStatement>
      <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/Role">
        <saml2:AttributeValue>{admin}</saml2:AttributeValue>
        <saml2:AttributeValue>
          {read}
        </saml2:AttributeValue>
        <saml2:AttributeValue>   </saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName">
        <saml2:AttributeValue>user&amp;name&#64;example.test</saml2:AttributeValue>
      </saml2:Attribute>
      <saml2:Attribute Name="cdata">
        <saml2:AttributeValue><![CDATA[a<b]]></saml2:AttributeValue>
      </saml2:Attribute>
    </saml2:AttributeStatement>
  </saml2:Assertion>
</saml2p:Response>'''.format(admin=ROLE_ADMIN, read=ROLE_READ)

SAML_NS = 'xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion"'


def b64(text):
    if isinstance(text, str):
        text = text.encode('utf-8')
    return base64.b64encode(text).decode('ascii')


def nested_document(depth):
    """Return a document whose deepest element sits at the given depth (root is 1)."""
    attribute = ('<saml2:Attribute Name="{}"><saml2:AttributeValue>{}</saml2:AttributeValue>'
                 '</saml2:Attribute>').format(AWS_ROLE_ATTRIBUTE, ROLE_ADMIN)
    wrappers = depth - 3  # root + Attribute + AttributeValue
    return '<saml2:Response {}>{}{}{}</saml2:Response>'.format(
        SAML_NS, '<w>' * wrappers, attribute, '</w>' * wrappers)


class TestValidAssertions(unittest.TestCase):

    def test_extracts_values_in_order_and_skips_blank(self):
        self.assertEqual(
            list(parse_saml_role_attributes(b64(VALID_RESPONSE), AWS_ROLE_ATTRIBUTE)),
            [ROLE_ADMIN, ROLE_READ])

    def test_predefined_and_character_references_and_cdata(self):
        self.assertEqual(
            list(parse_saml_role_attributes(
                b64(VALID_RESPONSE), 'https://aws.amazon.com/SAML/Attributes/RoleSessionName')),
            ['user&name@example.test'])
        self.assertEqual(list(parse_saml_role_attributes(b64(VALID_RESPONSE), 'cdata')), ['a<b'])

    def test_accepts_bytes_and_line_wrapped_base64(self):
        wrapped = '\n'.join(textwrap.wrap(b64(VALID_RESPONSE), 76))
        for encoded in (wrapped, wrapped.encode('ascii'), bytearray(wrapped, 'ascii')):
            self.assertEqual(
                list(parse_saml_role_attributes(encoded, AWS_ROLE_ATTRIBUTE)),
                [ROLE_ADMIN, ROLE_READ])

    def test_non_utf8_declared_encoding(self):
        doc = VALID_RESPONSE.replace('UTF-8', 'ISO-8859-1').replace('Admin', 'Admïn')
        self.assertEqual(
            list(parse_saml_role_attributes(b64(doc.encode('iso-8859-1')), AWS_ROLE_ATTRIBUTE))[0],
            ROLE_ADMIN.replace('Admin', 'Admïn'))

    def test_assertion_at_size_limit_is_accepted(self):
        prefix = '<saml2:Response {}><saml2:Attribute Name="r"><saml2:AttributeValue>'.format(SAML_NS)
        suffix = '</saml2:AttributeValue></saml2:Attribute></saml2:Response>'
        filler = 'x' * (common.MAX_SAML_ASSERTION_XML_BYTES - len(prefix) - len(suffix))
        values = list(parse_saml_role_attributes(b64(prefix + filler + suffix), 'r'))
        self.assertEqual(len(values[0]), len(filler))

    def test_nesting_at_depth_limit_is_accepted(self):
        doc = nested_document(common.MAX_SAML_XML_DEPTH)
        self.assertEqual(list(parse_saml_role_attributes(b64(doc), AWS_ROLE_ATTRIBUTE)), [ROLE_ADMIN])

    def test_callers_still_build_roles(self):
        roles = DefaultResolver()._enumerate_saml_roles(b64(VALID_RESPONSE), 'https://signin.aws.amazon.com/saml')
        self.assertEqual([r.role for r in roles], ['arn:aws:iam::123456789012:role/Admin',
                                                   'arn:aws:iam::210987654321:role/ReadOnly'])


class TestRejectedAssertions(unittest.TestCase):

    def assertRejected(self, encoded, fragment):
        with self.assertRaises(SamlAssertionError) as ctx:
            parse_saml_role_attributes(encoded, AWS_ROLE_ATTRIBUTE)
        self.assertIn(fragment, ctx.exception.message)
        return ctx.exception

    def test_error_is_cli_error_without_assertion_content(self):
        exc = self.assertRejected(b64('<saml2:Response {}>SECRET-MARKER'.format(SAML_NS)), 'malformed XML')
        self.assertIsInstance(exc, errors.GimmeAWSCredsError)
        self.assertEqual(exc.return_code, 1)
        self.assertNotIn('SECRET-MARKER', exc.message)

    def test_rejection_happens_before_iteration(self):
        # The function must fail on call, not lazily on first next().
        with self.assertRaises(SamlAssertionError):
            parse_saml_role_attributes(b64('<?xml version="1.0"?><!DOCTYPE r []><r/>'), AWS_ROLE_ATTRIBUTE)

    def test_encoded_size_limit_checked_before_decoding(self):
        encoded = 'A' * (common.MAX_SAML_ASSERTION_B64_CHARS + 1)
        with mock.patch.object(common.base64, 'b64decode') as decode:
            self.assertRejected(encoded, 'encoded size')
        decode.assert_not_called()

    def test_decoded_size_limit_checked_before_parsing(self):
        encoded = b64(b' ' * (common.MAX_SAML_ASSERTION_XML_BYTES + 1))
        self.assertLessEqual(len(encoded), common.MAX_SAML_ASSERTION_B64_CHARS)
        with mock.patch.object(common.xml.parsers.expat, 'ParserCreate') as create, \
                mock.patch.object(common.ET, 'fromstring') as fromstring:
            self.assertRejected(encoded, 'decoded size')
        create.assert_not_called()
        fromstring.assert_not_called()

    def test_limits_are_read_at_call_time(self):
        with mock.patch.object(common, 'MAX_SAML_ASSERTION_XML_BYTES', 100):
            self.assertRejected(b64(VALID_RESPONSE), 'decoded size')
        with mock.patch.object(common, 'MAX_SAML_ASSERTION_B64_CHARS', 100):
            self.assertRejected(b64(VALID_RESPONSE), 'encoded size')

    def test_invalid_base64(self):
        self.assertRejected('abc', 'invalid base64')
        self.assertRejected('éééé', 'invalid base64')

    def test_non_text_input(self):
        self.assertRejected(None, 'expected base64 text')
        self.assertRejected(12345, 'expected base64 text')

    def test_malformed_xml(self):
        self.assertRejected(b64(''), 'malformed XML')
        self.assertRejected(b64('<a><b></a>'), 'malformed XML')
        self.assertRejected(b64('<saml2:a>unbound prefix</saml2:a>'), 'malformed XML')

    def test_undeclared_entity_reference(self):
        self.assertRejected(b64('<r {}>&custom;</r>'.format(SAML_NS)), 'malformed XML')

    def test_nesting_beyond_limit(self):
        self.assertRejected(b64(nested_document(common.MAX_SAML_XML_DEPTH + 1)), 'nesting exceeds')

    def test_deep_nesting_stops_early(self):
        depth = 100000
        doc = '<a>' * depth + '</a>' * depth
        with mock.patch.object(common.ET, 'fromstring') as fromstring:
            self.assertRejected(b64(doc), 'nesting exceeds')
        fromstring.assert_not_called()

    def test_doctype_without_entities(self):
        self.assertRejected(b64('<!DOCTYPE r><r/>'), 'declarations are not allowed')

    def test_internal_entity_expansion(self):
        lol = '<!ENTITY a0 "lol">' + ''.join(
            '<!ENTITY a{} "{}">'.format(i, '&a{};'.format(i - 1) * 10) for i in range(1, 10))
        doc = '<?xml version="1.0"?><!DOCTYPE r [{}]><r {}><saml2:Attribute Name="{}">' \
              '<saml2:AttributeValue>&a9;</saml2:AttributeValue></saml2:Attribute></r>'.format(
                  lol, SAML_NS, AWS_ROLE_ATTRIBUTE)
        with mock.patch.object(common.ET, 'fromstring') as fromstring:
            self.assertRejected(b64(doc), 'declarations are not allowed')
        fromstring.assert_not_called()

    def test_external_entity_is_not_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            secret = os.path.join(tmp, 'secret.txt')
            with open(secret, 'w') as handle:
                handle.write('FILE-MARKER')
            uri = 'file://' + secret.replace(os.sep, '/')
            doc = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{}">]>'
                   '<r {}><saml2:Attribute Name="{}"><saml2:AttributeValue>&x;</saml2:AttributeValue>'
                   '</saml2:Attribute></r>').format(uri, SAML_NS, AWS_ROLE_ATTRIBUTE)
            exc = self.assertRejected(b64(doc), 'declarations are not allowed')
            self.assertNotIn('FILE-MARKER', exc.message)

    def test_external_dtd_and_parameter_entities(self):
        self.assertRejected(b64('<!DOCTYPE r SYSTEM "http://127.0.0.1:9/x.dtd"><r/>'),
                            'declarations are not allowed')
        self.assertRejected(b64('<!DOCTYPE r [<!ENTITY % p SYSTEM "http://127.0.0.1:9/p">%p;]><r/>'),
                            'declarations are not allowed')

    def test_callers_surface_rejection(self):
        doctype = b64('<!DOCTYPE r><r/>')
        with self.assertRaises(SamlAssertionError):
            DefaultResolver()._enumerate_saml_roles(doctype, 'https://signin.aws.amazon.com/saml')
        with self.assertRaises(SamlAssertionError):
            AlibabaCloudClient.enumerate_saml_roles(doctype)


if __name__ == '__main__':
    unittest.main()
