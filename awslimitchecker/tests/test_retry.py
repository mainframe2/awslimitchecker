"""
awslimitchecker/tests/test_retry.py

The latest version of this package is available at:
<https://github.com/jantman/awslimitchecker>

################################################################################
Copyright 2015 Jason Antman <jason@jasonantman.com> <http://www.jasonantman.com>

    This file is part of awslimitchecker, also known as awslimitchecker.

    awslimitchecker is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    awslimitchecker is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with awslimitchecker.  If not, see <http://www.gnu.org/licenses/>.

The Copyright and Authors attributions contained herein may not be removed or
otherwise altered, except to add the Author attribution of a contributor to
this work. (Additional Terms pursuant to Section 7b of the AGPL v3)
################################################################################
While not legally required, I sincerely request that anyone who finds
bugs please submit them at <https://github.com/jantman/awslimitchecker> or
to me via email, and that you send any contributions or improvements
either as a pull request on GitHub, or to me via email.
################################################################################

AUTHORS:
Jason Antman <jason@jasonantman.com> <http://www.jasonantman.com>
################################################################################
"""

from awslimitchecker.services.vpc import _VpcService
from awslimitchecker.tests.support import RetryTests
import sys
import boto3
import os
from botocore.exceptions import ClientError
import pytest

# https://code.google.com/p/mock/issues/detail?id=249
# py>=3.4 should use unittest.mock not the mock package on pypi
if (
        sys.version_info[0] < 3 or
        sys.version_info[0] == 3 and sys.version_info[1] < 4
):
    from mock import patch, call, Mock, PropertyMock
else:
    from unittest.mock import patch, call, Mock, PropertyMock


pbm = 'awslimitchecker.connectable'
pb = '%s.Connectable' % pbm


class Retrier(object):
    """side effect to return different responsed based on the number of times
    called"""

    def __init__(self, expected_body, fail_resp, ok_resp, num_fails):
        """

        :param expected_body: The request body to expect (otherwise return None)
        :type expected_body: str
        :param fail_resp: response to return up to num_fails
        :param ok_resp: response to return after num_fails
        :param num_fails: number of times to fail
        :type num_fails: int
        """
        self.expected_body = expected_body
        self.fail_resp = fail_resp
        self.ok_resp = ok_resp
        self.num_fails = num_fails
        self.count = 0

    def se_send(self, request, verify=True, stream=True, proxies=[], timeout=10):
        if request.body != self.expected_body:
            return None
        self.count += 1
        if self.count <= self.num_fails:
            return self.fail_resp
        return self.ok_resp


class TestRetry(object):

    def test_vpc_success(self):
        retrier = Retrier(
            'Action=DescribeVpcs&Version=2015-10-01',
            None,
            RetryTests.describe_vpcs_1,
            0
        )
        mock_sess = Mock()
        mock_sess.send.side_effect = retrier.se_send
        with patch.dict(
            'os.environ',
            {
                'AWS_ACCESS_KEY_ID': 'AKIAZZZZZZZZZZZZZZZZ',
                'AWS_SECRET_ACCESS_KEY': '2pzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzm7'
            },
            clear=True
        ):
            s = _VpcService(75, 90, region='us-east-1')
            s.connect()
            s.conn._endpoint.http_session = mock_sess
            s._find_usage_vpcs()
        assert s.limits['VPCs'].get_current_usage_str() == '1'
        assert len(mock_sess.mock_calls) == 1
        # first arg to first call should be a PreparedRequest
        req = mock_sess.mock_calls[0][1][0]
        assert req.body == 'Action=DescribeVpcs&Version=2015-10-01'
        assert req.url == 'https://ec2.us-east-1.amazonaws.com/'
        assert req.method == 'POST'
        assert 'Authorization' in req.headers
        assert 'Signature=' in req.headers['Authorization']

    def record_events(self, **kwargs):
        self._events.append(kwargs)

    def test_vpc_request_limit(self):
        retrier = Retrier(
            'Action=DescribeVpcs&Version=2015-10-01',
            RetryTests.describe_vpcs_rate_limit,
            RetryTests.describe_vpcs_1,
            4
        )
        mock_sess = Mock()
        mock_sess.send.side_effect = retrier.se_send
        self._events = []
        with patch.dict(
            'os.environ',
            {
                'AWS_ACCESS_KEY_ID': 'AKIAZZZZZZZZZZZZZZZZ',
                'AWS_SECRET_ACCESS_KEY': '2pzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzm7'
            },
            clear=True
        ):
            boto3._get_default_session().events.register('*', self.record_events)
            s = _VpcService(75, 90, region='us-east-1')
            s.connect()
            s.conn._endpoint.http_session = mock_sess
            with pytest.raises(ClientError) as excinfo:
                s._find_usage_vpcs()
        # this looks wrong....
        # NOTE - right now we're asserting on the current behavior, not what
        #   we want
        assert len(mock_sess.mock_calls) == 1
        # first arg to first call should be a PreparedRequest
        req = mock_sess.mock_calls[0][1][0]
        assert req.body == 'Action=DescribeVpcs&Version=2015-10-01'
        assert req.url == 'https://ec2.us-east-1.amazonaws.com/'
        assert req.method == 'POST'
        assert 'Authorization' in req.headers
        assert 'Signature=' in req.headers['Authorization']
        events = [x['event_name'] for x in self._events]
        assert events == [
            'creating-client-class.ec2',
            'provide-client-params.ec2.DescribeVpcs',
            'before-parameter-build.ec2.DescribeVpcs',
            'before-call.ec2.DescribeVpcs',
            'request-created.ec2.DescribeVpcs',
            'choose-signer.ec2.DescribeVpcs',
            'before-sign.ec2.DescribeVpcs',
            'needs-retry.ec2.DescribeVpcs',
            'after-call.ec2.DescribeVpcs'
        ]
        assert s.limits['VPCs'].get_current_usage_str() == '<unknown>'

    def test_vpc_throttling(self):
        retrier = Retrier(
            'Action=DescribeVpcs&Version=2015-10-01',
            RetryTests.describe_vpcs_throttling,
            RetryTests.describe_vpcs_1,
            4
        )
        mock_sess = Mock()
        mock_sess.send.side_effect = retrier.se_send

        self._events = []
        with patch.dict(
            'os.environ',
            {
                'AWS_ACCESS_KEY_ID': 'AKIAZZZZZZZZZZZZZZZZ',
                'AWS_SECRET_ACCESS_KEY': '2pzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzm7'
            },
            clear=True
        ):
            boto3._get_default_session().events.register('*', self.record_events)
            s = _VpcService(75, 90, region='us-east-1')
            s.connect()
            s.conn._endpoint.http_session = mock_sess
            s._find_usage_vpcs()
        # this looks wrong....
        # NOTE - right now we're asserting on the current behavior, not what
        #   we want
        assert len(mock_sess.mock_calls) == 5
        # first arg to first call should be a PreparedRequest
        req = mock_sess.mock_calls[0][1][0]
        assert req.body == 'Action=DescribeVpcs&Version=2015-10-01'
        assert req.url == 'https://ec2.us-east-1.amazonaws.com/'
        assert req.method == 'POST'
        assert 'Authorization' in req.headers
        assert 'Signature=' in req.headers['Authorization']
        events = [str(x['event_name']) for x in self._events]
        assert events == [
            'creating-client-class.ec2',
            'provide-client-params.ec2.DescribeVpcs',
            'before-parameter-build.ec2.DescribeVpcs',
            'before-call.ec2.DescribeVpcs',
            # first request
            'request-created.ec2.DescribeVpcs',
            'choose-signer.ec2.DescribeVpcs',
            'before-sign.ec2.DescribeVpcs',
            'needs-retry.ec2.DescribeVpcs',
            'request-created.ec2.DescribeVpcs',
            'choose-signer.ec2.DescribeVpcs',
            'before-sign.ec2.DescribeVpcs',
            'needs-retry.ec2.DescribeVpcs',
            'request-created.ec2.DescribeVpcs',
            'choose-signer.ec2.DescribeVpcs',
            'before-sign.ec2.DescribeVpcs',
            'needs-retry.ec2.DescribeVpcs',
            'request-created.ec2.DescribeVpcs',
            'choose-signer.ec2.DescribeVpcs',
            'before-sign.ec2.DescribeVpcs',
            'needs-retry.ec2.DescribeVpcs',
            'request-created.ec2.DescribeVpcs',
            'choose-signer.ec2.DescribeVpcs',
            'before-sign.ec2.DescribeVpcs',
            'needs-retry.ec2.DescribeVpcs',
            'after-call.ec2.DescribeVpcs',
        ]
        assert s.limits['VPCs'].get_current_usage_str() == '1'
