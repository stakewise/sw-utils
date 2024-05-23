import pytest
from sw_utils.common import urljoin

def test_urljoin_basic():
    assert urljoin('http://example.com', 'path') == 'http://example.com/path'
    assert urljoin('http://example.com/', 'path') == 'http://example.com/path'
    assert urljoin('http://example.com', 'path1', 'path2') == 'http://example.com/path1/path2'
    assert urljoin('http://example.com/', 'path1', 'path2') == 'http://example.com/path1/path2'

def test_urljoin_with_query():
    assert urljoin('http://example.com?query=1', 'path') == 'http://example.com/path?query=1'
    assert urljoin('http://example.com/?query=1', 'path') == 'http://example.com/path?query=1'
    assert urljoin('http://example.com?query=1', 'path1', 'path2') == 'http://example.com/path1/path2?query=1'
    assert urljoin('http://example.com/?query=1', 'path1', 'path2') == 'http://example.com/path1/path2?query=1'

def test_urljoin_with_fragment():
    assert urljoin('http://example.com#fragment', 'path') == 'http://example.com/path#fragment'
    assert urljoin('http://example.com/#fragment', 'path') == 'http://example.com/path#fragment'
    assert urljoin('http://example.com#fragment', 'path1', 'path2') == 'http://example.com/path1/path2#fragment'
    assert urljoin('http://example.com/#fragment', 'path1', 'path2') == 'http://example.com/path1/path2#fragment'

def test_urljoin_edge_cases():
    assert urljoin('http://example.com', '') == 'http://example.com'
    assert urljoin('http://example.com/', '') == 'http://example.com/'
    assert urljoin('http://example.com', '/', '/') == 'http://example.com/'
    assert urljoin('http://example.com/', '/', '/') == 'http://example.com/'
    assert urljoin('http://example.com//', 'path') == 'http://example.com/path'
    assert urljoin('http://example.com/', '//path') == 'http://example.com/path'
