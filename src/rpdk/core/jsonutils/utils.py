from collections.abc import Mapping, Sequence

from .pointer import fragment_encode


class FlatteningError(Exception):
    pass


class ConstraintError(FlatteningError, ValueError):
    def __init__(self, message, path, *args):
        self.path = fragment_encode(path)
        message = message.format(*args, path=self.path)
        super().__init__(message)


class CircularRefError(ConstraintError):
    def __init__(self, path):
        super().__init__("Detected circular reference at '{path}'", path)


class BaseRefPlaceholder:
    """A sentinel object representing a reference inside the base document."""

    def __repr__(self):
        """Readable representation for debugging.

        >>> repr(BaseRefPlaceholder())
        '<BASE>'
        """
        return "<BASE>"


#: The sentinel instance representing a reference inside the base document.
BASE = BaseRefPlaceholder()


def rewrite_ref(ref):
    """Rewrite a reference to be inside of the base document. A relative JSON
    pointer is returned (in URI fragment identifier representation).

    If the reference is already inside the base document (:const:`BASE`), the parts
    are simply encoded into a pointer.

    If the reference is outside of the base document, a unique pointer inside
    the base document is made by namespacing the reference under the remote base
    name inside the remote section.

    >>> rewrite_ref((BASE, "foo", "bar"))
    '#/foo/bar'
    >>> rewrite_ref((BASE,))
    '#'
    >>> rewrite_ref(("remote", "foo", "bar"))
    '#/remote/remote/foo/bar'
    >>> rewrite_ref(("remote",))
    '#/remote/remote'
    """
    base, *parts = ref
    if base is not BASE:
        parts = ["remote", base] + parts
    return fragment_encode(parts)


def traverse(document, path_parts):
    """Traverse the document according to the reference.

    Since the document is presumed to be the reference's base, the base is
    discarded. There is no validation that the reference is valid.

    :raises ValueError, LookupError: the reference is invalid for this document

    >>> traverse({"foo": {"bar": [42]}}, tuple())
    ({'foo': {'bar': [42]}}, (), None)
    >>> traverse({"foo": {"bar": [42]}}, ["foo"])
    ({'bar': [42]}, ('foo',), {'foo': {'bar': [42]}})
    >>> traverse({"foo": {"bar": [42]}}, ("foo", "bar"))
    ([42], ('foo', 'bar'), {'bar': [42]})
    >>> traverse({"foo": {"bar": [42]}}, ("foo", "bar", "0"))
    (42, ('foo', 'bar', 0), [42])
    >>> traverse({}, ["foo"])
    Traceback (most recent call last):
    ...
    KeyError: 'foo'
    >>> traverse([], ["foo"])
    Traceback (most recent call last):
    ...
    ValueError: invalid literal for int() with base 10: 'foo'
    >>> traverse([], [0])
    Traceback (most recent call last):
    ...
    IndexError: list index out of range
    """
    parent = None
    path = []
    for part in path_parts:
        if isinstance(document, Sequence):
            part = int(part)
        parent = document
        document = document[part]
        path.append(part)
    return document, tuple(path), parent


def schema_merge(target, src, path):
    """Merges the src schema into the target schema in place.

    If there are duplicate keys, src will overwrite target.

    :raises TypeError: either schema is not of type dict
    :raises ConstraintError: the schema tries to override "type" or "$ref"

    >>> schema_merge({}, {}, ())
    {}
    >>> schema_merge({'foo': 'a'}, {}, ())
    {'foo': 'a'}
    >>> schema_merge({}, {'foo': 'a'}, ())
    {'foo': 'a'}
    >>> schema_merge({'foo': 'a'}, {'foo': 'b'}, ())
    {'foo': 'b'}
    >>> a = {'foo': {'a': {'aa': 'a', 'bb': 'b'}}, 'bar': 1}
    >>> b = {'foo': {'a': {'aa': 'a', 'cc': 'c'}}}
    >>> schema_merge(a, b, ())
    {'foo': {'a': {'aa': 'a', 'bb': 'b', 'cc': 'c'}}, 'bar': 1}
    >>> a = {'type': {'a': 'aa'}, '$ref': {'a': 'aa'}}
    >>> b = {'type': {'a': 'bb'}, '$ref': {'a': 'bb'}}
    >>> schema_merge(a, b, ())
    {'type': {'a': 'bb'}, '$ref': {'a': 'bb'}}
    >>> schema_merge({'type': 'a'}, {'type': 'b'}, ()) # doctest: +NORMALIZE_WHITESPACE
    Traceback (most recent call last):
    ...
    core.jsonutils.utils.ConstraintError:
    Object at path '#' declared multiple values for 'type': found 'a' and 'b'
    >>> a, b = {'$ref': 'a'}, {'$ref': 'b'}
    >>> schema_merge(a, b, ('foo',)) # doctest: +NORMALIZE_WHITESPACE
    Traceback (most recent call last):
    ...
    core.jsonutils.utils.ConstraintError:
    Object at path '#/foo' declared multiple values for '$ref': found 'a' and 'b'
    >>> a, b = {'Foo': {'$ref': 'a'}}, {'Foo': {'$ref': 'b'}}
    >>> schema_merge(a, b, ('foo',)) # doctest: +NORMALIZE_WHITESPACE
    Traceback (most recent call last):
    ...
    core.jsonutils.utils.ConstraintError: Object at path '#/foo/Foo'
    declared multiple values for '$ref': found 'a' and 'b'
    >>> schema_merge('', {}, ())
    Traceback (most recent call last):
    ...
    TypeError: Both schemas must be dictionaries
    >>> schema_merge({}, 1, ())
    Traceback (most recent call last):
    ...
    TypeError: Both schemas must be dictionaries
    >>> schema_merge({'required': 'a'}, {'required': 'b'}, ())
    {'required': ['a', 'b']}
    """
    if not (isinstance(target, Mapping) and isinstance(src, Mapping)):
        raise TypeError("Both schemas must be dictionaries")
    for key, src_schema in src.items():
        try:
            target_schema = target[key]
        except KeyError:
            target[key] = src_schema
        else:
            next_path = path + (key,)
            try:
                target[key] = schema_merge(target_schema, src_schema, next_path)
            except TypeError:
                if key == "required":
                    target[key] = sorted(set(target_schema) | set(src_schema))
                else:
                    if key in ("type", "$ref") and target_schema != src_schema:
                        msg = (
                            "Object at path '{path}' declared multiple values "
                            "for '{}': found '{}' and '{}'"
                        )
                        raise ConstraintError(msg, path, key, target_schema, src_schema)
                    target[key] = src_schema
    return target
