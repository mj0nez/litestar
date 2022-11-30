# Request Data

For http requests except `GET` requests, you can access the request body by specifying the `data` kwarg in your
handler function or method:

```python
from starlite import post
from pydantic import BaseModel


class User(BaseModel):
    ...


@post(path="/user")
async def create_user(data: User) -> User:
    ...
```

The type of `data` does not need to be a pydantic model - it can be any supported type, e.g. a dataclass, or a
[`TypedDict`][typing.TypedDict]:

```python
from starlite import post
from dataclasses import dataclass


@dataclass()
class User:
    ...


@post(path="/user")
async def create_user(data: User) -> User:
    ...
```

It can also be simple types such as `str`, `dict` etc. or classes supported by [plugins](/usage/10-plugins/0-plugins-intro.md).


## The Body Function

You can use the `Body` function to customize the OpenAPI documentation for the request body schema or to control its validation:

```python
from starlite import Body, post
from pydantic import BaseModel


class User(BaseModel):
    ...


@post(path="/user")
async def create_user(
    data: User = Body(title="Create User", description="Create a new user.")
) -> User:
    ...
```

See the [API Reference][starlite.params.Body] for full details on the `Body` function and the kwargs it accepts.


## URL Encoded Form Data

To access data sent as [url-encoded form data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST),
i.e. `application/x-www-form-urlencoded` Content-Type header, use [`Body`][starlite.params.Body] and specify
[`RequestEncodingType.URL_ENCODED`][starlite.enums.RequestEncodingType] as the `media_type`:

```python
from starlite import Body, post, RequestEncodingType
from pydantic import BaseModel


class User(BaseModel):
    ...


@post(path="/user")
async def create_user(
    data: User = Body(media_type=RequestEncodingType.URL_ENCODED),
) -> User:
    ...
```

The above ensures that Starlite will inject data using the request.form() method rather than request.json() and set the correct media-type in the OpenAPI schema.

!!! important
    url encoded data is inherently less versatile than JSON data - for example, it cannot handle complex
    dictionaries and deeply nested data. It should only be used for simple data structures.


## MultiPart Form Data

Multipart formdata supports complex data including file uploads and nested dictionaries.

!!! note
    Starlite uses a dedicated library for parsing multipart data - [starlite-multipart](https://github.com/starlite-api/starlite-multipart),
    which offers strong performance and supports large file uploads.

You can access data uploaded using a request with a [`multipart/form-data`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/POST) Content-Type header by specifying it in
the [`Body`][starlite.params.Body] function:

```python
from starlite import Body, RequestEncodingType, post
from pydantic import BaseModel


class User(BaseModel):
    ...


@post(path="/user")
async def create_user(
    data: User = Body(media_type=RequestEncodingType.MULTI_PART),
) -> User:
    ...
```

### Accessing Files

In case of files uploaded, Starlite transforms the results into an instance
of [`UploadFile`][starlite.datastructures.UploadFile] class, which offer a convenient
interface for working with files. Therefore, you need to type your file uploads accordingly.

To access a single file simply type `data` as `UploadFile`:

```python
from starlite import Body, UploadFile, RequestEncodingType, post


@post(path="/file-upload")
async def handle_file_upload(
    data: UploadFile = Body(media_type=RequestEncodingType.MULTI_PART),
) -> None:
    ...
```

To access multiple files with known filenames, you can use a pydantic model:

```python
from pydantic import BaseModel, BaseConfig
from starlite import Body, RequestEncodingType, UploadFile, post


class FormData(BaseModel):
    cv: UploadFile
    image: UploadFile

    class Config(BaseConfig):
        arbitrary_types_allowed = True


@post(path="/file-upload")
async def handle_file_upload(
    data: FormData = Body(media_type=RequestEncodingType.MULTI_PART),
) -> None:
    ...
```

If you do not care about parsing and validation and only want to access the form data as a dictionary, you can use a `dict` instead:

```python
from starlite import Body, RequestEncodingType, UploadFile, post


@post(path="/file-upload")
async def handle_file_upload(
    data: dict[str, UploadFile] = Body(media_type=RequestEncodingType.MULTI_PART)
) -> None:
    ...
```

Finally, you can also access the files as a list without the filenames:

```python
from starlite import Body, RequestEncodingType, UploadFile, post


@post(path="/file-upload")
async def handle_file_upload(
    data: list[UploadFile] = Body(media_type=RequestEncodingType.MULTI_PART),
) -> None:
    ...
```


## MessagePack data

To receive `MessagePack` data, you can either specify the appropriate `Content-Type`
with `Body`,  or set the `Content-Type` header of the request to `application/x-msgpack`.

```py title="msgpack_request.py"
--8<-- "examples/request_data/msgpack_request.py"
```
