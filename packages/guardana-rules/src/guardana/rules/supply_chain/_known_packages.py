"""Curated allowlist of common top-level import names for well-known PyPI distributions.

Used by HallucinatedPackageRule to reduce false positives: this is not an
exhaustive PyPI mirror, just the popular ML/data/web packages a Guardana
target is likely to legitimately depend on. It is deliberately paired with
`installed_import_names()` — a package importable in the scanning environment
demonstrably exists, so the static list only has to cover what a target might
depend on *without* having it installed.
"""

from functools import cache
from importlib.metadata import packages_distributions

KNOWN_DISTRIBUTIONS: frozenset[str] = frozenset(
    {
        "torch",
        "torchvision",
        "torchaudio",
        "numpy",
        "pandas",
        "scipy",
        "sklearn",
        "transformers",
        "datasets",
        "tokenizers",
        "accelerate",
        "diffusers",
        "huggingface_hub",
        "sentencepiece",
        "safetensors",
        "onnx",
        "onnxruntime",
        "tensorflow",
        "keras",
        "jax",
        "jaxlib",
        "flax",
        "requests",
        "httpx",
        "urllib3",
        "aiohttp",
        "yaml",
        "toml",
        "pydantic",
        "fastapi",
        "starlette",
        "uvicorn",
        "flask",
        "django",
        "click",
        "typer",
        "rich",
        "tqdm",
        "attrs",
        "packaging",
        "setuptools",
        "wheel",
        "pytest",
        "boto3",
        "botocore",
        "sqlalchemy",
        "redis",
        "pillow",
        "PIL",
        "matplotlib",
        "seaborn",
        "networkx",
        "nltk",
        "spacy",
        "gensim",
        "openai",
        "anthropic",
        "langchain",
        "llama_index",
        "dotenv",
        "jinja2",
        "cryptography",
        "jsonschema",
        "defusedxml",
        # Common import names whose distribution name differs — the single largest
        # false-positive source on real ML repos (import name ≠ PyPI name).
        "bs4",  # beautifulsoup4
        "jwt",  # PyJWT
        "cv2",  # opencv-python
        "fitz",  # pymupdf
        "docx",  # python-docx
        "pptx",  # python-pptx
        "psycopg2",  # psycopg2-binary
        "psycopg",  # psycopg[binary]
        "sklearn_crfsuite",  # sklearn-crfsuite
        "sentence_transformers",  # sentence-transformers
        "pydantic_settings",  # pydantic-settings
        "prometheus_client",  # prometheus-client
        "rank_bm25",  # rank-bm25
        "dateutil",  # python-dateutil
        "yaml_include",  # pyyaml-include
        "google",  # google-* namespace (google-cloud-*, google-generativeai)
        "grpc",  # grpcio
        "OpenSSL",  # pyOpenSSL
        "dns",  # dnspython
        "serial",  # pyserial
        "usb",  # pyusb
        "win32api",  # pywin32
        # Widely-used ML / data / infra / web libraries, by import name.
        "peft",
        "trl",
        "bitsandbytes",
        "vllm",
        "einops",
        "xformers",
        "deepspeed",
        "optimum",
        "timm",
        "evaluate",
        "wandb",
        "mlflow",
        "tensorboard",
        "gradio",
        "streamlit",
        "tiktoken",
        "litellm",
        "cohere",
        "mistralai",
        "ollama",
        "groq",
        "together",
        "replicate",
        "langsmith",
        "langgraph",
        "llama_cpp",
        "instructor",
        "outlines",
        "faiss",
        "chromadb",
        "qdrant_client",
        "pinecone",
        "weaviate",
        "lancedb",
        "pyarrow",
        "polars",
        "duckdb",
        "openpyxl",
        "xlsxwriter",
        "h5py",
        "zarr",
        "pymongo",
        "asyncpg",
        "aiomysql",
        "pymysql",
        "psutil",
        "orjson",
        "ujson",
        "msgpack",
        "regex",
        "structlog",
        "loguru",
        "sentry_sdk",
        "celery",
        "kombu",
        "aiofiles",
        "websockets",
        "sqlmodel",
        "alembic",
        "sqlparse",
        "graphql",
        "strawberry",
        "gunicorn",
        "werkzeug",
        "markupsafe",
        "itsdangerous",
        "authlib",
        "passlib",
        "bcrypt",
        "jose",  # python-jose
        "jsonpath_ng",
        "yarl",
        "multidict",
        "tenacity",
        "backoff",
        "cachetools",
        "diskcache",
        "joblib",
        "dill",
        "cloudpickle",
        "pytest_asyncio",
        "hypothesis",
        "faker",
        "freezegun",
        "responses",
        "respx",
        "moto",
        "docker",
        "kubernetes",
        "boto",
        "s3fs",
        "gcsfs",
        "fsspec",
        "smart_open",
        "paramiko",
        "pytz",
        "tzdata",
        "humanize",
        "emoji",
        "unidecode",
        "ftfy",
        "chardet",
        "charset_normalizer",
        "certifi",
        "idna",
        "six",
        "typing_extensions",
        "importlib_metadata",
        "google_auth",
        "protobuf",
        "grpcio",
        "pyparsing",
        "more_itertools",
        "toolz",
        "wrapt",
        "decorator",
    }
)


@cache
def installed_import_names() -> frozenset[str]:
    """Top-level import names of every distribution installed in the scanning env.

    A package that is actually importable here demonstrably exists on an index,
    so it cannot be a *hallucinated* (non-existent) one — folding these in
    removes the rule's largest false-positive source (import name ≠ distribution
    name) without ever weakening the check: a name that does not exist can never
    appear in this set. Cached because the environment does not change mid-scan.
    """
    return frozenset(packages_distributions())
