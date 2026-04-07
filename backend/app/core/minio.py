from minio import Minio
from minio.error import S3Error
from app.core.config import settings

minio_client: Minio = None


def get_minio() -> Minio:
    global minio_client
    if minio_client is None:
        minio_client = Minio(
            settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=False,
        )
    return minio_client


async def init_minio():
    client = get_minio()
    bucket_name = settings.MINIO_BUCKET
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)


async def upload_log_file(file_name: str, data: bytes) -> str:
    client = get_minio()
    bucket_name = settings.MINIO_BUCKET
    try:
        client.put_object(
            bucket_name,
            file_name,
            data,
            length=len(data),
        )
        return f"s3://{bucket_name}/{file_name}"
    except S3Error as e:
        raise Exception(f"Failed to upload file: {e}")
