"""VULN: CWE-798 — AWS access keys hardcoded as module-level constants."""
import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def upload_to_s3(bucket: str, local_file: str) -> None:
    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name="us-east-1",
    )
    s3 = session.client("s3")
    s3.upload_file(local_file, bucket, local_file)
