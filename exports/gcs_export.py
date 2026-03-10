#!/usr/bin/env python3
"""
Google Cloud Storage export for DAST scan results.
Uploads scan results as a gzipped tarball in RapiDAST format:
  gs://{bucket}/{directory}/{timestamp}-RapiDAST-{app_name}-{random}.tgz
"""

import datetime
import os
import random
import re
import string
import tarfile
from io import BytesIO

from google.cloud import storage


def _sanitize_filename(filename: str) -> str:
    """Allow only [a-zA-Z0-9.-_] characters for safe filenames."""
    return re.sub(r"[^a-zA-Z0-9.-]+", "_", filename)


class GoogleCloudStorage:
    """
    Sends the scan results to a Google Cloud Storage bucket.
    Blob naming matches RapiDAST format for compatibility.
    """

    def __init__(self, bucket_name, app_name, directory=None, keyfile=None):
        if keyfile:
            client = storage.Client.from_service_account_json(keyfile)
        else:
            client = storage.Client()
        try:
            self.bucket = client.get_bucket(bucket_name)
        except Exception as e:
            raise RuntimeError(f"Failed to get GCS bucket '{bucket_name}': {e}") from e

        self.directory = directory or f"RapiDAST-{_sanitize_filename(app_name)}"
        self.app_name = app_name

    def export_scan(self, result_dir_name):
        """
        Send the scan results to GCS.
        The results are sent as a tar file containing the results directory.
        Blob format: {directory}/{timestamp}-RapiDAST-{app_name}-{random}.tgz

        Args:
            result_dir_name: path to the directory containing scan results
        """
        if not result_dir_name:
            raise RuntimeError("GoogleCloudStorage: result_dir_name is not specified")

        result_dir_name = str(result_dir_name)
        if not os.path.isdir(result_dir_name):
            raise RuntimeError(f"GoogleCloudStorage: result_dir not found: {result_dir_name}")

        print(f"  Uploading to GCS: {result_dir_name}")

        # Create tar containing the directory and its contents
        tar_stream = BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
            tar.add(
                name=result_dir_name,
                arcname=os.path.basename(result_dir_name.rstrip("/")),
            )
        tar_stream.seek(0)

        # Generate blob filename (RapiDAST format)
        unique_id = "{}-RapiDAST-{}-{}.tgz".format(
            datetime.datetime.now(tz=datetime.timezone.utc).isoformat(),
            _sanitize_filename(self.app_name),
            "".join(random.choices(string.ascii_letters + string.ascii_uppercase + string.digits, k=6)),
        )
        blob_name = self.directory.rstrip("/") + "/" + unique_id

        # Push to GCS
        blob = self.bucket.blob(blob_name)
        with blob.open(mode="wb") as dest:
            dest.write(tar_stream.getbuffer())

        gcs_path = f"gs://{self.bucket.name}/{blob_name}"
        print(f"  [OK] Results exported to {gcs_path}")
        return gcs_path
