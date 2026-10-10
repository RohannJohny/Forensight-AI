if __name__ == "__main__":
    import urllib.request

    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="evidence_type"\r\n\r\n'
        f"DISK_IMAGE\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="Acquired_WS_FIN_04_Image.E01"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
        f"EXPERT_WITNESS_E01_FORENSIC_RAW_HEADER_CHECKSUM_OK\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    req = urllib.request.Request(
        "http://localhost:8000/api/cases/68622688-0bc8-4bbd-bf63-679dbeefdafa/evidence/upload",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"}
    )

    try:
        with urllib.request.urlopen(req) as res:
            print("Status:", res.status)
            print("Body:", res.read().decode())
    except Exception as e:
        print("Upload request error:", e)
