import requests
import logging
import os
from io import BytesIO
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
logger.addHandler(logging.StreamHandler())

def get_virustotal_positives(api_key: str, file_hash: str, proxy: dict) -> int:
    """
    Retrieves the count of malicious detections for a specific file from VirusTotal using the requests library.

    Args:
        api_key (str): The API key used to authenticate with the VirusTotal API.
        file_hash (str): The hash of the file (MD5, SHA1, or SHA256) to query for detections.

    Returns:
        int: The number of malicious detections found for the file. Returns -1 if an error occurs.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers, proxies=proxy)
        if response.ok:
            file_analysis = response.json()
            logger.info(file_analysis)
            logger.info(f"VirusTotal response: {str(response.json().get('data').get('id'))}")
            return (
                file_analysis.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
                .get("malicious", 0)
            )
        else:
            if response.status_code == 404:
                logging.info(f"Not found querying VirusTotal: {' '.join(response.text.split(os.linesep))}")
            else:
                logging.error(f"Error querying VirusTotal: {' '.join(response.text.split(os.linesep))}")

            return -1
    except Exception as e:
        logging.error(f"Exception querying VirusTotal: {e}")
        return -1

def download_vt_bytes(api_key: str, file_hash: str, proxy: dict) -> BytesIO:
    """
    Downloads a file from VirusTotal and returns it as a byte stream using the requests library.

    Args:
        api_key (str): The API key for accessing VirusTotal.
        file_hash (str): The hash of the file to be downloaded.

    Returns:
        BytesIO: A buffer containing the downloaded file.

    Raises:
        Exception: If the download fails.
    """
    download_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/download"
    headers = {"x-apikey": api_key}

    response = requests.get(download_url, headers=headers, stream=True, proxies=proxy)

    if response.ok:
        file_buffer = BytesIO(response.content)
        return file_buffer
    else:
        error_msg = f"Error downloading file from VirusTotal: {response.text}"
        logging.error(error_msg)
        raise Exception(error_msg)

if __name__ == "__main__":
    proxy = {
        "http": "http://192.168.2.2:7890",
        "https": "http://192.168.2.2:7890",
    }
    api_key = "231f774bcc014e4fcb03213822ff5b2d93502545d614b825ea036eecfb583baa"
    file_hash = "209a288c68207d57e0ce6e60ebf60729"
    # print(get_virustotal_positives(api_key, file_hash, proxy))
    with open("test.exe", "wb") as f:
        f.write(download_vt_bytes(api_key, file_hash, proxy).getbuffer())