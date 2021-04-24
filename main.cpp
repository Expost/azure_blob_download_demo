#include <stdio.h>
#include <string.h>

#include <string>

#include <openssl/hmac.h>
#include <curl/curl.h>

std::string get_ms_date();
std::string azure_sign(const std::string &url,
                       const std::string &ms_date,
                       const std::string &ms_version,
                       const std::string &account_name,
                       const std::string &account_key);

struct FileBuf
{
  char *buf_;
  uint32_t len_;
  uint32_t capacity_;
};

int write_data(void *buffer, size_t size, size_t nmemb, void *file_buf)
{
  int recv_bytes = 0;
  FileBuf *buf = (FileBuf *)(file_buf);

  if (buf != NULL)
  {
    recv_bytes = size * nmemb;

    if (buf->len_ + recv_bytes >= buf->capacity_)
    {
      printf("recv size[%u] + [%u] is bigger than %u",
             recv_bytes,
             buf->len_,
             buf->capacity_);
      return -1;
    }

    memcpy(buf->buf_ + buf->len_, (char *)buffer, recv_bytes);
    buf->len_ += recv_bytes;
  }

  return recv_bytes;
}

int main()
{
  char url[] = "xxx";
  char account_name[] = "xxx";
  char account_key[] = "xxx";

  CURL *curl_handle = curl_easy_init();
  if (!curl_handle)
  {
    printf("curl init failed");
    return -1;
  }

  FileBuf file_buf;
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &write_data);
  file_buf.len_ = 0;
  file_buf.buf_ = new char[4096];
  file_buf.capacity_ = 4096;

  struct curl_slist *headers = nullptr;

  std::string ms_date = get_ms_date();
  std::string ms_version = "2018-11-09"; // 常量
  std::string authorization = azure_sign(url,
                                         ms_date,
                                         ms_version,
                                         account_name,
                                         account_key);

  headers = curl_slist_append(headers, ("x-ms-date: " + ms_date).c_str());
  headers = curl_slist_append(headers, ("x-ms-version: " + ms_version).c_str());
  headers = curl_slist_append(headers, ("Authorization: " + authorization).c_str());
  curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, headers);

  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&file_buf);
  // disable ssl verify to CA
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, false);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, false);
  curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
  curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 3);
  curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 20);

  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 5);
  char errbuf[CURL_ERROR_SIZE];
  curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errbuf);

  CURLcode curl_result = curl_easy_perform(curl_handle);

  long response_code;
  curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &response_code);

  if (headers != nullptr)
  {
    curl_slist_free_all(headers);
  }

  printf("curl_result:%d, response_code:%d\n", curl_result, response_code);
  printf("data:\n%s\n", file_buf.buf_);

  curl_easy_cleanup(curl_handle);
  return 0;
}